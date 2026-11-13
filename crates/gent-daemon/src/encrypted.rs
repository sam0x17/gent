//! Native MLS persistence. Configuration authority can share the live RPC store;
//! encrypted agent-message delivery and remote transport remain separate work.
//!
//! Callers are trusted daemon code, never MCP agents. Node authentication here
//! does not grant permission to communicate as an agent. Initial authority and
//! expected group membership must come from authenticated local state.
//! New caller-selected operation IDs use UUIDv4 or deterministic UUIDv8. UUIDv7
//! is reserved for daemon allocations; unknown UUIDv7 IDs cannot initiate work.
//! Retained legacy retries remain valid regardless of UUID version.
pub mod history;
pub mod ordered;
mod requests;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gent_crypto::{Checkpoint, NodeIdentity, SignedState, TrustAnchor, VerifiedState};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::ErrorKind,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use uuid::Uuid;

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_WIRE_BYTES: usize = 2 * 1024 * 1024;
const MAX_MEMBERS: usize = 16;
const MAX_KEY_PACKAGE_BYTES: usize = 16 * 1024;

#[derive(Default)]
struct JsonCodec;
impl Codec for JsonCodec {
    type Error = serde_json::Error;
    fn to_vec<T: Serialize>(value: &T) -> std::result::Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }
    fn from_slice<T: serde::de::DeserializeOwned>(
        bytes: &[u8],
    ) -> std::result::Result<T, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

struct Provider<'a> {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, &'a Connection>,
}
impl<'a> Provider<'a> {
    fn new(db: &'a Connection) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: SqliteStorageProvider::new(db),
        }
    }
}
impl<'a> OpenMlsProvider for Provider<'a> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, &'a Connection>;
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}

/// Ciphertext or an MLS Welcome. Public key packages are a separate, private
/// enrollment artifact and must not be published as unencrypted metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub id: Uuid,
    pub group_id: Vec<u8>,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Received {
    Application { id: Uuid, sender: String },
    ConfigurationPart { revision: u64, complete: bool },
    Commit,
    Duplicate,
}

/// Plaintext in trusted local storage. Intentionally no Debug implementation.
pub struct InboxMessage {
    pub id: Uuid,
    pub sender: String,
    pub body: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u32,
    cluster: String,
    node: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    id: Uuid,
    body: String,
}

pub struct EncryptedEndpoint<'a> {
    db: Connection,
    identity: &'a NodeIdentity,
}

impl<'a> EncryptedEndpoint<'a> {
    pub fn authority_state(&self) -> Result<VerifiedState> {
        authority(&self.db, self.identity)
    }

    pub fn open(home: &Path, identity: &'a NodeIdentity) -> Result<Self> {
        let db = open_database(home, "mls.sqlite3")?;
        Ok(Self { db, identity })
    }

    /// One-time bootstrap from independently authenticated authority. Opening an
    /// existing database cannot replace its pin, checkpoint, or node identity.
    pub fn initialize(&mut self, state: &VerifiedState, now: u64) -> Result<()> {
        state.authorize_node(self.identity.id(), &self.identity.public_key(), now)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        initialize_authority(&tx, self.identity, state)?;
        tx.commit()?;
        Ok(())
    }

    /// Authority updates may advance through expired history. Every cryptographic
    /// operation still requires fresh authority. Revoked nodes can save the update.
    pub fn apply_authority(&mut self, updates: &[SignedState]) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut state = authority(&tx, self.identity)?;
        state.advance_history(updates)?;
        persist_authority(&tx, self.identity, &state, updates)?;
        tx.commit()?;
        Ok(())
    }

    // Reload all MLS objects within an immediate transaction. A failed operation
    // drops both the transaction and its in-memory ratchets; a retry must reload.
    fn transact<T>(
        &mut self,
        now: u64,
        operation: impl FnOnce(&Session<'_>) -> Result<T>,
    ) -> Result<T> {
        self.transact_mode(now, false, operation)
    }

    fn transact_mode<T>(
        &mut self,
        now: u64,
        configuration_only: bool,
        operation: impl FnOnce(&Session<'_>) -> Result<T>,
    ) -> Result<T> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = authority(&tx, self.identity)?;
        if configuration_only {
            authorize_saved_node(&state, self.identity.id(), &self.identity.public_key())?;
        } else {
            state.authorize_node(self.identity.id(), &self.identity.public_key(), now)?;
        }
        let session = Session {
            db: &tx,
            provider: Provider::new(&tx),
            state,
            signer: self.identity,
            now,
            configuration_only,
        };
        let result = operation(&session)?;
        tx.commit()?;
        Ok(result)
    }

    /// Generate once and reuse the same public package on transport retries.
    /// Consumed private key packages are deleted by OpenMLS during successful join.
    pub fn key_package(&mut self, request: Uuid, now: u64) -> Result<Vec<u8>> {
        self.transact(now, |session| session.key_package(request))
    }

    /// Create a group with an explicit set of approved nodes. The returned Welcome
    /// and the sender's new group state are committed atomically.
    pub fn create_group(
        &mut self,
        request: Uuid,
        peers: &[(&str, &[u8])],
        now: u64,
    ) -> Result<Outgoing> {
        self.transact(now, |session| session.create_group(request, peers))
    }

    /// The expected roster is a trusted local decision, never a relay assertion.
    pub fn join(&mut self, invitation: &Outgoing, expected: &[&str], now: u64) -> Result<()> {
        self.transact(now, |session| {
            reject_ordered_group(session.db, &invitation.group_id)?;
            session.join(invitation, expected, None)
        })
    }

    /// Idempotent encryption: retrying an ID returns the exact committed wire bytes.
    pub fn send(&mut self, group_id: &[u8], id: Uuid, body: &[u8], now: u64) -> Result<Outgoing> {
        self.transact(now, |session| {
            reject_ordered_group(session.db, group_id)?;
            session.send(group_id, id, body)
        })
    }

    /// Advance the epoch; no previous-epoch secrets are retained in logical state.
    pub fn rotate(&mut self, group_id: &[u8], request: Uuid, now: u64) -> Result<Outgoing> {
        self.transact(now, |session| {
            reject_ordered_group(session.db, group_id)?;
            session.rotate(group_id, request)
        })
    }

    /// Remove every credential no longer authorized by the saved owner state.
    /// A revoked member prevents application sends until this succeeds.
    pub fn remove_revoked(&mut self, group_id: &[u8], request: Uuid, now: u64) -> Result<Outgoing> {
        self.transact(now, |session| {
            reject_ordered_group(session.db, group_id)?;
            session.remove_revoked(group_id, request)
        })
    }

    /// Decrypt into the durable local inbox, committing ratchets and receipts in
    /// the same transaction. Replays never create a second inbox entry.
    pub fn receive(&mut self, group_id: &[u8], wire: &[u8], now: u64) -> Result<Received> {
        self.transact(now, |session| {
            reject_ordered_group(session.db, group_id)?;
            session.receive(group_id, wire, None)
        })
    }

    /// Queued opaque packets in commit order, bounded for transport polling.
    /// Transport must apply current recipient authorization before sending.
    pub fn outbox(&self, after: i64, limit: usize) -> Result<Vec<(i64, Outgoing)>> {
        ensure!((1..=128).contains(&limit), "invalid outbox limit");
        let mut statement = self.db.prepare("SELECT sequence,id,group_id,bytes FROM outbox WHERE sequence>?1 AND (length(bytes)>0 OR EXISTS(SELECT 1 FROM stream_outbox s WHERE s.id=outbox.id AND length(s.packet)>0)) ORDER BY sequence LIMIT ?2")?;
        let rows = statement.query_map(params![after, limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (sequence, id, group_id, bytes) = row?;
            let bytes = ordered::storage::bytes(&self.db, &id, &group_id, bytes)?;
            Ok((
                sequence,
                Outgoing {
                    id: Uuid::parse_str(&id)?,
                    group_id,
                    bytes,
                },
            ))
        })
        .collect()
    }

    /// Trusted local inspection only. Agent policy and revocation must be checked
    /// again before exposing a stored plaintext to an MCP conversation.
    pub fn inbox(
        &self,
        group_id: &[u8],
        after: i64,
        limit: usize,
    ) -> Result<Vec<(i64, InboxMessage)>> {
        ensure!((1..=128).contains(&limit), "invalid inbox limit");
        let mut statement = self.db.prepare("SELECT sequence,id,sender,body FROM inbox WHERE group_id=?1 AND sequence>?2 ORDER BY sequence LIMIT ?3")?;
        let rows = statement.query_map(params![group_id, after, limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (sequence, id, sender, body) = row?;
            Ok((
                sequence,
                InboxMessage {
                    id: Uuid::parse_str(&id)?,
                    sender,
                    body,
                },
            ))
        })
        .collect()
    }
}

fn reject_ordered_group(db: &Connection, group: &[u8]) -> Result<()> {
    let ordered: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM streams WHERE group_id=?1)",
        [group],
        |row| row.get(0),
    )?;
    ensure!(!ordered, "use the ordered stream interface for this group");
    Ok(())
}

pub(crate) fn authority(db: &Connection, signer: &NodeIdentity) -> Result<VerifiedState> {
    let (anchor, checkpoint, state, node, key): (Vec<u8>, Vec<u8>, Vec<u8>, String, Vec<u8>) = db
        .query_row(
        "SELECT anchor,checkpoint,state,node,key FROM authority WHERE singleton=1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    ensure!(
        node == signer.id() && key == signer.public_key(),
        "database belongs to another node key"
    );
    let anchor: TrustAnchor = serde_json::from_slice(&anchor)?;
    let checkpoint: Checkpoint = serde_json::from_slice(&checkpoint)?;
    VerifiedState::restore(anchor, checkpoint, SignedState::decode(&state)?)
}

fn credential(state: &VerifiedState, signer: &NodeIdentity) -> Result<CredentialWithKey> {
    Ok(CredentialWithKey {
        credential: BasicCredential::new(serde_json::to_vec(&Identity {
            version: 1,
            cluster: state.anchor().cluster_id.clone(),
            node: signer.id().into(),
        })?)
        .into(),
        signature_key: signer.public_key().to_vec().into(),
    })
}

fn authenticate(
    state: &VerifiedState,
    credential: &Credential,
    key: &[u8],
    now: u64,
) -> Result<String> {
    state.require_fresh(now)?;
    authenticate_saved(state, credential, key)
}

fn authorize_saved_node(
    state: &VerifiedState,
    node: &str,
    key: &gent_crypto::PublicKey,
) -> Result<()> {
    ensure!(
        state
            .state()
            .nodes
            .get(node)
            .is_some_and(|member| &member.signing_key == key),
        "node unavailable in saved authority"
    );
    Ok(())
}

fn authenticate_saved(
    state: &VerifiedState,
    credential: &Credential,
    key: &[u8],
) -> Result<String> {
    let basic = BasicCredential::try_from(credential.clone())?;
    ensure!(basic.identity().len() <= 256, "credential too large");
    let identity: Identity = serde_json::from_slice(basic.identity())?;
    ensure!(
        identity.version == 1 && identity.cluster == state.anchor().cluster_id,
        "wrong credential scope"
    );
    authorize_saved_node(
        state,
        &identity.node,
        key.try_into().context("invalid signing key length")?,
    )?;
    Ok(identity.node)
}

fn members(
    state: &VerifiedState,
    members: impl Iterator<Item = Member>,
    now: u64,
) -> Result<BTreeSet<String>> {
    members_mode(state, members, now, false)
}

fn members_mode(
    state: &VerifiedState,
    members: impl Iterator<Item = Member>,
    now: u64,
    configuration_only: bool,
) -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    for member in members {
        ensure!(
            ids.len() < MAX_MEMBERS
                && ids.insert(if configuration_only {
                    authenticate_saved(state, &member.credential, &member.signature_key)?
                } else {
                    authenticate(state, &member.credential, &member.signature_key, now)?
                }),
            "invalid group roster"
        );
    }
    ensure!(!ids.is_empty(), "empty group");
    Ok(ids)
}

fn roster(ids: &[&str]) -> Result<BTreeSet<String>> {
    let expected: BTreeSet<_> = ids.iter().map(|id| (*id).to_owned()).collect();
    ensure!(
        (2..=MAX_MEMBERS).contains(&ids.len()) && expected.len() == ids.len(),
        "invalid expected roster"
    );
    Ok(expected)
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .padding_size(256)
        .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::MaxEpochs(0))
        .number_of_resumption_psks(0)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(32, 128))
        .build()
}

fn load_group(provider: &Provider<'_>, id: &[u8]) -> Result<MlsGroup> {
    ensure!(!id.is_empty() && id.len() <= 256, "invalid group ID");
    let group =
        MlsGroup::load(provider.storage(), &GroupId::from_slice(id))?.context("unknown group")?;
    ensure!(group.is_active(), "inactive MLS group");
    Ok(group)
}

fn decode(wire: &[u8]) -> Result<MlsMessageIn> {
    ensure!(
        !wire.is_empty() && wire.len() <= MAX_WIRE_BYTES,
        "invalid MLS wire size"
    );
    Ok(MlsMessageIn::tls_deserialize_exact(wire)?)
}

fn request_hash(domain: &str, input: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"gent/mls-operation/v1\0");
    hash.update(domain);
    hash.update([0]);
    hash.update(input);
    hash.finalize().to_vec()
}

fn retry(db: &Connection, id: Uuid, fingerprint: &[u8]) -> Result<Option<Outgoing>> {
    ensure!(!id.is_nil(), "nil request ID");
    let saved: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT group_id,request_hash,bytes FROM outbox WHERE id=?1",
            [id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if saved.is_none() {
        requests::admit(db, id, fingerprint)?;
    }
    saved
        .map(|(group_id, hash, bytes)| {
            ensure!(hash == fingerprint, "conflicting request ID");
            let bytes = ordered::storage::bytes(db, &id.to_string(), &group_id, bytes)?;
            Ok(Outgoing {
                id,
                group_id,
                bytes,
            })
        })
        .transpose()
}

fn enqueue(
    db: &Connection,
    id: Uuid,
    group_id: &GroupId,
    fingerprint: &[u8],
    bytes: Vec<u8>,
) -> Result<Outgoing> {
    ensure!(
        bytes.len() <= MAX_WIRE_BYTES,
        "outgoing MLS message too large"
    );
    db.execute(
        "INSERT INTO outbox(id,group_id,request_hash,bytes) VALUES(?1,?2,?3,?4)",
        params![id.to_string(), group_id.as_slice(), fingerprint, bytes],
    )?;
    Ok(Outgoing {
        id,
        group_id: group_id.as_slice().to_vec(),
        bytes,
    })
}

fn received(db: &Connection, group_id: &[u8], wire: &[u8]) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM receipts WHERE wire_hash=?1 AND group_id=?2)",
        params![Sha256::digest(wire).as_slice(), group_id],
        |row| row.get(0),
    )?)
}

fn receipt(db: &Connection, group_id: &[u8], wire: &[u8]) -> Result<()> {
    db.execute(
        "INSERT INTO receipts(wire_hash,group_id) VALUES(?1,?2)",
        params![Sha256::digest(wire).as_slice(), group_id],
    )?;
    Ok(())
}

struct Session<'a> {
    db: &'a Connection,
    provider: Provider<'a>,
    state: VerifiedState,
    signer: &'a NodeIdentity,
    now: u64,
    configuration_only: bool,
}
impl Session<'_> {
    fn key_package(&self, request: Uuid) -> Result<Vec<u8>> {
        let db = self.db;
        let provider = &self.provider;
        let state = &self.state;
        let signer = self.signer;
        ensure!(!request.is_nil(), "nil request ID");
        if let Some(bytes) = db
            .query_row(
                "SELECT bytes FROM key_packages WHERE id=?1",
                [request.to_string()],
                |row| row.get(0),
            )
            .optional()?
        {
            return Ok(bytes);
        }
        ensure!(
            !requests::managed(request),
            "UUIDv7 transport IDs cannot create key packages"
        );
        let package =
            KeyPackage::builder().build(SUITE, provider, signer, credential(state, signer)?)?;
        let bytes = package.key_package().tls_serialize_detached()?;
        db.execute(
            "INSERT INTO key_packages VALUES(?1,?2)",
            params![request.to_string(), bytes],
        )?;
        Ok(bytes)
    }
    fn create_group(&self, request: Uuid, peers: &[(&str, &[u8])]) -> Result<Outgoing> {
        let db = self.db;
        let provider = &self.provider;
        let state = &self.state;
        let signer = self.signer;
        let now = self.now;
        ensure!(
            !peers.is_empty() && peers.len() < MAX_MEMBERS,
            "invalid peer count"
        );
        for (_, package) in peers {
            ensure!(
                package.len() <= MAX_KEY_PACKAGE_BYTES,
                "key package too large"
            );
        }
        let fingerprint = request_hash("create", &serde_json::to_vec(peers)?);
        // Revalidate packages before returning a retry, including revocation.
        let mut ids = BTreeSet::from([signer.id().to_owned()]);
        let mut packages = Vec::new();
        for (expected, wire) in peers {
            ensure!(ids.insert((*expected).to_owned()), "duplicate group member");
            let package = KeyPackageIn::tls_deserialize_exact(wire)?
                .validate(provider.crypto(), ProtocolVersion::Mls10)?;
            ensure!(package.ciphersuite() == SUITE, "unsupported ciphersuite");
            let leaf = package.leaf_node();
            let node = authenticate(
                state,
                leaf.credential(),
                leaf.signature_key().as_slice(),
                now,
            )?;
            ensure!(node == *expected, "key package belongs to another node");
            packages.push(package);
        }
        if let Some(packet) = retry(db, request, &fingerprint)? {
            return Ok(packet);
        }
        let config = create_config();
        let mut group = MlsGroup::new(provider, signer, &config, credential(state, signer)?)?;
        let (_, welcome, _) = group.add_members(provider, signer, &packages)?;
        group.merge_pending_commit(provider)?;
        enqueue(
            db,
            request,
            group.group_id(),
            &fingerprint,
            welcome.to_bytes()?,
        )
    }
    fn join(&self, invitation: &Outgoing, expected: &[&str], writer: Option<&str>) -> Result<()> {
        let db = self.db;
        let provider = &self.provider;
        let state = &self.state;
        let signer = self.signer;
        let now = self.now;
        ensure!(
            !invitation.group_id.is_empty() && invitation.group_id.len() <= 256,
            "invalid group ID"
        );
        let expected = roster(expected)?;
        let message = decode(&invitation.bytes)?;
        ensure!(
            expected.contains(signer.id()),
            "own identity missing from expected roster"
        );
        if received(db, &invitation.group_id, &invitation.bytes)? {
            ensure!(
                writer.is_none(),
                "cannot adopt a previously used raw MLS group"
            );
            let group = load_group(provider, &invitation.group_id)?;
            ensure!(
                members(state, group.members(), now)? == expected,
                "unexpected group roster"
            );
            return Ok(());
        }
        ensure!(
            MlsGroup::load(
                provider.storage(),
                &GroupId::from_slice(&invitation.group_id)
            )?
            .is_none(),
            "group already exists"
        );
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            bail!("expected Welcome");
        };
        let staged = StagedWelcome::new_from_welcome(
            provider,
            create_config().join_config(),
            welcome,
            None,
        )?;
        ensure!(
            staged.group_context().group_id().as_slice() == invitation.group_id,
            "wrong group ID"
        );
        ensure!(
            staged.group_context().ciphersuite() == SUITE,
            "unsupported ciphersuite"
        );
        ensure!(
            members(state, staged.members(), now)? == expected,
            "unexpected group roster"
        );
        if let Some(writer) = writer {
            let creator = staged.welcome_sender()?;
            ensure!(
                authenticate(
                    state,
                    creator.credential(),
                    creator.signature_key().as_slice(),
                    now
                )? == writer,
                "Welcome creator is not the stream writer"
            );
        }
        staged.into_group(provider)?;
        receipt(db, &invitation.group_id, &invitation.bytes)?;
        Ok(())
    }
    fn send(&self, group_id: &[u8], id: Uuid, body: &[u8]) -> Result<Outgoing> {
        let db = self.db;
        let provider = &self.provider;
        let state = &self.state;
        let signer = self.signer;
        let now = self.now;
        ensure!(
            !body.is_empty() && body.len() <= MAX_PAYLOAD_BYTES,
            "invalid payload size"
        );
        let fingerprint = request_hash("send", &serde_json::to_vec(&(group_id, body))?);
        let mut group = load_group(provider, group_id)?;
        members_mode(state, group.members(), now, self.configuration_only)?;
        if let Some(packet) = retry(db, id, &fingerprint)? {
            return Ok(packet);
        }
        let envelope = serde_json::to_vec(&Envelope {
            version: 1,
            id,
            body: STANDARD.encode(body),
        })?;
        let bytes = group
            .create_message(provider, signer, &envelope)?
            .to_bytes()?;
        enqueue(db, id, group.group_id(), &fingerprint, bytes)
    }
    fn rotate(&self, group_id: &[u8], request: Uuid) -> Result<Outgoing> {
        let db = self.db;
        let provider = &self.provider;
        let state = &self.state;
        let signer = self.signer;
        let now = self.now;
        let fingerprint = request_hash("rotate", group_id);
        let mut group = load_group(provider, group_id)?;
        members(state, group.members(), now)?;
        if let Some(packet) = retry(db, request, &fingerprint)? {
            return Ok(packet);
        }
        let (commit, _, _) = group
            .self_update(provider, signer, LeafNodeParameters::default())?
            .into_contents();
        group.merge_pending_commit(provider)?;
        enqueue(
            db,
            request,
            group.group_id(),
            &fingerprint,
            commit.to_bytes()?,
        )
    }
    fn remove_revoked(&self, group_id: &[u8], request: Uuid) -> Result<Outgoing> {
        let db = self.db;
        let provider = &self.provider;
        let state = &self.state;
        let signer = self.signer;
        let now = self.now;
        let fingerprint = request_hash("remove", group_id);
        let mut group = load_group(provider, group_id)?;
        if let Some(packet) = retry(db, request, &fingerprint)? {
            return Ok(packet);
        }
        let removed: Vec<_> = group
            .members()
            .filter(|member| {
                authenticate(state, &member.credential, &member.signature_key, now).is_err()
            })
            .map(|member| member.index)
            .collect();
        ensure!(!removed.is_empty(), "no revoked credentials to remove");
        let (commit, _, _) = group.remove_members(provider, signer, &removed)?;
        group.merge_pending_commit(provider)?;
        members(state, group.members(), now)?;
        enqueue(
            db,
            request,
            group.group_id(),
            &fingerprint,
            commit.to_bytes()?,
        )
    }
    fn receive(&self, group_id: &[u8], wire: &[u8], writer: Option<&str>) -> Result<Received> {
        self.receive_with(group_id, wire, writer, |id, sender, body| {
            let runtime: bool = self.db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='network_links')", [], |r| r.get(0))?;
            if runtime {
                let pending: usize = self.db.query_row("SELECT COALESCE(SUM(length(body)),0) FROM inbox WHERE group_id IN (SELECT incoming FROM network_links)", [], |r| r.get(0))?;
                ensure!(pending + body.len() <= crate::messages::MAX_PENDING_BYTES, "pending node-record queue is full");
            }
            self.db.execute(
                "INSERT INTO inbox(group_id,sender,id,body) VALUES(?1,?2,?3,?4)",
                params![group_id, sender, id.to_string(), body],
            )?;
            Ok(Received::Application { id, sender })
        })
    }

    fn receive_with(
        &self,
        group_id: &[u8],
        wire: &[u8],
        writer: Option<&str>,
        handle_application: impl FnOnce(Uuid, String, Vec<u8>) -> Result<Received>,
    ) -> Result<Received> {
        let db = self.db;
        let provider = &self.provider;
        let state = &self.state;
        let now = self.now;
        let message = decode(wire)?;
        let MlsMessageBodyIn::PrivateMessage(private) = message.extract() else {
            bail!("expected encrypted MLS message");
        };
        let mut group = load_group(provider, group_id)?;
        if received(db, group_id, wire)? {
            return Ok(Received::Duplicate);
        }
        let before = group.members().collect::<Vec<_>>();
        let processed = group.process_message(provider, ProtocolMessage::from(private))?;
        let Sender::Member(index) = processed.sender() else {
            bail!("external sender is not allowed");
        };
        let member = before
            .iter()
            .find(|member| member.index == *index)
            .context("sender missing from roster")?;
        let sender = if self.configuration_only {
            authenticate_saved(state, &member.credential, &member.signature_key)?
        } else {
            authenticate(state, &member.credential, &member.signature_key, now)?
        };
        if let Some(writer) = writer {
            ensure!(sender == writer, "MLS sender is not the stream writer");
        }
        let result = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                // Directional backlog may predate another recipient's removal.
                // Its sender and the local receiver must still be authorized;
                // sends under a group containing revoked members remain blocked.
                if writer.is_none() {
                    members(state, before.into_iter(), now)?;
                }
                let bytes = application.into_bytes();
                ensure!(
                    bytes.len() <= MAX_WIRE_BYTES,
                    "application envelope too large"
                );
                let envelope: Envelope = serde_json::from_slice(&bytes)?;
                ensure!(
                    envelope.version == 1 && !envelope.id.is_nil(),
                    "invalid application envelope"
                );
                let body = STANDARD.decode(envelope.body)?;
                ensure!(
                    !body.is_empty() && body.len() <= MAX_PAYLOAD_BYTES,
                    "invalid payload size"
                );
                handle_application(envelope.id, sender, body)?
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                // Existing-group membership additions require a separate approved
                // workflow. This proof accepts refreshes and owner revocations only.
                let expected = before
                    .iter()
                    .filter_map(|member| {
                        authenticate(state, &member.credential, &member.signature_key, now).ok()
                    })
                    .collect::<BTreeSet<_>>();
                group.merge_staged_commit(provider, *commit)?;
                if self.configuration_only {
                    let after: Vec<_> = group.members().collect();
                    ensure!(
                        after.len() == before.len()
                            && after.iter().all(|member| before
                                .iter()
                                .any(|old| old.signature_key == member.signature_key
                                    && old.credential == member.credential)),
                        "configuration stream membership cannot change"
                    );
                } else if writer.is_some() {
                    validate_ordered_transition(state, &before, group.members().collect(), now)?;
                } else {
                    ensure!(
                        members(state, group.members(), now)? == expected,
                        "unapproved membership change"
                    );
                }
                Received::Commit
            }
            _ => bail!("standalone MLS proposals are not supported"),
        };
        receipt(db, group_id, wire)?;
        Ok(result)
    }
}

// A buffered refresh can precede a later owner revocation. Accept that historical
// refresh without letting it add members, replace signing keys, or remove an
// authorized node. Sending still requires every current member to be authorized.
fn validate_ordered_transition(
    state: &VerifiedState,
    before: &[Member],
    after: Vec<Member>,
    now: u64,
) -> Result<()> {
    let mut keys = BTreeSet::new();
    for member in &after {
        ensure!(
            keys.insert(&member.signature_key)
                && before
                    .iter()
                    .any(|old| old.signature_key == member.signature_key
                        && old.credential == member.credential),
            "unapproved stream membership change"
        );
    }
    for member in before {
        if !keys.contains(&member.signature_key) {
            ensure!(
                authenticate(state, &member.credential, &member.signature_key, now).is_err(),
                "cannot remove an authorized stream member"
            );
        }
    }
    Ok(())
}

pub(crate) fn persist_authority(
    db: &Connection,
    identity: &NodeIdentity,
    state: &VerifiedState,
    updates: &[SignedState],
) -> Result<()> {
    // All callers own a transaction. Cleanup may release records required only
    // by peers revoked in this update; a capacity or cleanup failure restores
    // the previous authority together with its history.
    db.execute(
        "UPDATE authority SET checkpoint=?1,state=?2 WHERE singleton=1",
        params![
            serde_json::to_vec(state.checkpoint())?,
            state.signed().encode()?
        ],
    )?;
    history::clean(db, false)?;
    for update in updates {
        let wire = update.encode()?;
        history::capacity(db, wire.len())?;
        history::remember(db, &update.verified_checkpoint(state.anchor())?)?;
        db.execute(
            "INSERT INTO authority_history VALUES(?1,?2)",
            params![update.state.revision, wire],
        )?;
    }
    let runtime: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata')",
        [],
        |row| row.get(0),
    )?;
    if runtime {
        let initialized: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM metadata WHERE key='signed_authority')",
            [],
            |row| row.get(0),
        )?;
        if initialized {
            crate::runtime::queue_projection(db)?;
        }
    }
    // A retired writer can never drain its queue again. Release its pending
    // ciphertext in this same authority transaction so it cannot consume the
    // endpoint's receive quota after revocation or signing-key replacement.
    let own_active = state
        .state()
        .nodes
        .get(identity.id())
        .is_some_and(|member| member.signing_key == identity.public_key());
    if !own_active {
        db.execute("DELETE FROM stream_pending", [])?;
        db.execute("DELETE FROM configuration_fragments", [])?;
    } else {
        let mut query = db.prepare("SELECT group_id,writer,writer_key FROM streams")?;
        let rows = query.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        for row in rows {
            let (group, writer, key) = row?;
            if !state
                .state()
                .nodes
                .get(&writer)
                .is_some_and(|member| member.signing_key.as_slice() == key)
            {
                db.execute("DELETE FROM stream_pending WHERE group_id=?1", [&group])?;
                db.execute(
                    "DELETE FROM configuration_fragments WHERE group_id=?1",
                    [&group],
                )?;
            }
        }
    }
    Ok(())
}

/// Shared runtime database: authority, MLS state, and local RPC queues.
pub(crate) fn open_database(home: &Path, filename: &str) -> Result<Connection> {
    crate::config::private_dir(home)?;
    let path = home.join(filename);
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o077 == 0,
        "MLS database must be a private regular file"
    );
    let mut db = Connection::open(path)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
    ensure!(matches!(version, 0..=9), "unsupported MLS database version");
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;")?;
    // The original RPC proof used this name for a messages index.
    // Free it before the MLS inbox table is introduced in the same database.
    let legacy_index: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name='inbox' AND tbl_name='messages')",
            [], |row| row.get(0),
        )?;
    if legacy_index {
        db.execute_batch("DROP INDEX inbox;")?;
    }
    SqliteStorageProvider::<JsonCodec, _>::new(&mut db).run_migrations()?;
    let schema = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    schema.execute_batch(
            "
          CREATE TABLE IF NOT EXISTS authority (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), anchor BLOB NOT NULL,
            checkpoint BLOB NOT NULL, state BLOB NOT NULL, node TEXT NOT NULL, key BLOB NOT NULL
          );
          CREATE TABLE IF NOT EXISTS key_packages (id TEXT PRIMARY KEY, bytes BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS outbox (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
            group_id BLOB NOT NULL, request_hash BLOB NOT NULL, bytes BLOB NOT NULL
          );
          CREATE TABLE IF NOT EXISTS inbox (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, group_id BLOB NOT NULL,
            sender TEXT NOT NULL, id TEXT NOT NULL, body BLOB NOT NULL,
            UNIQUE(group_id,sender,id)
          );
          CREATE TABLE IF NOT EXISTS receipts (
            wire_hash BLOB PRIMARY KEY, group_id BLOB NOT NULL
          );
          CREATE TABLE IF NOT EXISTS streams (
            group_id BLOB PRIMARY KEY, writer TEXT NOT NULL, writer_key BLOB NOT NULL,
            head INTEGER NOT NULL, head_hash BLOB NOT NULL, origin_hash BLOB NOT NULL,
            roster_hash BLOB NOT NULL
          );
          CREATE TABLE IF NOT EXISTS stream_outbox (
            id TEXT PRIMARY KEY, group_id BLOB NOT NULL, sequence INTEGER NOT NULL,
            packet BLOB NOT NULL, UNIQUE(group_id,sequence)
          );
          CREATE TABLE IF NOT EXISTS stream_seen (
            group_id BLOB NOT NULL, sequence INTEGER NOT NULL, digest BLOB NOT NULL,
            PRIMARY KEY(group_id,sequence)
          );
          CREATE TABLE IF NOT EXISTS stream_pending (
            group_id BLOB NOT NULL, sequence INTEGER NOT NULL, digest BLOB NOT NULL,
            packet BLOB NOT NULL, PRIMARY KEY(group_id,sequence)
          );
          CREATE TABLE IF NOT EXISTS authority_history (revision INTEGER PRIMARY KEY, state BLOB NOT NULL);
          INSERT OR IGNORE INTO authority_history SELECT json_extract(checkpoint,'$.revision'),state FROM authority;
          CREATE TABLE IF NOT EXISTS configuration_streams (
            group_id BLOB PRIMARY KEY, grant BLOB NOT NULL, revision INTEGER NOT NULL,
            state_hash BLOB NOT NULL, offset INTEGER NOT NULL DEFAULT 0
          );
          CREATE TABLE IF NOT EXISTS configuration_fragments (
            group_id BLOB PRIMARY KEY, revision INTEGER NOT NULL, digest BLOB NOT NULL,
            total INTEGER NOT NULL, bytes BLOB NOT NULL
          );
          CREATE TABLE IF NOT EXISTS configuration_requests (id TEXT PRIMARY KEY, group_id BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS stream_confirmed (
            group_id BLOB PRIMARY KEY,reader TEXT NOT NULL,reader_key BLOB NOT NULL,
            sequence INTEGER NOT NULL,digest BLOB NOT NULL,receipt BLOB NOT NULL);
          PRAGMA user_version=9;",
        )?;
    let has_purpose = {
        let mut columns = schema.prepare("PRAGMA table_info(streams)")?;
        columns
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|column| column == "purpose")
    };
    if !has_purpose {
        schema.execute_batch("ALTER TABLE streams ADD COLUMN purpose TEXT NOT NULL DEFAULT 'data' CHECK(purpose IN ('data','configuration'));")?;
    }
    let receipt_columns = schema
        .prepare("PRAGMA table_info(receipts)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !receipt_columns.iter().any(|name| name == "stream_sequence") {
        schema.execute_batch("ALTER TABLE receipts ADD COLUMN stream_sequence INTEGER;")?;
    }
    schema.execute_batch(
        "CREATE INDEX IF NOT EXISTS receipt_stream_sequence ON receipts(group_id,stream_sequence);",
    )?;
    history::schema(&schema, version)?;
    requests::schema(&schema)?;
    schema.commit()?;
    Ok(db)
}

pub(crate) fn initialize_authority(
    db: &Connection,
    identity: &NodeIdentity,
    state: &VerifiedState,
) -> Result<()> {
    db.execute(
        "INSERT INTO authority VALUES(1,?1,?2,?3,?4,?5)",
        params![
            serde_json::to_vec(state.anchor())?,
            serde_json::to_vec(state.checkpoint())?,
            state.signed().encode()?,
            identity.id(),
            identity.public_key().as_slice()
        ],
    )?;
    db.execute(
        "INSERT INTO authority_history VALUES(?1,?2)",
        params![state.checkpoint().revision, state.signed().encode()?],
    )?;
    history::remember(db, state.checkpoint())?;
    Ok(())
}
