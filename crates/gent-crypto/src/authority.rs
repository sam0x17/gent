use anyhow::{Context, Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use gent_protocol::{Policy, Selector};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub type Digest = [u8; 32];
pub type PublicKey = [u8; 32];
pub const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_STATE_LIFETIME: u64 = 24 * 60 * 60;
pub const REQUEST_LIFETIME: u64 = 15 * 60;
pub const MAX_CHAIN_LENGTH: usize = 1024;
pub const MAX_CHAIN_BYTES: usize = 16 * 1024 * 1024;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
const STATE_DOMAIN: &[u8] = b"gent/cluster-state/v1\0";
const REQUEST_DOMAIN: &[u8] = b"gent/enrollment-request/v1\0";

/// Owner signing authority, distinct from the local owner RPC credential and node keys.
/// Deliberately has no Debug or Serialize implementation.
pub struct OwnerKey(SigningKey);

/// A node's signing identity. Encryption keys will belong to the selected session protocol.
/// Deliberately has no Debug or Serialize implementation.
pub struct NodeIdentity {
    id: String,
    key: SigningKey,
}

// MLS supplies its standard domain-separated signing inputs. Keep the secret
// inside the identity instead of exporting another copy to an MLS credential.
#[cfg(feature = "mls")]
impl openmls_traits::signatures::Signer for NodeIdentity {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, openmls_traits::signatures::SignerError> {
        Ok(self.key.sign(payload).to_bytes().to_vec())
    }

    fn signature_scheme(&self) -> openmls_traits::types::SignatureScheme {
        openmls_traits::types::SignatureScheme::ED25519
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeMember {
    pub name: String,
    pub signing_key: PublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterState {
    pub version: u32,
    pub cluster_id: String,
    pub name: String,
    pub owner_key: PublicKey,
    pub revision: u64,
    pub previous: Option<Digest>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nodes: BTreeMap<String, NodeMember>,
    pub retired_nodes: BTreeSet<String>,
    pub retired_keys: BTreeSet<PublicKey>,
    pub policy: Policy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedState {
    pub state: ClusterState,
    pub signature: Vec<u8>,
}

/// Pin this through an already trusted endpoint, never from an unverified directory.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchor {
    pub cluster_id: String,
    pub owner_key: PublicKey,
    pub genesis_hash: Digest,
}

/// Persist with the accepted signed state before exposing any new authorization.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub revision: u64,
    pub state_hash: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub version: u32,
    pub anchor: TrustAnchor,
    pub base: Checkpoint,
    pub node_id: String,
    pub member: NodeMember,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnrollment {
    pub request: EnrollmentRequest,
    pub signature: Vec<u8>,
}

/// A verified history prefix. Its fields cannot be mutated without validation.
#[derive(Clone)]
pub struct VerifiedState {
    anchor: TrustAnchor,
    signed: SignedState,
    checkpoint: Checkpoint,
}

fn signing_key() -> Result<SigningKey> {
    let mut secret = Zeroizing::new([0; 32]);
    getrandom::fill(secret.as_mut())?;
    Ok(SigningKey::from_bytes(&secret))
}

fn id(value: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(value).context("invalid identity")?;
    ensure!(
        !parsed.is_nil() && parsed.to_string() == value,
        "identity must be a canonical nonzero UUID"
    );
    Ok(())
}

fn label(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control),
        "invalid display label"
    );
    Ok(())
}

fn public_key(bytes: &PublicKey) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(bytes).context("invalid public key")?;
    ensure!(!key.is_weak(), "weak public key");
    Ok(key)
}

fn lifetime(issued: u64, expires: u64, maximum: u64) -> Result<()> {
    ensure!(
        expires <= MAX_SAFE_INTEGER && expires > issued && expires - issued <= maximum,
        "invalid validity period"
    );
    Ok(())
}

fn fresh(issued: u64, expires: u64, now: u64) -> Result<()> {
    ensure!(
        issued <= now && now < expires,
        "authorization is expired or not yet valid"
    );
    Ok(())
}

fn signing_input(domain: &[u8], value: &impl Serialize, limit: usize) -> Result<Vec<u8>> {
    let canonical = serde_jcs::to_vec(value)?;
    ensure!(canonical.len() <= limit, "signed record exceeds size limit");
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn digest(domain: &[u8], value: &impl Serialize, limit: usize) -> Result<Digest> {
    Ok(Sha256::digest(signing_input(domain, value, limit)?).into())
}

fn verify(
    key: &PublicKey,
    domain: &[u8],
    value: &impl Serialize,
    signature: &[u8],
    limit: usize,
) -> Result<()> {
    public_key(key)?
        .verify_strict(
            &signing_input(domain, value, limit)?,
            &Signature::try_from(signature)?,
        )
        .context("invalid signature")
}

fn encode(value: &impl Serialize, limit: usize) -> Result<Vec<u8>> {
    let bytes = serde_jcs::to_vec(value)?;
    ensure!(bytes.len() <= limit, "record exceeds size limit");
    Ok(bytes)
}

fn decode<T: Serialize + DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T> {
    ensure!(bytes.len() <= limit, "record exceeds size limit");
    let value: T = serde_json::from_slice(bytes)?;
    // Requiring canonical wire bytes also rejects duplicate map keys and ambiguous encodings.
    ensure!(
        serde_jcs::to_vec(&value)? == bytes,
        "record must use canonical JSON"
    );
    Ok(value)
}

fn validate_policy(policy: &Policy) -> Result<()> {
    ensure!(
        policy.rules.len() <= 4096 && policy.groups.len() <= 256,
        "policy exceeds limits"
    );
    for (name, members) in &policy.groups {
        label(name)?;
        ensure!(members.len() <= 4096, "group exceeds limits");
        let mut distinct = BTreeSet::new();
        for member in members {
            id(member)?;
            ensure!(distinct.insert(member), "duplicate group member");
        }
    }
    for rule in &policy.rules {
        for selector in [&rule.actor, &rule.peer] {
            match selector {
                Selector::Agent(value) | Selector::Node(value) => id(value)?,
                Selector::Group(name) => {
                    label(name)?;
                    ensure!(policy.groups.contains_key(name), "unknown policy group");
                }
                Selector::All | Selector::SameNode => {}
            }
        }
    }
    Ok(())
}

impl ClusterState {
    fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported state version");
        id(&self.cluster_id)?;
        label(&self.name)?;
        public_key(&self.owner_key)?;
        ensure!(
            self.revision <= MAX_SAFE_INTEGER && (self.revision == 0) == self.previous.is_none(),
            "invalid revision"
        );
        lifetime(self.issued_at, self.expires_at, MAX_STATE_LIFETIME)?;
        ensure!(
            !self.nodes.is_empty() && self.nodes.len() <= 1024,
            "invalid node count"
        );
        ensure!(
            self.retired_nodes.len() <= 8192 && self.retired_keys.len() <= 8192,
            "retirement history exceeds limits"
        );
        let mut keys = BTreeSet::new();
        for (node_id, member) in &self.nodes {
            id(node_id)?;
            label(&member.name)?;
            public_key(&member.signing_key)?;
            ensure!(
                member.signing_key != self.owner_key && keys.insert(member.signing_key),
                "node keys must be distinct from each other and owner authority"
            );
            ensure!(
                !self.retired_nodes.contains(node_id)
                    && !self.retired_keys.contains(&member.signing_key),
                "retired identity cannot be reenrolled"
            );
        }
        for retired in &self.retired_nodes {
            id(retired)?;
        }
        for retired in &self.retired_keys {
            public_key(retired)?;
        }
        validate_policy(&self.policy)
    }
}

impl OwnerKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(signing_key()?))
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    /// For protected endpoint storage only. Never pass the result to an agent or relay.
    pub fn expose_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.0.as_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        self.0.verifying_key().to_bytes()
    }

    pub fn create_cluster(
        &self,
        name: &str,
        first: &NodeIdentity,
        node_name: &str,
        now: u64,
    ) -> Result<VerifiedState> {
        let state = ClusterState {
            version: 1,
            cluster_id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            owner_key: self.public_key(),
            revision: 0,
            previous: None,
            issued_at: now,
            expires_at: now
                .checked_add(MAX_STATE_LIFETIME)
                .context("timestamp overflow")?,
            nodes: BTreeMap::from([(first.id.clone(), first.member(node_name)?)]),
            retired_nodes: BTreeSet::new(),
            retired_keys: BTreeSet::new(),
            policy: Policy::default(),
        };
        let signed = self.sign(state)?;
        let anchor = TrustAnchor {
            cluster_id: signed.state.cluster_id.clone(),
            owner_key: self.public_key(),
            genesis_hash: signed.digest()?,
        };
        VerifiedState::bootstrap(anchor, signed)
    }

    fn sign(&self, state: ClusterState) -> Result<SignedState> {
        state.validate()?;
        ensure!(
            state.owner_key == self.public_key(),
            "wrong owner authority"
        );
        let signature = self
            .0
            .sign(&signing_input(STATE_DOMAIN, &state, MAX_STATE_BYTES)?)
            .to_bytes()
            .to_vec();
        let signed = SignedState { state, signature };
        signed.encode()?;
        Ok(signed)
    }
}

impl NodeIdentity {
    /// Authenticate an opaque packet and its position in a directional stream.
    pub fn sign_stream_packet(
        &self,
        group: &[u8],
        sequence: u64,
        previous: Digest,
        ciphertext: &[u8],
    ) -> Result<crate::stream::Packet> {
        let mut packet = crate::stream::Packet::unsigned(group, sequence, previous, ciphertext);
        packet.signature = self.key.sign(&packet.signing_input()?).to_bytes().to_vec();
        Ok(packet)
    }

    pub fn generate() -> Result<Self> {
        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            key: signing_key()?,
        })
    }

    pub fn from_secret_bytes(node_id: &str, bytes: &[u8; 32]) -> Result<Self> {
        id(node_id)?;
        Ok(Self {
            id: node_id.into(),
            key: SigningKey::from_bytes(bytes),
        })
    }

    /// Generate replacement signing material while retaining the stable node ID.
    pub fn replacement(&self) -> Result<Self> {
        Ok(Self {
            id: self.id.clone(),
            key: signing_key()?,
        })
    }

    /// For protected endpoint storage only. Never pass the result to an agent or relay.
    pub fn expose_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.key.as_bytes())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn public_key(&self) -> PublicKey {
        self.key.verifying_key().to_bytes()
    }

    fn member(&self, name: &str) -> Result<NodeMember> {
        label(name)?;
        Ok(NodeMember {
            name: name.into(),
            signing_key: self.public_key(),
        })
    }

    /// The anchor and checkpoint must be obtained through the trusted pairing flow.
    pub fn request_enrollment(
        &self,
        anchor: &TrustAnchor,
        base: &Checkpoint,
        name: &str,
        now: u64,
    ) -> Result<SignedEnrollment> {
        let request = EnrollmentRequest {
            version: 1,
            anchor: anchor.clone(),
            base: base.clone(),
            node_id: self.id.clone(),
            member: self.member(name)?,
            nonce: uuid::Uuid::new_v4().to_string(),
            issued_at: now,
            expires_at: now
                .checked_add(REQUEST_LIFETIME)
                .context("timestamp overflow")?,
        };
        request.validate()?;
        let signature = self
            .key
            .sign(&signing_input(REQUEST_DOMAIN, &request, MAX_REQUEST_BYTES)?)
            .to_bytes()
            .to_vec();
        let signed = SignedEnrollment { request, signature };
        signed.encode()?;
        Ok(signed)
    }
}

impl EnrollmentRequest {
    fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported request version");
        id(&self.anchor.cluster_id)?;
        id(&self.node_id)?;
        id(&self.nonce)?;
        label(&self.member.name)?;
        public_key(&self.anchor.owner_key)?;
        public_key(&self.member.signing_key)?;
        ensure!(
            self.member.signing_key != self.anchor.owner_key,
            "node cannot use owner signing key"
        );
        ensure!(
            self.base.revision <= MAX_SAFE_INTEGER,
            "invalid base revision"
        );
        lifetime(self.issued_at, self.expires_at, REQUEST_LIFETIME)
    }
}

impl SignedEnrollment {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode(self, MAX_REQUEST_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode(bytes, MAX_REQUEST_BYTES)
    }

    /// Compare all 32 bytes via a channel independent of the untrusted relay.
    pub fn fingerprint(&self) -> Result<Digest> {
        self.request.validate()?;
        verify(
            &self.request.member.signing_key,
            REQUEST_DOMAIN,
            &self.request,
            &self.signature,
            MAX_REQUEST_BYTES,
        )?;
        digest(REQUEST_DOMAIN, &self.request, MAX_REQUEST_BYTES)
    }
}

impl SignedState {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode(self, MAX_STATE_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode(bytes, MAX_STATE_BYTES)
    }

    fn digest(&self) -> Result<Digest> {
        digest(STATE_DOMAIN, &self.state, MAX_STATE_BYTES)
    }

    fn verify(&self, anchor: &TrustAnchor) -> Result<Checkpoint> {
        self.state.validate()?;
        ensure!(
            self.state.cluster_id == anchor.cluster_id && self.state.owner_key == anchor.owner_key,
            "state does not match pinned authority"
        );
        verify(
            &anchor.owner_key,
            STATE_DOMAIN,
            &self.state,
            &self.signature,
            MAX_STATE_BYTES,
        )?;
        self.encode()?;
        Ok(Checkpoint {
            revision: self.state.revision,
            state_hash: self.digest()?,
        })
    }
}

impl VerifiedState {
    /// Bootstrap from the genesis whose digest and owner key were pinned independently.
    /// Expired state can be loaded for synchronization, but cannot authorize operations.
    pub fn bootstrap(anchor: TrustAnchor, genesis: SignedState) -> Result<Self> {
        let checkpoint = genesis.verify(&anchor)?;
        ensure!(
            checkpoint.revision == 0 && checkpoint.state_hash == anchor.genesis_hash,
            "genesis does not match trust anchor"
        );
        Ok(Self {
            anchor,
            signed: genesis,
            checkpoint,
        })
    }

    /// Restore only the exact checkpoint held in trusted endpoint storage.
    pub fn restore(
        anchor: TrustAnchor,
        checkpoint: Checkpoint,
        signed: SignedState,
    ) -> Result<Self> {
        let actual = signed.verify(&anchor)?;
        ensure!(
            actual == checkpoint,
            "state does not match saved checkpoint"
        );
        if actual.revision == 0 {
            ensure!(actual.state_hash == anchor.genesis_hash, "genesis mismatch");
        }
        Ok(Self {
            anchor,
            signed,
            checkpoint,
        })
    }

    pub fn anchor(&self) -> &TrustAnchor {
        &self.anchor
    }
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }
    pub fn signed(&self) -> &SignedState {
        &self.signed
    }
    pub fn state(&self) -> &ClusterState {
        &self.signed.state
    }

    pub fn require_fresh(&self, now: u64) -> Result<()> {
        fresh(self.state().issued_at, self.state().expires_at, now)
    }

    /// Authorizes a node key, not agent discovery or messaging. Check agent policy separately.
    pub fn authorize_node(
        &self,
        node_id: &str,
        signing_key: &PublicKey,
        now: u64,
    ) -> Result<&NodeMember> {
        self.require_fresh(now)?;
        let member = self
            .state()
            .nodes
            .get(node_id)
            .context("node unavailable")?;
        ensure!(&member.signing_key == signing_key, "node unavailable");
        Ok(member)
    }

    /// Validate a full contiguous update chain before changing any in-memory authority.
    /// Historical intermediate records may be expired; the final record must be fresh.
    pub fn apply_chain(&mut self, updates: &[SignedState], now: u64) -> Result<()> {
        let next = self.verify_chain(updates)?;
        next.require_fresh(now)?;
        *self = next;
        Ok(())
    }

    /// Advance verified history in bounded batches while offline or catching up.
    /// This may leave expired state; authorize_node still requires fresh authority.
    pub fn advance_history(&mut self, updates: &[SignedState]) -> Result<()> {
        *self = self.verify_chain(updates)?;
        Ok(())
    }

    fn verify_chain(&self, updates: &[SignedState]) -> Result<Self> {
        ensure!(
            !updates.is_empty() && updates.len() <= MAX_CHAIN_LENGTH,
            "invalid update chain length"
        );
        let mut next = self.clone();
        let mut total_bytes = 0;
        for update in updates {
            total_bytes += update.encode()?.len();
            ensure!(
                total_bytes <= MAX_CHAIN_BYTES,
                "update chain exceeds size limit"
            );
            let checkpoint = update.verify(&self.anchor)?;
            let previous = next.state();
            ensure!(
                checkpoint.revision == next.checkpoint.revision + 1
                    && update.state.previous == Some(next.checkpoint.state_hash),
                "revision rollback, gap, or conflict"
            );
            ensure!(
                update.state.issued_at >= previous.issued_at,
                "revision time moved backwards"
            );
            ensure!(
                previous.retired_keys.is_subset(&update.state.retired_keys)
                    && previous
                        .retired_nodes
                        .is_subset(&update.state.retired_nodes),
                "retirement history cannot be removed"
            );
            for (node_id, member) in &previous.nodes {
                match update.state.nodes.get(node_id) {
                    None => ensure!(
                        update.state.retired_nodes.contains(node_id)
                            && update.state.retired_keys.contains(&member.signing_key),
                        "removed node requires retirement"
                    ),
                    Some(replacement) if replacement.signing_key != member.signing_key => ensure!(
                        update.state.retired_keys.contains(&member.signing_key),
                        "replaced key requires retirement"
                    ),
                    _ => {}
                }
            }
            next.signed = update.clone();
            next.checkpoint = checkpoint;
        }
        Ok(next)
    }

    fn revise(
        &self,
        owner: &OwnerKey,
        now: u64,
        edit: impl FnOnce(&mut ClusterState) -> Result<()>,
    ) -> Result<SignedState> {
        ensure!(
            owner.public_key() == self.anchor.owner_key,
            "wrong owner authority"
        );
        ensure!(
            now >= self.state().issued_at,
            "revision time moved backwards"
        );
        let mut state = self.state().clone();
        state.revision = state.revision.checked_add(1).context("revision overflow")?;
        state.previous = Some(self.checkpoint.state_hash);
        state.issued_at = now;
        state.expires_at = now
            .checked_add(MAX_STATE_LIFETIME)
            .context("timestamp overflow")?;
        edit(&mut state)?;
        owner.sign(state)
    }

    /// Renewal may repair an expired configuration using endpoint-held owner authority.
    pub fn renew(&self, owner: &OwnerKey, now: u64) -> Result<SignedState> {
        self.revise(owner, now, |_| Ok(()))
    }

    pub fn set_policy(&self, owner: &OwnerKey, policy: Policy, now: u64) -> Result<SignedState> {
        self.revise(owner, now, |state| {
            state.policy = policy;
            Ok(())
        })
    }

    /// `approved_fingerprint` must be independently confirmed by the owner; merely
    /// echoing a fingerprint supplied by the relay does not authenticate enrollment.
    pub fn enroll(
        &self,
        owner: &OwnerKey,
        request: &SignedEnrollment,
        approved_fingerprint: Digest,
        now: u64,
    ) -> Result<SignedState> {
        self.accept_request(owner, request, approved_fingerprint, now, false)
    }

    pub fn rotate_node_key(
        &self,
        owner: &OwnerKey,
        request: &SignedEnrollment,
        approved_fingerprint: Digest,
        now: u64,
    ) -> Result<SignedState> {
        self.accept_request(owner, request, approved_fingerprint, now, true)
    }

    fn accept_request(
        &self,
        owner: &OwnerKey,
        signed: &SignedEnrollment,
        approved: Digest,
        now: u64,
        rotation: bool,
    ) -> Result<SignedState> {
        self.require_fresh(now)?;
        ensure!(
            signed.fingerprint()? == approved,
            "enrollment fingerprint does not match owner approval"
        );
        let request = &signed.request;
        fresh(request.issued_at, request.expires_at, now)?;
        ensure!(
            request.anchor == self.anchor && request.base == self.checkpoint,
            "enrollment targets another cluster or stale revision"
        );
        self.revise(owner, now, |state| {
            match (rotation, state.nodes.get(&request.node_id)) {
                (true, Some(previous)) => {
                    ensure!(
                        previous.signing_key != request.member.signing_key,
                        "replacement key is unchanged"
                    );
                    state.retired_keys.insert(previous.signing_key);
                }
                (false, None) => {}
                _ => anyhow::bail!("node enrollment mode does not match membership"),
            }
            state
                .nodes
                .insert(request.node_id.clone(), request.member.clone());
            Ok(())
        })
    }

    pub fn revoke_node(&self, owner: &OwnerKey, node_id: &str, now: u64) -> Result<SignedState> {
        self.revise(owner, now, |state| {
            let member = state.nodes.remove(node_id).context("node unavailable")?;
            state.retired_nodes.insert(node_id.into());
            state.retired_keys.insert(member.signing_key);
            Ok(())
        })
    }
}
