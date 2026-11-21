use anyhow::{Context, Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use gent_protocol::administration::MAX_ADMIN_GRANT_LIFETIME;
use gent_protocol::{MAX_RELAY_GRANT_LIFETIME, Policy, Selector};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;
mod agents;
mod helper;
mod hosting;
#[cfg(feature = "invitation")]
mod noise;
pub mod peer;
pub use agents::*;
pub use helper::verify_helper_channel;
#[cfg(feature = "invitation")]
pub mod invitation;
pub mod recovery;
pub mod succession;
use succession::{MAX_OWNER_CHAIN_BYTES, SignedOwnerTransition, verify_lineage};

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
const CONFIGURATION_DOMAIN: &[u8] = b"gent/configuration-grant/v1\0";
const MAX_CONFIGURATION_GRANT_BYTES: usize = MAX_OWNER_CHAIN_BYTES + 8192;

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
    /// Owner-approved configuration editing, independent of node membership.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub can_configure: bool,
    /// Signed delegation of chat transport only; configuration authority is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosted_by: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterState {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<peer::Authority>,
    pub cluster_id: String,
    pub name: String,
    pub owner_key: PublicKey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_transitions: Vec<SignedOwnerTransition>,
    pub revision: u64,
    pub previous: Option<Digest>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nodes: BTreeMap<String, NodeMember>,
    pub retired_nodes: BTreeSet<String>,
    pub retired_keys: BTreeSet<PublicKey>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub retired_relay_grants: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub retired_admin_grants: BTreeSet<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<ReplacedNode>,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Public identity of a lost joined node, pinned through the owner channel.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplacedNode {
    pub id: String,
    pub signing_key: PublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnrollment {
    pub request: EnrollmentRequest,
    pub signature: Vec<u8>,
}

/// Owner authorization for a private, two-node configuration distribution stream.
/// The grant itself contains private metadata and needs protected pairing transport.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationGrant {
    pub version: u32,
    pub anchor: TrustAnchor,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_transitions: Vec<SignedOwnerTransition>,
    pub base: Checkpoint,
    pub group: Vec<u8>,
    pub origin: Digest,
    pub writer: String,
    pub writer_key: PublicKey,
    pub reader: String,
    pub reader_key: PublicKey,
    /// A prepared successor stream may publish only after this exact candidate
    /// is selected at `base`. Absent on ordinary, immediately usable streams.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_candidate: Option<Digest>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedConfigurationGrant {
    pub grant: ConfigurationGrant,
    pub signature: Vec<u8>,
}

impl SignedConfigurationGrant {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode(self, MAX_CONFIGURATION_GRANT_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode(bytes, MAX_CONFIGURATION_GRANT_BYTES)
    }

    /// Does not grant messaging authority or require an unexpired lease. The
    /// receiver must also enforce the grant's saved stream and node-key bindings.
    pub fn verify(&self, anchor: &TrustAnchor) -> Result<()> {
        let grant = &self.grant;
        let owner = verify_lineage(anchor, &grant.owner_transitions)?;
        ensure!(
            grant.version == 1 && &grant.anchor == anchor,
            "wrong configuration grant authority"
        );
        id(&grant.writer)?;
        id(&grant.reader)?;
        public_key(&grant.writer_key)?;
        public_key(&grant.reader_key)?;
        ensure!(
            grant.writer != grant.reader
                && grant.writer_key != grant.reader_key
                && grant.writer_key != anchor.owner_key
                && grant.reader_key != anchor.owner_key
                && grant.writer_key != owner
                && grant.reader_key != owner,
            "configuration grant requires two distinct node identities"
        );
        ensure!(
            !grant.group.is_empty()
                && grant.group.len() <= 256
                && grant.origin != [0; 32]
                && grant.owner_candidate != Some([0; 32])
                && grant.base.revision <= MAX_SAFE_INTEGER,
            "invalid configuration stream binding"
        );
        ensure!(
            grant
                .owner_transitions
                .last()
                .is_none_or(|t| t.transition.base.revision < grant.base.revision),
            "configuration grant precedes owner activation"
        );
        verify(
            &owner,
            CONFIGURATION_DOMAIN,
            grant,
            &self.signature,
            MAX_CONFIGURATION_GRANT_BYTES,
        )
    }

    /// Enrollment of this exception requires the exact fresh approved checkpoint.
    pub fn verify_initial(&self, state: &VerifiedState, now: u64) -> Result<()> {
        self.verify(state.anchor())?;
        ensure!(
            self.grant.owner_transitions == state.state().owner_transitions,
            "configuration grant is from another owner epoch"
        );
        ensure!(
            &self.grant.base == state.checkpoint(),
            "configuration grant has a stale base"
        );
        state.authorize_node(&self.grant.writer, &self.grant.writer_key, now)?;
        state.authorize_node(&self.grant.reader, &self.grant.reader_key, now)?;
        Ok(())
    }

    /// Check the pins of a candidate already verified against its initial state.
    /// This alone does not authorize a new candidate or activate an owner.
    pub fn verify_owner_candidate(
        &self,
        candidate: &succession::SignedOwnerCandidate,
    ) -> Result<()> {
        self.verify(&candidate.candidate.anchor)?;
        ensure!(
            self.grant.owner_candidate == Some(candidate.digest()?)
                && self.grant.base == candidate.candidate.base
                && self.grant.writer == candidate.candidate.node.id
                && self.grant.writer_key == candidate.candidate.node.signing_key,
            "configuration grant belongs to another owner candidate"
        );
        Ok(())
    }

    /// Standby streams wait for their exact handoff. Later accepted epochs may
    /// still distribute retained history through an established stream.
    pub fn can_publish(&self, state: &VerifiedState) -> Result<bool> {
        self.verify(state.anchor())?;
        let Some(candidate) = self.grant.owner_candidate else {
            return Ok(true);
        };
        let chain = &state.state().owner_transitions;
        let preceding = &self.grant.owner_transitions;
        Ok(chain.starts_with(preceding)
            && chain.get(preceding.len()).is_some_and(|signed| {
                let transition = &signed.transition;
                transition.base == self.grant.base
                    && transition.successor.as_ref().is_some_and(|s| {
                        s.candidate == candidate
                            && s.node.id == self.grant.writer
                            && s.node.signing_key == self.grant.writer_key
                    })
            }))
    }
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

/// Shared validation for TOML proposals and owner-signed policy records.
pub fn validate_policy(policy: &Policy) -> Result<()> {
    ensure!(
        policy.rules.len() <= 4096
            && policy.groups.len() <= 256
            && policy.relay_grants.len() <= 1024
            && policy.admin_grants.len() + policy.group_admin_grants.len() <= 1024,
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
    for selector in policy
        .rules
        .iter()
        .flat_map(|r| [&r.actor, &r.peer])
        .chain(
            policy
                .admin_grants
                .values()
                .flat_map(|g| [&g.actor, &g.peer]),
        )
        .chain(policy.group_admin_grants.values().map(|g| &g.members))
    {
        match selector {
            Selector::Agent(value) | Selector::Node(value) => id(value)?,
            Selector::Group(name) => {
                label(name)?;
                ensure!(policy.groups.contains_key(name), "unknown policy group");
            }
            Selector::All | Selector::SameNode => {}
        }
    }
    for (grant_id, grant) in &policy.relay_grants {
        id(grant_id)?;
        id(&grant.intermediary)?;
        id(&grant.target)?;
        ensure!(
            grant.intermediary != grant.target,
            "relay endpoints must differ"
        );
        lifetime(grant.issued_at, grant.expires_at, MAX_RELAY_GRANT_LIFETIME)?;
    }
    for (grant_id, grant) in &policy.admin_grants {
        id(grant_id)?;
        id(&grant.administrator)?;
        ensure!(
            !grant.permissions.is_empty() && grant.permissions.len() <= 3,
            "invalid administration permissions"
        );
        for (i, permission) in grant.permissions.iter().enumerate() {
            ensure!(
                !grant.permissions[..i].contains(permission),
                "duplicate administration permission"
            );
        }
        lifetime(grant.issued_at, grant.expires_at, MAX_ADMIN_GRANT_LIFETIME)?;
    }
    for (grant_id, grant) in &policy.group_admin_grants {
        id(grant_id)?;
        id(&grant.administrator)?;
        label(&grant.group)?;
        ensure!(
            !policy.admin_grants.contains_key(grant_id),
            "duplicate administration grant ID"
        );
        ensure!(
            policy.groups.contains_key(&grant.group),
            "unknown administration group"
        );
        ensure!(
            !grant.actions.is_empty() && grant.actions.len() <= 2,
            "invalid group administration actions"
        );
        for (i, action) in grant.actions.iter().enumerate() {
            ensure!(
                !grant.actions[..i].contains(action),
                "duplicate group administration action"
            );
        }
        lifetime(grant.issued_at, grant.expires_at, MAX_ADMIN_GRANT_LIFETIME)?;
    }
    Ok(())
}

impl ClusterState {
    fn validate(&self) -> Result<()> {
        ensure!(
            (self.version == 1 && self.owner_transitions.is_empty() && self.peer.is_none())
                || (self.version == 2 && !self.owner_transitions.is_empty() && self.peer.is_none())
                || (self.version == 3 && self.peer.is_some()),
            "unsupported state version"
        );
        id(&self.cluster_id)?;
        label(&self.name)?;
        public_key(&self.owner_key)?;
        if let Some(authority) = &self.peer {
            authority.validate(self)?;
        }
        if let Some(successor) = self
            .owner_transitions
            .last()
            .and_then(|t| t.transition.successor.as_ref())
            .filter(|_| self.peer.is_none())
        {
            ensure!(
                self.nodes.get(&successor.node.id).is_some_and(|n| {
                    n.signing_key == successor.node.signing_key && n.hosted_by.is_none()
                }),
                "active owner node must remain enrolled and native until another handoff"
            );
        }
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
            self.retired_nodes.len() <= 8192
                && self.retired_keys.len() <= 8192
                && self.retired_relay_grants.len() <= 8192
                && self.retired_admin_grants.len() <= 8192,
            "retirement history exceeds limits"
        );
        let mut keys = BTreeSet::new();
        let owner_keys = succession::owner_keys(&self.owner_transitions, self.owner_key);
        ensure!(
            owner_keys.is_disjoint(&self.retired_keys),
            "retired node keys cannot be owner signing keys"
        );
        for (node_id, member) in &self.nodes {
            id(node_id)?;
            self.transport_host(node_id)?;
            label(&member.name)?;
            public_key(&member.signing_key)?;
            ensure!(
                !owner_keys.contains(&member.signing_key) && keys.insert(member.signing_key),
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
        for retired in &self.retired_relay_grants {
            id(retired)?;
            ensure!(
                !self.policy.relay_grants.contains_key(retired),
                "retired relay grant cannot be restored"
            );
        }
        for grant in self.policy.relay_grants.values() {
            ensure!(
                grant.issued_at <= self.issued_at,
                "relay grant issued after its configuration"
            );
        }
        for retired in &self.retired_admin_grants {
            id(retired)?;
            ensure!(
                !self.policy.admin_grants.contains_key(retired)
                    && !self.policy.group_admin_grants.contains_key(retired),
                "retired administration grant cannot be restored"
            );
        }
        for grant in self.policy.admin_grants.values() {
            ensure!(
                grant.issued_at <= self.issued_at,
                "administration grant issued after its configuration"
            );
        }
        for grant in self.policy.group_admin_grants.values() {
            ensure!(
                grant.issued_at <= self.issued_at,
                "administration grant issued after its configuration"
            );
        }
        validate_policy(&self.policy)
    }
}

impl OwnerKey {
    pub fn authorize_configuration_stream(
        &self,
        state: &VerifiedState,
        group: &[u8],
        origin: Digest,
        endpoints: (&str, &str),
        now: u64,
    ) -> Result<SignedConfigurationGrant> {
        self.configuration_grant(state, group, origin, endpoints, None, now)
    }

    pub fn authorize_standby_configuration_stream(
        &self,
        state: &VerifiedState,
        candidate: &succession::SignedOwnerCandidate,
        group: &[u8],
        origin: Digest,
        reader: &str,
        now: u64,
    ) -> Result<SignedConfigurationGrant> {
        candidate.verify(state, now)?;
        self.configuration_grant(
            state,
            group,
            origin,
            (&candidate.candidate.node.id, reader),
            Some(candidate.digest()?),
            now,
        )
    }

    fn configuration_grant(
        &self,
        state: &VerifiedState,
        group: &[u8],
        origin: Digest,
        endpoints: (&str, &str),
        owner_candidate: Option<Digest>,
        now: u64,
    ) -> Result<SignedConfigurationGrant> {
        ensure!(
            self.public_key() == state.state().owner_key,
            "wrong owner authority"
        );
        state.require_fresh(now)?;
        let (writer, reader) = endpoints;
        let grant = ConfigurationGrant {
            version: 1,
            anchor: state.anchor().clone(),
            owner_transitions: state.state().owner_transitions.clone(),
            base: state.checkpoint().clone(),
            group: group.into(),
            origin,
            writer: writer.into(),
            writer_key: state
                .state()
                .nodes
                .get(writer)
                .context("unknown configuration writer")?
                .signing_key,
            reader: reader.into(),
            reader_key: state
                .state()
                .nodes
                .get(reader)
                .context("unknown configuration reader")?
                .signing_key,
            owner_candidate,
        };
        let signature = self
            .0
            .sign(&signing_input(
                CONFIGURATION_DOMAIN,
                &grant,
                MAX_CONFIGURATION_GRANT_BYTES,
            )?)
            .to_bytes()
            .to_vec();
        let signed = SignedConfigurationGrant { grant, signature };
        signed.verify_initial(state, now)?;
        signed.encode()?;
        Ok(signed)
    }

    pub fn generate() -> Result<Self> {
        Ok(Self(signing_key()?))
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    /// For protected endpoint storage only. Never pass the result to a chat or relay.
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
        self.create_cluster_with_id(
            (&uuid::Uuid::new_v4().to_string(), name),
            first,
            node_name,
            Policy::cluster_default(),
            now,
        )
    }

    /// Bootstrap a locally owned cluster while preserving an existing local ID.
    /// This does not authorize replacing any previously pinned trust anchor.
    pub fn create_cluster_with_id(
        &self,
        cluster: (&str, &str),
        first: &NodeIdentity,
        node_name: &str,
        policy: Policy,
        now: u64,
    ) -> Result<VerifiedState> {
        let state = ClusterState {
            version: 1,
            peer: None,
            cluster_id: cluster.0.into(),
            name: cluster.1.into(),
            owner_key: self.public_key(),
            owner_transitions: Vec::new(),
            revision: 0,
            previous: None,
            issued_at: now,
            expires_at: now
                .checked_add(MAX_STATE_LIFETIME)
                .context("timestamp overflow")?,
            nodes: BTreeMap::from([(first.id.clone(), first.member(node_name)?)]),
            retired_nodes: BTreeSet::new(),
            retired_keys: BTreeSet::new(),
            retired_relay_grants: BTreeSet::new(),
            retired_admin_grants: BTreeSet::new(),
            policy,
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
            state.peer.is_none(),
            "legacy signing is fenced by peer authority"
        );
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
    pub fn sign_stream_receipt(
        &self,
        group: &[u8],
        sequence: u64,
        digest: Digest,
    ) -> Result<crate::stream::Receipt> {
        let mut receipt = crate::stream::Receipt::unsigned(group, sequence, digest);
        receipt.signature = self.key.sign(&receipt.signing_input()?).to_bytes().to_vec();
        Ok(receipt)
    }
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

    /// For protected endpoint storage only. Never pass the result to a chat or relay.
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
            can_configure: false,
            hosted_by: None,
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
        self.enrollment_request(anchor, base, name, None, now)
    }

    pub fn request_replacement(
        &self,
        anchor: &TrustAnchor,
        base: &Checkpoint,
        name: &str,
        replaces: ReplacedNode,
        now: u64,
    ) -> Result<SignedEnrollment> {
        self.enrollment_request(anchor, base, name, Some(replaces), now)
    }

    fn enrollment_request(
        &self,
        anchor: &TrustAnchor,
        base: &Checkpoint,
        name: &str,
        replaces: Option<ReplacedNode>,
        now: u64,
    ) -> Result<SignedEnrollment> {
        let request = EnrollmentRequest {
            version: 1,
            anchor: anchor.clone(),
            base: base.clone(),
            node_id: self.id.clone(),
            member: self.member(name)?,
            replaces,
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
        ensure!(
            !self.member.can_configure,
            "enrollment cannot self-grant administration"
        );
        ensure!(
            self.member.hosted_by.is_none(),
            "hosting requires a separate configuration edit"
        );
        public_key(&self.anchor.owner_key)?;
        public_key(&self.member.signing_key)?;
        if let Some(replaces) = &self.replaces {
            id(&replaces.id)?;
            public_key(&replaces.signing_key)?;
            ensure!(
                replaces.id != self.node_id && replaces.signing_key != self.member.signing_key,
                "replacement requires a fresh node identity and key"
            );
        }
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
    /// Verify one record, without authorizing it or establishing history continuity.
    /// Apply through VerifiedState before changing live authority.
    pub fn verified_checkpoint(&self, anchor: &TrustAnchor) -> Result<Checkpoint> {
        self.verify(anchor)
    }

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
        let owner = verify_lineage(anchor, &self.state.owner_transitions)?;
        ensure!(
            self.state.cluster_id == anchor.cluster_id && self.state.owner_key == owner,
            "state does not match pinned authority"
        );
        if let Some(last) = self.state.owner_transitions.last() {
            let transition = &last.transition;
            ensure!(
                transition.base.revision < self.state.revision
                    && transition.issued_at <= self.state.issued_at,
                "state precedes owner activation"
            );
            if self.state.revision == transition.base.revision + 1 {
                ensure!(
                    self.state.previous == Some(transition.base.state_hash),
                    "owner activation checkpoint mismatch"
                );
            }
        }
        let signer = self.state.peer.as_ref().map_or(owner, |peer| {
            if peer.migration { owner } else { peer.signer }
        });
        verify(
            &signer,
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

    /// Authorizes a node key, not chat discovery or messaging. Check chat policy separately.
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
        ensure!(
            updates.iter().all(|s| s.state.peer.is_none()),
            "peer authority requires the committed configuration log"
        );
        let next = self.verify_chain(updates)?;
        next.require_fresh(now)?;
        *self = next;
        Ok(())
    }

    /// Advance verified history in bounded batches while offline or catching up.
    /// This may leave expired state; authorize_node still requires fresh authority.
    pub fn advance_history(&mut self, updates: &[SignedState]) -> Result<()> {
        ensure!(
            updates.iter().all(|s| s.state.peer.is_none()),
            "peer authority requires the committed configuration log"
        );
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
            peer::verify_step(&next, update)?;
            succession::verify_step(&next, update)?;
            hosting::verify_step(previous, &update.state)?;
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
                        .is_subset(&update.state.retired_nodes)
                    && previous
                        .retired_relay_grants
                        .is_subset(&update.state.retired_relay_grants)
                    && previous
                        .retired_admin_grants
                        .is_subset(&update.state.retired_admin_grants),
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
            for (id, grant) in &previous.policy.relay_grants {
                match update.state.policy.relay_grants.get(id) {
                    Some(next) => ensure!(next == grant, "relay grant identity is immutable"),
                    None => ensure!(
                        update.state.retired_relay_grants.contains(id),
                        "removed relay grant requires retirement"
                    ),
                }
            }
            for (id, grant) in &previous.policy.admin_grants {
                match update.state.policy.admin_grants.get(id) {
                    Some(next) => {
                        ensure!(next == grant, "administration grant identity is immutable")
                    }
                    None => ensure!(
                        update.state.retired_admin_grants.contains(id),
                        "removed administration grant requires retirement"
                    ),
                }
            }
            for (id, grant) in &previous.policy.group_admin_grants {
                match update.state.policy.group_admin_grants.get(id) {
                    Some(next) => ensure!(
                        next == grant,
                        "group administration grant identity is immutable"
                    ),
                    None => ensure!(
                        update.state.retired_admin_grants.contains(id),
                        "removed administration grant requires retirement"
                    ),
                }
            }
            next.signed = update.clone();
            next.checkpoint = checkpoint;
        }
        Ok(next)
    }

    fn revise(
        &self,
        owner: &(impl peer::ConfigurationSigner + ?Sized),
        now: u64,
        edit: impl FnOnce(&mut ClusterState) -> Result<()>,
    ) -> Result<SignedState> {
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
        for (id, grant) in &self.state().policy.relay_grants {
            match state.policy.relay_grants.get(id) {
                Some(next) => ensure!(next == grant, "relay grant identity is immutable"),
                None => {
                    state.retired_relay_grants.insert(id.clone());
                }
            }
        }
        for (id, grant) in &self.state().policy.admin_grants {
            match state.policy.admin_grants.get(id) {
                Some(next) => ensure!(next == grant, "administration grant identity is immutable"),
                None => {
                    state.retired_admin_grants.insert(id.clone());
                }
            }
        }
        for (id, grant) in &self.state().policy.group_admin_grants {
            match state.policy.group_admin_grants.get(id) {
                Some(next) => ensure!(
                    next == grant,
                    "group administration grant identity is immutable"
                ),
                None => {
                    state.retired_admin_grants.insert(id.clone());
                }
            }
        }
        owner.sign_revision(self, state)
    }

    /// Renewal may repair an expired configuration using endpoint-held owner authority.
    pub fn renew(
        &self,
        owner: &(impl peer::ConfigurationSigner + ?Sized),
        now: u64,
    ) -> Result<SignedState> {
        self.revise(owner, now, |_| Ok(()))
    }

    pub fn set_policy(
        &self,
        owner: &(impl peer::ConfigurationSigner + ?Sized),
        policy: Policy,
        now: u64,
    ) -> Result<SignedState> {
        self.revise(owner, now, |state| {
            state.policy = policy;
            Ok(())
        })
    }

    /// Apply an owner-authorized TOML edit as one ordered cluster revision.
    pub fn configure(
        &self,
        owner: &(impl peer::ConfigurationSigner + ?Sized),
        name: &str,
        node: (&str, &str),
        policy: Policy,
        now: u64,
    ) -> Result<SignedState> {
        self.revise(owner, now, |state| {
            state.name = name.into();
            state.nodes.get_mut(node.0).context("unknown node")?.name = node.1.into();
            state.policy = policy;
            Ok(())
        })
    }

    /// `approved_fingerprint` must be independently confirmed by the owner; merely
    /// echoing a fingerprint supplied by the relay does not authenticate enrollment.
    pub fn enroll(
        &self,
        owner: &(impl peer::ConfigurationSigner + ?Sized),
        request: &SignedEnrollment,
        approved_fingerprint: Digest,
        now: u64,
    ) -> Result<SignedState> {
        self.accept_request(owner, request, approved_fingerprint, now, false, false)
    }

    /// Explicit owner approval for a machine used to manage cluster configuration.
    pub fn enroll_configurator(
        &self,
        owner: &(impl peer::ConfigurationSigner + ?Sized),
        request: &SignedEnrollment,
        approved: Digest,
        now: u64,
    ) -> Result<SignedState> {
        self.accept_request(owner, request, approved, now, false, true)
    }

    pub fn delegate_configuration(
        &self,
        owner: &(impl peer::ConfigurationSigner + ?Sized),
        node: &str,
        allow: bool,
        now: u64,
    ) -> Result<SignedState> {
        self.revise(owner, now, |state| {
            state
                .nodes
                .get_mut(node)
                .context("unknown node")?
                .can_configure = allow;
            Ok(())
        })
    }

    pub fn rotate_node_key(
        &self,
        owner: &(impl peer::ConfigurationSigner + ?Sized),
        request: &SignedEnrollment,
        approved_fingerprint: Digest,
        now: u64,
    ) -> Result<SignedState> {
        self.accept_request(owner, request, approved_fingerprint, now, true, false)
    }

    fn accept_request(
        &self,
        owner: &(impl peer::ConfigurationSigner + ?Sized),
        signed: &SignedEnrollment,
        approved: Digest,
        now: u64,
        rotation: bool,
        can_configure: bool,
    ) -> Result<SignedState> {
        ensure!(
            signed.request.replaces.is_none(),
            "replacement requires explicit owner approval"
        );
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
            let mut member = request.member.clone();
            member.can_configure = if rotation {
                state.nodes[&request.node_id].can_configure
            } else {
                can_configure
            };
            if rotation {
                member
                    .hosted_by
                    .clone_from(&state.nodes[&request.node_id].hosted_by);
            }
            state.nodes.insert(request.node_id.clone(), member);
            Ok(())
        })
    }

    pub fn revoke_node(
        &self,
        owner: &(impl peer::ConfigurationSigner + ?Sized),
        node_id: &str,
        now: u64,
    ) -> Result<SignedState> {
        self.revise(owner, now, |state| {
            state.require_no_hosted_children(node_id)?;
            let member = state.nodes.remove(node_id).context("node unavailable")?;
            state.retired_nodes.insert(node_id.into());
            state.retired_keys.insert(member.signing_key);
            Ok(())
        })
    }

    /// Retire the pinned old identity and admit a fresh identity atomically.
    /// Endpoint code separately refuses replacing the active signing owner.
    pub fn replace_node(
        &self,
        owner: &(impl peer::ConfigurationSigner + ?Sized),
        signed: &SignedEnrollment,
        approved: Digest,
        can_configure: bool,
        now: u64,
    ) -> Result<SignedState> {
        self.require_fresh(now)?;
        ensure!(
            signed.fingerprint()? == approved,
            "replacement fingerprint does not match owner approval"
        );
        let request = &signed.request;
        fresh(request.issued_at, request.expires_at, now)?;
        ensure!(
            request.anchor == self.anchor && request.base == self.checkpoint,
            "replacement targets another cluster or stale revision"
        );
        let replaces = request
            .replaces
            .as_ref()
            .context("replacement target is missing")?;
        let previous = self
            .state()
            .nodes
            .get(&replaces.id)
            .context("replacement target is unavailable")?;
        ensure!(
            previous.signing_key == replaces.signing_key,
            "replacement target key changed"
        );
        ensure!(
            !self.state().nodes.contains_key(&request.node_id),
            "replacement identity is already enrolled"
        );
        let mut member = request.member.clone();
        member.can_configure = previous.can_configure && can_configure;
        member.hosted_by.clone_from(&previous.hosted_by);
        self.revise(owner, now, |state| {
            state.require_no_hosted_children(&replaces.id)?;
            state.nodes.remove(&replaces.id);
            state.retired_nodes.insert(replaces.id.clone());
            state.retired_keys.insert(replaces.signing_key);
            state.nodes.insert(request.node_id.clone(), member);
            Ok(())
        })
    }
}
