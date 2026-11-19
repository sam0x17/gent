//! Versioned transition from owner-signed state to node-signed, ordered state.
use super::*;
use gent_protocol::configuration_log::{Commit, Head, Header};
#[cfg(feature = "invitation")]
pub mod direct;
#[cfg(feature = "invitation")]
pub mod envelope;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub header: Header,
    pub signer: PublicKey,
    /// The one transition record is signed by the previously pinned owner.
    /// Every subsequent record is signed by an authorized member node.
    pub migration: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,
}

/// Logical request identity, encrypted with configuration. Delegated requests
/// keep this identity when a different administrator publishes their result.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub origin: String,
    pub id: String,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection: Option<String>,
}

impl Request {
    fn validate(&self) -> Result<()> {
        id(&self.origin)?;
        id(&self.id)?;
        ensure!(
            self.rejection.as_ref().is_none_or(|r| r.len() <= 1024),
            "configuration rejection exceeds limit"
        );
        ensure!(
            self.fingerprint.len() == 64
                && self
                    .fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid logical configuration request"
        );
        Ok(())
    }
}

impl Authority {
    pub(super) fn validate(&self, state: &ClusterState) -> Result<()> {
        ensure!(self.header.valid(), "invalid peer ordering header");
        public_key(&self.signer)?;
        if let Some(request) = &self.request {
            ensure!(!self.migration, "migration cannot decide a new edit");
            request.validate()?;
        }
        ensure!(
            self.header.cluster == state.cluster_id
                && self.header.previous.sequence + 1 == state.revision,
            "peer authority does not match configuration sequence"
        );
        ensure!(
            state
                .nodes
                .values()
                .any(|n| n.can_configure && n.hosted_by.is_none()),
            "cluster requires a native configuration administrator"
        );
        Ok(())
    }
}

/// Signing a candidate does not apply it. Only the committed encrypted log can
/// advance a peer-authority checkpoint.
pub trait ConfigurationSigner {
    fn sign_revision(&self, previous: &VerifiedState, state: ClusterState) -> Result<SignedState>;
}

impl ConfigurationSigner for OwnerKey {
    fn sign_revision(&self, previous: &VerifiedState, state: ClusterState) -> Result<SignedState> {
        ensure!(
            previous.state().peer.is_none(),
            "legacy signing is fenced by peer authority"
        );
        ensure!(
            self.public_key() == previous.state().owner_key,
            "wrong owner authority"
        );
        self.sign(state)
    }
}

pub struct NodeSigner<'a> {
    node: &'a NodeIdentity,
    header: Header,
    request: Option<Request>,
}

impl<'a> NodeSigner<'a> {
    pub fn new(node: &'a NodeIdentity, header: Header) -> Result<Self> {
        ensure!(
            header.valid() && header.origin == node.id(),
            "wrong proposal identity"
        );
        Ok(Self {
            node,
            header,
            request: None,
        })
    }

    pub fn with_request(mut self, request: Request) -> Result<Self> {
        request.validate()?;
        self.request = Some(request);
        Ok(self)
    }
}

impl ConfigurationSigner for NodeSigner<'_> {
    fn sign_revision(
        &self,
        previous: &VerifiedState,
        mut state: ClusterState,
    ) -> Result<SignedState> {
        ensure!(
            previous.state().peer.is_some(),
            "peer authority is not active"
        );
        let member = previous
            .state()
            .nodes
            .get(self.node.id())
            .context("node unavailable")?;
        ensure!(
            member.signing_key == self.node.public_key() && member.can_configure,
            "node cannot administer configuration"
        );
        ensure!(
            self.header.previous.sequence == previous.checkpoint().revision,
            "proposal requires current sequence"
        );
        state.version = 3;
        state.peer = Some(Authority {
            header: self.header.clone(),
            signer: self.node.public_key(),
            migration: false,
            request: self.request.clone(),
        });
        state.validate()?;
        let signature = self
            .node
            .key
            .sign(&signing_input(STATE_DOMAIN, &state, MAX_STATE_BYTES)?)
            .to_bytes()
            .to_vec();
        let signed = SignedState { state, signature };
        // Check retirement continuity before any network publication.
        previous.verify_chain(std::slice::from_ref(&signed))?;
        Ok(signed)
    }
}

impl VerifiedState {
    /// Prepare the single owner-authenticated migration. The caller first
    /// durably fences the legacy writer, then publishes this candidate through
    /// the log. Existing restrictions and identities are preserved exactly.
    pub fn migrate_to_peers(
        &self,
        owner: &OwnerKey,
        node: &NodeIdentity,
        header: Header,
        now: u64,
    ) -> Result<SignedState> {
        ensure!(self.state().peer.is_none(), "peer authority already active");
        ensure!(
            owner.public_key() == self.state().owner_key,
            "wrong migration authority"
        );
        ensure!(
            header.origin == node.id() && header.previous.sequence == self.checkpoint().revision,
            "wrong migration checkpoint"
        );
        let member = self
            .state()
            .nodes
            .get(node.id())
            .context("migration node unavailable")?;
        ensure!(
            member.signing_key == node.public_key(),
            "migration node key mismatch"
        );
        let mut state = self.renew(owner, now)?.state;
        // The legacy signing owner always had effective configuration access,
        // even in older encodings that left its delegated-access flag false.
        state.nodes.get_mut(node.id()).unwrap().can_configure = true;
        state.version = 3;
        state.peer = Some(Authority {
            header,
            signer: node.public_key(),
            migration: true,
            request: None,
        });
        state.validate()?;
        let signature = owner
            .0
            .sign(&signing_input(STATE_DOMAIN, &state, MAX_STATE_BYTES)?)
            .to_bytes()
            .to_vec();
        let signed = SignedState { state, signature };
        self.verify_chain(std::slice::from_ref(&signed))?;
        Ok(signed)
    }

    /// Called only after opening the committed ciphertext. `head` is the
    /// durable local log checkpoint, never a value supplied by the proposal.
    /// The runtime must persist the returned head and authority transactionally.
    pub fn advance_committed(
        &mut self,
        update: SignedState,
        commit: &Commit,
        head: &Head,
    ) -> Result<Head> {
        ensure!(
            &commit.header.previous == head && head.sequence == self.checkpoint().revision,
            "configuration log rollback, gap, or fork"
        );
        let receipt = crate::configuration_log::verify(commit)?;
        let peer = update
            .state
            .peer
            .as_ref()
            .context("committed state requires peer authority")?;
        ensure!(
            peer.header == commit.header,
            "encrypted state does not match committed header"
        );
        let next = self.verify_chain(&[update])?;
        *self = next;
        Ok(receipt.head)
    }
}

pub(super) fn verify_step(previous: &VerifiedState, update: &SignedState) -> Result<()> {
    match (&previous.state().peer, &update.state.peer) {
        (None, None) => Ok(()),
        (Some(_), None) => anyhow::bail!("peer authority cannot return to legacy signing"),
        (old, Some(peer)) => {
            ensure!(
                previous.state().owner_key == update.state.owner_key
                    && previous.state().owner_transitions == update.state.owner_transitions,
                "peer authority freezes legacy owner lineage"
            );
            ensure!(
                peer.migration == old.is_none(),
                "invalid peer migration transition"
            );
            let member = previous
                .state()
                .nodes
                .get(&peer.header.origin)
                .context("peer signer is not enrolled")?;
            ensure!(
                member.signing_key == peer.signer && (peer.migration || member.can_configure),
                "peer signer is not authorized by prior state"
            );
            if peer.migration {
                let mut expected = previous.state().clone();
                expected.version = 3;
                expected.peer = update.state.peer.clone();
                expected.revision = update.state.revision;
                expected.previous = update.state.previous;
                expected.issued_at = update.state.issued_at;
                expected.expires_at = update.state.expires_at;
                expected
                    .nodes
                    .get_mut(&peer.header.origin)
                    .unwrap()
                    .can_configure = true;
                ensure!(
                    encode(&expected, MAX_STATE_BYTES)? == encode(&update.state, MAX_STATE_BYTES)?,
                    "migration cannot change membership or policy"
                );
            }
            Ok(())
        }
    }
}
