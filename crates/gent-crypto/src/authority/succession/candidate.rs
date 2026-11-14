use super::*;

pub const MAX_CANDIDATE_BYTES: usize = 8192;
pub const CANDIDATE_LIFETIME: u64 = 15 * 60;
const NODE_DOMAIN: &[u8] = b"gent/owner-candidate/v1\0";
const KEY_DOMAIN: &[u8] = b"gent/owner-candidate-key/v1\0";
const CANDIDATE_DOMAIN: &[u8] = b"gent/owner-candidate-record/v1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerSuccessor {
    pub node: ReplacedNode,
    pub candidate: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal: Option<Digest>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerCandidate {
    pub version: u32,
    pub id: String,
    pub anchor: TrustAnchor,
    pub base: Checkpoint,
    pub node: ReplacedNode,
    pub owner_key: PublicKey,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOwnerCandidate {
    pub candidate: OwnerCandidate,
    pub node_signature: Vec<u8>,
    pub key_signature: Vec<u8>,
}

impl SignedOwnerCandidate {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode(self, MAX_CANDIDATE_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode(bytes, MAX_CANDIDATE_BYTES)
    }
    pub fn digest(&self) -> Result<Digest> {
        digest(CANDIDATE_DOMAIN, self, MAX_CANDIDATE_BYTES)
    }

    /// Verify against independently trusted live state before approving a signer.
    pub fn verify(&self, state: &VerifiedState, now: u64) -> Result<()> {
        let proposal = &self.candidate;
        ensure!(
            proposal.version == 1
                && &proposal.anchor == state.anchor()
                && &proposal.base == state.checkpoint(),
            "owner candidate has a different cluster or checkpoint"
        );
        id(&proposal.id)?;
        lifetime(proposal.issued_at, proposal.expires_at, CANDIDATE_LIFETIME)?;
        fresh(proposal.issued_at, proposal.expires_at, now)?;
        ensure!(
            proposal.issued_at >= state.state().issued_at,
            "candidate predates its state"
        );
        state.authorize_node(&proposal.node.id, &proposal.node.signing_key, now)?;
        public_key(&proposal.owner_key)?;
        ensure!(
            !owner_keys(&state.state().owner_transitions, state.state().owner_key)
                .contains(&proposal.owner_key)
                && !state.state().retired_keys.contains(&proposal.owner_key)
                && state
                    .state()
                    .nodes
                    .values()
                    .all(|n| n.signing_key != proposal.owner_key),
            "candidate must use a fresh separate owner key"
        );
        verify(
            &proposal.node.signing_key,
            NODE_DOMAIN,
            proposal,
            &self.node_signature,
            MAX_CANDIDATE_BYTES,
        )?;
        verify(
            &proposal.owner_key,
            KEY_DOMAIN,
            proposal,
            &self.key_signature,
            MAX_CANDIDATE_BYTES,
        )?;
        self.encode()?;
        Ok(())
    }
}

impl NodeIdentity {
    pub fn prepare_owner_candidate(
        &self,
        state: &VerifiedState,
        key: &OwnerKey,
        request: &str,
        now: u64,
    ) -> Result<SignedOwnerCandidate> {
        let candidate = OwnerCandidate {
            version: 1,
            id: request.into(),
            anchor: state.anchor().clone(),
            base: state.checkpoint().clone(),
            node: ReplacedNode {
                id: self.id().into(),
                signing_key: self.public_key(),
            },
            owner_key: key.public_key(),
            issued_at: now,
            expires_at: now
                .checked_add(CANDIDATE_LIFETIME)
                .context("timestamp overflow")?,
        };
        let node_signature = self
            .key
            .sign(&signing_input(
                NODE_DOMAIN,
                &candidate,
                MAX_CANDIDATE_BYTES,
            )?)
            .to_bytes()
            .to_vec();
        let key_signature = key
            .0
            .sign(&signing_input(KEY_DOMAIN, &candidate, MAX_CANDIDATE_BYTES)?)
            .to_bytes()
            .to_vec();
        let signed = SignedOwnerCandidate {
            candidate,
            node_signature,
            key_signature,
        };
        signed.verify(state, now)?;
        Ok(signed)
    }
}

impl VerifiedState {
    /// Persist a write fence before returning this authorization to another node.
    pub fn authorize_owner_candidate(
        &self,
        owner: &OwnerKey,
        candidate: &SignedOwnerCandidate,
        now: u64,
    ) -> Result<SignedOwnerTransition> {
        self.authorize_candidate(owner, candidate, None, now)
    }

    /// The caller snapshots completed decisions in the same transaction that
    /// freezes signing. The digest authenticates that exact transfer manifest.
    pub fn authorize_owner_candidate_with_journal(
        &self,
        owner: &OwnerKey,
        candidate: &SignedOwnerCandidate,
        journal: Digest,
        now: u64,
    ) -> Result<SignedOwnerTransition> {
        self.authorize_candidate(owner, candidate, Some(journal), now)
    }

    fn authorize_candidate(
        &self,
        owner: &OwnerKey,
        candidate: &SignedOwnerCandidate,
        journal: Option<Digest>,
        now: u64,
    ) -> Result<SignedOwnerTransition> {
        ensure!(
            owner.public_key() == self.state().owner_key,
            "wrong current owner authority"
        );
        candidate.verify(self, now)?;
        ensure!(
            self.state().owner_transitions.len() < MAX_OWNER_TRANSITIONS,
            "owner succession history is full"
        );
        let transition = OwnerTransition {
            version: 1,
            anchor: self.anchor().clone(),
            epoch: self.owner_epoch() + 1,
            previous: self
                .state()
                .owner_transitions
                .last()
                .map(SignedOwnerTransition::digest)
                .transpose()?
                .unwrap_or(self.anchor().genesis_hash),
            base: self.checkpoint().clone(),
            owner_key: candidate.candidate.owner_key,
            successor: Some(OwnerSuccessor {
                node: candidate.candidate.node.clone(),
                candidate: candidate.digest()?,
                journal,
            }),
            issued_at: now,
        };
        let signature = owner
            .0
            .sign(&signing_input(
                DOMAIN,
                &transition,
                MAX_OWNER_TRANSITION_BYTES,
            )?)
            .to_bytes()
            .to_vec();
        let signed = SignedOwnerTransition {
            transition,
            signature,
        };
        self.verify_owner_authorization(candidate, &signed)?;
        Ok(signed)
    }

    /// Verifies authorization at its original issue time. Once issued, retrying
    /// completion after the candidate deadline must preserve the same decision.
    pub fn verify_owner_authorization(
        &self,
        candidate: &SignedOwnerCandidate,
        authorization: &SignedOwnerTransition,
    ) -> Result<()> {
        candidate.verify(self, authorization.transition.issued_at)?;
        let expected = OwnerSuccessor {
            node: candidate.candidate.node.clone(),
            candidate: candidate.digest()?,
            journal: authorization
                .transition
                .successor
                .as_ref()
                .and_then(|s| s.journal),
        };
        ensure!(
            authorization.transition.base == *self.checkpoint()
                && authorization.transition.owner_key == candidate.candidate.owner_key
                && authorization.transition.successor.as_ref() == Some(&expected),
            "owner authorization does not match candidate"
        );
        let mut chain = self.state().owner_transitions.clone();
        chain.push(authorization.clone());
        verify_lineage(self.anchor(), &chain)?;
        Ok(())
    }

    pub fn accept_owner_authorization(
        &self,
        key: &OwnerKey,
        candidate: &SignedOwnerCandidate,
        authorization: &SignedOwnerTransition,
        now: u64,
    ) -> Result<SignedState> {
        self.verify_owner_authorization(candidate, authorization)?;
        ensure!(
            now >= authorization.transition.issued_at,
            "owner completion clock moved backwards"
        );
        self.sign_owner_transition(key, authorization.clone())
    }
}
