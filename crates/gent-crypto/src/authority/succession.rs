//! Authenticated signer succession, separate from daemon activation and key recovery.
use super::*;

pub const MAX_OWNER_TRANSITIONS: usize = 64;
pub const MAX_OWNER_CHAIN_BYTES: usize = 128 * 1024;
pub const MAX_OWNER_TRANSITION_BYTES: usize = 4096;
const DOMAIN: &[u8] = b"gent/owner-succession/v1\0";
const RECORD_DOMAIN: &[u8] = b"gent/owner-succession-record/v1\0";
mod candidate;
pub use candidate::*;
pub mod journal;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerTransition {
    pub version: u32,
    pub anchor: TrustAnchor,
    pub epoch: u32,
    pub previous: Digest,
    pub base: Checkpoint,
    pub owner_key: PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor: Option<OwnerSuccessor>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOwnerTransition {
    pub transition: OwnerTransition,
    pub signature: Vec<u8>,
}

impl SignedOwnerTransition {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode(self, MAX_OWNER_TRANSITION_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode(bytes, MAX_OWNER_TRANSITION_BYTES)
    }
    pub fn digest(&self) -> Result<Digest> {
        digest(RECORD_DOMAIN, self, MAX_OWNER_TRANSITION_BYTES)
    }
}

pub(super) fn owner_keys(
    chain: &[SignedOwnerTransition],
    current: PublicKey,
) -> BTreeSet<PublicKey> {
    let mut keys = BTreeSet::from([current]);
    for link in chain {
        keys.insert(link.transition.anchor.owner_key);
        keys.insert(link.transition.owner_key);
    }
    keys
}

/// Authenticates a historical delegation chain. It does not select an active
/// chain or prove that the predecessor has stopped. Accepted state does that
/// selection through exact checkpoints and append-only epoch history.
pub(super) fn verify_lineage(
    anchor: &TrustAnchor,
    chain: &[SignedOwnerTransition],
) -> Result<PublicKey> {
    id(&anchor.cluster_id)?;
    public_key(&anchor.owner_key)?;
    ensure!(anchor.genesis_hash != [0; 32], "invalid genesis hash");
    ensure!(
        chain.len() <= MAX_OWNER_TRANSITIONS,
        "owner succession history is full"
    );
    encode(&chain, MAX_OWNER_CHAIN_BYTES)?;
    let mut owner = anchor.owner_key;
    let mut previous = anchor.genesis_hash;
    let mut seen = BTreeSet::from([owner]);
    let mut last: Option<&OwnerTransition> = None;
    for (index, signed) in chain.iter().enumerate() {
        let record = &signed.transition;
        ensure!(
            record.version == 1
                && &record.anchor == anchor
                && record.epoch as usize == index + 1
                && record.previous == previous,
            "owner succession chain mismatch"
        );
        public_key(&record.owner_key)?;
        ensure!(
            seen.insert(record.owner_key),
            "owner signing key cannot be reused"
        );
        if let Some(successor) = &record.successor {
            id(&successor.node.id)?;
            public_key(&successor.node.signing_key)?;
            ensure!(
                !seen.contains(&successor.node.signing_key)
                    && successor.candidate != [0; 32]
                    && successor.journal.is_none_or(|digest| digest != [0; 32]),
                "invalid successor node binding"
            );
        }
        ensure!(
            record.base.revision < MAX_SAFE_INTEGER
                && record.base.state_hash != [0; 32]
                && record.issued_at > 0
                && record.issued_at <= MAX_SAFE_INTEGER,
            "invalid owner succession checkpoint or time"
        );
        if record.base.revision == 0 {
            ensure!(
                record.base.state_hash == anchor.genesis_hash,
                "owner succession genesis mismatch"
            );
        }
        if let Some(last) = last {
            ensure!(
                record.base.revision > last.base.revision && record.issued_at >= last.issued_at,
                "owner succession moved backwards"
            );
        }
        verify(
            &owner,
            DOMAIN,
            record,
            &signed.signature,
            MAX_OWNER_TRANSITION_BYTES,
        )?;
        previous = signed.digest()?;
        owner = record.owner_key;
        last = Some(record);
    }
    Ok(owner)
}

pub(super) fn verify_step(previous: &VerifiedState, update: &SignedState) -> Result<()> {
    let old = &previous.state().owner_transitions;
    let new = &update.state.owner_transitions;
    if old == new {
        return Ok(());
    }
    ensure!(
        new.len() == old.len() + 1 && new.starts_with(old),
        "owner succession cannot be removed, replaced or skipped"
    );
    let transition = &new.last().context("missing owner transition")?.transition;
    if let Some(successor) = &transition.successor {
        ensure!(
            previous
                .state()
                .nodes
                .get(&successor.node.id)
                .is_some_and(|n| n.signing_key == successor.node.signing_key),
            "successor node is not enrolled at the handoff checkpoint"
        );
    }
    ensure!(
        &transition.base == previous.checkpoint() && transition.issued_at == update.state.issued_at,
        "owner succession requires the exact accepted checkpoint and activation time"
    );
    // The handoff changes only signing authority. Policy and membership changes
    // require a subsequent ordinary revision signed by the successor.
    let mut expected = previous.state().clone();
    expected.version = 2;
    expected.owner_key = transition.owner_key;
    expected.owner_transitions = new.clone();
    expected.revision = update.state.revision;
    expected.previous = update.state.previous;
    expected.issued_at = update.state.issued_at;
    expected.expires_at = update.state.expires_at;
    ensure!(
        encode(&expected, MAX_STATE_BYTES)? == encode(&update.state, MAX_STATE_BYTES)?,
        "owner handoff cannot change membership or policy"
    );
    ensure!(
        !previous
            .state()
            .retired_keys
            .contains(&transition.owner_key),
        "retired node key cannot become an owner key"
    );
    Ok(())
}

impl VerifiedState {
    pub fn owner_epoch(&self) -> u32 {
        self.state().owner_transitions.len() as u32
    }

    /// Requires possession of both the current signer and a fresh successor.
    /// This creates a record only; persistence, fencing and recovery approval
    /// belong to the caller. An expired lease does not invalidate the signer.
    pub fn transfer_owner(
        &self,
        owner: &OwnerKey,
        successor: &OwnerKey,
        now: u64,
    ) -> Result<SignedState> {
        ensure!(
            owner.public_key() == self.state().owner_key,
            "wrong current owner authority"
        );
        ensure!(
            self.state().owner_transitions.len() < MAX_OWNER_TRANSITIONS,
            "owner succession history is full"
        );
        ensure!(
            now >= self.state().issued_at && now > 0,
            "owner succession clock moved backwards"
        );
        let key = successor.public_key();
        ensure!(
            !owner_keys(&self.state().owner_transitions, owner.public_key()).contains(&key)
                && !self.state().retired_keys.contains(&key)
                && self
                    .state()
                    .nodes
                    .values()
                    .all(|node| node.signing_key != key),
            "owner succession requires a fresh separate signing key"
        );
        let previous = self
            .state()
            .owner_transitions
            .last()
            .map(SignedOwnerTransition::digest)
            .transpose()?
            .unwrap_or(self.anchor().genesis_hash);
        let transition = OwnerTransition {
            version: 1,
            anchor: self.anchor().clone(),
            epoch: self.owner_epoch() + 1,
            previous,
            base: self.checkpoint().clone(),
            owner_key: key,
            successor: None,
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
        self.sign_owner_transition(
            successor,
            SignedOwnerTransition {
                transition,
                signature,
            },
        )
    }

    fn sign_owner_transition(
        &self,
        successor: &OwnerKey,
        transition: SignedOwnerTransition,
    ) -> Result<SignedState> {
        let now = transition.transition.issued_at;
        ensure!(
            transition.transition.owner_key == successor.public_key(),
            "wrong successor signing key"
        );
        let mut state = self.state().clone();
        state.version = 2;
        state.owner_key = successor.public_key();
        state.owner_transitions.push(transition);
        state.revision = state.revision.checked_add(1).context("revision overflow")?;
        state.previous = Some(self.checkpoint().state_hash);
        state.issued_at = now;
        state.expires_at = now
            .checked_add(MAX_STATE_LIFETIME)
            .context("timestamp overflow")?;
        let update = successor.sign(state)?;
        self.verify_chain(std::slice::from_ref(&update))?;
        Ok(update)
    }
}
