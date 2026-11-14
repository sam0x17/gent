//! Signed observations for owner recovery review. These never freeze a writer,
//! grant ownership, choose a winning fork, or reactivate archived state.
use super::*;

pub const MAX_CHALLENGE_BYTES: usize = 4096;
pub const MAX_OBSERVATION_BYTES: usize = MAX_STATE_BYTES + 8192;
pub const OBSERVATION_LIFETIME: u64 = 15 * 60;
const DOMAIN: &[u8] = b"gent/recovery-observation/v1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryChallenge {
    pub version: u32,
    pub id: String,
    pub anchor: TrustAnchor,
    pub base: Checkpoint,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl RecoveryChallenge {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode(self, MAX_CHALLENGE_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode(bytes, MAX_CHALLENGE_BYTES)
    }
    pub fn validate(&self, now: u64) -> Result<()> {
        ensure!(self.version == 1, "unsupported recovery challenge");
        id(&self.id)?;
        id(&self.anchor.cluster_id)?;
        public_key(&self.anchor.owner_key)?;
        ensure!(
            self.anchor.genesis_hash != [0; 32]
                && self.base.state_hash != [0; 32]
                && self.base.revision <= MAX_SAFE_INTEGER,
            "invalid recovery checkpoint"
        );
        lifetime(self.issued_at, self.expires_at, OBSERVATION_LIFETIME)?;
        fresh(self.issued_at, self.expires_at, now)?;
        self.encode()?;
        Ok(())
    }
}

/// Obtain this file from the intended, independently trusted local node.
/// The self-contained owner signature does not select the user's trust anchor.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBaseline {
    pub challenge: RecoveryChallenge,
    pub state: SignedState,
}

impl RecoveryBaseline {
    pub fn new(state: &VerifiedState, now: u64) -> Result<Self> {
        ensure!(
            now >= state.state().issued_at,
            "recovery clock precedes saved state"
        );
        let baseline = Self {
            challenge: RecoveryChallenge {
                version: 1,
                id: uuid::Uuid::new_v4().to_string(),
                anchor: state.anchor().clone(),
                base: state.checkpoint().clone(),
                issued_at: now,
                expires_at: now
                    .checked_add(OBSERVATION_LIFETIME)
                    .context("timestamp overflow")?,
            },
            state: state.signed().clone(),
        };
        baseline.verify(now)?;
        Ok(baseline)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode(self, MAX_OBSERVATION_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode(bytes, MAX_OBSERVATION_BYTES)
    }
    pub fn verify(&self, now: u64) -> Result<VerifiedState> {
        self.challenge.validate(now)?;
        ensure!(
            self.state.state.issued_at <= self.challenge.issued_at,
            "baseline state is from the future"
        );
        self.encode()?;
        VerifiedState::restore(
            self.challenge.anchor.clone(),
            self.challenge.base.clone(),
            self.state.clone(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryObservationBody {
    pub version: u32,
    pub challenge: RecoveryChallenge,
    pub observer: String,
    pub observer_key: PublicKey,
    pub observed_at: u64,
    pub state: SignedState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecoveryObservation {
    pub observation: RecoveryObservationBody,
    pub signature: Vec<u8>,
}

impl NodeIdentity {
    /// May report an expired configuration, but never grants new authority.
    pub fn observe_recovery(
        &self,
        state: &VerifiedState,
        challenge: &RecoveryChallenge,
        now: u64,
    ) -> Result<SignedRecoveryObservation> {
        challenge.validate(now)?;
        ensure!(
            state.anchor() == &challenge.anchor,
            "recovery challenge belongs to another cluster"
        );
        ensure!(
            state.state().issued_at <= now,
            "observed state is from the future"
        );
        ensure!(
            state
                .state()
                .nodes
                .get(self.id())
                .is_some_and(|n| n.signing_key == self.public_key()),
            "observer is not a member of its reported state"
        );
        let observation = RecoveryObservationBody {
            version: 1,
            challenge: challenge.clone(),
            observer: self.id().into(),
            observer_key: self.public_key(),
            observed_at: now,
            state: state.signed().clone(),
        };
        let signature = self
            .key
            .sign(&signing_input(DOMAIN, &observation, MAX_OBSERVATION_BYTES)?)
            .to_bytes()
            .to_vec();
        let report = SignedRecoveryObservation {
            observation,
            signature,
        };
        report.encode()?;
        Ok(report)
    }
}

impl SignedRecoveryObservation {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode(self, MAX_OBSERVATION_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode(bytes, MAX_OBSERVATION_BYTES)
    }
    /// This authenticates a statement, not the completeness of the node's
    /// knowledge or the absence of a later/competing owner revision.
    pub fn verify(&self, challenge: &RecoveryChallenge, now: u64) -> Result<Checkpoint> {
        challenge.validate(now)?;
        let body = &self.observation;
        ensure!(
            body.version == 1 && &body.challenge == challenge,
            "wrong recovery challenge"
        );
        id(&body.observer)?;
        ensure!(
            body.observed_at >= challenge.issued_at
                && body.observed_at <= now
                && body.observed_at < challenge.expires_at
                && body.state.state.issued_at <= body.observed_at,
            "invalid recovery observation time"
        );
        let checkpoint = body.state.verified_checkpoint(&challenge.anchor)?;
        ensure!(
            checkpoint.revision != 0 || checkpoint.state_hash == challenge.anchor.genesis_hash,
            "observed genesis does not match the pinned cluster"
        );
        ensure!(
            body.state
                .state
                .nodes
                .get(&body.observer)
                .is_some_and(|n| n.signing_key == body.observer_key),
            "observer is not a member of its reported state"
        );
        verify(
            &body.observer_key,
            DOMAIN,
            body,
            &self.signature,
            MAX_OBSERVATION_BYTES,
        )?;
        self.encode()?;
        Ok(checkpoint)
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointRelation {
    Matches,
    Behind,
    Ahead,
    Conflict,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObservationSummary {
    pub node: String,
    pub checkpoint: Checkpoint,
    pub observed_at: u64,
    pub relation: CheckpointRelation,
    pub state_expires_at: u64,
    pub state_expired: bool,
}

#[derive(Debug, Serialize)]
pub struct RecoveryReview {
    pub challenge: String,
    pub base: Checkpoint,
    pub valid_until: u64,
    pub observations: Vec<ObservationSummary>,
    pub missing_nodes: Vec<String>,
    pub conflicting_revisions: Vec<u64>,
    pub all_match_baseline: bool,
    pub authorizes_owner_change: bool,
    pub proves_writer_stopped: bool,
    pub proves_global_freshness: bool,
}

/// Stream reports one at a time, retaining only small verified summaries.
pub struct RecoveryReviewer {
    baseline: RecoveryBaseline,
    reports: BTreeMap<String, ObservationSummary>,
    hashes: BTreeMap<u64, BTreeSet<Digest>>,
}

impl RecoveryReviewer {
    pub fn new(baseline: RecoveryBaseline, now: u64) -> Result<Self> {
        baseline.verify(now)?;
        let hashes = BTreeMap::from([(
            baseline.challenge.base.revision,
            BTreeSet::from([baseline.challenge.base.state_hash]),
        )]);
        Ok(Self {
            baseline,
            reports: BTreeMap::new(),
            hashes,
        })
    }

    pub fn observe(&mut self, report: &SignedRecoveryObservation, now: u64) -> Result<()> {
        let checkpoint = report.verify(&self.baseline.challenge, now)?;
        let body = &report.observation;
        ensure!(
            self.baseline
                .state
                .state
                .nodes
                .get(&body.observer)
                .is_some_and(|n| n.signing_key == body.observer_key),
            "observer is not the node key pinned by the baseline; obtain a current trusted baseline"
        );
        ensure!(
            !self.reports.contains_key(&body.observer),
            "duplicate observer report"
        );
        let base = &self.baseline.challenge.base;
        let relation = if checkpoint.revision < base.revision {
            CheckpointRelation::Behind
        } else if checkpoint.revision > base.revision {
            CheckpointRelation::Ahead
        } else if checkpoint.state_hash == base.state_hash {
            CheckpointRelation::Matches
        } else {
            CheckpointRelation::Conflict
        };
        self.hashes
            .entry(checkpoint.revision)
            .or_default()
            .insert(checkpoint.state_hash);
        self.reports.insert(
            body.observer.clone(),
            ObservationSummary {
                node: body.observer.clone(),
                checkpoint,
                observed_at: body.observed_at,
                relation,
                state_expires_at: body.state.state.expires_at,
                state_expired: body.state.state.expires_at <= now,
            },
        );
        Ok(())
    }

    pub fn finish(self, now: u64) -> Result<RecoveryReview> {
        self.baseline.challenge.validate(now)?;
        ensure!(
            self.reports.values().all(|r| r.observed_at <= now),
            "review clock moved backwards"
        );
        let missing_nodes: Vec<_> = self
            .baseline
            .state
            .state
            .nodes
            .keys()
            .filter(|id| !self.reports.contains_key(*id))
            .cloned()
            .collect();
        let conflicting_revisions: Vec<_> = self
            .hashes
            .iter()
            .filter_map(|(revision, hashes)| (hashes.len() > 1).then_some(*revision))
            .collect();
        let all_match_baseline = missing_nodes.is_empty()
            && conflicting_revisions.is_empty()
            && self
                .reports
                .values()
                .all(|r| r.relation == CheckpointRelation::Matches);
        Ok(RecoveryReview {
            challenge: self.baseline.challenge.id,
            base: self.baseline.challenge.base,
            valid_until: self.baseline.challenge.expires_at,
            observations: self
                .reports
                .into_values()
                .map(|mut summary| {
                    summary.state_expired = summary.state_expires_at <= now;
                    summary
                })
                .collect(),
            missing_nodes,
            conflicting_revisions,
            all_match_baseline,
            authorizes_owner_change: false,
            proves_writer_stopped: false,
            proves_global_freshness: false,
        })
    }
}
