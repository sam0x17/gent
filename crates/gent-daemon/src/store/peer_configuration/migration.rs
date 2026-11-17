//! Carry accepted legacy decisions and the retained history through the signed,
//! encrypted transition. Nothing here is trusted until that transition verifies.
use super::*;
use configuration::storage::handoff;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Archive {
    pub base: gent_crypto::Checkpoint,
    pub history: Vec<gent_crypto::SignedState>,
    decisions: String,
    entries: usize,
}

impl Archive {
    pub fn capture(db: &Connection, state: &VerifiedState) -> Result<Vec<u8>> {
        let (entries, decisions) = handoff::snapshot(db, state.checkpoint())?;
        let mut history = Vec::new();
        let mut bytes = decisions.len();
        let mut query = db.prepare("SELECT state FROM authority_history ORDER BY revision")?;
        for row in query.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            let wire = row?;
            bytes = bytes.saturating_add(wire.len());
            ensure!(
                bytes <= 1024 * 1024,
                "retained migration archive exceeds capacity; no authority was changed"
            );
            history.push(gent_crypto::SignedState::decode(&wire)?);
        }
        Ok(serde_json::to_vec(&Self {
            base: state.checkpoint().clone(),
            history,
            decisions: STANDARD.encode(decisions),
            entries,
        })?)
    }

    pub fn verify_history(&self, state: &VerifiedState) -> Result<VerifiedState> {
        ensure!(
            self.base.revision >= state.checkpoint().revision,
            "migration base rolled back"
        );
        let mut next = state.clone();
        for signed in &self.history {
            if signed.state.revision > state.checkpoint().revision {
                next.advance_history(std::slice::from_ref(signed))?;
            } else if signed.state.revision == state.checkpoint().revision {
                ensure!(
                    signed.verified_checkpoint(state.anchor())? == *state.checkpoint(),
                    "migration history fork"
                );
            }
        }
        ensure!(
            next.checkpoint() == &self.base,
            "migration history has a gap"
        );
        Ok(next)
    }

    pub fn adopt(&self, db: &Connection) -> Result<()> {
        handoff::adopt(
            db,
            &self.base,
            self.entries,
            &STANDARD.decode(&self.decisions)?,
        )
    }
}
