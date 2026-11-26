use super::*;
use gent_protocol::{
    babysitter::ForegroundInputs,
    wake::{WakeState, WakeTarget},
};

impl StoreSession<'_> {
    pub(super) fn foreground_ordinal(
        &self,
        who: &Agent,
        proof: &ForegroundInputs,
        failed: i64,
    ) -> Result<Option<i64>> {
        let [first, later @ ..] = proof.inputs.as_slice() else {
            return Ok(None);
        };
        if proof.thread.is_nil() || !(2..=MAX_CHAT_INPUTS).contains(&proof.inputs.len()) {
            return Ok(None);
        }
        let turn = proof.turn.to_string();
        let opener = first.client.to_string();
        let additional: Vec<_> = later.iter().map(|i| i.client.to_string()).collect();
        let mut clients = BTreeSet::new();
        if !proof
            .inputs
            .iter()
            .all(|i| !i.client.is_nil() && clients.insert(i.client))
            || self
                .db
                .prepare("SELECT 1 FROM babysitter_chat_mixed_inputs WHERE agent=?1 AND opener=?2")?
                .exists(params![who.id, opener])?
        {
            return Ok(None);
        }

        // Completely human steers retain their ordinary retry budget.
        if self.chat_operator_inputs_allowed(who, &turn, Some(&opener), &additional)? {
            return Ok(Some(1));
        }
        if !proof.inputs.iter().all(|i| {
            i.sha256.len() == 64
                && i.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                && (proof.started_at..=failed).contains(&i.received_at_ms.div_euclid(1000))
        }) || !proof
            .inputs
            .windows(2)
            .all(|p| p[0].received_at_ms <= p[1].received_at_ms)
        {
            return Ok(None);
        }

        // Include disputed submissions and other threads targeting this same
        // turn. Any extra, incomplete, or contradictory dispatch closes the exception.
        let mut query = self.db.prepare(
            "SELECT message_id FROM wake_dispatches WHERE agent=?1 AND
             (json_extract(payload,'$.submission_id')=?2 OR json_extract(payload,'$.direct.turn_id')=?2)
             ORDER BY claimed_at LIMIT ?3")?;
        let messages = query
            .query_map(params![who.id, turn, MAX_CHAT_INPUTS], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // Only a contiguous suffix may be Gent deliveries. The native proof pairs
        // every input with its receipt. Exclude all known automatic client IDs in
        // the foreground prefix, including dispatches attributed to different turns.
        if messages.is_empty() || messages.len() >= proof.inputs.len() {
            return Ok(None);
        }
        let (foreground, deliveries) = proof.inputs.split_at(proof.inputs.len() - messages.len());
        if !self.chat_client_ids_allowed(who, Some(&opener), &additional[..foreground.len() - 1])? {
            return Ok(None);
        }
        let target = WakeTarget::Codex {
            thread_id: proof.thread.to_string(),
        };
        let mut automatic = self.db.prepare(
            "SELECT 1 FROM babysitter_chat_attempts WHERE agent=?1 AND attempt=?2
             UNION ALL SELECT 1 FROM babysitter_attempts WHERE agent=?1 AND attempt=?2",
        )?;
        let mut previous_claim = foreground[foreground.len() - 1]
            .received_at_ms
            .div_euclid(1000);
        for (input, message) in deliveries.iter().zip(messages) {
            let id = input.client.to_string();
            let Some(record) = super::super::wake::record(self.db, &message)? else {
                return Ok(None);
            };
            let Some(direct) = record.direct else {
                return Ok(None);
            };
            let received = input.received_at_ms.div_euclid(1000);
            if record.attempt_id != id
                || record.agent != who.id
                || record.target != target
                || record.state != WakeState::Submitted
                || record.submission_id.as_ref() != Some(&turn)
                || direct.turn_id.as_ref() != Some(&turn)
                || !direct.finished
                || direct.input_hash != input.sha256
                || foreground
                    .iter()
                    .any(|input| input.sha256 == direct.input_hash)
                || record.claimed_at <= previous_claim
                || record.claimed_at > received
                || record
                    .inbox_seen_at
                    .is_none_or(|at| at < received || at > failed)
                || record.updated_at > failed
                || automatic.exists(params![who.id, id])?
            {
                return Ok(None);
            }
            previous_claim = record.claimed_at;
        }
        // Zero admits this failed root once and cannot authorize a child retry.
        Ok(Some(0))
    }
}
