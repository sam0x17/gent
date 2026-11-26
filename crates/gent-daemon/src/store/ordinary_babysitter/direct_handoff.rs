//! Bind every input on a named host handoff to a distinct local direct delivery.
use super::*;
use gent_protocol::{
    babysitter::ForegroundInputs,
    wake::{WakeState, WakeTarget},
};

impl StoreSession<'_> {
    pub(super) fn direct_handoff_allowed(
        &self,
        who: &Agent,
        turn: &str,
        failed: i64,
        proof: &ForegroundInputs,
    ) -> Result<bool> {
        if proof.thread.is_nil()
            || proof.turn.to_string() != turn
            || !(1..=MAX_CHAT_INPUTS).contains(&proof.inputs.len())
            || !proof
                .inputs
                .windows(2)
                .all(|p| p[0].received_at_ms <= p[1].received_at_ms)
        {
            return Ok(false);
        }
        // Count disputed submissions and other targets. A join to messages here
        // could hide a second dispatch whose source was subsequently pruned.
        let mut query = self.db.prepare(
            "SELECT message_id FROM wake_dispatches WHERE agent=?1 AND
             (json_extract(payload,'$.submission_id')=?2 OR json_extract(payload,'$.direct.turn_id')=?2)
             ORDER BY claimed_at LIMIT ?3",
        )?;
        let mut rows = query.query(params![who.id, turn, proof.inputs.len() + 1])?;
        let target = WakeTarget::Codex {
            thread_id: proof.thread.to_string(),
        };
        let mut ordinary = self.db.prepare(
            "SELECT 1 FROM messages m WHERE id=?1 AND recipient=?2 AND json_type(payload,'$.relay') IS NULL
             AND NOT EXISTS(SELECT 1 FROM relay_turns WHERE id=?1)
             AND NOT EXISTS(SELECT 1 FROM work_entries WHERE message_id=?1)
             AND NOT EXISTS(SELECT 1 FROM messages reply
                 WHERE json_extract(reply.payload,'$.exchange_id')=json_extract(m.payload,'$.exchange_id')
                 AND reply.sender=?2 AND json_extract(reply.payload,'$.reply_to')=?1)
             AND NOT EXISTS(SELECT 1 FROM babysitter_chat_attempts WHERE agent=?2 AND attempt=?3)
             AND NOT EXISTS(SELECT 1 FROM babysitter_attempts WHERE agent=?2 AND attempt=?3)",
        )?;
        let mut previous_claim = None;
        let mut hashes = BTreeSet::new();
        for input in &proof.inputs {
            let Some(row) = rows.next()? else {
                return Ok(false);
            };
            let message: String = row.get(0)?;
            let Some(record) = super::super::wake::record(self.db, &message)? else {
                return Ok(false);
            };
            let Some(direct) = record.direct else {
                return Ok(false);
            };
            let received = input.received_at_ms.div_euclid(1000);
            let client = input.client.to_string();
            // The delivered text includes the unique Gent message ID.
            if !hashes.insert(&input.sha256)
                || record.attempt_id != client
                || record.target != target
                || record.state != WakeState::Submitted
                || record.submission_id.as_deref() != Some(turn)
                || direct.turn_id.as_deref() != Some(turn)
                || !direct.finished
                || direct.response_hash.is_some()
                || direct.response_message_id.is_some()
                || direct.input_hash != input.sha256
                || !(proof.started_at..=failed).contains(&received)
                || previous_claim.is_some_and(|prev| prev >= record.claimed_at)
                || record.claimed_at > received
                || record
                    .inbox_seen_at
                    .is_none_or(|at| at < received || at > failed)
                || record.updated_at > failed
                || !ordinary.exists(params![message, who.id, client])?
            {
                return Ok(false);
            }
            previous_claim = Some(record.claimed_at);
        }
        Ok(rows.next()?.is_none())
    }

    pub(super) fn direct_handoff_status(&self, who: &Agent, attempt: Uuid) -> Result<Option<bool>> {
        let row = self
            .db
            .query_row(
                "SELECT a.turn,a.failed_at,d.proof FROM babysitter_chat_direct_handoffs d
             JOIN babysitter_chat_attempts a USING(attempt) WHERE a.agent=?1 AND d.attempt=?2",
                params![who.id, attempt.to_string()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((turn, failed, proof)) = row else {
            return Ok(None);
        };
        self.direct_handoff_allowed(who, &turn, failed, &serde_json::from_str(&proof)?)
            .map(Some)
    }
}
