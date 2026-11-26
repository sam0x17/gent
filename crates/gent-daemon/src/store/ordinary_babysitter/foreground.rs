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
        let mut messages = query.query(params![who.id, turn, MAX_CHAT_INPUTS])?;
        let mut deliveries = Vec::new();
        while let Some(row) = messages.next()? {
            let Some(record) = super::super::wake::record(self.db, &row.get::<_, String>(0)?)?
            else {
                return Ok(None);
            };
            deliveries.push(record);
        }
        // A user starts this root. Its last receipt must settle the final Gent
        // dispatch. Human steers between two deliveries must follow the previous
        // delivery's completion and precede the next claim.
        if deliveries.is_empty()
            || deliveries.len() >= proof.inputs.len()
            || deliveries.last().map(|r| &r.attempt_id) != additional.last()
        {
            return Ok(None);
        }
        let target = WakeTarget::Codex {
            thread_id: proof.thread.to_string(),
        };
        let mut automatic = self.db.prepare(
            "SELECT 1 FROM babysitter_chat_attempts WHERE agent=?1 AND attempt=?2
             UNION ALL SELECT 1 FROM babysitter_attempts WHERE agent=?1 AND attempt=?2",
        )?;
        let mut deliveries = deliveries.into_iter().peekable();
        let mut last_human = first.received_at_ms.div_euclid(1000);
        let mut previous_claim = None;
        let mut previous_finished = None;
        let mut human_ids = Vec::new();
        let mut human_hashes = BTreeSet::from([first.sha256.as_str()]);
        let mut delivery_hashes = BTreeSet::new();
        for (input, id) in later.iter().zip(&additional) {
            let Some(record) = deliveries.next_if(|r| &r.attempt_id == id) else {
                let received = input.received_at_ms.div_euclid(1000);
                if previous_finished.is_some_and(|at| at >= received) {
                    return Ok(None);
                }
                last_human = received;
                human_ids.push(id.clone());
                human_hashes.insert(input.sha256.as_str());
                continue;
            };
            let Some(direct) = record.direct else {
                return Ok(None);
            };
            let received = input.received_at_ms.div_euclid(1000);
            if record.agent != who.id
                || record.target != target
                || record.state != WakeState::Submitted
                || record.submission_id.as_ref() != Some(&turn)
                || direct.turn_id.as_ref() != Some(&turn)
                || !direct.finished
                || direct.input_hash != input.sha256
                || previous_claim.is_some_and(|at| record.claimed_at <= at)
                || record.claimed_at < last_human
                // Claims use seconds. If the opener shares the claim's second,
                // the later host receipt must put delivery in a separate second.
                || received <= last_human
                || record.claimed_at > received
                || record
                    .inbox_seen_at
                    .is_none_or(|at| at < received || at > record.updated_at)
                || record.updated_at > failed
                || automatic.exists(params![who.id, id])?
            {
                return Ok(None);
            }
            previous_claim = Some(record.claimed_at);
            previous_finished = Some(record.updated_at);
            delivery_hashes.insert(input.sha256.as_str());
        }
        if deliveries.next().is_some()
            || !human_hashes.is_disjoint(&delivery_hashes)
            || !self.chat_client_ids_allowed(who, Some(&opener), &human_ids)?
        {
            return Ok(None);
        }
        // Zero admits this failed root once and cannot authorize a child retry.
        Ok(Some(0))
    }
}
