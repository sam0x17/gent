//! Claims and native submission receipts stay on the registered chat's node.
use super::*;
use gent_protocol::{
    babysitter::{CHAT_CHAIN_MAX_AGE, CHAT_FAILURE_MAX_AGE, ChatOrigin, MAX_CHAT_INPUTS},
    notifications::Failure,
};
use uuid::Uuid;

const FIRST_RETRY_DELAY: i64 = 15;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS babysitter_chat_attempts(
            agent TEXT NOT NULL, turn TEXT NOT NULL, failed_at INTEGER NOT NULL,
            operator TEXT NOT NULL, operator_at INTEGER NOT NULL, ordinal INTEGER NOT NULL,
            reason TEXT NOT NULL, attempt TEXT NOT NULL UNIQUE, claimed_at INTEGER NOT NULL,
            admitted INTEGER NOT NULL DEFAULT 0, submitted INTEGER NOT NULL DEFAULT 0,
            cancelled INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(agent,turn), UNIQUE(agent,operator,ordinal)
        );
        CREATE INDEX IF NOT EXISTS babysitter_chat_retention ON babysitter_chat_attempts(claimed_at);
        CREATE TABLE IF NOT EXISTS babysitter_chat_handoffs(
            attempt TEXT PRIMARY KEY REFERENCES babysitter_chat_attempts(attempt) ON DELETE CASCADE,
            agent TEXT NOT NULL, item TEXT NOT NULL, UNIQUE(agent,item)
        );",
    )?;
    Ok(())
}

fn retry_due(previous: i64, failed: i64, now: i64) -> bool {
    let delay = match previous {
        1 => FIRST_RETRY_DELAY,
        2 => 60,
        _ => return false,
    };
    failed.saturating_add(delay) <= now
}

impl StoreSession<'_> {
    fn chat_enabled(&self, who: &Agent) -> Result<bool> {
        Ok(config::ordinary_babysitter_enabled(self.home)? && self.babysitter_allowed(who)?)
    }

    pub(super) fn chat_claimed_turn(&self, who: &Agent, turn: Uuid) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM babysitter_chat_attempts WHERE agent=?1 AND turn=?2)",
            params![who.id, turn.to_string()],
            |r| r.get(0),
        )?)
    }

    fn chat_available(&self, who: &Agent, turn: Uuid, failed: i64) -> Result<bool> {
        if !self.chat_enabled(who)?
            || turn.is_nil()
            || !(self.timestamp - CHAT_FAILURE_MAX_AGE..=self.timestamp).contains(&failed)
        {
            return Ok(false);
        }
        Ok(!self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM babysitter_chat_attempts WHERE agent=?1 AND turn=?2
             UNION ALL SELECT 1 FROM babysitter_attempts WHERE agent=?1 AND turn=?2 AND attempt IS NOT NULL)",
            params![who.id, turn.to_string()], |row| row.get::<_, bool>(0),
        )?)
    }

    // Keep opted-out, already-claimed and exhausted threads out of the rollout
    // reader. This cheap probe grants no right to submit or reserve an attempt.
    pub(super) fn babysitter_chat_probe(
        &self,
        who: &Agent,
        turn: Uuid,
        operator: Uuid,
        failed: i64,
    ) -> Result<bool> {
        if !self.chat_available(who, turn, failed)? {
            return Ok(false);
        }
        if operator == turn {
            return Ok(true);
        }
        let previous = self
            .db
            .query_row(
                "SELECT ordinal FROM babysitter_chat_attempts WHERE agent=?1 AND operator=?2
             AND admitted=1 AND cancelled=0 AND EXISTS(
                SELECT 1 FROM babysitter_chat_attempts root WHERE root.agent=?1 AND root.turn=?2 AND root.failed_at>=?3)
             AND rowid=(SELECT MAX(rowid) FROM babysitter_chat_attempts WHERE agent=?1)",
                params![
                    who.id,
                    operator.to_string(),
                    self.timestamp - CHAT_CHAIN_MAX_AGE
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        Ok(previous.is_some_and(|previous| retry_due(previous, failed, self.timestamp)))
    }

    fn chat_operator_inputs_allowed(
        &self,
        who: &Agent,
        turn: &str,
        client_id: Option<&str>,
        additional_client_ids: &[String],
    ) -> Result<bool> {
        let multi_input = !additional_client_ids.is_empty();
        if additional_client_ids.len() >= MAX_CHAT_INPUTS || (multi_input && client_id.is_none()) {
            return Ok(false);
        }
        if let Some(first) = client_id {
            let mut seen = BTreeSet::new();
            let mut attempt = self.db.prepare(
                "SELECT 1 FROM wake_dispatches WHERE agent=?1 AND attempt_id=?2
                 UNION ALL SELECT 1 FROM babysitter_chat_attempts WHERE agent=?1 AND attempt=?2
                 UNION ALL SELECT 1 FROM babysitter_attempts WHERE agent=?1 AND attempt=?2
                 LIMIT 1",
            )?;
            for id in std::iter::once(first).chain(additional_client_ids.iter().map(String::as_str))
            {
                if id.len() > 256 || (multi_input && (id.trim().is_empty() || !seen.insert(id))) {
                    return Ok(false);
                }
                if attempt.exists(params![who.id, id])? {
                    return Ok(false);
                }
            }
        }
        // A direct wake can record the native turn even if the host omits or
        // changes its client ID. Check this agent's journal once per candidate.
        Ok(!self.db.prepare(
            "SELECT 1 FROM wake_dispatches WHERE agent=?1
             AND json_extract(payload,'$.target.host')='codex' AND json_type(payload,'$.direct')='object'
             AND (json_extract(payload,'$.submission_id')=?2 OR json_extract(payload,'$.direct.turn_id')=?2)
             LIMIT 1",
        )?.exists(params![who.id, turn])?)
    }

    pub(super) fn babysitter_chat_claim(
        &self,
        who: &Agent,
        turn: Uuid,
        failed: i64,
        reason: Failure,
        origin: ChatOrigin,
    ) -> Result<Value> {
        let no = json!({"claim":null});
        let now = self.timestamp;
        if !self.chat_available(who, turn, failed)? {
            return Ok(no);
        }
        let turn = turn.to_string();

        let mut handoff = None;
        let (operator, operator_at, ordinal, parent) = match origin {
            ChatOrigin::Operator {
                turn: operator,
                started_at,
                client_id,
                additional_client_ids,
            } => {
                if operator.to_string() != turn
                    || !self.chat_operator_inputs_allowed(
                        who,
                        &turn,
                        client_id.as_deref(),
                        &additional_client_ids,
                    )?
                {
                    return Ok(no);
                }
                (operator.to_string(), started_at, 1, None)
            }
            ChatOrigin::ThreadHandoff { item, started_at } => {
                if item.is_nil()
                    || !self.chat_operator_inputs_allowed(who, &turn, None, &[])?
                    || self
                        .db
                        .prepare(
                            "SELECT 1 FROM babysitter_chat_handoffs WHERE agent=?1 AND item=?2
                         UNION ALL SELECT 1 FROM babysitter_chat_attempts
                         WHERE agent=?1 AND ordinal=0 AND claimed_at>?3 LIMIT 1",
                        )?
                        .exists(params![who.id, item.to_string(), now - FIRST_RETRY_DELAY])?
                {
                    return Ok(no);
                }
                handoff = Some(item);
                // The legacy operator column groups attempts by root. Zero is outside
                // the human retry sequence, including for an older daemon after rollback.
                (turn.clone(), started_at, 0, None)
            }
            ChatOrigin::Continuation { attempt }
            | ChatOrigin::SteeredContinuation { attempt, .. } => {
                // Admission is durable even if turn/start's reply was lost. Only
                // the host adapter that observed the matching native input can continue it.
                let parent = self.db.query_row(
                    "SELECT operator,operator_at,ordinal,claimed_at,turn,failed_at FROM babysitter_chat_attempts
                     WHERE agent=?1 AND attempt=?2 AND admitted=1 AND cancelled=0
                     AND EXISTS(SELECT 1 FROM babysitter_chat_attempts root WHERE root.agent=?1
                                AND root.turn=babysitter_chat_attempts.operator AND root.failed_at>=?3)
                     AND rowid=(SELECT MAX(rowid) FROM babysitter_chat_attempts WHERE agent=?1)",
                    params![who.id, attempt.to_string(), now-CHAT_CHAIN_MAX_AGE],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    },
                ).optional()?;
                let Some((operator, operator_at, previous, claimed, parent, previous_failure)) =
                    parent
                else {
                    return Ok(no);
                };
                if failed < claimed || !retry_due(previous, failed, now) {
                    return Ok(no);
                }
                if let ChatOrigin::SteeredContinuation {
                    root,
                    parent: native_parent,
                    parent_failed_at,
                    started_at,
                    additional_client_ids,
                    ..
                } = origin
                {
                    let Some((first, rest)) = additional_client_ids.split_first() else {
                        return Ok(no);
                    };
                    if root.to_string() != operator
                        || native_parent.to_string() != parent
                        || turn == parent
                        || turn == operator
                        || parent_failed_at != previous_failure
                        || !(claimed..=failed).contains(&started_at)
                        || first.trim().is_empty()
                        || additional_client_ids.len() >= MAX_CHAT_INPUTS
                        || !self.chat_operator_inputs_allowed(who, &turn, Some(first), rest)?
                        || self
                            .db
                            .prepare(
                                "SELECT 1 FROM wake_dispatches WHERE agent=?1 AND attempt_id=?2
                                 UNION ALL SELECT 1 FROM babysitter_attempts WHERE agent=?1 AND attempt=?2",
                            )?
                            .exists(params![who.id, attempt.to_string()])?
                    {
                        return Ok(no);
                    }
                }
                (operator, operator_at, previous + 1, Some(parent))
            }
        };
        if !(0..=failed).contains(&operator_at) {
            return Ok(no);
        }
        // Keep tombstones beyond every admissible failure and operator window.
        self.db.execute(
            "DELETE FROM babysitter_chat_attempts WHERE claimed_at<?1",
            [now - 86400],
        )?;
        let id = Uuid::new_v4();
        let inserted = self.db.execute(
            "INSERT INTO babysitter_chat_attempts(agent,turn,failed_at,operator,operator_at,ordinal,reason,attempt,claimed_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT DO NOTHING",
            params![who.id,turn,failed,operator,operator_at,ordinal,serde_json::to_string(&reason)?,id.to_string(),now],
        )?;
        if inserted == 0 {
            return Ok(no);
        }
        if let Some(item) = handoff {
            self.db.execute(
                "INSERT INTO babysitter_chat_handoffs(attempt,agent,item) VALUES(?1,?2,?3)",
                params![id.to_string(), who.id, item.to_string()],
            )?;
        }
        Ok(json!({"claim":id,"operator":operator,"operator_at":operator_at,"parent":parent}))
    }

    pub(super) fn babysitter_chat_check(&self, who: &Agent, attempt: Uuid) -> Result<Value> {
        let eligible = self.chat_enabled(who)?
            && self.wake_pending(who)?["pending"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && self.db.execute(
                "UPDATE babysitter_chat_attempts SET admitted=1 WHERE agent=?1 AND attempt=?2
             AND admitted=0 AND cancelled=0 AND claimed_at>=?3 AND failed_at>=?4
             AND EXISTS(SELECT 1 FROM babysitter_chat_attempts root WHERE root.agent=?1
                        AND root.turn=babysitter_chat_attempts.operator AND root.failed_at>=?5)
             AND rowid=(SELECT MAX(rowid) FROM babysitter_chat_attempts WHERE agent=?1)
             AND NOT EXISTS(SELECT 1 FROM wake_dispatches WHERE agent=?1
                            AND claimed_at>=babysitter_chat_attempts.failed_at)",
                params![
                    who.id,
                    attempt.to_string(),
                    self.timestamp - 30,
                    self.timestamp - CHAT_FAILURE_MAX_AGE,
                    self.timestamp - CHAT_CHAIN_MAX_AGE
                ],
            )? == 1;
        Ok(json!({"eligible":eligible}))
    }

    pub(super) fn babysitter_chat_submitted(&self, who: &Agent, attempt: Uuid) -> Result<Value> {
        // A host acceptance is not evidence of a resumed goal or successful work.
        let submitted: Option<bool> = self.db.query_row(
            "SELECT submitted FROM babysitter_chat_attempts WHERE agent=?1 AND attempt=?2 AND admitted=1",
            params![who.id,attempt.to_string()], |row| row.get(0)
        ).optional()?;
        if submitted == Some(false) {
            self.db.execute(
                "UPDATE babysitter_chat_attempts SET submitted=1 WHERE agent=?1 AND attempt=?2",
                params![who.id, attempt.to_string()],
            )?;
            self.db.execute("UPDATE usage_tracking SET ordinary_submitted=ordinary_submitted+1 WHERE singleton=1", [])?;
        }
        Ok(json!({"submitted":submitted.is_some()}))
    }
}
