//! A committed claim can authorize one host-input submission. Its retries only
//! return evidence. No operation here invokes a host or grants execution rights.
use super::*;
use gent_protocol::wake::{WakeRecord, WakeState, WakeTarget};

mod direct;
pub(super) mod retention;

const MAX_RECORDS: u64 = 16_384;
const RECORD_BYTES: usize = 2048;
const AGENT_HOURLY_LIMIT: u64 = 12;
const NODE_HOURLY_LIMIT: u64 = 120;
const MIN_INTERVAL: i64 = 5;

pub(super) fn schema(db: &Connection) -> Result<()> {
    let tx = rusqlite::Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let version: Option<String> = tx
        .query_row(
            "SELECT value FROM metadata WHERE key='wake_journal_version'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let tables: u64 = tx.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='wake_dispatches'",
        [],
        |r| r.get(0),
    )?;
    if let Some(version) = version {
        ensure!(
            version == "1" && tables == 1,
            "wake journal is missing or unsupported; do not repeat uncertain dispatches"
        );
    } else {
        ensure!(
            tables == 0,
            "unversioned wake journal; refusing to recreate it"
        );
        tx.execute_batch(
            "CREATE TABLE wake_dispatches (
            message_id TEXT PRIMARY KEY, agent TEXT NOT NULL REFERENCES agents(id),
            attempt_id TEXT NOT NULL UNIQUE, claimed_at INTEGER NOT NULL,
            payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB))<=2048));
            CREATE INDEX wake_dispatch_budget ON wake_dispatches(claimed_at,agent);
            INSERT INTO metadata(key,value) VALUES('wake_journal_version','1');",
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn id(value: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(value).context("invalid wake identifier")?;
    ensure!(
        !parsed.is_nil() && parsed.to_string() == value,
        "invalid wake identifier"
    );
    Ok(())
}

fn target(value: &WakeTarget) -> Result<()> {
    match value {
        WakeTarget::Codex { thread_id } => id(thread_id),
        WakeTarget::ClaudeCode { session_id } => id(session_id),
    }
}

fn limits() -> Value {
    json!({"records":MAX_RECORDS,"bytes_per_record":RECORD_BYTES,
        "claims_per_agent_per_hour":AGENT_HOURLY_LIMIT,"claims_per_node_per_hour":NODE_HOURLY_LIMIT,
        "minimum_agent_interval_seconds":MIN_INTERVAL})
}

fn record(db: &Connection, message_id: &str) -> Result<Option<WakeRecord>> {
    id(message_id)?;
    let row: Option<(String, String, i64, String)> = db
        .query_row(
            "SELECT agent,attempt_id,claimed_at,payload FROM wake_dispatches WHERE message_id=?1",
            [message_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    row.map(|(agent, attempt, claimed, payload)| {
        ensure!(payload.len() <= RECORD_BYTES, "oversized wake record");
        let record: WakeRecord = serde_json::from_str(&payload)?;
        id(&record.agent)?;
        id(&record.attempt_id)?;
        target(&record.target)?;
        if let Some(direct) = &record.direct {
            id(&direct.reply_request_id)?;
            ensure!(
                direct.input_hash.len() == 64
                    && direct.input_hash.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid direct input hash"
            );
            if let Some(turn) = &direct.turn_id {
                id(turn)?;
            }
            if let Some(message) = &direct.response_message_id {
                id(message)?;
            }
            ensure!(
                direct
                    .response_hash
                    .as_ref()
                    .is_none_or(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())),
                "invalid direct response hash"
            );
            ensure!(
                !direct.finished || direct.turn_id.is_some(),
                "direct completion has no native turn"
            );
        }
        if let Some(submission) = &record.submission_id {
            id(submission)?;
        }
        ensure!(
            record.message_id == message_id
                && record.agent == agent
                && record.attempt_id == attempt
                && record.claimed_at == claimed
                && record.claimed_at >= 0
                && record.updated_at >= record.claimed_at
                && record
                    .inbox_seen_at
                    .is_none_or(|at| at >= claimed && at <= record.updated_at)
                && (record.state == WakeState::Submitted) == record.submission_id.is_some(),
            "inconsistent wake record; do not repeat uncertain dispatches"
        );
        Ok(record)
    })
    .transpose()
}

impl StoreSession<'_> {
    pub(super) fn wake_check(
        &self,
        who: &Agent,
        message_id: &str,
        attempt_id: &str,
        target_id: &WakeTarget,
    ) -> Result<Value> {
        id(attempt_id)?;
        target(target_id)?;
        let record = self.wake_record(message_id)?.context(UNAVAILABLE)?;
        ensure!(record.agent == who.id, UNAVAILABLE);
        ensure!(
            record.attempt_id == attempt_id && &record.target == target_id,
            "wake dispatch does not match this attempt and host conversation"
        );
        let message = self.message(message_id)?;
        let eligible = record.state == WakeState::Uncertain
            && message.recipient == who.id
            && !message.acknowledged
            && self.deliverable(&message)?
            && self.relay_inbox_visible(&message)?;
        // This is a read-only check for the adapter still holding the original
        // claim response. It never permits recovery/retry of a lost submission.
        Ok(json!({"record":record,"eligible":eligible}))
    }

    fn wake_record(&self, message_id: &str) -> Result<Option<WakeRecord>> {
        record(self.db, message_id)
    }

    fn wake_write(&self, record: &WakeRecord) -> Result<()> {
        let payload = serde_json::to_string(record)?;
        ensure!(payload.len() <= RECORD_BYTES, "wake record too large");
        ensure!(self.db.execute("UPDATE wake_dispatches SET payload=?1 WHERE message_id=?2 AND agent=?3 AND attempt_id=?4",
            params![payload,record.message_id,record.agent,record.attempt_id])? == 1, "wake record changed");
        Ok(())
    }

    pub(super) fn wake_pending(&self, who: &Agent) -> Result<Value> {
        let mut statement = self.db.prepare(
            "SELECT m.payload FROM messages m
            WHERE m.recipient=?1 AND m.acknowledged=0
            AND NOT EXISTS(SELECT 1 FROM wake_dispatches w WHERE w.message_id=m.id)
            ORDER BY m.rowid",
        )?;
        let rows = statement.query_map([&who.id], |r| r.get::<_, String>(0))?;
        let mut pending = Vec::new();
        for row in rows {
            let message: Message = serde_json::from_str(&row?)?;
            if self.deliverable(&message)? && self.relay_inbox_visible(&message)? {
                pending.push(json!({"message_id":message.id,"expires_at":message.expires_at}));
                if pending.len() == 50 {
                    break;
                }
            }
        }
        Ok(json!({"agent":who.id,"pending":pending,"limits":limits()}))
    }

    pub(super) fn wake_claim(
        &self,
        who: &Agent,
        message_id: &str,
        attempt_id: &str,
        target_id: WakeTarget,
    ) -> Result<Value> {
        id(message_id)?;
        id(attempt_id)?;
        target(&target_id)?;
        if let Some(record) = self.wake_record(message_id)? {
            ensure!(record.agent == who.id, UNAVAILABLE);
            ensure!(
                record.attempt_id == attempt_id && record.target == target_id,
                "wake dispatch already claimed; inspect its outcome before any new submission"
            );
            return Ok(json!({"may_submit":false,"record":record}));
        }
        let message = self.message(message_id)?;
        ensure!(
            message.recipient == who.id
                && !message.acknowledged
                && self.deliverable(&message)?
                && self.relay_inbox_visible(&message)?,
            UNAVAILABLE
        );
        let count: u64 = self
            .db
            .query_row("SELECT COUNT(*) FROM wake_dispatches", [], |r| r.get(0))?;
        ensure!(
            count < MAX_RECORDS,
            "wake journal is full; inspect gent wake status and gent wake clean; leave messages pending"
        );
        let (node_count, agent_count, last): (u64, u64, Option<i64>) = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(agent=?1),0),MAX(CASE WHEN agent=?1 THEN claimed_at END)
             FROM wake_dispatches WHERE claimed_at>?2",
            params![who.id, self.timestamp - 3600],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure!(
            node_count < NODE_HOURLY_LIMIT
                && agent_count < AGENT_HOURLY_LIMIT
                && last.is_none_or(|at| self.timestamp - at >= MIN_INTERVAL),
            "wake budget exhausted; leave messages pending"
        );
        let record = WakeRecord {
            direct: None,
            message_id: message_id.into(),
            agent: who.id.clone(),
            attempt_id: attempt_id.into(),
            target: target_id,
            state: WakeState::Uncertain,
            submission_id: None,
            inbox_seen_at: None,
            claimed_at: self.timestamp,
            updated_at: self.timestamp,
        };
        let payload = serde_json::to_string(&record)?;
        ensure!(payload.len() <= RECORD_BYTES, "wake record too large");
        self.db.execute("INSERT INTO wake_dispatches(message_id,agent,attempt_id,claimed_at,payload) VALUES(?1,?2,?3,?4,?5)",
            params![record.message_id,record.agent,record.attempt_id,record.claimed_at,payload])?;
        Ok(json!({"may_submit":true,"record":record}))
    }

    pub(super) fn wake_submitted(
        &self,
        who: &Agent,
        message_id: &str,
        attempt_id: &str,
        submission_id: &str,
    ) -> Result<Value> {
        id(attempt_id)?;
        id(submission_id)?;
        let mut record = self.wake_record(message_id)?.context(UNAVAILABLE)?;
        ensure!(record.agent == who.id, UNAVAILABLE);
        ensure!(
            record.attempt_id == attempt_id,
            "wake attempt does not match"
        );
        if let Some(existing) = &record.submission_id {
            ensure!(existing == submission_id, "wake submission does not match");
        } else {
            record.submission_id = Some(submission_id.into());
            record.state = WakeState::Submitted;
            record.updated_at = self.timestamp;
            self.wake_write(&record)?;
        }
        Ok(json!(record))
    }

    pub(super) fn wake_observe(&self, who: &Agent, message_id: &str) -> Result<()> {
        if let Some(mut record) = self.wake_record(message_id)? {
            ensure!(
                record.agent == who.id,
                "wake record belongs to another agent"
            );
            if record.inbox_seen_at.is_none() {
                record.inbox_seen_at = Some(self.timestamp);
                record.updated_at = self.timestamp;
                self.wake_write(&record)?;
            }
        }
        Ok(())
    }

    pub(super) fn wake_show(&self, message_id: &str) -> Result<Value> {
        Ok(json!(
            self.wake_record(message_id)?
                .context("wake dispatch is not recorded")?
        ))
    }

    pub(super) fn wake_list(&self, after: Option<&str>) -> Result<Value> {
        if let Some(after) = after {
            id(after)?;
        }
        let mut statement = self.db.prepare("SELECT message_id FROM wake_dispatches WHERE message_id>?1 ORDER BY message_id LIMIT 51")?;
        let ids = statement
            .query_map([after.unwrap_or("")], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let entries = ids
            .iter()
            .take(50)
            .map(|id| self.wake_show(id))
            .collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"entries":entries,"has_more":ids.len()>50,"next_after":ids.iter().take(50).next_back(),"limits":limits()}),
        )
    }
}
