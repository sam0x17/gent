//! Recipient-local execution reports. Nothing here executes host work, sends a
//! message, or restores authority from a backup. An uncertain begin retry must
//! never return permission to start again.
use super::*;
use gent_protocol::work::{WorkResolution, WorkState};
use serde::{Deserialize, Serialize};

const MAX_RECORDS: u64 = 4096;
const MAX_EVENTS: u64 = 65_536;
const MAX_REVISION: u64 = 64;
const RECORD_BYTES: u64 = 8192;
const EVENT_BYTES: u64 = 16_384;
const MAX_BYTES: u64 = 128 * 1024 * 1024;

pub(super) fn schema(db: &Connection) -> Result<()> {
    let tx = rusqlite::Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let version: Option<String> = tx
        .query_row(
            "SELECT value FROM metadata WHERE key='work_journal_version'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let tables: u64 = tx.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('work_entries','work_events')", [], |r| r.get(0)
    )?;
    if let Some(version) = version {
        ensure!(
            version == "1" && tables == 2,
            "work journal is missing or unsupported; do not repeat uncertain work"
        );
    } else {
        ensure!(
            tables == 0,
            "unversioned work journal; refusing to recreate it"
        );
        tx.execute_batch("CREATE TABLE work_entries (
            message_id TEXT PRIMARY KEY, agent TEXT NOT NULL REFERENCES agents(id), payload TEXT NOT NULL);
            CREATE TABLE work_events (
            message_id TEXT NOT NULL REFERENCES work_entries(message_id), revision INTEGER NOT NULL,
            payload TEXT NOT NULL, PRIMARY KEY(message_id,revision));
            INSERT INTO metadata(key,value) VALUES('work_journal_version','1');")?;
    }
    tx.commit()?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    message_id: String,
    agent: String,
    sender: String,
    message_sha256: String,
    description: String,
    state: WorkState,
    revision: u64,
    attempts: u64,
    created_at: i64,
    updated_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    revision: u64,
    state: WorkState,
    attempts: u64,
    actor: String,
    note: String,
    at: i64,
}

fn id(value: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(value).context("invalid message ID")?;
    ensure!(
        !parsed.is_nil() && parsed.to_string() == value,
        "invalid message ID"
    );
    Ok(())
}

fn text(value: &str, maximum: usize) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= maximum,
        "work text is empty or too long"
    );
    Ok(())
}

fn reserved(state: WorkState) -> u64 {
    match state {
        WorkState::Started => 1,
        WorkState::RetryApproved => 2,
        _ => 0,
    }
}

impl StoreSession<'_> {
    fn work_message(&self, who: &Agent, message_id: &str) -> Result<Message> {
        id(message_id)?;
        let mut message = self.message(message_id)?;
        ensure!(
            message.recipient == who.id && self.deliverable(&message)?,
            UNAVAILABLE
        );
        if let Some(relay) = &message.relay {
            ensure!(
                relay.kind == RelayMessageKind::Request,
                "work must reference a relay request"
            );
        }
        message.acknowledged = false;
        Ok(message)
    }

    fn work_record(&self, message_id: &str) -> Result<Option<Record>> {
        id(message_id)?;
        let row: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT agent,payload FROM work_entries WHERE message_id=?1",
                [message_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(agent, payload)| {
            ensure!(
                payload.len() as u64 <= RECORD_BYTES,
                "oversized work record"
            );
            let record: Record = serde_json::from_str(&payload)?;
            ensure!(
                record.message_id == message_id
                    && record.agent == agent
                    && record.revision > 0
                    && record.revision <= MAX_REVISION
                    && record.revision + reserved(record.state) <= MAX_REVISION
                    && record.attempts > 0
                    && record.attempts <= record.revision
                    && record.created_at <= record.updated_at
                    && record.message_sha256.len() == 64
                    && record
                        .message_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "inconsistent work record"
            );
            text(&record.description, 1024)?;
            id(&record.agent)?;
            id(&record.sender)?;
            Ok(record)
        })
        .transpose()
    }

    fn work_events(&self, record: &Record) -> Result<Vec<Event>> {
        let mut statement = self
            .db
            .prepare("SELECT revision,payload FROM work_events WHERE message_id=?1 ORDER BY revision LIMIT 65")?;
        let rows = statement.query_map([&record.message_id], |r| {
            Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut events: Vec<Event> = Vec::new();
        for row in rows {
            let (revision, payload) = row?;
            ensure!(payload.len() as u64 <= EVENT_BYTES, "oversized work event");
            let event: Event = serde_json::from_str(&payload)?;
            ensure!(
                revision == events.len() as u64 + 1 && event.revision == revision,
                "incomplete work journal"
            );
            if let Some(previous) = events.last() {
                let valid_transition = if event.state == WorkState::Started {
                    previous.state == WorkState::RetryApproved
                        && event.actor == "agent"
                        && event.attempts == previous.attempts + 1
                        && event.note.is_empty()
                } else {
                    text(&event.note, 2048)?;
                    event.attempts == previous.attempts
                        && (event.actor == "owner"
                            || (event.actor == "agent"
                                && previous.state == WorkState::Started
                                && event.state == WorkState::Completed))
                };
                ensure!(
                    valid_transition && event.at >= previous.at,
                    "invalid work transition"
                );
            } else {
                ensure!(
                    event.state == WorkState::Started
                        && event.attempts == 1
                        && event.actor == "agent"
                        && event.note.is_empty()
                        && event.at == record.created_at,
                    "invalid first work event"
                );
            }
            events.push(event);
        }
        ensure!(
            events.len() as u64 == record.revision,
            "incomplete work journal"
        );
        let event = events.last().context("work journal event missing")?;
        ensure!(
            event.revision == record.revision
                && event.state == record.state
                && event.attempts == record.attempts
                && event.at == record.updated_at,
            "inconsistent work event"
        );
        Ok(events)
    }

    fn work_event(&self, record: &Record) -> Result<Event> {
        self.work_events(record)?
            .pop()
            .context("work journal event missing")
    }

    fn work_source_matches(&self, who: &Agent, record: &Record) -> Result<Message> {
        let message = self.work_message(who, &record.message_id)?;
        ensure!(
            record.agent == who.id
                && record.sender == message.sender
                && record.message_sha256 == hash(&serde_json::to_string(&message)?),
            UNAVAILABLE
        );
        Ok(message)
    }

    fn work_can_start(&self, who: &Agent, message: &Message) -> Result<()> {
        if message.relay.is_some() {
            let next = self.relay_next(who)?;
            ensure!(
                next["request"]["id"] == message.id && next["cancel_requested"] == false,
                "relay work is not current or cancellation was requested"
            );
        }
        Ok(())
    }

    fn work_value(&self, record: &Record) -> Result<Value> {
        Ok(
            json!({"record":record,"last_event":self.work_event(record)?,
            "execution_verified":false}),
        )
    }

    fn work_save(&self, record: &Record, actor: &str, note: &str) -> Result<()> {
        ensure!(
            record.revision + reserved(record.state) <= MAX_REVISION,
            "work revision capacity exhausted; preserve this journal; automatic retry is unavailable"
        );
        let payload = serde_json::to_string(record)?;
        let event = serde_json::to_string(&Event {
            revision: record.revision,
            state: record.state,
            attempts: record.attempts,
            actor: actor.into(),
            note: note.into(),
            at: record.updated_at,
        })?;
        ensure!(
            payload.len() as u64 <= RECORD_BYTES && event.len() as u64 <= EVENT_BYTES,
            "work record too large"
        );
        self.db.execute(
            "INSERT INTO work_entries(message_id,agent,payload) VALUES(?1,?2,?3)
            ON CONFLICT(message_id) DO UPDATE SET payload=excluded.payload",
            params![record.message_id, record.agent, payload],
        )?;
        self.db.execute(
            "INSERT INTO work_events VALUES(?1,?2,?3)",
            params![record.message_id, record.revision, event],
        )?;
        let (records, reserves): (u64, u64) = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(CASE json_extract(payload,'$.state')
             WHEN 'started' THEN 1 WHEN 'retry_approved' THEN 2 ELSE 0 END),0) FROM work_entries",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (events, bytes): (u64, u64) = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM work_events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            records <= MAX_RECORDS
                && events + reserves <= MAX_EVENTS
                && records * RECORD_BYTES + bytes + reserves * EVENT_BYTES <= MAX_BYTES,
            "work journal capacity reached; uncertain work must not start"
        );
        Ok(())
    }

    pub(super) fn work_status(&self, who: &Agent, message_id: &str) -> Result<Value> {
        self.work_message(who, message_id)?;
        match self.work_record(message_id)? {
            Some(record) => {
                self.work_source_matches(who, &record)?;
                self.work_value(&record)
            }
            None => Ok(json!({"record":null,"execution_verified":false})),
        }
    }

    pub(super) fn work_begin(
        &self,
        who: &Agent,
        message_id: &str,
        expected: u64,
        description: &str,
    ) -> Result<Value> {
        text(description, 1024)?;
        let message = self.work_message(who, message_id)?;
        let fingerprint = hash(&serde_json::to_string(&message)?);
        let mut record = if let Some(record) = self.work_record(message_id)? {
            ensure!(
                record.agent == who.id
                    && record.sender == message.sender
                    && record.message_sha256 == fingerprint,
                UNAVAILABLE
            );
            self.work_event(&record)?;
            ensure!(
                record.description == description,
                "work description changed"
            );
            if expected.checked_add(1) == Some(record.revision)
                && record.state == WorkState::Started
            {
                let mut result = self.work_value(&record)?;
                result["started_now"] = json!(false);
                return Ok(result);
            }
            ensure!(
                expected == record.revision && record.state == WorkState::RetryApproved,
                "work already recorded; reconcile before another attempt"
            );
            record
        } else {
            ensure!(expected == 0, "work revision changed");
            Record {
                message_id: message_id.into(),
                agent: who.id.clone(),
                sender: message.sender.clone(),
                message_sha256: fingerprint,
                description: description.into(),
                state: WorkState::Started,
                revision: 0,
                attempts: 0,
                created_at: self.timestamp,
                updated_at: self.timestamp,
            }
        };
        self.work_can_start(who, &message)?;
        record.state = WorkState::Started;
        record.revision += 1;
        record.attempts += 1;
        record.updated_at = self.timestamp.max(record.updated_at);
        self.work_save(&record, "agent", "")?;
        let mut result = self.work_value(&record)?;
        result["started_now"] = json!(true);
        Ok(result)
    }

    pub(super) fn work_complete(
        &self,
        who: &Agent,
        message_id: &str,
        expected: u64,
        note: &str,
    ) -> Result<Value> {
        self.work_message(who, message_id)?;
        let record = self
            .work_record(message_id)?
            .context("work is not recorded")?;
        self.work_source_matches(who, &record)?;
        self.work_transition(record, expected, WorkState::Completed, "agent", note)
    }

    fn work_transition(
        &self,
        mut record: Record,
        expected: u64,
        state: WorkState,
        actor: &str,
        note: &str,
    ) -> Result<Value> {
        text(note, 2048)?;
        let previous = self.work_event(&record)?;
        if expected.checked_add(1) == Some(record.revision)
            && record.state == state
            && previous.actor == actor
            && previous.note == note
        {
            return self.work_value(&record);
        }
        ensure!(record.revision == expected, "work revision changed");
        ensure!(
            actor == "owner" || record.state == WorkState::Started,
            "work is not started"
        );
        record.state = state;
        record.revision += 1;
        record.updated_at = self.timestamp.max(record.updated_at);
        self.work_save(&record, actor, note)?;
        self.work_value(&record)
    }

    pub(super) fn work_reconcile(
        &self,
        message_id: &str,
        expected: u64,
        resolution: WorkResolution,
        note: &str,
    ) -> Result<Value> {
        let record = self
            .work_record(message_id)?
            .context("work is not recorded")?;
        if resolution == WorkResolution::RetryApproved {
            self.state.authorize_node(
                self.identity.node.id(),
                &self.identity.node.public_key(),
                self.timestamp as u64,
            )?;
            let who = self.get_agent(&record.agent)?;
            ensure!(!who.revoked, "registration revoked");
            let message = self.work_source_matches(&who, &record)?;
            self.work_can_start(&who, &message)?;
        }
        self.work_transition(record, expected, resolution.into(), "owner", note)
    }

    pub(super) fn work_show(&self, message_id: &str) -> Result<Value> {
        let record = self
            .work_record(message_id)?
            .context("work is not recorded")?;
        let mut value = self.work_value(&record)?;
        let events = self.work_events(&record)?;
        value["events"] = json!(events);
        Ok(value)
    }

    pub(super) fn work_list(&self, after: Option<&str>) -> Result<Value> {
        if let Some(after) = after {
            id(after)?;
        }
        let mut statement = self.db.prepare(
            "SELECT message_id FROM work_entries WHERE message_id>?1 ORDER BY message_id LIMIT 51",
        )?;
        let ids = statement
            .query_map([after.unwrap_or("")], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let records = ids
            .iter()
            .take(50)
            .map(|id| {
                self.work_record(id)?
                    .context("work record missing")
                    .and_then(|r| self.work_value(&r))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"entries":records,"has_more":ids.len()>50,"next_after":ids.iter().take(50).next_back(),
            "limits":{"records":MAX_RECORDS,"events":MAX_EVENTS,"reserved_bytes":MAX_BYTES,"revisions_per_record":MAX_REVISION}}),
        )
    }
}
