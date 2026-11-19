//! Event deduplication follows message expiry or registration generations.
//! Legacy IDs and timeless configuration/mesh operations retain their records.
use super::*;

const CLEAN_BATCH: usize = 256;
const MAX_EVENTS: u64 = 16384;
const MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RETRIES: u64 = 131072;
const MAX_ANNOUNCEMENTS: u64 = 65536;

#[cfg(test)]
mod tests;

pub(super) fn schema(db: &Connection) -> Result<()> {
    let tx = db.unchecked_transaction()?;
    for table in ["network_events", "network_sent"] {
        let columns = tx
            .prepare(&format!("PRAGMA table_info({table})"))?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (name, definition) in [
            ("traffic", "TEXT NOT NULL DEFAULT 'legacy'"),
            ("retire_after", "INTEGER"),
        ] {
            if !columns.iter().any(|c| c == name) {
                tx.execute_batch(&format!(
                    "ALTER TABLE {table} ADD COLUMN {name} {definition}"
                ))?;
            }
        }
        if table == "network_events" && !columns.iter().any(|c| c == "announcement") {
            tx.execute_batch(
                "ALTER TABLE network_events ADD COLUMN announcement INTEGER NOT NULL DEFAULT 0",
            )?;
        }
    }
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS network_announcements (
        peer TEXT NOT NULL,agent TEXT NOT NULL,generation INTEGER NOT NULL,PRIMARY KEY(peer,agent));
        CREATE INDEX IF NOT EXISTS network_sent_retirement ON network_sent(retire_after);
        CREATE INDEX IF NOT EXISTS network_sent_traffic ON network_sent(traffic);
        CREATE INDEX IF NOT EXISTS network_event_traffic ON network_events(traffic);",
    )?;
    tx.commit()?;
    Ok(())
}

fn usage(db: &Connection, traffic: &str) -> Result<(u64, u64, u64)> {
    // Unclassified legacy rows consume both reserves until they can drain.
    Ok(db.query_row("SELECT COUNT(*),COALESCE(SUM(length(body)),0),
        COALESCE(SUM(announcement=0),0)+(SELECT COUNT(*) FROM network_sent WHERE traffic IN (?1,'legacy'))
        FROM network_events WHERE traffic IN (?1,'legacy')", [traffic],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?)
}

fn capacity(db: &Connection, traffic: &str, bytes: usize, announcement: bool) -> Result<()> {
    let (events, used, retries) = usage(db, traffic)?;
    ensure!(
        events < MAX_EVENTS && used.saturating_add(bytes as u64) <= MAX_BYTES,
        "{traffic} node event queue quota exhausted; inspect gent history status and let pending delivery drain"
    );
    ensure!(
        announcement || retries < MAX_RETRIES,
        "{traffic} node event retry quota exhausted; inspect gent history status and clean expired history; legacy retries remain retained"
    );
    Ok(())
}

impl StoreSession<'_> {
    pub(super) fn enqueue_event(
        &self,
        peer: &str,
        id: Uuid,
        event: Event,
        subject: Option<&str>,
        receipt_expires: Option<i64>,
    ) -> Result<()> {
        let timestamp = requests::clock(self.db, self.timestamp)?;
        let id = id.to_string();
        if self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_sent WHERE id=?1)
            OR EXISTS(SELECT 1 FROM network_events WHERE id=?1)",
            [&id],
            |r| r.get::<_, bool>(0),
        )? {
            return Ok(());
        }
        let (traffic, deadline, announcement) = match &event {
            Event::Message { message, .. } => ("data", Some(message.expires_at), None),
            Event::Receipt { .. } => (
                "data",
                Some(receipt_expires.context("receipt lacks a retention deadline")?),
                None,
            ),
            Event::ConversationActivity { .. } => ("control", Some(timestamp + 86400), None),
            Event::Registration { agent } => {
                ("control", None, Some((agent.id.clone(), agent.generation)))
            }
            _ => ("control", None, None),
        };
        let deadline = if matches!(event, Event::Presence { .. } | Event::Directory { .. }) {
            // Probe ownership lives in one persistent row per peer. These
            // transport retry IDs need only a short deduplication window;
            // forgotten replies can never match a later random challenge.
            Some(timestamp + presence::RETRY_RETENTION)
        } else {
            deadline
                .map(|expiry| {
                    expiry
                        .checked_add(history::RETENTION)
                        .context("event retention deadline overflow")
                })
                .transpose()?
        };
        // Replayed expired messages must not recreate negative receipts forever.
        // The same check prevents old local message snapshots from requeueing.
        if deadline.is_some_and(|d| d <= timestamp) {
            return Ok(());
        }
        if let Some((agent, generation)) = &announcement {
            let previous: Option<u64> = self
                .db
                .query_row(
                    "SELECT generation FROM network_announcements WHERE peer=?1 AND agent=?2",
                    params![peer, agent],
                    |r| r.get(0),
                )
                .optional()?;
            if previous.is_some_and(|g| g >= *generation) {
                return Ok(());
            }
            if previous.is_none() {
                let count: u64 =
                    self.db
                        .query_row("SELECT COUNT(*) FROM network_announcements", [], |r| {
                            r.get(0)
                        })?;
                ensure!(
                    count < MAX_ANNOUNCEMENTS,
                    "registration announcement quota exhausted; inspect gent history status"
                );
            }
        }
        let version = if matches!(&event, Event::Presence { .. }) {
            1
        } else if matches!(&event, Event::Directory { .. }) {
            3
        } else {
            self.wire_version(peer)?
        };
        let body = serde_json::to_vec(&Record {
            version,
            authority: self.state.checkpoint().clone(),
            event,
        })?;
        ensure!(
            body.len() <= MAX_RECORD_BYTES,
            "node event exceeds transport record limit"
        );
        clean(self.db, timestamp, false)?;
        capacity(self.db, traffic, body.len(), announcement.is_some())?;
        self.db.execute("INSERT INTO network_events(id,peer,body,subject,traffic,retire_after,announcement) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![id,peer,body,subject,traffic,deadline,announcement.is_some()])?;
        if let Some((agent, generation)) = announcement {
            // The durable queue and its greatest admitted generation commit
            // together. A failed enqueue never suppresses a future retry.
            self.db.execute("INSERT INTO network_announcements VALUES(?1,?2,?3)
                ON CONFLICT(peer,agent) DO UPDATE SET generation=MAX(generation,excluded.generation)",
                params![peer,agent,generation])?;
        }
        Ok(())
    }
}

/// The caller commits this with deletion/advancement of the pending event.
pub(super) fn finish(db: &Connection, id: Uuid) -> Result<()> {
    db.execute(
        "INSERT OR IGNORE INTO network_sent(id,traffic,retire_after)
        SELECT id,traffic,retire_after FROM network_events WHERE id=?1 AND announcement=0",
        [id.to_string()],
    )?;
    Ok(())
}

pub(in crate::store) fn clean(db: &Connection, timestamp: i64, dry_run: bool) -> Result<usize> {
    let ids = db
        .prepare(
            "SELECT id FROM network_sent WHERE retire_after<=?1
        AND NOT EXISTS(SELECT 1 FROM network_events WHERE id=network_sent.id)
        ORDER BY retire_after,id LIMIT ?2",
        )?
        .query_map(params![timestamp, CLEAN_BATCH], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !dry_run {
        for id in &ids {
            db.execute("DELETE FROM network_sent WHERE id=?1", [id])?;
        }
    }
    Ok(ids.len())
}

pub(in crate::store) fn status(db: &Connection, timestamp: i64) -> Result<Value> {
    let mut classes = serde_json::Map::new();
    for class in ["data", "control"] {
        let (events, bytes, retries) = usage(db, class)?;
        classes.insert(class.into(),json!({"queued_events":events,"queued_bytes":bytes,"retry_slots":retries,
            "max_queued_events":MAX_EVENTS,"max_queued_bytes":MAX_BYTES,"max_retry_slots":MAX_RETRIES}));
    }
    let (sent,legacy,due,announcements):(u64,u64,u64,u64)=db.query_row("SELECT COUNT(*),COALESCE(SUM(traffic='legacy'),0),
        COALESCE(SUM(retire_after<=?1 AND NOT EXISTS(SELECT 1 FROM network_events WHERE id=network_sent.id)),0),
        (SELECT COUNT(*) FROM network_announcements) FROM network_sent",[timestamp],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    Ok(
        json!({"traffic":classes,"sent_retries":sent,"legacy_sent_retries":legacy,"sent_retries_due":due,
        "announcement_watermarks":announcements,"max_announcement_watermarks":MAX_ANNOUNCEMENTS,"cleanup_batch_limit":CLEAN_BATCH}),
    )
}
