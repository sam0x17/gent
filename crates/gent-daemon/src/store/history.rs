//! Retire whole expired exchanges only after new requests/replays are inadmissible.
use super::*;

pub(super) const RETENTION: i64 = 7 * 24 * 60 * 60;
const BATCH: usize = 8;
const MAX_MESSAGES: u64 = 8192;
const MAX_MESSAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_IMPORTS: u64 = 16384;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE INDEX IF NOT EXISTS exchanges_retention ON exchanges(expires_at);
        CREATE INDEX IF NOT EXISTS network_event_subject ON network_events(subject);",
    )?;
    Ok(())
}

pub(super) fn message_capacity(db: &Connection, bytes: usize) -> Result<()> {
    let (count, used): (u64, u64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM messages",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(
        count < MAX_MESSAGES && used.saturating_add(bytes as u64) <= MAX_MESSAGE_BYTES,
        "message history quota exhausted; run gent history clean and inspect gent history status"
    );
    Ok(())
}

pub(super) fn import_capacity(db: &Connection) -> Result<()> {
    let count: u64 = db.query_row("SELECT COUNT(*) FROM file_imports", [], |r| r.get(0))?;
    ensure!(
        count < MAX_IMPORTS,
        "file import retry quota exhausted; run gent history clean"
    );
    Ok(())
}

fn clean(db: &Connection, timestamp: i64, dry_run: bool) -> Result<Value> {
    let legacy_until: i64 = db.query_row(
        "SELECT legacy_until FROM request_clock WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let exchanges = db
        .prepare("SELECT id FROM exchanges WHERE expires_at<=?1 ORDER BY expires_at,id LIMIT ?2")?
        .query_map(params![timestamp - RETENTION, BATCH], |r| {
            r.get::<_, String>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let (mut groups, mut messages, mut payload_bytes, mut cancelled, mut deferred) =
        (0, 0, 0u64, 0, 0);
    for exchange in &exchanges {
        let rows = db
            .prepare(
                "SELECT id,request_id,length(CAST(payload AS BLOB)) FROM messages
            WHERE json_extract(payload,'$.exchange_id')=?1",
            )?
            .query_map([exchange], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if timestamp < legacy_until
            && rows
                .iter()
                .any(|(_, request, _)| requests::issued(request).is_none())
        {
            deferred += 1;
            continue;
        }
        groups += 1;
        messages += rows.len();
        for (id, _, bytes) in rows {
            payload_bytes += bytes;
            let events: u64 = db.query_row(
                "SELECT COUNT(*) FROM network_events WHERE subject=?1",
                [&id],
                |r| r.get(0),
            )?;
            cancelled += events;
            if !dry_run {
                // An earlier fragment may already have committed to MLS even
                // when offset=0. Retain the cancellation cursor, never drop it.
                db.execute(
                    "UPDATE network_events SET body=X'',cancelled=1,subject=NULL WHERE subject=?1",
                    [&id],
                )?;
                db.execute("DELETE FROM file_objects WHERE id IN (SELECT object_id FROM agent_files WHERE message=?1)",[&id])?;
                db.execute("DELETE FROM message_file_proofs WHERE message=?1", [&id])?;
                db.execute("DELETE FROM network_rejections WHERE message=?1", [&id])?;
            }
        }
        if !dry_run {
            db.execute("DELETE FROM relay_turns WHERE id IN (SELECT id FROM messages WHERE json_extract(payload,'$.exchange_id')=?1)",[exchange])?;
            db.execute(
                "DELETE FROM messages WHERE json_extract(payload,'$.exchange_id')=?1",
                [exchange],
            )?;
            db.execute("DELETE FROM exchanges WHERE id=?1", [exchange])?;
        }
    }
    // Imported objects have an independent seven-day deadline. Do not forget a
    // request while its ID could still be admitted as new after object cleanup.
    let imports = db
        .prepare(
            "SELECT agent,request_id FROM file_imports
        WHERE retire_after<=?1 AND NOT EXISTS(SELECT 1 FROM file_objects WHERE id=file_imports.object_id)
        ORDER BY retire_after,agent,request_id LIMIT 256",
        )?
        .query_map([timestamp], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut imports_removed = 0;
    for (agent, request) in imports {
        if requests::issued(&request).is_some_and(|issued| issued > timestamp - requests::LIFETIME)
        {
            continue;
        }
        imports_removed += 1;
        if !dry_run {
            db.execute(
                "DELETE FROM file_imports WHERE agent=?1 AND request_id=?2",
                params![agent, request],
            )?;
        }
    }
    let attachments = db
        .prepare(
            "SELECT id FROM relay_attachments
        WHERE (json_extract(payload,'$.expires_at')<=?1
          OR (detached=1 AND json_extract(payload,'$.created_at')<=?1))
          AND NOT EXISTS(SELECT 1 FROM relay_turns WHERE attachment=relay_attachments.id)
        ORDER BY rowid LIMIT 128",
        )?
        .query_map([timestamp - RETENTION], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !dry_run {
        for id in &attachments {
            db.execute("DELETE FROM relay_attachments WHERE id=?1", [id])?;
        }
    }
    let due: u64 = db.query_row(
        "SELECT COUNT(*) FROM exchanges WHERE expires_at<=?1",
        [timestamp - RETENTION],
        |r| r.get(0),
    )?;
    let sent = network::retention::clean(db, timestamp, dry_run)?;
    let edits = configuration::storage::clean(db, dry_run)?;
    let mesh = mesh::storage::clean(db, dry_run)?;
    Ok(
        json!({"dry_run":dry_run,"exchanges_removed":groups,"messages_removed":messages,
        "payload_bytes_removed":payload_bytes,"outbound_events_cancelled":cancelled,
        "import_retries_removed":imports_removed,"relay_attachments_removed":attachments.len(),
        "legacy_exchanges_deferred":deferred,"more_exchanges_due":if dry_run {due.saturating_sub(groups)} else {due},
        "exchange_batch_limit":BATCH,"sent_event_retries_removed":sent,"configuration_edits":edits,"mesh_jobs":mesh}),
    )
}

impl StoreSession<'_> {
    pub(super) fn history_clean(&self, dry_run: bool) -> Result<Value> {
        clean(self.db, self.timestamp, dry_run)
    }
    pub(super) fn history_status(&self) -> Result<Value> {
        let (messages, bytes): (u64, u64) = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM messages",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (exchanges, due): (u64, u64) = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(expires_at<=?1),0) FROM exchanges",
            [self.timestamp - RETENTION],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let imports: u64 = self
            .db
            .query_row("SELECT COUNT(*) FROM file_imports", [], |r| r.get(0))?;
        let attachments: u64 =
            self.db
                .query_row("SELECT COUNT(*) FROM relay_attachments", [], |r| r.get(0))?;
        let legacy_until: i64 = self.db.query_row(
            "SELECT legacy_until FROM request_clock WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let (events,event_bytes,cancellations):(u64,u64,u64)=self.db.query_row("SELECT COUNT(*),COALESCE(SUM(length(body)),0),COALESCE(SUM(cancelled),0) FROM network_events",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        Ok(
            json!({"messages":messages,"message_payload_bytes":bytes,"exchanges":exchanges,"expired_exchanges_due":due,
            "import_retry_records":imports,"relay_attachments":attachments,
            "limits":{"messages":MAX_MESSAGES,"message_payload_bytes":MAX_MESSAGE_BYTES,"import_retry_records":MAX_IMPORTS},
            "message_retention_after_expiry_seconds":RETENTION,"new_request_lifetime_seconds":requests::LIFETIME,
            "request_clock":self.timestamp,"legacy_remote_admission_until":legacy_until,
            "queued_events":events,"queued_event_bytes":event_bytes,"queued_cancellations":cancellations,
            "network":network::retention::status(self.db,self.timestamp)?,
            "configuration_edits":configuration::storage::status(self.db)?,
            "mesh_jobs":mesh::storage::status(self.db)?,
            "recovered":recovered::status(self.db)?,
            "scope":"Gent messages, agent retries, node event queues, configuration edits and peer setup jobs; encrypted streams, signed authority history, and provider histories are separate"}),
        )
    }
}

impl Store {
    pub(crate) fn clean_history(&mut self) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let timestamp = requests::clock(&tx, now())?;
        clean(&tx, timestamp, false)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_quota_counts_bytes_and_accepts_the_exact_boundary() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE messages(payload TEXT); INSERT INTO messages VALUES('é');")
            .unwrap();
        message_capacity(&db, MAX_MESSAGE_BYTES as usize - 2).unwrap();
        assert!(message_capacity(&db, MAX_MESSAGE_BYTES as usize - 1).is_err());
        assert!(message_capacity(&db, usize::MAX).is_err());
    }
}
