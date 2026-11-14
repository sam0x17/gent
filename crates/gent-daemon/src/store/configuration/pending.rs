//! Preserve a proposal until its decision arrives, independently of transport
//! acknowledgment. A future writer change must not need the retired receiver.
use super::*;

const MAX_RECORDS: u64 = 4096;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const BATCH: usize = 8;

pub(crate) fn schema(db: &Connection, previous: i64) -> Result<()> {
    let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='configuration_pending')", [], |r| r.get(0))?;
    if !exists {
        ensure!(
            previous < 20,
            "pending configuration payload storage is missing"
        );
        db.execute_batch("CREATE TABLE configuration_pending(origin TEXT NOT NULL,id TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=2097152),PRIMARY KEY(origin,id),FOREIGN KEY(origin,id) REFERENCES configuration_edits(origin,id));")?;
    } else {
        db.prepare("SELECT origin,id,body FROM configuration_pending LIMIT 0")?;
    }
    Ok(())
}

fn usage(db: &Connection) -> Result<(u64, u64)> {
    Ok(db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM configuration_pending",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}

fn capacity(db: &Connection, bytes: usize) -> Result<bool> {
    let (records, used) = usage(db)?;
    Ok(records < MAX_RECORDS && used.saturating_add(bytes as u64) <= MAX_BYTES)
}

pub(super) fn status(db: &Connection) -> Result<Value> {
    let (records, bytes) = usage(db)?;
    let missing: u64 = db.query_row("SELECT COUNT(*) FROM configuration_edits e WHERE result IS NULL AND NOT EXISTS(SELECT 1 FROM configuration_pending p WHERE p.origin=e.origin AND p.id=e.id)", [], |r| r.get(0))?;
    Ok(
        json!({"records":records,"stored_bytes":bytes,"max_records":MAX_RECORDS,"max_bytes":MAX_BYTES,"missing":missing,"recovery_batch_limit":BATCH}),
    )
}

/// Caller holds the request/result transaction. Exact retries may repair a
/// legacy missing body, but cannot replace a different retained proposal.
pub(super) fn retain(
    db: &Connection,
    origin: &str,
    id: &str,
    edit: &ConfigurationEdit,
) -> Result<()> {
    let (expected, completed): (String, bool) = db.query_row(
        "SELECT fingerprint,result IS NOT NULL FROM configuration_edits WHERE origin=?1 AND id=?2",
        params![origin, id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(
        fingerprint(edit)? == expected,
        "pending configuration fingerprint mismatch"
    );
    if completed {
        return Ok(());
    }
    let body = serde_json::to_vec(edit)?;
    ensure!(
        body.len() <= crate::messages::MAX_RECORD_BYTES,
        "pending configuration payload exceeds limit"
    );
    let saved: Option<Vec<u8>> = db
        .query_row(
            "SELECT body FROM configuration_pending WHERE origin=?1 AND id=?2",
            params![origin, id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(saved) = saved {
        ensure!(saved == body, "pending configuration payload changed");
        return Ok(());
    }
    ensure!(
        capacity(db, body.len())?,
        "pending configuration payload quota exhausted; let queued edits complete before submitting more"
    );
    db.execute(
        "INSERT INTO configuration_pending VALUES(?1,?2,?3)",
        params![origin, id, body],
    )?;
    Ok(())
}

pub(in crate::store) fn load(db: &Connection, origin: &str, id: &str) -> Result<ConfigurationEdit> {
    let (body, expected, pending): (Vec<u8>, String, bool) = db.query_row("SELECT p.body,e.fingerprint,e.result IS NULL FROM configuration_pending p JOIN configuration_edits e USING(origin,id) WHERE p.origin=?1 AND p.id=?2", params![origin,id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    ensure!(
        pending && body.len() <= crate::messages::MAX_RECORD_BYTES,
        "configuration request is not pending or exceeds limit"
    );
    let edit = serde_json::from_slice(&body)?;
    ensure!(
        fingerprint(&edit)? == expected,
        "pending configuration fingerprint mismatch"
    );
    Ok(edit)
}

pub(super) fn release(db: &Connection, origin: &str, id: &str) -> Result<()> {
    ensure!(
        db.query_row(
            "SELECT result IS NOT NULL FROM configuration_edits WHERE origin=?1 AND id=?2",
            params![origin, id],
            |r| r.get::<_, bool>(0)
        )?,
        "configuration decision is still pending"
    );
    db.execute(
        "DELETE FROM configuration_pending WHERE origin=?1 AND id=?2",
        params![origin, id],
    )?;
    Ok(())
}

pub(in crate::store) fn capture_record(db: &Connection, origin: &str, body: &[u8]) -> Result<()> {
    ensure!(
        body.len() <= crate::messages::MAX_RECORD_BYTES,
        "configuration event exceeds limit"
    );
    let record: crate::messages::Record = serde_json::from_slice(body)?;
    if let Event::ConfigurationRequest { request_id, edit } = record.event {
        retain(db, origin, &request_id.to_string(), &edit)?;
    }
    Ok(())
}

/// Recover old full edits or still-queued events before their payloads retire.
/// Missing legacy bytes stay explicitly missing; summaries cannot recreate them.
pub(in crate::store) fn recover(db: &Connection, origin: &str) -> Result<()> {
    let cursor: Option<String> = db
        .query_row(
            "SELECT value FROM metadata WHERE key='pending_configuration_cursor'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let cursor: i64 = cursor.map(|s| s.parse()).transpose()?.unwrap_or(0);
    ensure!(cursor >= 0, "invalid pending configuration recovery cursor");
    let rows = db.prepare("SELECT rowid,id,edit,compact FROM configuration_edits e WHERE origin=?1 AND rowid>?2 AND result IS NULL AND NOT EXISTS(SELECT 1 FROM configuration_pending p WHERE p.origin=e.origin AND p.id=e.id) ORDER BY rowid LIMIT ?3")?
        .query_map(params![origin,cursor,BATCH], |r| Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,bool>(3)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let next = rows.last().map_or(0, |r| r.0);
    for (_, id, body, compact) in rows {
        if !compact {
            if capacity(db, body.len())? {
                retain(db, origin, &id, &serde_json::from_slice(&body)?)?;
            }
            continue;
        }
        let request = Uuid::parse_str(&id)?;
        let event = scoped_id(
            b"gent/configuration-request/v1\0",
            &[origin.as_bytes(), request.as_bytes()],
        );
        let body: Option<Vec<u8>> = db
            .query_row(
                "SELECT body FROM network_events WHERE id=?1",
                [event.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(body) = body {
            let record: crate::messages::Record = serde_json::from_slice(&body)?;
            let Event::ConfigurationRequest { request_id, edit } = record.event else {
                anyhow::bail!("pending configuration event changed kind");
            };
            ensure!(
                request_id == request,
                "pending configuration event changed identity"
            );
            if capacity(db, serde_json::to_vec(&edit)?.len())? {
                retain(db, origin, &id, &edit)?;
            }
        }
    }
    db.execute("INSERT INTO metadata VALUES('pending_configuration_cursor',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [next.to_string()])?;
    Ok(())
}

pub(super) fn ready(db: &Connection, origin: &str, id: &str) -> Result<bool> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM configuration_pending WHERE origin=?1 AND id=?2)",
        params![origin, id],
        |r| r.get(0),
    )?;
    if exists {
        load(db, origin, id)?;
    }
    Ok(exists)
}
