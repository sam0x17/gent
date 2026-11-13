//! Retain pending bootstrap inputs and compact completed ones to retry digests.
//! All mutations run inside their caller's admission/completion transaction.
use super::*;

const MAX_PENDING: u64 = 8192;
const MAX_RECORDS: u64 = 65536;
const MAX_BYTES: u64 = 128 * 1024 * 1024;
const ERROR_RESERVE: usize = 1024;
const CLEAN_BATCH: usize = 8;

pub(super) fn schema(db: &Connection) -> Result<()> {
    let tx = db.unchecked_transaction()?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS mesh_peers(peer TEXT PRIMARY KEY,peer_key BLOB NOT NULL,link TEXT UNIQUE NOT NULL,outgoing BLOB,incoming BLOB);
        CREATE TABLE IF NOT EXISTS mesh_jobs(id TEXT PRIMARY KEY,body BLOB NOT NULL,done INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,retry_at INTEGER NOT NULL DEFAULT 0,error TEXT);
        CREATE INDEX IF NOT EXISTS mesh_jobs_pending ON mesh_jobs(done,retry_at);")?;
    let columns = tx
        .prepare("PRAGMA table_info(mesh_jobs)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|c| c == "fingerprint") {
        tx.execute_batch("ALTER TABLE mesh_jobs ADD COLUMN fingerprint BLOB")?;
    }
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS mesh_jobs_compaction ON mesh_jobs(done) WHERE length(body)>0",
    )?;
    tx.commit()?;
    Ok(())
}

fn fingerprint(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

pub(super) fn decode(id: &str, body: &[u8], saved: Option<&[u8]>) -> Result<MeshEnvelope> {
    let envelope: MeshEnvelope = serde_json::from_slice(body).context("invalid saved mesh job")?;
    ensure!(
        envelope.id().to_string() == id,
        "mesh job identity mismatch"
    );
    ensure!(
        serde_json::to_vec(&envelope)? == body,
        "noncanonical saved mesh job"
    );
    ensure!(
        saved.is_none_or(|saved| saved == fingerprint(body)),
        "mesh job fingerprint mismatch"
    );
    Ok(envelope)
}

struct Usage {
    records: u64,
    pending: u64,
    due: u64,
    bytes: u64,
    reserved: u64,
}

fn usage(db: &Connection) -> Result<Usage> {
    Ok(db.query_row("SELECT COUNT(*),COALESCE(SUM(done=0),0),COALESCE(SUM(done=1 AND length(body)>0),0),
        COALESCE(SUM(length(CAST(id AS BLOB))+length(body)+COALESCE(length(fingerprint),0)+COALESCE(length(CAST(error AS BLOB)),0)),0),
        COALESCE(SUM(CASE WHEN done=0 THEN MAX(?1-COALESCE(length(CAST(error AS BLOB)),0),0) ELSE 0 END),0)
        FROM mesh_jobs", [ERROR_RESERVE], |r| {
        let bytes: u64 = r.get(3)?;
        let reserve: u64 = r.get(4)?;
        Ok(Usage { records:r.get(0)?, pending:r.get(1)?, due:r.get(2)?, bytes, reserved:bytes.saturating_add(reserve) })
    })?)
}

pub(in crate::store) fn status(db: &Connection) -> Result<Value> {
    let used = usage(db)?;
    Ok(
        json!({"records":used.records,"pending":used.pending,"completed_bodies_due":used.due,
        "stored_bytes":used.bytes,"reserved_bytes":used.reserved,"max_records":MAX_RECORDS,
        "max_pending":MAX_PENDING,"max_reserved_bytes":MAX_BYTES,"pending_error_reservation_bytes":ERROR_RESERVE,
        "cleanup_batch_limit":CLEAN_BATCH}),
    )
}

pub(super) fn admit(db: &Connection, envelope: &MeshEnvelope) -> Result<()> {
    let id = envelope.id().to_string();
    let body = serde_json::to_vec(envelope)?;
    let digest = fingerprint(&body);
    let saved: Option<(Option<Vec<u8>>, Vec<u8>)> = db
        .query_row(
            "SELECT fingerprint,body FROM mesh_jobs WHERE id=?1",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((previous, original)) = saved {
        let same = previous.map_or_else(|| original == body, |previous| previous == digest);
        ensure!(same, "conflicting mesh signal");
        return Ok(());
    }
    clean(db, false)?;
    let used = usage(db)?;
    let bytes = id.len() as u64 + body.len() as u64 + digest.len() as u64 + ERROR_RESERVE as u64;
    ensure!(
        used.pending < MAX_PENDING,
        "pending mesh queue is full; inspect gent history status"
    );
    ensure!(
        used.records < MAX_RECORDS && used.reserved.saturating_add(bytes) <= MAX_BYTES,
        "mesh job history quota exhausted; inspect gent history status; compact completed bodies with gent history clean; retry records remain retained"
    );
    db.execute(
        "INSERT INTO mesh_jobs(id,body,fingerprint) VALUES(?1,?2,?3)",
        params![id, body, digest.as_slice()],
    )?;
    Ok(())
}

pub(super) fn error_text(mut error: String) -> String {
    if error.len() > ERROR_RESERVE {
        let mut end = ERROR_RESERVE;
        while !error.is_char_boundary(end) {
            end -= 1;
        }
        error.truncate(end);
    }
    error
}

pub(super) fn finish(db: &Connection, id: &str, error: Option<&str>) -> Result<()> {
    ensure!(
        error.is_none_or(|s| s.len() <= ERROR_RESERVE),
        "mesh result exceeds reserved space"
    );
    let (body, saved): (Vec<u8>, Option<Vec<u8>>) = db.query_row(
        "SELECT body,fingerprint FROM mesh_jobs WHERE id=?1 AND done=0",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    decode(id, &body, saved.as_deref())?;
    db.execute(
        "UPDATE mesh_jobs SET done=1,body=X'',fingerprint=?1,error=?2 WHERE id=?3",
        params![fingerprint(&body).as_slice(), error, id],
    )?;
    Ok(())
}

pub(in crate::store) fn clean(db: &Connection, dry_run: bool) -> Result<Value> {
    let rows = db.prepare("SELECT id,body,fingerprint FROM mesh_jobs WHERE done=1 AND length(body)>0 ORDER BY rowid LIMIT ?1")?
        .query_map([CLEAN_BATCH], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Option<Vec<u8>>>(2)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut bytes = 0u64;
    for (id, body, saved) in &rows {
        decode(id, body, saved.as_deref())?;
        bytes += body.len() as u64;
        if !dry_run {
            db.execute(
                "UPDATE mesh_jobs SET body=X'',fingerprint=?1 WHERE id=?2",
                params![fingerprint(body).as_slice(), id],
            )?;
        }
    }
    let due: u64 = db.query_row(
        "SELECT COUNT(*) FROM mesh_jobs WHERE done=1 AND length(body)>0",
        [],
        |r| r.get(0),
    )?;
    Ok(
        json!({"records_compacted":rows.len(),"body_bytes_removed":bytes,
        "more_due":if dry_run {due.saturating_sub(rows.len() as u64)} else {due},"batch_limit":CLEAN_BATCH}),
    )
}

#[cfg(test)]
mod tests;
