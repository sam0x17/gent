//! Keep immutable retry evidence and status fields, without another policy copy.
//! Call mutations inside the proposal/result or maintenance transaction.
use super::*;
use serde::{Deserialize, Serialize};

const CLEAN_BATCH: usize = 8;
const MAX_RECORDS: u64 = 65536;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_REASON_BYTES: usize = 1024;
// Includes JSON escaping of a rejection (up to six bytes per input byte).
const RESULT_RESERVE: usize = 8192;

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Summary {
    Policy,
    Replace,
    RenameNode { name: String },
    Renew,
    GrantRelay { grant_id: String },
    RevokeRelay { grant_id: String },
}

impl From<&ConfigurationEdit> for Summary {
    fn from(edit: &ConfigurationEdit) -> Self {
        match edit {
            ConfigurationEdit::Policy { .. } => Self::Policy,
            ConfigurationEdit::Replace { .. } => Self::Replace,
            ConfigurationEdit::RenameNode { name } => Self::RenameNode { name: name.clone() },
            ConfigurationEdit::Renew => Self::Renew,
            ConfigurationEdit::GrantRelay { grant_id, .. } => Self::GrantRelay {
                grant_id: grant_id.clone(),
            },
            ConfigurationEdit::RevokeRelay { grant_id } => Self::RevokeRelay {
                grant_id: grant_id.clone(),
            },
        }
    }
}

pub(super) fn schema(db: &Connection) -> Result<()> {
    let tx = db.unchecked_transaction()?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS configuration_edits(origin TEXT NOT NULL,id TEXT NOT NULL,writer TEXT NOT NULL,fingerprint TEXT NOT NULL,edit BLOB NOT NULL,result BLOB,PRIMARY KEY(origin,id));")?;
    let columns = tx
        .prepare("PRAGMA table_info(configuration_edits)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|c| c == "compact") {
        tx.execute_batch("ALTER TABLE configuration_edits ADD COLUMN compact INTEGER NOT NULL DEFAULT 0 CHECK(compact IN (0,1))")?;
    }
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS configuration_edits_format ON configuration_edits(compact)",
    )?;
    tx.commit()?;
    Ok(())
}

struct Usage {
    records: u64,
    pending: u64,
    legacy: u64,
    bytes: u64,
    reserved: u64,
}

fn usage(db: &Connection) -> Result<Usage> {
    Ok(db.query_row("SELECT COUNT(*),COALESCE(SUM(result IS NULL),0),COALESCE(SUM(compact=0),0),
        COALESCE(SUM(length(CAST(origin AS BLOB))+length(CAST(id AS BLOB))+length(CAST(writer AS BLOB))+
        length(CAST(fingerprint AS BLOB))+length(edit)+COALESCE(length(result),0)),0)
        FROM configuration_edits", [], |r| {
        let pending: u64 = r.get(1)?;
        let bytes: u64 = r.get(3)?;
        Ok(Usage { records: r.get(0)?, pending, legacy: r.get(2)?, bytes,
            reserved: bytes.saturating_add(pending.saturating_mul(RESULT_RESERVE as u64)) })
    })?)
}

pub(in crate::store) fn status(db: &Connection) -> Result<Value> {
    let used = usage(db)?;
    Ok(
        json!({"records":used.records,"pending":used.pending,"legacy_records":used.legacy,
        "stored_bytes":used.bytes,"reserved_bytes":used.reserved,"max_records":MAX_RECORDS,
        "max_reserved_bytes":MAX_BYTES,"pending_result_reservation_bytes":RESULT_RESERVE,
        "cleanup_batch_limit":CLEAN_BATCH}),
    )
}

pub(super) fn result_size(result: &[u8]) -> Result<()> {
    ensure!(
        result.len() <= RESULT_RESERVE,
        "configuration result exceeds reserved space"
    );
    Ok(())
}

pub(super) fn rejection_reason(mut reason: String) -> String {
    if reason.len() > MAX_REASON_BYTES {
        let mut end = MAX_REASON_BYTES;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        reason.truncate(end);
    }
    reason
}

pub(super) fn insert(
    db: &Connection,
    origin: &str,
    id: &str,
    writer: &str,
    fingerprint: &str,
    edit: &ConfigurationEdit,
    result: Option<&[u8]>,
) -> Result<()> {
    if let Some(result) = result {
        result_size(result)?;
    }
    let summary = serde_json::to_vec(&Summary::from(edit))?;
    clean(db, false)?;
    let used = usage(db)?;
    let bytes = [
        origin.len(),
        id.len(),
        writer.len(),
        fingerprint.len(),
        summary.len(),
        result.map_or(RESULT_RESERVE, <[u8]>::len),
    ]
    .into_iter()
    .fold(0u64, |total, size| total.saturating_add(size as u64));
    ensure!(
        used.records < MAX_RECORDS && used.reserved.saturating_add(bytes) <= MAX_BYTES,
        "configuration edit history quota exhausted; inspect gent history status; clean legacy bodies with gent history clean; retry records remain retained"
    );
    db.execute("INSERT INTO configuration_edits(origin,id,writer,fingerprint,edit,result,compact) VALUES(?1,?2,?3,?4,?5,?6,1)",
        params![origin,id,writer,fingerprint,summary,result])?;
    Ok(())
}

pub(in crate::store) fn clean(db: &Connection, dry_run: bool) -> Result<Value> {
    let rows = db.prepare("SELECT rowid,fingerprint,edit FROM configuration_edits WHERE compact=0 ORDER BY rowid LIMIT ?1")?
        .query_map([CLEAN_BATCH], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut removed = 0u64;
    for (row, expected, body) in &rows {
        let edit: ConfigurationEdit =
            serde_json::from_slice(body).context("invalid legacy configuration edit")?;
        // Rejected historical edits may be invalid policies. Verify their retry
        // identity without imposing today's admission rules on their contents.
        ensure!(
            fingerprint(&edit)? == *expected,
            "legacy configuration edit fingerprint mismatch"
        );
        let summary = serde_json::to_vec(&Summary::from(&edit))?;
        removed += body.len().saturating_sub(summary.len()) as u64;
        if !dry_run {
            db.execute(
                "UPDATE configuration_edits SET edit=?1,compact=1 WHERE rowid=?2",
                params![summary, row],
            )?;
        }
    }
    let due: u64 = db.query_row(
        "SELECT COUNT(*) FROM configuration_edits WHERE compact=0",
        [],
        |r| r.get(0),
    )?;
    Ok(
        json!({"records_compacted":rows.len(),"body_bytes_removed":removed,
        "more_due":if dry_run {due.saturating_sub(rows.len() as u64)} else {due},"batch_limit":CLEAN_BATCH}),
    )
}

pub(super) fn describe(body: &[u8], compact: bool, status: &mut Value) -> Result<()> {
    let summary: Summary = if compact {
        serde_json::from_slice(body)?
    } else {
        Summary::from(&serde_json::from_slice::<ConfigurationEdit>(body)?)
    };
    match summary {
        Summary::RenameNode { name } => status["name"] = name.into(),
        Summary::GrantRelay { grant_id } | Summary::RevokeRelay { grant_id } => {
            status["grant_id"] = grant_id.into()
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests;
