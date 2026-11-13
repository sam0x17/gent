//! Allocation policy for Gent-owned SQLite connections.
//!
//! A page limit covers tables, indexes and reusable pages. WAL cannot be bounded
//! by journal_size_limit: readers can pin it across arbitrarily many commits.
//! DELETE journaling instead retains before-images for the current transaction.
//! Gent serializes runtime access; other local readers may delay a commit.
use anyhow::{Result, ensure};
use rusqlite::Connection;
use serde_json::{Value, json};

pub(crate) const MAX_DATABASE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub(crate) fn configure(db: &Connection) -> Result<()> {
    configure_limit(db, MAX_DATABASE_BYTES)
}

fn configure_limit(db: &Connection, bytes: u64) -> Result<()> {
    // SQLite performs WAL recovery/checkpointing and obtains the required locks.
    // Never remove WAL/journal files ourselves, including on a failed upgrade.
    let mode: String = db.query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))?;
    ensure!(mode == "delete", "database requires rollback journaling");
    // EXTRA also syncs the directory after deleting the rollback journal.
    db.execute_batch("PRAGMA synchronous=EXTRA; PRAGMA secure_delete=ON;")?;
    let page_size: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
    let pages: u64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
    // Never discard data from an oversized legacy database. Its existing pages
    // remain usable; raising the limit beyond them would allow further growth.
    let limit = (bytes / page_size).max(pages).max(1);
    let actual: u64 = db.query_row(&format!("PRAGMA max_page_count={limit}"), [], |r| r.get(0))?;
    ensure!(actual == limit, "could not apply database page limit");
    Ok(())
}

pub(crate) fn usage(db: &Connection) -> Result<Value> {
    let page_size: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
    let pages: u64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
    let free: u64 = db.pragma_query_value(None, "freelist_count", |r| r.get(0))?;
    let max: u64 = db.pragma_query_value(None, "max_page_count", |r| r.get(0))?;
    let mode: String = db.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    Ok(json!({
        "logical_bytes": pages * page_size,
        "reusable_bytes": free * page_size,
        "max_bytes": max * page_size,
        "configured_max_bytes": MAX_DATABASE_BYTES,
        "oversized": pages * page_size > MAX_DATABASE_BYTES,
        "journal_mode": mode,
        "scope": "database pages including indexes and freelist; excludes transaction journals, temporary files and handoff files"
    }))
}

#[cfg(test)]
mod tests;
