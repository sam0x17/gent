//! Local handoff retention. No paths, names, or file contents leave this node.
use super::*;

const BATCH: usize = 8;
const RETRY_SECONDS: i64 = 15 * 60;
pub(super) const MAX_HANDOFFS: u64 = 4096;
pub(super) const MAX_HANDOFF_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS file_handoffs (
            id TEXT PRIMARY KEY, agent TEXT NOT NULL REFERENCES agents(id),
            slot TEXT NOT NULL, name TEXT NOT NULL, stamp TEXT NOT NULL,
            digest TEXT NOT NULL, bytes INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            next_attempt INTEGER NOT NULL DEFAULT 0, outcome TEXT NOT NULL DEFAULT 'tracked',
            error TEXT,
            UNIQUE(agent,slot,name,stamp));
         CREATE INDEX IF NOT EXISTS file_handoffs_due ON file_handoffs(next_attempt,expires_at);",
    )?;
    exports::schema(db)?;
    Ok(())
}

pub(super) fn usage(db: &Connection) -> Result<(u64, u64)> {
    Ok(db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM
        (SELECT bytes FROM file_handoffs UNION ALL SELECT bytes FROM file_exports)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}

pub(super) fn capacity(db: &Connection, bytes: u64) -> Result<()> {
    let (count, used) = usage(db)?;
    ensure!(
        count < MAX_HANDOFFS && used.saturating_add(bytes) <= MAX_HANDOFF_BYTES,
        "plaintext handoff quota reached; inspect gent files and clean expired copies"
    );
    Ok(())
}

pub(super) fn error_text(text: &str) -> String {
    let mut end = text.len().min(1024);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

pub(super) fn track(
    db: &Connection,
    agent: &str,
    slot: &str,
    name: &str,
    stamp: &host::Stamp,
    digest: &str,
    expires_at: u64,
) -> Result<()> {
    let encoded = serde_json::to_string(stamp)?;
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM file_handoffs
        WHERE agent=?1 AND slot=?2 AND name=?3 AND stamp=?4)",
        params![agent, slot, name, encoded],
        |r| r.get(0),
    )?;
    if !exists {
        capacity(db, stamp.bytes)?;
    }
    record(db, agent, slot, name, stamp, digest, expires_at)
}

pub(super) fn finish_export(
    db: &Connection,
    agent: &str,
    descriptor: &FileDescriptor,
    stamp: &host::Stamp,
    expires_at: u64,
    reservation: &str,
) -> Result<()> {
    ensure!(stamp.bytes == descriptor.byte_length, "export size changed");
    ensure!(
        db.execute(
            "DELETE FROM file_exports WHERE id=?1 AND agent=?2 AND object_id=?3
        AND bytes=?4 AND name=?5 AND digest=?6 AND expires_at=?7",
            params![
                reservation,
                agent,
                descriptor.id,
                stamp.bytes,
                descriptor.name,
                descriptor.sha256,
                expires_at
            ]
        )? == 1,
        "export reservation changed"
    );
    // This is a transfer of already reserved capacity, including oversized
    // legacy usage. The enclosing transaction restores it if recording fails.
    record(
        db,
        agent,
        &descriptor.id,
        &descriptor.name,
        stamp,
        &descriptor.sha256,
        expires_at,
    )
}

fn record(
    db: &Connection,
    agent: &str,
    slot: &str,
    name: &str,
    stamp: &host::Stamp,
    digest: &str,
    expires_at: u64,
) -> Result<()> {
    let encoded = serde_json::to_string(stamp)?;
    db.execute(
        "INSERT INTO file_handoffs(id,agent,slot,name,stamp,digest,bytes,expires_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
         ON CONFLICT(agent,slot,name,stamp) DO UPDATE SET
            expires_at=MAX(expires_at,excluded.expires_at),next_attempt=0,outcome='tracked',error=NULL",
        params![uuid::Uuid::new_v4().to_string(), agent, slot, name,
            encoded, digest, stamp.bytes, expires_at],
    )?;
    Ok(())
}

pub(super) fn clean(db: &Connection, home: &Path, timestamp: i64, dry_run: bool) -> Result<Value> {
    let objects: u64 = db.query_row(
        "SELECT COUNT(*) FROM file_objects WHERE expires_at<=?1 OR (complete=0 AND incomplete_until<=?1)",
        [timestamp], |r| r.get(0))?;
    if !dry_run {
        Objects::in_transaction(db, timestamp as u64)?.reap()?;
    }
    let rows = db
        .prepare(
            "SELECT id,agent,slot,name,stamp,digest,bytes FROM file_handoffs
         WHERE expires_at<=?1 AND next_attempt<=?1 ORDER BY next_attempt,expires_at,id LIMIT ?2",
        )?
        .query_map(params![timestamp, BATCH], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, u64>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let (mut removed, mut missing, mut preserved, mut blocked, mut bytes) = (0, 0, 0, 0, 0u64);
    for (id, agent, slot, name, encoded, digest, size) in &rows {
        let outcome = serde_json::from_str::<host::Stamp>(encoded)
            .map_err(anyhow::Error::from)
            .and_then(|stamp| {
                host::cleanup(
                    home,
                    host::TrackedFile {
                        agent,
                        slot,
                        name,
                        id,
                        stamp: &stamp,
                        digest,
                    },
                    dry_run,
                )
            });
        let reason = outcome.as_ref().err().map(|e| error_text(&e.to_string()));
        let state = match outcome {
            Ok(host::Cleanup::Removed) => {
                removed += 1;
                bytes += size;
                "removed"
            }
            Ok(host::Cleanup::Missing) => {
                missing += 1;
                "missing"
            }
            Ok(host::Cleanup::Preserved) => {
                preserved += 1;
                "preserved"
            }
            Err(_) => {
                blocked += 1;
                "blocked"
            }
        };
        if !dry_run {
            if matches!(state, "removed" | "missing") {
                db.execute("DELETE FROM file_handoffs WHERE id=?1", [id])?;
            } else {
                db.execute(
                    "UPDATE file_handoffs SET outcome=?2,next_attempt=?3,error=?4 WHERE id=?1",
                    params![id, state, timestamp + RETRY_SECONDS, reason],
                )?;
            }
        }
    }
    let due: u64 = db.query_row(
        "SELECT COUNT(*) FROM file_handoffs WHERE expires_at<=?1 AND next_attempt<=?1",
        [timestamp],
        |r| r.get(0),
    )?;
    let exports = exports::clean(db, home, timestamp, dry_run)?;
    Ok(
        json!({"dry_run":dry_run,"expired_objects":objects,"handoffs_checked":rows.len(),
        "handoffs_removed":removed,"handoffs_missing":missing,"handoffs_preserved":preserved,
        "handoffs_blocked":blocked,"plaintext_bytes_removed":bytes,
        "more_due":if dry_run { due.saturating_sub(rows.len() as u64) } else { due },"batch_limit":BATCH,"exports":exports}),
    )
}

impl StoreSession<'_> {
    pub(in crate::store) fn files_clean(&self, dry_run: bool) -> Result<Value> {
        clean(self.db, self.home, self.timestamp, dry_run)
    }

    pub(in crate::store) fn files_status(&self) -> Result<Value> {
        let objects = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(reserved_bytes),0),COALESCE(SUM(complete),0),
              COALESCE(SUM(expires_at<=?1 OR (complete=0 AND incomplete_until<=?1)),0)
             FROM file_objects", [self.timestamp], |r| Ok(json!({"count":r.get::<_,u64>(0)?,
                "reserved_bytes":r.get::<_,u64>(1)?,"complete":r.get::<_,u64>(2)?,"expired":r.get::<_,u64>(3)?,
                "max_count":crate::file_objects::MAX_OBJECTS,"max_reserved_bytes":crate::file_objects::MAX_RESERVED_BYTES})))?;
        let chunks = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(ciphertext)),0) FROM file_chunks",
            [],
            |r| Ok(json!({"count":r.get::<_,u64>(0)?,"stored_bytes":r.get::<_,u64>(1)?})),
        )?;
        let mut handoffs = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(bytes),0),COALESCE(SUM(expires_at<=?1),0),
                COALESCE(SUM(outcome='preserved'),0),COALESCE(SUM(outcome='blocked'),0) FROM file_handoffs",
            [self.timestamp], |r| Ok(json!({"tracked_copies":r.get::<_,u64>(0)?,
                "recorded_bytes":r.get::<_,u64>(1)?,"expired":r.get::<_,u64>(2)?,
                "preserved":r.get::<_,u64>(3)?,"blocked":r.get::<_,u64>(4)?,
                "scope":"tracked copies only; untracked files and host edits are not measured"})))?;
        let (count, bytes) = usage(self.db)?;
        handoffs["reserved_copies"] = json!(count);
        handoffs["reserved_bytes"] = json!(bytes);
        handoffs["max_copies"] = json!(MAX_HANDOFFS);
        handoffs["max_bytes"] = json!(MAX_HANDOFF_BYTES);
        let attention = self.db.prepare(
            "SELECT id,agent,slot,name,outcome,error FROM file_handoffs WHERE outcome IN ('preserved','blocked') ORDER BY id LIMIT 100")?
            .query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,Option<String>>(5)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?.into_iter().map(|(id,agent,slot,name,outcome,error)| {
                let base = self.home.join("files").join(agent);
                let dir = if slot.is_empty() { base.join("outbox") } else { base.join("inbox").join(slot) };
                json!({"path":dir.join(name),"recovery_path":dir.join(format!(".gent-clean-{id}.tmp")),"outcome":outcome,"reason":error})
            }).collect::<Vec<_>>();
        let imports: u64 = self
            .db
            .query_row("SELECT COUNT(*) FROM file_imports", [], |r| r.get(0))?;
        let messages: u64 = self
            .db
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?;
        Ok(
            json!({"objects":objects,"ciphertext_chunks":chunks,"handoffs":handoffs,"attention":attention,
            "database":crate::storage::usage(self.db)?,"exports":exports::status(self.db,self.home)?,
            "retained_import_retries":imports,"retained_messages":messages,
            "cleanup_interval_seconds":RETRY_SECONDS,"cleanup_batch_limit":BATCH}),
        )
    }
}

impl Store {
    pub(crate) fn clean_files(&mut self) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        clean(&tx, &self.home, now(), false)?;
        tx.commit()?;
        Ok(())
    }
}
