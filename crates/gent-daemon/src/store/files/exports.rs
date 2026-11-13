//! Durable capacity reservations and publication of native plaintext exports.
use super::*;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS file_exports (
        id TEXT PRIMARY KEY, agent TEXT NOT NULL REFERENCES agents(id),
        object_id TEXT NOT NULL, name TEXT NOT NULL, digest TEXT NOT NULL,
        bytes INTEGER NOT NULL CHECK(bytes>=0), expires_at INTEGER NOT NULL, stamp TEXT,
        next_attempt INTEGER NOT NULL DEFAULT 0, outcome TEXT NOT NULL DEFAULT 'pending',
        error TEXT, UNIQUE(agent,object_id));
        CREATE INDEX IF NOT EXISTS file_exports_due ON file_exports(expires_at,next_attempt);",
    )?;
    Ok(())
}

pub(super) fn clean(db: &Connection, home: &Path, now: i64, dry_run: bool) -> Result<Value> {
    let rows = db
        .prepare(
            "SELECT id,agent,object_id,name,digest,stamp FROM file_exports
        WHERE expires_at<=?1 AND next_attempt<=?1 ORDER BY next_attempt,expires_at,id LIMIT 8",
        )?
        .query_map([now], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let (mut removed, mut missing, mut preserved, mut blocked) = (0, 0, 0, 0);
    for (id, agent, slot, name, digest, encoded) in &rows {
        let result = (|| -> Result<host::Cleanup> {
            let stamp: Option<host::Stamp> =
                encoded.as_deref().map(serde_json::from_str).transpose()?;
            host::clean_export(
                home,
                host::ExportFile {
                    agent,
                    slot,
                    name,
                    id,
                    digest,
                    stamp: stamp.as_ref(),
                },
                dry_run,
            )
        })();
        let reason = result
            .as_ref()
            .err()
            .map(|e| retention::error_text(&e.to_string()));
        let outcome = match result {
            Ok(host::Cleanup::Removed) => {
                removed += 1;
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
            if matches!(outcome, "removed" | "missing") {
                db.execute("DELETE FROM file_exports WHERE id=?1", [id])?;
            } else {
                db.execute(
                    "UPDATE file_exports SET outcome=?2,error=?3,next_attempt=?4 WHERE id=?1",
                    params![id, outcome, reason, now + 15 * 60],
                )?;
            }
        }
    }
    let due: u64 = db.query_row(
        "SELECT COUNT(*) FROM file_exports WHERE expires_at<=?1 AND next_attempt<=?1",
        [now],
        |r| r.get(0),
    )?;
    Ok(
        json!({"checked":rows.len(),"removed":removed,"missing":missing,"preserved":preserved,"blocked":blocked,
        "more_due":if dry_run {due.saturating_sub(rows.len() as u64)} else {due},"batch_limit":8}),
    )
}

pub(super) fn status(db: &Connection, home: &Path) -> Result<Value> {
    let (count, bytes): (u64, u64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM file_exports",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let attention = db.prepare("SELECT id,agent,object_id,name,stamp,outcome,error FROM file_exports ORDER BY id LIMIT 100")?
        .query_map([],|r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,
            r.get::<_,Option<String>>(4)?,r.get::<_,String>(5)?,r.get::<_,Option<String>>(6)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?.into_iter().map(|(id,agent,slot,name,stamp,outcome,error)| {
            let dir=home.join("files").join(agent).join("inbox").join(slot);
            json!({"path":dir.join(name),"temporary_path":dir.join(host::export_temporary(&id)),
                "recovery_path":dir.join(format!(".gent-clean-{id}.tmp")),"ready":stamp.is_some(),"outcome":outcome,"reason":error})
        }).collect::<Vec<_>>();
    Ok(json!({"pending":count,"reserved_bytes":bytes,"attention":attention}))
}

impl StoreSession<'_> {
    pub(in crate::store) fn file_export(
        &self,
        who: &Agent,
        id: &str,
        step: ExportStep,
    ) -> Result<Value> {
        let grant = self.accessible_file(who, id)?;
        let descriptor = grant.descriptor();
        let status = self.objects()?.status(id)?;
        ensure!(status.complete, "file is not ready");
        let pending: Option<(String, Option<String>, bool)> = self
            .db
            .query_row(
                "SELECT id,stamp,name=?3 AND digest=?4 AND bytes=?5 AND expires_at=?6
                 FROM file_exports WHERE agent=?1 AND object_id=?2",
                params![
                    who.id,
                    id,
                    descriptor.name,
                    descriptor.sha256,
                    descriptor.byte_length,
                    status.expires_at
                ],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        ensure!(
            pending.as_ref().is_none_or(|row| row.2),
            "export reservation conflicts with file; inspect gent files"
        );
        match step {
            ExportStep::Reserve => {
                if pending.is_none() {
                    let paths = host::Folders::open(self.home, &who.id)?;
                    if let Some(stamp) = paths.existing_export(descriptor)? {
                        retention::track(
                            self.db,
                            &who.id,
                            id,
                            &descriptor.name,
                            &stamp,
                            &descriptor.sha256,
                            status.expires_at,
                        )?;
                        return Ok(
                            json!({"file":descriptor,"path":paths.export_path.join(id).join(&descriptor.name),"cleanup_after":status.expires_at}),
                        );
                    }
                    retention::capacity(self.db, descriptor.byte_length)?;
                    self.db.execute(
                        "INSERT INTO file_exports(id,agent,object_id,name,digest,bytes,expires_at)
                        VALUES(?1,?2,?3,?4,?5,?6,?7)",
                        params![
                            uuid::Uuid::new_v4().to_string(),
                            who.id,
                            id,
                            descriptor.name,
                            descriptor.sha256,
                            descriptor.byte_length,
                            status.expires_at
                        ],
                    )?;
                }
            }
            ExportStep::Write => {
                let (reservation, stamp, _) = pending.context("export reservation missing")?;
                if stamp.is_none() {
                    let bytes = self.objects()?.read(id)?;
                    let paths = host::Folders::open(self.home, &who.id)?;
                    let stamp = paths.stage(descriptor, &reservation, &bytes)?;
                    self.db.execute("UPDATE file_exports SET stamp=?2,next_attempt=0,outcome='pending',error=NULL WHERE id=?1",
                        params![reservation,serde_json::to_string(&stamp)?])?;
                }
            }
            ExportStep::Publish => {
                let (reservation, stamp, _) = pending.context("export reservation missing")?;
                let stamp: host::Stamp =
                    serde_json::from_str(&stamp.context("export is not staged")?)?;
                let paths = host::Folders::open(self.home, &who.id)?;
                let (path, stamp) = paths.publish(descriptor, &reservation, &stamp)?;
                // Transfer the reserved slot/bytes to the handoff ledger in this
                // transaction. Rollback retains the committed reservation.
                retention::finish_export(
                    self.db,
                    &who.id,
                    descriptor,
                    &stamp,
                    status.expires_at,
                    &reservation,
                )?;
                return Ok(
                    json!({"file":descriptor,"path":path,"cleanup_after":status.expires_at}),
                );
            }
        }
        Ok(Value::Null)
    }
}
