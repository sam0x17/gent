//! Delivery routes change with the owner epoch; committed decision provenance
//! does not. Retained full inputs allow a route to be rebuilt after restart.
use super::*;

pub(crate) fn schema(db: &Connection, previous: i64) -> Result<()> {
    let count: usize = db.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('configuration_routes','retired_configuration_requests')", [], |r| r.get(0))?;
    if count == 0 && previous < 22 {
        db.execute_batch("CREATE TABLE configuration_routes(origin TEXT NOT NULL,id TEXT NOT NULL,epoch INTEGER NOT NULL CHECK(epoch BETWEEN 0 AND 64),writer TEXT NOT NULL,PRIMARY KEY(origin,id,epoch),FOREIGN KEY(origin,id) REFERENCES configuration_edits(origin,id));
            CREATE TABLE retired_configuration_requests(origin TEXT NOT NULL,id TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)<=2097152),PRIMARY KEY(origin,id));")?;
    } else {
        ensure!(count == 2, "configuration routing storage is missing");
        db.prepare("SELECT origin,id,epoch,writer FROM configuration_routes LIMIT 0")?;
        db.prepare("SELECT origin,id,body FROM retired_configuration_requests LIMIT 0")?;
    }
    Ok(())
}

pub(in crate::store) fn known_route(
    db: &Connection,
    origin: &str,
    id: &str,
    writer: &str,
) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM configuration_routes WHERE origin=?1 AND id=?2 AND writer=?3)",
        params![origin, id, writer],
        |r| r.get(0),
    )?)
}

fn remember(db: &Connection, origin: &str, id: &str, epoch: u32, writer: &str) -> Result<()> {
    let saved: Option<String> = db
        .query_row(
            "SELECT writer FROM configuration_routes WHERE origin=?1 AND id=?2 AND epoch=?3",
            params![origin, id, epoch],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(saved) = saved {
        ensure!(
            saved == writer,
            "configuration route conflicts within an owner epoch"
        );
    } else {
        db.execute(
            "INSERT INTO configuration_routes VALUES(?1,?2,?3,?4)",
            params![origin, id, epoch, writer],
        )?;
    }
    Ok(())
}

pub(in crate::store) fn cancel_requests(db: &Connection, origin: &str, id: &str) -> Result<()> {
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='peer_configuration_routes')",
        [],
        |r| r.get::<_, bool>(0),
    )? {
        db.execute("UPDATE network_events SET cancelled=1 WHERE id IN (SELECT event FROM peer_configuration_routes WHERE origin=?1 AND id=?2)", params![origin,id])?;
    }
    let request = Uuid::parse_str(id)?;
    let mut events = vec![event_id(false, 0, origin, request, "")];
    let mut query =
        db.prepare("SELECT epoch,writer FROM configuration_routes WHERE origin=?1 AND id=?2")?;
    for row in query.query_map(params![origin, id], |r| {
        Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?))
    })? {
        let (epoch, writer) = row?;
        events.push(event_id(false, epoch, origin, request, &writer));
    }
    for id in events {
        db.execute(
            "UPDATE network_events SET cancelled=1 WHERE id=?1",
            [id.to_string()],
        )?;
    }
    Ok(())
}

pub(in crate::store) fn retired_status(db: &Connection) -> Result<Value> {
    let (records, bytes): (u64, u64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM retired_configuration_requests",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(json!({"records":records,"stored_bytes":bytes,"max_records":4096,"max_bytes":64*1024*1024}))
}

pub(super) fn event_id(
    result: bool,
    epoch: u32,
    origin: &str,
    request: Uuid,
    writer: &str,
) -> Uuid {
    if epoch == 0 {
        scoped_id(
            if result {
                b"gent/configuration-result/v1\0"
            } else {
                b"gent/configuration-request/v1\0"
            },
            &[origin.as_bytes(), request.as_bytes()],
        )
    } else {
        scoped_id(
            if result {
                b"gent/configuration-result/v2\0"
            } else {
                b"gent/configuration-request/v2\0"
            },
            &[
                origin.as_bytes(),
                request.as_bytes(),
                writer.as_bytes(),
                &epoch.to_be_bytes(),
            ],
        )
    }
}

impl StoreSession<'_> {
    pub(super) fn queue_configuration(
        &self,
        origin: &str,
        request: Uuid,
        writer: &str,
        edit: ConfigurationEdit,
    ) -> Result<()> {
        if self.state.state().peer.is_some() {
            for (target, member) in &self.state.state().nodes {
                if !member.can_configure || member.hosted_by.is_some() || target == origin {
                    continue;
                }
                let linked: bool = self.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM network_links WHERE peer=?1 AND peer_key=?2)",
                    params![target, member.signing_key.as_slice()],
                    |r| r.get(0),
                )?;
                if !linked {
                    continue;
                }
                let event = scoped_id(
                    b"gent/peer-configuration-request/v1\0",
                    &[origin.as_bytes(), request.as_bytes(), target.as_bytes()],
                );
                let known: bool = self.db.query_row("SELECT EXISTS(SELECT 1 FROM peer_configuration_routes WHERE origin=?1 AND id=?2 AND writer=?3)",params![origin,request.to_string(),target],|r|r.get(0))?;
                if known {
                    continue;
                }
                self.queue(
                    target,
                    event,
                    Event::ConfigurationRequest {
                        request_id: request,
                        edit: Box::new(edit.clone()),
                    },
                    None,
                )?;
                self.db.execute(
                    "INSERT INTO peer_configuration_routes VALUES(?1,?2,?3,?4)",
                    params![origin, request.to_string(), target, event.to_string()],
                )?;
            }
            return Ok(());
        }
        remember(
            self.db,
            origin,
            &request.to_string(),
            self.state.owner_epoch(),
            writer,
        )?;
        self.queue(
            writer,
            event_id(false, self.state.owner_epoch(), origin, request, writer),
            Event::ConfigurationRequest {
                request_id: request,
                edit: Box::new(edit),
            },
            None,
        )
    }

    fn reroute_configuration(&mut self) -> Result<bool> {
        if self.state.state().peer.is_some() {
            let before = self.db.total_changes();
            if !self.identity.can_administer(&self.state) {
                let origin = self.identity.node.id();
                let ids = self.db.prepare("SELECT e.id FROM configuration_edits e JOIN configuration_pending p USING(origin,id) WHERE origin=?1 AND result IS NULL ORDER BY e.rowid LIMIT 64")?.query_map([origin],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                for id in ids {
                    let edit = pending::load(self.db, origin, &id)?;
                    if administration::edit_identity(&edit).is_some() {
                        self.queue_configuration(origin, Uuid::parse_str(&id)?, "", edit)?;
                    }
                }
            }
            return Ok(self.db.total_changes() != before);
        }
        if self.state.owner_epoch() == 0 {
            return Ok(false);
        }
        let writer = if self.identity.is_current_owner(&self.state) {
            self.identity.node.id().to_owned()
        } else {
            self.configuration_writer()?
        };
        let origin = self.identity.node.id().to_owned();
        let rows = self.db.prepare("SELECT e.id,e.writer FROM configuration_edits e JOIN configuration_pending p USING(origin,id) WHERE e.origin=?1 AND e.result IS NULL AND e.writer!=?2 ORDER BY e.rowid LIMIT 8")?
            .query_map(params![origin,writer], |r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, previous) in &rows {
            let request = Uuid::parse_str(id)?;
            let edit = pending::load(self.db, &origin, id)?;
            // Legacy requests lack route rows. Retain the original address for
            // rejecting delayed results without blocking its shared stream.
            if !known_route(self.db, &origin, id, previous)? {
                remember(self.db, &origin, id, self.state.owner_epoch() - 1, previous)?;
            }
            cancel_requests(self.db, &origin, id)?;
            if writer == origin {
                self.accept_configuration(&origin, request, edit)?;
                self.config.policy = self.state.state().policy.clone();
            } else {
                self.queue_configuration(&origin, request, &writer, edit)?;
                self.db.execute(
                    "UPDATE configuration_edits SET writer=?1 WHERE origin=?2 AND id=?3",
                    params![writer, origin, id],
                )?;
            }
        }
        Ok(!rows.is_empty())
    }

    /// Keep stale full inputs on a retired owner, including legacy inputs whose
    /// origin no longer has a retained payload. They grant no execution rights.
    pub(super) fn retain_retired_request(
        &self,
        origin: &str,
        request: Uuid,
        edit: &ConfigurationEdit,
    ) -> Result<()> {
        let body = serde_json::to_vec(edit)?;
        let completed: Option<String> = self.db.query_row("SELECT fingerprint FROM configuration_edits WHERE origin=?1 AND id=?2 AND result IS NOT NULL", params![origin,request.to_string()], |r|r.get(0)).optional()?;
        if let Some(expected) = completed {
            ensure!(
                expected == fingerprint(edit)?,
                "retired configuration input changed"
            );
            return Ok(());
        }
        let saved: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT body FROM retired_configuration_requests WHERE origin=?1 AND id=?2",
                params![origin, request.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(saved) = saved {
            ensure!(saved == body, "retired configuration input changed");
            return Ok(());
        }
        let (rows, bytes): (u64, u64) = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM retired_configuration_requests",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            rows < 4096 && bytes.saturating_add(body.len() as u64) <= 64 * 1024 * 1024,
            "retired configuration input capacity exhausted"
        );
        self.db.execute(
            "INSERT INTO retired_configuration_requests VALUES(?1,?2,?3)",
            params![origin, request.to_string(), body],
        )?;
        Ok(())
    }
}

impl Store {
    pub(crate) fn reconcile_configuration(&mut self) -> Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        let changed = self.network_session(&tx, state).reroute_configuration()?;
        tx.commit()?;
        if changed {
            self.sync_wakeup.notify_one();
        }
        Ok(())
    }
}
