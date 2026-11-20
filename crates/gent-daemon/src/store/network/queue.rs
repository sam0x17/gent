//! Prefer presence, chat delivery and directory checks between complete records,
//! preserving interrupted fragments. Inventory churn cannot delay those checks.
use super::*;

pub(super) fn next_id(db: &Connection, peer: &str) -> Result<Option<String>> {
    let mut candidates = db.prepare(
        "SELECT id,offset,cancelled FROM network_events e WHERE peer=?1 AND NOT EXISTS(
             SELECT 1 FROM hosted_event_gates g JOIN hosted_checkpoints c ON c.node=g.node
             WHERE g.id=e.id AND c.durable<g.revision) ORDER BY rowid LIMIT 2",
    )?;
    let mut rows = candidates.query([peer])?;
    let Some(first) = rows.next()? else {
        return Ok(None);
    };
    let id: String = first.get(0)?;
    let offset = first.get(1)?;
    let cancelled = first.get(2)?;
    // A lone chat waiting for upload needs no priority scan of its payload.
    if rows.next()?.is_none() {
        return Ok(Some(id));
    }
    // Older releases used deterministic request IDs. A committed first fragment
    // can exist even when the separate queue cursor write failed at offset zero.
    let legacy = messages::packet_id(Uuid::parse_str(&id)?, offset, cancelled);
    let started: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM outbox WHERE id=?1)",
        [legacy.to_string()],
        |r| r.get(0),
    )?;
    if started {
        return Ok(Some(id));
    }
    Ok(db
        .query_row(
            "SELECT e.id FROM network_events e WHERE e.peer=?1 AND NOT EXISTS(
             SELECT 1 FROM hosted_event_gates g JOIN hosted_checkpoints c ON c.node=g.node
             WHERE g.id=e.id AND c.durable<g.revision) ORDER BY
             CASE WHEN e.offset>0 OR EXISTS(
                 SELECT 1 FROM transport_requests r JOIN network_links l ON l.outgoing=r.group_id
                 WHERE l.peer=e.peer AND r.event=e.id) THEN 0
             WHEN CASE WHEN json_valid(CAST(e.body AS TEXT))
                 THEN json_extract(CAST(e.body AS TEXT),'$.event.kind')='presence' ELSE 0 END THEN 1
             WHEN CASE WHEN json_valid(CAST(e.body AS TEXT))
                 THEN json_extract(CAST(e.body AS TEXT),'$.event.kind') IN ('message','receipt') ELSE 0 END THEN 2
             WHEN CASE WHEN json_valid(CAST(e.body AS TEXT))
                 THEN json_extract(CAST(e.body AS TEXT),'$.event.kind')='directory' ELSE 0 END THEN 3
             ELSE 4 END,e.rowid LIMIT 1",
            [peer],
            |r| r.get(0),
        )
        .optional()?)
}

pub(super) struct ReadyEvent {
    pub(super) id: String,
    pub(super) subject: Option<String>,
    pub(super) cancelled: bool,
}

/// Check the selected event before loading its payload for encryption.
/// Both scheduling and packet preparation must honor the same gates.
pub(super) fn ready_event(store: &Store, peer: &str) -> Result<Option<ReadyEvent>> {
    let Some(id) = next_id(&store.db, peer)? else {
        return Ok(None);
    };
    let (subject, mut cancelled): (Option<String>, bool) = store.db.query_row(
        "SELECT subject,cancelled FROM network_events WHERE id=?1",
        [&id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if let Some(subject) = &subject {
        let session = store.network_session(&store.db, store.identity.state(&store.db)?);
        let message = session.message(subject)?;
        if !session.web_message_ready(&message)? {
            return Ok(None);
        }
        if !session.deliverable(&message)? {
            cancelled = true;
        } else if !cancelled {
            for file in &message.attachments {
                let chunks: Option<(u64, u64)> = store
                    .db
                    .query_row(
                        "SELECT (SELECT COUNT(*) FROM file_chunks WHERE object_id=?1),
                            (SELECT COALESCE(SUM(uploaded),0) FROM file_chunks WHERE object_id=?1)
                     FROM file_objects WHERE id=?1 AND complete=1 AND expires_at>?2",
                        params![file.id, session.timestamp],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                match chunks {
                    None => {
                        cancelled = true;
                        break;
                    }
                    Some((present, uploaded)) if present == 0 || present != uploaded => {
                        return Ok(None);
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(Some(ReadyEvent {
        id,
        subject,
        cancelled,
    }))
}

impl Store {
    pub(in crate::store) fn add_ready_network_groups(
        &self,
        groups: &mut BTreeSet<Vec<u8>>,
    ) -> Result<()> {
        // Most control queues have no message or hosted durability gates and
        // need no priority scan to establish that at least one event can run.
        let mut query = self.db.prepare(
            "SELECT l.peer,l.outgoing,MAX(e.subject IS NOT NULL OR g.id IS NOT NULL)
             FROM network_events e JOIN network_links l ON l.peer=e.peer
             LEFT JOIN hosted_event_gates g ON g.id=e.id GROUP BY l.peer",
        )?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let group: Vec<u8> = row.get(1)?;
            if groups.contains(&group) {
                continue;
            }
            let has_gates: bool = row.get(2)?;
            // An error still belongs to this stream's transfer/retry path.
            // A waiting head remains discoverable on its next local wake.
            if !has_gates || !matches!(ready_event(self, &row.get::<_, String>(0)?), Ok(None)) {
                groups.insert(group);
            }
        }
        Ok(())
    }
}
