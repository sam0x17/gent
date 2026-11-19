//! Prefer presence and directory checks between complete records, preserving
//! interrupted fragments. Reconciliation must not wait behind inventory churn.
use super::*;

pub(super) fn next_id(db: &Connection, peer: &str) -> Result<Option<String>> {
    let oldest: Option<(String, usize, bool)> = db
        .query_row(
            "SELECT id,offset,cancelled FROM network_events WHERE peer=?1 ORDER BY rowid LIMIT 1",
            [peer],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((id, offset, cancelled)) = oldest else {
        return Ok(None);
    };
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
            "SELECT e.id FROM network_events e WHERE e.peer=?1 ORDER BY
             CASE WHEN e.offset>0 OR EXISTS(
                 SELECT 1 FROM transport_requests r JOIN network_links l ON l.outgoing=r.group_id
                 WHERE l.peer=e.peer AND r.event=e.id) THEN 0
             WHEN CASE WHEN json_valid(CAST(e.body AS TEXT))
                 THEN json_extract(CAST(e.body AS TEXT),'$.event.kind')='presence' ELSE 0 END THEN 1
             WHEN CASE WHEN json_valid(CAST(e.body AS TEXT))
                 THEN json_extract(CAST(e.body AS TEXT),'$.event.kind')='directory' ELSE 0 END THEN 2
             ELSE 3 END,e.rowid LIMIT 1",
            [peer],
            |r| r.get(0),
        )
        .optional()?)
}
