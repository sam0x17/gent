//! Daemon-allocated transport requests. UUIDv7 is reserved in the MLS operation
//! namespace: an unknown ID can never start work. Its timestamp is not a lease.
//! Existing legacy retries keep their original records, including UUIDv7 IDs.
use super::*;

#[cfg(test)]
mod tests;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS transport_requests (
          id TEXT PRIMARY KEY, group_id BLOB NOT NULL, request_hash BLOB NOT NULL,
          event TEXT, offset INTEGER, cancelled INTEGER,
          UNIQUE(group_id,event,offset,cancelled));
        CREATE INDEX IF NOT EXISTS transport_request_event ON transport_requests(event,offset);",
    )?;
    Ok(())
}

pub(super) fn managed(id: Uuid) -> bool {
    id.get_version_num() == 7 && id.get_variant() == uuid::Variant::RFC4122
}

/// Called only after looking for a retained exact retry, before changing MLS.
pub(super) fn admit(db: &Connection, id: Uuid, fingerprint: &[u8]) -> Result<()> {
    if managed(id) {
        let saved: Option<Vec<u8>> = db
            .query_row(
                "SELECT request_hash FROM transport_requests WHERE id=?1",
                [id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            saved.as_deref() == Some(fingerprint),
            "transport request is unallocated, conflicting, or retired; it cannot start work"
        );
    }
    Ok(())
}

/// Allocation, encryption and packet persistence must share one transaction.
/// A daemon event binds each part/cancellation until its separate cursor commits.
/// The legacy deterministic ID is checked first to recover pre-upgrade crashes.
pub(super) fn allocate(
    db: &Connection,
    group: &[u8],
    body: &[u8],
    fragment: Option<(Uuid, usize, bool)>,
) -> Result<Uuid> {
    let fingerprint = request_hash("send", &serde_json::to_vec(&(group, body))?);
    if let Some((event, offset, cancelled)) = fragment {
        let legacy = crate::messages::packet_id(event, offset, cancelled);
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM outbox WHERE id=?1)",
            [legacy.to_string()],
            |r| r.get(0),
        )?;
        if exists {
            return Ok(legacy);
        }
        let saved: Option<String> = db.query_row(
            "SELECT id FROM transport_requests WHERE group_id=?1 AND event=?2 AND offset=?3 AND cancelled=?4",
            params![group,event.to_string(),offset,cancelled], |r| r.get(0),
        ).optional()?;
        if let Some(saved) = saved {
            let id = Uuid::parse_str(&saved)?;
            admit(db, id, &fingerprint)?;
            return Ok(id);
        }
    }
    let id = Uuid::now_v7();
    db.execute(
        "INSERT INTO transport_requests VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            id.to_string(),
            group,
            fingerprint,
            fragment.map(|f| f.0.to_string()),
            fragment.map(|f| f.1),
            fragment.map(|f| f.2)
        ],
    )?;
    Ok(id)
}
