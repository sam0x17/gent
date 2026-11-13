//! Bounded replay evidence and single-copy ciphertext storage. Outbound packets
//! remain available for offline peers; a relay acknowledgment cannot retire them.
use super::*;
use serde_json::{Value, json};

pub const RECENT_PACKETS: u64 = 128;
const CLEAN_BATCH: usize = 256;
const COPY_BATCH: usize = 8;
const DATA_PACKETS: u64 = 65536;
const DATA_BYTES: u64 = 512 * 1024 * 1024;
const CONFIGURATION_PACKETS: u64 = 65536;
const CONFIGURATION_BYTES: u64 = 128 * 1024 * 1024;

pub(super) fn capacity(db: &Connection, purpose: &str, bytes: usize) -> Result<()> {
    let (count, used): (u64, u64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(o.packet)),0) FROM stream_outbox o
         JOIN streams s USING(group_id) WHERE s.purpose=?1",
        [purpose],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let (max_count, max_bytes) = limits(purpose)?;
    ensure!(
        count < max_count && used.saturating_add(bytes as u64) <= max_bytes,
        "{purpose} transport history quota exhausted; inspect gent transport status; cleaning duplicate copies does not release retained packet quota"
    );
    Ok(())
}

fn limits(purpose: &str) -> Result<(u64, u64)> {
    Ok(match purpose {
        "data" => (DATA_PACKETS, DATA_BYTES),
        "configuration" => (CONFIGURATION_PACKETS, CONFIGURATION_BYTES),
        _ => bail!("unknown stream purpose"),
    })
}

/// Reconstruct the original MLS bytes for a compacted retry without advancing
/// cryptographic state. Raw, unsequenced operations retain their own bytes.
pub(crate) fn bytes(db: &Connection, id: &str, group: &[u8], raw: Vec<u8>) -> Result<Vec<u8>> {
    if !raw.is_empty() {
        return Ok(raw);
    }
    let (wire,sequence,key):(Vec<u8>,u64,PublicKey) = db.query_row(
        "SELECT o.packet,o.sequence,s.writer_key FROM stream_outbox o JOIN streams s USING(group_id)
         WHERE o.id=?1 AND o.group_id=?2",params![id,group],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    let packet = Packet::decode(&wire)?;
    packet.verify(&key)?;
    ensure!(
        packet.group() == group && packet.sequence() == sequence,
        "compacted retry packet mismatch"
    );
    Ok(packet.ciphertext().to_vec())
}

pub(super) fn received(db: &Connection, packet: &Packet) -> Result<()> {
    db.execute(
        "UPDATE receipts SET stream_sequence=?1 WHERE group_id=?2 AND wire_hash=?3",
        params![
            packet.sequence(),
            packet.group(),
            Sha256::digest(packet.ciphertext()).as_slice()
        ],
    )?;
    Ok(())
}

pub(super) fn trim_group(db: &Connection, group: &[u8], head: u64) -> Result<()> {
    let floor = head.saturating_sub(RECENT_PACKETS);
    db.execute("DELETE FROM stream_seen WHERE rowid IN
        (SELECT rowid FROM stream_seen WHERE group_id=?1 AND sequence>0 AND sequence<=?2 ORDER BY sequence LIMIT ?3)",
        params![group,floor,CLEAN_BATCH])?;
    // Legacy receipts lack sequence metadata. An ordered stream already pins its
    // head and origin; raw receive APIs refuse it, and consumed MLS generations
    // cannot be replayed under a new signed position.
    db.execute(
        "DELETE FROM receipts WHERE rowid IN
        (SELECT rowid FROM receipts WHERE group_id=?1 AND
          (stream_sequence IS NULL OR (stream_sequence>0 AND stream_sequence<=?2))
         ORDER BY stream_sequence LIMIT ?3)",
        params![group, floor, CLEAN_BATCH],
    )?;
    Ok(())
}

/// Caller owns an immediate transaction. No authority lease is needed for local
/// compaction, which never changes stream heads, packets, or application state.
pub(crate) fn clean(db: &Connection, dry_run: bool) -> Result<Value> {
    let copies = db
        .prepare(
            "SELECT o.id,o.group_id,o.bytes FROM outbox o JOIN stream_outbox s ON s.id=o.id
        WHERE length(o.bytes)>0 ORDER BY o.sequence LIMIT ?1",
        )?
        .query_map([COPY_BATCH], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut removed_bytes = 0u64;
    for (id, group, raw) in &copies {
        ensure!(
            bytes(db, id, group, vec![])? == *raw,
            "duplicate ciphertext copies disagree"
        );
        removed_bytes += raw.len() as u64;
        if !dry_run {
            db.execute("UPDATE outbox SET bytes=X'' WHERE id=?1", [id])?;
        }
    }
    let seen = db
        .prepare(
            "SELECT d.rowid FROM stream_seen d JOIN streams s USING(group_id)
        WHERE d.sequence>0 AND d.sequence<=s.head-?1 ORDER BY d.rowid LIMIT ?2",
        )?
        .query_map(params![RECENT_PACKETS, CLEAN_BATCH], |r| r.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let receipts = db
        .prepare(
            "SELECT r.rowid FROM receipts r JOIN streams s USING(group_id)
        WHERE r.stream_sequence IS NULL OR (r.stream_sequence>0 AND r.stream_sequence<=s.head-?1)
        ORDER BY r.rowid LIMIT ?2",
        )?
        .query_map(params![RECENT_PACKETS, CLEAN_BATCH], |r| r.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !dry_run {
        for id in &seen {
            db.execute("DELETE FROM stream_seen WHERE rowid=?1", [id])?;
        }
        for id in &receipts {
            db.execute("DELETE FROM receipts WHERE rowid=?1", [id])?;
        }
    }
    Ok(
        json!({"dry_run":dry_run,"duplicate_copies_compacted":copies.len(),"duplicate_bytes_removed":removed_bytes,
        "accepted_digests_removed":seen.len(),"wire_receipts_removed":receipts.len(),
        "copy_batch_limit":COPY_BATCH,"replay_batch_limit":CLEAN_BATCH,
        "retained_packets_removed":0}),
    )
}

pub(crate) fn status(db: &Connection) -> Result<Value> {
    let mut classes = serde_json::Map::new();
    for purpose in ["data", "configuration"] {
        let (count, bytes): (u64, u64) = db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(o.packet)),0)
            FROM stream_outbox o JOIN streams s USING(group_id) WHERE s.purpose=?1",
            [purpose],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (max_count, max_bytes) = limits(purpose)?;
        classes.insert(purpose.into(),json!({"packets":count,"packet_bytes":bytes,"max_packets":max_count,"max_packet_bytes":max_bytes}));
    }
    let (copies, copy_bytes): (u64, u64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(o.bytes)),0)
        FROM outbox o JOIN stream_outbox s ON s.id=o.id WHERE length(o.bytes)>0",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let (digests, due): (u64, u64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(d.sequence>0 AND d.sequence<=s.head-?1),0)
        FROM stream_seen d JOIN streams s USING(group_id)",
        [RECENT_PACKETS],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let (receipts,receipts_due):(u64,u64)=db.query_row("SELECT COUNT(*),COALESCE(SUM(r.stream_sequence IS NULL OR
        (r.stream_sequence>0 AND r.stream_sequence<=s.head-?1)),0) FROM receipts r JOIN streams s USING(group_id)",
        [RECENT_PACKETS],|r|Ok((r.get(0)?,r.get(1)?)))?;
    Ok(
        json!({"outgoing":classes,"duplicate_copies":copies,"duplicate_bytes":copy_bytes,
        "accepted_digests":digests,"accepted_digests_due":due,"ordered_wire_receipts":receipts,"wire_receipts_due":receipts_due,
        "recent_packets_per_stream":RECENT_PACKETS,
        "scope":"Ordered transport only; outbound packets stay retained for offline peers. Authority history, raw groups, application queues, plaintext, and total database size are separate."}),
    )
}

impl OrderedEndpoint<'_> {
    pub fn storage_status(&self) -> Result<Value> {
        status(&self.inner.db)
    }
    pub fn clean_storage(&mut self, dry_run: bool) -> Result<Value> {
        let tx = self
            .inner
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = clean(&tx, dry_run)?;
        tx.commit()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_byte_quotas_have_exact_boundaries_and_separate_reserves() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE streams(group_id BLOB,purpose TEXT); CREATE TABLE stream_outbox(group_id BLOB,packet BLOB);
            INSERT INTO streams VALUES(X'01','data'),(X'02','configuration');
            INSERT INTO stream_outbox VALUES(X'01',X'0001'),(X'02',X'000102');").unwrap();
        capacity(&db, "data", DATA_BYTES as usize - 2).unwrap();
        capacity(&db, "configuration", CONFIGURATION_BYTES as usize - 3).unwrap();
        assert!(capacity(&db, "data", DATA_BYTES as usize - 1).is_err());
        assert!(capacity(&db, "configuration", CONFIGURATION_BYTES as usize - 2).is_err());
        assert!(capacity(&db, "data", usize::MAX).is_err());
    }
}
