//! Full signed records are a publication queue. Accepted revision digests remain
//! after compaction for delayed messages, duplicate streams, and fork checks.
use super::*;
use gent_crypto::{Digest, PublicKey, SignedConfigurationGrant};
use serde_json::{Value, json};

pub const RECENT_STATES: u64 = 64;
const CLEAN_BATCH: u64 = 8;
const MAX_RECORDS: u64 = 8192;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ACCEPTED_REVISIONS: u64 = 1_048_576;
type StoredAuthority = (Vec<u8>, Vec<u8>, Vec<u8>, String);

fn current(db: &Connection) -> Result<Option<(VerifiedState, String)>> {
    let row: Option<StoredAuthority> = db
        .query_row(
            "SELECT anchor,checkpoint,state,node FROM authority WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    row.map(|(anchor, checkpoint, state, node)| {
        Ok((
            VerifiedState::restore(
                serde_json::from_slice(&anchor)?,
                serde_json::from_slice(&checkpoint)?,
                SignedState::decode(&state)?,
            )?,
            node,
        ))
    })
    .transpose()
}

/// These hashes come only from locally verified signed records. The database is
/// trusted endpoint state, like the current authority and stream checkpoints.
pub(crate) fn checkpoint(
    db: &Connection,
    revision: u64,
    anchor: &TrustAnchor,
) -> Result<Checkpoint> {
    let wire: Option<Vec<u8>> = db
        .query_row(
            "SELECT state FROM authority_history WHERE revision=?1",
            [revision],
            |r| r.get(0),
        )
        .optional()?;
    let saved: Option<Digest> = db
        .query_row(
            "SELECT digest FROM authority_digests WHERE revision=?1",
            [revision],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(wire) = wire {
        let checkpoint = SignedState::decode(&wire)?.verified_checkpoint(anchor)?;
        ensure!(
            checkpoint.revision == revision
                && saved.is_none_or(|hash| hash == checkpoint.state_hash),
            "conflicting authority digest"
        );
        return Ok(checkpoint);
    }
    Ok(Checkpoint {
        revision,
        state_hash: saved.context("accepted authority history is unavailable")?,
    })
}

pub(crate) fn remember(db: &Connection, checkpoint: &Checkpoint) -> Result<()> {
    let saved: Option<Digest> = db
        .query_row(
            "SELECT digest FROM authority_digests WHERE revision=?1",
            [checkpoint.revision],
            |r| r.get(0),
        )
        .optional()?;
    ensure!(
        saved.is_none_or(|hash| hash == checkpoint.state_hash),
        "authority history fork"
    );
    if saved.is_some() {
        return Ok(());
    }
    // Legacy full records already represent accepted revisions. Their slots
    // stay reserved until a verified digest replaces the full body, even when
    // an old database exceeds today's admission limit.
    let reserved: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM authority_history WHERE revision=?1)",
        [checkpoint.revision],
        |r| r.get(0),
    )?;
    if !reserved {
        let (digests, legacy) = digest_usage(db)?;
        ensure!(
            digests.saturating_add(legacy) < MAX_ACCEPTED_REVISIONS,
            "accepted revision history quota exhausted; inspect gent transport status; cleanup preserves verification digests"
        );
    }
    db.execute(
        "INSERT INTO authority_digests VALUES(?1,?2)",
        params![checkpoint.revision, checkpoint.state_hash.as_slice()],
    )?;
    Ok(())
}

fn digest_usage(db: &Connection) -> Result<(u64, u64)> {
    Ok(db.query_row(
        "SELECT (SELECT COUNT(*) FROM authority_digests),
        (SELECT COUNT(*) FROM authority_history h WHERE NOT EXISTS
            (SELECT 1 FROM authority_digests d WHERE d.revision=h.revision))",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}

/// Hold the complete suffix needed by a join interrupted before its daemon is
/// running. Repeated enrollment must not move that starting point forward.
pub(crate) fn pin_join(db: &Connection, peer: &str, key: &PublicKey, revision: u64) -> Result<()> {
    db.execute("INSERT INTO authority_join_pins VALUES(?1,?2,?3)
        ON CONFLICT(peer) DO UPDATE SET revision=CASE WHEN peer_key=excluded.peer_key THEN MIN(revision,excluded.revision) ELSE excluded.revision END,peer_key=excluded.peer_key",
        params![peer, key.as_slice(), revision])?;
    Ok(())
}

pub(crate) fn schema(db: &Connection, previous: i64) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS authority_digests(revision INTEGER PRIMARY KEY,digest BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS authority_join_pins(peer TEXT PRIMARY KEY,peer_key BLOB NOT NULL,revision INTEGER NOT NULL);")?;
    if previous > 0 && previous < 6 {
        // Old databases didn't record interrupted enrollment. Conservatively
        // retain history for every enrolled peer until its live daemon confirms
        // current configuration, or the owner revokes/replaces its key.
        if let Some((state, node)) = current(db)? {
            let first: u64 =
                db.query_row("SELECT MIN(revision) FROM authority_history", [], |r| {
                    r.get(0)
                })?;
            for (peer, member) in &state.state().nodes {
                if peer != &node {
                    pin_join(db, peer, &member.signing_key, first.saturating_sub(1))?;
                }
            }
        }
    }
    Ok(())
}

fn floor(db: &Connection, state: &VerifiedState, node: &str) -> Result<(u64, Vec<String>, usize)> {
    let mut floor = state
        .checkpoint()
        .revision
        .saturating_sub(RECENT_STATES - 1);
    let mut active_streams = Vec::new();
    let mut query = db.prepare(
        "SELECT c.group_id,c.grant,c.revision,c.offset,s.head,
        COALESCE(a.sequence,-1) FROM configuration_streams c JOIN streams s USING(group_id)
        LEFT JOIN stream_confirmed a USING(group_id) WHERE s.writer=?1",
    )?;
    let rows = query.query_map([node], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, u64>(2)?,
            r.get::<_, u64>(3)?,
            r.get::<_, u64>(4)?,
            r.get::<_, i64>(5)?,
        ))
    })?;
    for row in rows {
        let (group, wire, revision, offset, head, confirmed) = row?;
        let signed = SignedConfigurationGrant::decode(&wire)?;
        signed.verify(state.anchor())?;
        // An unselected candidate cannot publish this suffix. Do not retain
        // unrelated future revisions forever for an abandoned preparation.
        if signed.grant.owner_candidate.is_some() && !signed.can_publish(state)? {
            continue;
        }
        if ordered::configuration::publication_limit(&signed, state)
            .is_some_and(|last| revision >= last && offset == 0)
        {
            continue;
        }
        let grant = signed.grant;
        ensure!(
            grant.group == group && grant.writer == node,
            "configuration history pin mismatch"
        );
        let active = |id: &str, key: &PublicKey| {
            state
                .state()
                .nodes
                .get(id)
                .is_some_and(|n| n.signing_key == *key)
        };
        if active(&grant.writer, &grant.writer_key) && active(&grant.reader, &grant.reader_key) {
            floor = floor.min(revision + 1);
            if offset == 0
                && revision >= state.checkpoint().revision
                && confirmed >= 0
                && confirmed as u64 == head
            {
                active_streams.push(grant.reader);
            }
        }
    }
    let has_links: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='network_links' AND type='table')",
        [],
        |r| r.get(0),
    )?;
    let mut released = vec![];
    let mut pins = 0;
    let mut query = db.prepare("SELECT peer,peer_key,revision FROM authority_join_pins")?;
    for row in query.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, PublicKey>(1)?,
            r.get::<_, u64>(2)?,
        ))
    })? {
        let (peer, key, revision) = row?;
        let active = state
            .state()
            .nodes
            .get(&peer)
            .is_some_and(|n| n.signing_key == key);
        let connected = has_links
            && db.query_row(
                "SELECT EXISTS(SELECT 1 FROM network_links WHERE peer=?1 AND peer_key=?2)",
                params![&peer, key.as_slice()],
                |r| r.get::<_, bool>(0),
            )?;
        if !active || (connected && active_streams.contains(&peer)) {
            released.push(peer);
        } else {
            pins += 1;
            floor = floor.min(revision + 1);
        }
    }
    Ok((floor, released, pins))
}

/// Caller owns the transaction. Verify each original before replacing its body
/// with a digest, so a cleanup failure cannot destroy the accepted evidence.
pub(crate) fn clean(db: &Connection, dry_run: bool) -> Result<(usize, u64)> {
    let Some((state, node)) = current(db)? else {
        return Ok((0, 0));
    };
    let (floor, released, _) = floor(db, &state, &node)?;
    let rows = db.prepare("SELECT revision,length(state) FROM authority_history WHERE revision<?1 ORDER BY revision LIMIT ?2")?
        .query_map(params![floor,CLEAN_BATCH], |r| Ok((r.get::<_,u64>(0)?,r.get::<_,u64>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut bytes = 0;
    for (revision, size) in &rows {
        let checkpoint = checkpoint(db, *revision, state.anchor())?;
        bytes += size;
        if !dry_run {
            remember(db, &checkpoint)?;
            db.execute(
                "DELETE FROM authority_history WHERE revision=?1",
                [revision],
            )?;
        }
    }
    if !dry_run {
        for peer in released {
            db.execute("DELETE FROM authority_join_pins WHERE peer=?1", [&peer])?;
        }
    }
    Ok((rows.len(), bytes))
}

pub(crate) fn capacity(db: &Connection, bytes: usize) -> Result<()> {
    let (count, used): (u64, u64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(state)),0) FROM authority_history",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(
        count < MAX_RECORDS && used.saturating_add(bytes as u64) <= MAX_BYTES,
        "signed configuration history quota exhausted; inspect gent transport status and let publication or interrupted node joins catch up"
    );
    Ok(())
}

pub(crate) fn status(db: &Connection) -> Result<Value> {
    let (count, bytes): (u64, u64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(state)),0) FROM authority_history",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let (digests, legacy) = digest_usage(db)?;
    let (floor, pins) = if let Some((state, node)) = current(db)? {
        let (f, _, p) = floor(db, &state, &node)?;
        (f, p)
    } else {
        (0, 0)
    };
    let eligible: u64 = db.query_row(
        "SELECT COUNT(*) FROM authority_history WHERE revision<?1",
        [floor],
        |r| r.get(0),
    )?;
    Ok(
        json!({"full_records":count,"full_record_bytes":bytes,"max_records":MAX_RECORDS,"max_record_bytes":MAX_BYTES,
        "accepted_digests":digests,"full_records_due":eligible,"retain_from_revision":floor,"pending_join_pins":pins,
        "accepted_revisions":digests.saturating_add(legacy),"legacy_digest_reservations":legacy,
        "max_accepted_revisions":MAX_ACCEPTED_REVISIONS,"max_digest_payload_bytes":MAX_ACCEPTED_REVISIONS*32,
        "recent_full_records":RECENT_STATES,"compaction_batch_limit":CLEAN_BATCH}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_history_byte_quota_accepts_the_boundary_without_overflow() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE authority_history(revision INTEGER,state BLOB); INSERT INTO authority_history VALUES(0,X'0001');").unwrap();
        capacity(&db, MAX_BYTES as usize - 2).unwrap();
        assert!(capacity(&db, MAX_BYTES as usize - 1).is_err());
        assert!(capacity(&db, usize::MAX).is_err());
    }

    #[test]
    fn accepted_revision_capacity_reserves_legacy_records_and_keeps_existing_forks_detectable() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE authority_history(revision INTEGER PRIMARY KEY,state BLOB)")
            .unwrap();
        schema(&db, 10).unwrap();
        db.execute(
            "WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<?1)
            INSERT INTO authority_digests SELECT i,zeroblob(32) FROM n",
            [MAX_ACCEPTED_REVISIONS - 2],
        )
        .unwrap();
        let legacy = MAX_ACCEPTED_REVISIONS - 1;
        db.execute("INSERT INTO authority_history VALUES(?1,X'00')", [legacy])
            .unwrap();
        assert_eq!(digest_usage(&db).unwrap(), (MAX_ACCEPTED_REVISIONS - 1, 1));
        let unknown = Checkpoint {
            revision: MAX_ACCEPTED_REVISIONS,
            state_hash: [3; 32],
        };
        assert!(
            remember(&db, &unknown)
                .unwrap_err()
                .to_string()
                .contains("accepted revision history quota")
        );
        remember(
            &db,
            &Checkpoint {
                revision: 0,
                state_hash: [0; 32],
            },
        )
        .unwrap();
        assert!(
            remember(
                &db,
                &Checkpoint {
                    revision: 0,
                    state_hash: [1; 32]
                }
            )
            .unwrap_err()
            .to_string()
            .contains("fork")
        );
        remember(
            &db,
            &Checkpoint {
                revision: legacy,
                state_hash: [2; 32],
            },
        )
        .unwrap();
        db.execute("DELETE FROM authority_history WHERE revision=?1", [legacy])
            .unwrap();
        assert_eq!(digest_usage(&db).unwrap(), (MAX_ACCEPTED_REVISIONS, 0));
        assert!(remember(&db, &unknown).is_err());
        // An oversized migrated database also retains previously reserved work.
        db.execute(
            "INSERT INTO authority_history VALUES(?1,X'00')",
            [unknown.revision],
        )
        .unwrap();
        remember(&db, &unknown).unwrap();
        assert_eq!(digest_usage(&db).unwrap(), (MAX_ACCEPTED_REVISIONS + 1, 0));
    }
}
