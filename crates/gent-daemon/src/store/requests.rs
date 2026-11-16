//! Request admission has a finite lifetime, independent of retained results.
//! Persisted time never moves backward, so cleanup cannot resurrect an old ID.
use super::*;
use uuid::{NoContext, Timestamp, Uuid};

pub(super) const LIFETIME: i64 = 24 * 60 * 60;
pub(super) const CLOCK_SKEW: i64 = 60;

pub(super) fn schema(db: &Connection, observed: i64) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS request_clock (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        floor INTEGER NOT NULL,legacy_until INTEGER NOT NULL);",
    )?;
    db.execute(
        "INSERT OR IGNORE INTO request_clock VALUES(1,?1,?2)",
        params![observed, observed + EXCHANGE_TTL_SECONDS + CLOCK_SKEW],
    )?;
    Ok(())
}

pub(super) fn clock(db: &Connection, observed: i64) -> Result<i64> {
    ensure!(
        (0..i64::MAX - 365 * LIFETIME).contains(&observed),
        "invalid request clock"
    );
    db.execute(
        "UPDATE request_clock SET floor=?1 WHERE singleton=1 AND floor<?1",
        [observed],
    )?;
    Ok(db.query_row(
        "SELECT floor FROM request_clock WHERE singleton=1",
        [],
        |r| r.get(0),
    )?)
}

/// Pure owner diagnostics do not admit requests or advance durable time.
pub(super) fn diagnostic_clock(db: &Connection, observed: i64) -> Result<i64> {
    ensure!(
        (0..i64::MAX - 365 * LIFETIME).contains(&observed),
        "invalid request clock"
    );
    let saved: i64 = db.query_row(
        "SELECT floor FROM request_clock WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    Ok(saved.max(observed))
}

pub(super) fn issued(id: &str) -> Option<i64> {
    let id_parsed = Uuid::parse_str(id).ok()?;
    if id_parsed.to_string() != id
        || id_parsed.get_version_num() != 7
        || id_parsed.get_variant() != uuid::Variant::RFC4122
    {
        return None;
    }
    let (seconds, _) = id_parsed.get_timestamp()?.to_unix();
    i64::try_from(seconds).ok()
}

pub(super) fn admit(id: &str, timestamp: i64) -> Result<()> {
    let issued = issued(id).context("new request_id must be UUIDv7; use gent_request_ids")?;
    ensure!(
        issued <= timestamp + CLOCK_SKEW,
        "request_id is from the future; use gent_request_ids for new work"
    );
    ensure!(
        issued > timestamp - LIFETIME,
        "request_id expired and has no retained result; do not replace it to retry old work"
    );
    Ok(())
}

pub(super) fn remote(
    db: &Connection,
    id: &str,
    created: i64,
    expires: i64,
    timestamp: i64,
) -> Result<bool> {
    if issued(id).is_some() {
        return Ok(admit(id, created).is_ok());
    }
    // A bounded migration period admits already queued pre-upgrade messages.
    // Legacy records are retained until this entire period has ended.
    let until: i64 = db.query_row(
        "SELECT legacy_until FROM request_clock WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    Ok(timestamp < until && created <= until - EXCHANGE_TTL_SECONDS && expires <= until)
}

impl StoreSession<'_> {
    pub(super) fn request_ids(&self, count: u32) -> Result<Value> {
        ensure!((1..=32).contains(&count), "request ID count must be 1-32");
        let timestamp = Timestamp::from_unix(NoContext, self.timestamp as u64, 0);
        let ids = (0..count)
            .map(|_| Uuid::new_v7(timestamp).to_string())
            .collect::<Vec<_>>();
        Ok(
            json!({"request_ids":ids,"new_request_valid_until":self.timestamp+LIFETIME,
            "retry":"reuse the original ID for an identical retry; expired IDs never authorize new work"}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(seconds: i64) -> String {
        Uuid::new_v7(Timestamp::from_unix(NoContext, seconds as u64, 0)).to_string()
    }
    #[test]
    fn canonical_ids_have_bounded_admission_and_future_skew() {
        let now = 2_000_000_000;
        for time in [now - LIFETIME + 1, now, now + CLOCK_SKEW] {
            admit(&id(time), now).unwrap();
        }
        for time in [now - LIFETIME, now + CLOCK_SKEW + 1] {
            assert!(admit(&id(time), now).is_err());
        }
        assert!(admit(&Uuid::new_v4().to_string(), now).is_err());
        let canonical = id(now);
        assert!(admit(&canonical.replace('-', ""), now).is_err());
        assert!(admit(&Uuid::nil().to_string(), now).is_err());
        let mut wrong_variant = *Uuid::parse_str(&canonical).unwrap().as_bytes();
        wrong_variant[8] &= 0x3f;
        assert!(admit(&Uuid::from_bytes(wrong_variant).to_string(), now).is_err());
    }
    #[test]
    fn committed_clock_survives_restart_and_rejects_rollback_replays() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("clock.sqlite");
        let mut db = Connection::open(&path).unwrap();
        let start = 2_000_000_000;
        schema(&db, start).unwrap();
        let request = id(start);
        {
            let tx = db.transaction().unwrap();
            clock(&tx, start + LIFETIME).unwrap();
            tx.commit().unwrap();
        }
        drop(db);
        let mut db = Connection::open(&path).unwrap();
        schema(&db, start - 100).unwrap();
        assert!(admit(&request, clock(&db, start - 100).unwrap()).is_err());
        let tx = db.transaction().unwrap();
        clock(&tx, start + 2 * LIFETIME).unwrap();
        tx.rollback().unwrap();
        assert_eq!(clock(&db, start).unwrap(), start + LIFETIME);
    }
    #[test]
    fn legacy_remote_admission_ends_before_legacy_records_can_be_forgotten() {
        let db = Connection::open_in_memory().unwrap();
        let start = 2_000_000_000;
        schema(&db, start).unwrap();
        let old = Uuid::new_v4().to_string();
        let until = start + EXCHANGE_TTL_SECONDS + CLOCK_SKEW;
        assert!(remote(&db, &old, start, start + EXCHANGE_TTL_SECONDS, start + 1).unwrap());
        assert!(!remote(&db, &old, start + 61, until + 1, start + 1).unwrap());
        assert!(!remote(&db, &old, start, until, until).unwrap());
        assert!(
            remote(
                &db,
                &id(start),
                start + LIFETIME - 1,
                start + LIFETIME * 2 - 1,
                until
            )
            .unwrap()
        );
        assert!(
            !remote(
                &db,
                &id(start),
                start + LIFETIME,
                start + LIFETIME * 2,
                until
            )
            .unwrap()
        );
    }
}
