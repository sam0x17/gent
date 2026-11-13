use super::*;

fn db() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE network_sent(id TEXT PRIMARY KEY);
        CREATE TABLE network_events(id TEXT PRIMARY KEY,peer TEXT,body BLOB);",
    )
    .unwrap();
    schema(&db).unwrap();
    db
}

#[test]
fn queue_and_retry_caps_reserve_control_capacity_and_count_pending_slots_and_legacy_rows() {
    let db = db();
    db.execute(
        "INSERT INTO network_events(id,body,traffic) VALUES('one',X'0001','data')",
        [],
    )
    .unwrap();
    capacity(&db, "data", MAX_BYTES as usize - 2, false).unwrap();
    assert!(capacity(&db, "data", MAX_BYTES as usize - 1, false).is_err());
    assert!(capacity(&db, "data", usize::MAX, false).is_err());
    capacity(&db, "control", MAX_BYTES as usize, false).unwrap();
    db.execute(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1)
        INSERT INTO network_events(id,body,traffic) SELECT 'queued-'||x,X'','data' FROM n",
        [MAX_EVENTS - 1],
    )
    .unwrap();
    assert!(capacity(&db, "data", 0, false).is_err());
    capacity(&db, "control", 0, false).unwrap();
    db.execute("DELETE FROM network_events WHERE id<>'one'", [])
        .unwrap();
    db.execute(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1)
        INSERT INTO network_sent(id,traffic) SELECT 'retry-'||x,'data' FROM n",
        [MAX_RETRIES - 1],
    )
    .unwrap();
    assert!(capacity(&db, "data", 1, false).is_err());
    // Pending work already reserved its final sent-record slot.
    db.execute("UPDATE network_events SET announcement=1", [])
        .unwrap();
    capacity(&db, "data", 1, false).unwrap();
    db.execute("UPDATE network_sent SET traffic='legacy'", [])
        .unwrap();
    db.execute("INSERT INTO network_sent(id) VALUES('legacy-last')", [])
        .unwrap();
    assert!(capacity(&db, "data", 1, false).is_err());
    assert!(capacity(&db, "control", 1, false).is_err());
    capacity(&db, "control", 1, true).unwrap();
}

#[test]
fn cleanup_is_bounded_and_never_forgets_legacy_control_or_pending_work() {
    let mut db = db();
    db.execute(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<270)
        INSERT INTO network_sent(id,traffic,retire_after) SELECT 'old-'||x,'data',5 FROM n",
        [],
    )
    .unwrap();
    db.execute_batch(
        "INSERT INTO network_sent VALUES('legacy','legacy',NULL),('edit','control',NULL),
        ('pending','data',5),('live','data',11);
        INSERT INTO network_events(id,body) VALUES('pending',X'');",
    )
    .unwrap();
    assert_eq!(clean(&db, 10, true).unwrap(), 256);
    let tx = db.transaction().unwrap();
    assert_eq!(clean(&tx, 10, false).unwrap(), 256);
    tx.rollback().unwrap();
    assert_eq!(clean(&db, 10, false).unwrap(), 256);
    assert_eq!(clean(&db, 10, false).unwrap(), 14);
    assert_eq!(clean(&db, 10, false).unwrap(), 0);
    assert_eq!(status(&db, 10).unwrap()["sent_retries"], 4);
}
