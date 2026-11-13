use super::*;

#[test]
fn unknown_allocated_ids_fail_closed_while_retained_legacy_v7_retries_remain_valid() {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let db = open_database(home.path(), "mls.sqlite3").unwrap();
    let request = Uuid::now_v7();
    let fingerprint = request_hash("send", b"legacy operation");
    assert!(retry(&db, request, &fingerprint).is_err());
    // A pre-upgrade UUIDv7 record has no allocation. Its retained response still
    // wins before new-work admission and is never reclassified for deletion.
    db.execute(
        "INSERT INTO outbox(id,group_id,request_hash,bytes) VALUES(?1,X'01',?2,X'0102')",
        params![request.to_string(), fingerprint],
    )
    .unwrap();
    db.execute_batch("DROP TABLE transport_requests; PRAGMA user_version=6;")
        .unwrap();
    drop(db);
    let db = open_database(home.path(), "mls.sqlite3").unwrap();
    assert_eq!(
        retry(&db, request, &fingerprint).unwrap().unwrap().bytes,
        vec![1, 2]
    );
    assert!(retry(&db, request, b"different operation").is_err());
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM transport_requests", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn allocation_scope_rejects_changed_group_body_and_operation_kind() {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut db = open_database(home.path(), "mls.sqlite3").unwrap();
    let tx = db.transaction().unwrap();
    let fragment = Some((Uuid::new_v4(), 0, false));
    let request = allocate(&tx, b"group", b"body", fragment).unwrap();
    assert_eq!(allocate(&tx, b"group", b"body", fragment).unwrap(), request);
    assert!(allocate(&tx, b"group", b"changed", fragment).is_err());
    let correct = request_hash(
        "send",
        &serde_json::to_vec(&(b"group".as_slice(), b"body".as_slice())).unwrap(),
    );
    assert!(retry(&tx, request, &correct).unwrap().is_none());
    for bad in [
        request_hash("rotate", b"group"),
        request_hash("create", b"group"),
        request_hash(
            "send",
            &serde_json::to_vec(&(b"other".as_slice(), b"body".as_slice())).unwrap(),
        ),
    ] {
        assert!(retry(&tx, request, &bad).is_err());
    }
    tx.rollback().unwrap();
    assert!(retry(&db, request, &correct).is_err());
}
