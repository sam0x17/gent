use gent_crypto::files::{CHUNK_BYTES, FileGrant, MAX_FILE_BYTES, seal};
use gent_daemon::file_objects::{
    self, INCOMPLETE_TTL_SECONDS, MAX_OBJECTS, MAX_RESERVED_BYTES, MAX_RETENTION_SECONDS, Objects,
};
use rusqlite::{Connection, TransactionBehavior, params};
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000;
const EXPIRY: u64 = NOW + 86_400;

fn open(path: &std::path::Path) -> Connection {
    let mut db = Connection::open(path).unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .unwrap();
    file_objects::initialize(&mut db).unwrap();
    db
}

fn count(db: &Connection, table: &str) -> u64 {
    // Test-owned table names only.
    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn sender_restarts_retry_exact_ciphertext_without_duplicate_upload_state() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("state.sqlite3");
    let bytes: Vec<u8> = (0..CHUNK_BYTES * 2 + 9).map(|n| (n % 251) as u8).collect();
    let sealed = seal("private-shot.png", "image/png", &bytes).unwrap();
    let id = &sealed.grant().descriptor().id;
    {
        let mut db = open(&path);
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let store = Objects::new(&tx, NOW).unwrap();
        store.stage(&sealed, EXPIRY).unwrap();
        assert_eq!(store.pending_uploads(id).unwrap(), [0, 1, 2]);
        assert_eq!(store.upload_chunk(id, 0).unwrap(), sealed.chunks()[0]);
        store.acknowledge_upload(id, 0).unwrap();
        store.acknowledge_upload(id, 0).unwrap();
        tx.commit().unwrap();
    }
    let mut db = open(&path);
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let store = Objects::new(&tx, NOW + 1).unwrap();
    store.stage(&sealed, EXPIRY).unwrap();
    assert_eq!(count(&tx, "file_objects"), 1);
    assert_eq!(count(&tx, "file_chunks"), 3);
    assert_eq!(store.pending_uploads(id).unwrap(), [1, 2]);
    assert_eq!(
        store.transport_manifest(id).unwrap(),
        sealed.transport_manifest(EXPIRY).unwrap()
    );
    assert_eq!(
        store.grant(id).unwrap().encode_private().unwrap(),
        sealed.grant().encode_private().unwrap()
    );
    assert_eq!(*store.read(id).unwrap(), bytes);
    for index in [1, 2] {
        assert_eq!(
            store.upload_chunk(id, index).unwrap(),
            sealed.chunks()[index as usize]
        );
        store.acknowledge_upload(id, index).unwrap();
    }
    assert!(store.pending_uploads(id).unwrap().is_empty());
    assert_eq!(store.status(id).unwrap().chunks_uploaded, 3);
    assert!(store.acknowledge_upload(id, 3).is_err());
    store.retry_upload(id).unwrap();
    assert_eq!(store.pending_uploads(id).unwrap(), [0, 1, 2]);
    assert_eq!(store.upload_chunk(id, 0).unwrap(), sealed.chunks()[0]);
    tx.commit().unwrap();
}

#[test]
fn receiver_resumes_out_of_order_chunks_and_verifies_before_reading() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("state.sqlite3");
    let bytes = vec![71; CHUNK_BYTES * 2 + 9];
    let sealed = seal("private.bin", "application/octet-stream", &bytes).unwrap();
    let id = &sealed.grant().descriptor().id;
    {
        let mut db = open(&path);
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let store = Objects::new(&tx, NOW).unwrap();
        store.expect(sealed.grant(), EXPIRY).unwrap();
        store.accept_chunk(id, 2, &sealed.chunks()[2]).unwrap();
        store.accept_chunk(id, 2, &sealed.chunks()[2]).unwrap();
        let mut damaged = sealed.chunks()[0].clone();
        damaged[0] ^= 1;
        assert!(store.accept_chunk(id, 0, &damaged).is_err());
        assert!(store.accept_chunk(id, 0, &sealed.chunks()[1]).is_err());
        assert!(store.accept_chunk(id, 3, &sealed.chunks()[2]).is_err());
        assert_eq!(store.missing_chunks(id).unwrap(), [0, 1]);
        assert!(store.read(id).is_err());
        assert!(store.upload_chunk(id, 2).is_err());
        assert!(store.pending_uploads(id).is_err());
        assert!(store.transport_manifest(id).is_err());
        assert!(store.acknowledge_upload(id, 2).is_err());
        assert!(store.finish(id).is_err());
        tx.commit().unwrap();
    }
    {
        let mut db = open(&path);
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let store = Objects::new(&tx, NOW + 5).unwrap();
        store.expect(sealed.grant(), EXPIRY).unwrap();
        assert_eq!(
            store.status(id).unwrap().incomplete_until,
            NOW + INCOMPLETE_TTL_SECONDS
        );
        for index in [1, 0] {
            store
                .accept_chunk(id, index, &sealed.chunks()[index as usize])
                .unwrap();
        }
        assert!(store.missing_chunks(id).unwrap().is_empty());
        assert!(store.read(id).is_err());
        tx.commit().unwrap();
    }
    let mut db = open(&path);
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let store = Objects::new(&tx, NOW + 9).unwrap();
    store.finish(id).unwrap();
    assert_eq!(*store.read(id).unwrap(), bytes);
    store.finish(id).unwrap();
    assert!(store.status(id).unwrap().complete);
    assert_eq!(count(&tx, "file_chunks"), 3);
    tx.commit().unwrap();
}

#[test]
fn storage_failures_roll_back_files_and_enclosing_message_transaction() {
    let home = tempfile::tempdir().unwrap();
    let mut db = open(&home.path().join("state.sqlite3"));
    let sealed = seal("image.png", "image/png", &vec![1; CHUNK_BYTES + 1]).unwrap();
    db.execute_batch(
        "CREATE TABLE message_markers(id TEXT PRIMARY KEY);
         CREATE TRIGGER fail_chunk BEFORE INSERT ON file_chunks WHEN NEW.position=1
         BEGIN SELECT RAISE(ABORT,'injected chunk failure'); END;",
    )
    .unwrap();
    {
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute("INSERT INTO message_markers VALUES('first')", [])
            .unwrap();
        let store = Objects::new(&tx, NOW).unwrap();
        assert!(store.stage(&sealed, EXPIRY).is_err());
        // Dropping the failed transaction must discard both message and files.
    }
    for table in ["file_objects", "file_chunks", "message_markers"] {
        assert_eq!(count(&db, table), 0);
    }
    db.execute_batch(
        "DROP TRIGGER fail_chunk;
         CREATE TRIGGER fail_message BEFORE INSERT ON message_markers
         BEGIN SELECT RAISE(ABORT,'injected message failure'); END;",
    )
    .unwrap();
    {
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        Objects::new(&tx, NOW)
            .unwrap()
            .stage(&sealed, EXPIRY)
            .unwrap();
        assert!(
            tx.execute("INSERT INTO message_markers VALUES('first')", [])
                .is_err()
        );
    }
    assert_eq!(count(&db, "file_objects"), 0);
    assert_eq!(count(&db, "file_chunks"), 0);
    db.execute_batch("DROP TRIGGER fail_message;").unwrap();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    Objects::new(&tx, NOW)
        .unwrap()
        .stage(&sealed, EXPIRY)
        .unwrap();
    tx.execute("INSERT INTO message_markers VALUES('first')", [])
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(count(&db, "file_objects"), 1);
    assert_eq!(count(&db, "file_chunks"), 2);
    assert_eq!(count(&db, "message_markers"), 1);
}

#[test]
fn retries_cannot_replace_keys_manifests_deadlines_or_committed_chunks() {
    let home = tempfile::tempdir().unwrap();
    let mut db = open(&home.path().join("state.sqlite3"));
    let sealed = seal("image.png", "image/png", b"secret original bytes").unwrap();
    let id = &sealed.grant().descriptor().id;
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let store = Objects::new(&tx, NOW).unwrap();
    store.stage(&sealed, EXPIRY).unwrap();
    assert!(store.expect(sealed.grant(), EXPIRY + 1).is_err());
    for (field, value) in [
        ("name", json!("other.png")),
        ("sha256", json!("f".repeat(64))),
    ] {
        let mut changed: Value =
            serde_json::from_slice(&sealed.grant().encode_private().unwrap()).unwrap();
        changed["manifest"][field] = value;
        let changed = FileGrant::decode_private(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(store.expect(&changed, EXPIRY).is_err());
    }
    let mut changed: Value =
        serde_json::from_slice(&sealed.grant().encode_private().unwrap()).unwrap();
    changed["key"][0] = json!((changed["key"][0].as_u64().unwrap() + 1) % 256);
    let changed = FileGrant::decode_private(&serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(store.expect(&changed, EXPIRY).is_err());
    let mut damaged = sealed.chunks()[0].clone();
    damaged[0] ^= 1;
    assert!(store.accept_chunk(id, 0, &damaged).is_err());
    assert_eq!(store.upload_chunk(id, 0).unwrap(), sealed.chunks()[0]);
    // Disk corruption must not result in returning unauthenticated plaintext.
    tx.execute(
        "UPDATE file_chunks SET ciphertext=?1 WHERE object_id=?2",
        params![damaged, id],
    )
    .unwrap();
    assert!(store.read(id).is_err());
    assert!(store.upload_chunk(id, 0).is_err());
    assert!(store.stage(&sealed, EXPIRY).is_err());
    tx.commit().unwrap();
}

#[test]
fn quotas_reserve_full_objects_and_cleanup_releases_chunks_and_keys() {
    let home = tempfile::tempdir().unwrap();
    let mut db = open(&home.path().join("state.sqlite3"));
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let store = Objects::new(&tx, NOW).unwrap();
    let mut ids = Vec::new();
    for _ in 0..MAX_OBJECTS {
        let sealed = seal("empty", "application/octet-stream", b"").unwrap();
        store.stage(&sealed, EXPIRY).unwrap();
        ids.push(sealed.grant().descriptor().id.clone());
    }
    let one_more = seal("extra", "application/octet-stream", b"x").unwrap();
    assert!(store.stage(&one_more, EXPIRY).is_err());
    assert!(store.delete(&ids[0]).unwrap());
    assert!(!store.delete(&ids[0]).unwrap());
    store.stage(&one_more, EXPIRY).unwrap();
    assert_eq!(count(&tx, "file_objects"), MAX_OBJECTS);
    assert_eq!(count(&tx, "file_chunks"), MAX_OBJECTS);
    assert_eq!(
        Objects::new(&tx, EXPIRY).unwrap().reap().unwrap() as u64,
        MAX_OBJECTS
    );
    assert_eq!(count(&tx, "file_chunks"), 0);
    let store = Objects::new(&tx, NOW).unwrap();
    // Authenticate and reserve declared size before downloading. No need to
    // allocate 256 MiB of real ciphertext to exercise aggregate reservation.
    let mut total = 0;
    loop {
        let sealed = seal("large", "application/octet-stream", b"").unwrap();
        let mut wire: Value =
            serde_json::from_slice(&sealed.grant().encode_private().unwrap()).unwrap();
        wire["manifest"]["byte_length"] = json!(MAX_FILE_BYTES);
        let grant = FileGrant::decode_private(&serde_json::to_vec(&wire).unwrap()).unwrap();
        if total + grant.ciphertext_bytes() > MAX_RESERVED_BYTES {
            assert!(store.expect(&grant, EXPIRY).is_err());
            break;
        }
        store.expect(&grant, EXPIRY).unwrap();
        total += grant.ciphertext_bytes();
    }
    assert_eq!(count(&tx, "file_objects"), 7); // AEAD tags also consume quota.
    assert_eq!(count(&tx, "file_chunks"), 0);
    let expired = Objects::new(&tx, NOW + INCOMPLETE_TTL_SECONDS).unwrap();
    assert_eq!(expired.reap().unwrap(), 7);
    assert_eq!(count(&tx, "file_objects"), 0);
    expired.stage(&one_more, EXPIRY).unwrap();
    tx.commit().unwrap();
}

#[test]
fn expiry_and_abandonment_are_enforced_before_cleanup_and_cannot_be_extended() {
    let home = tempfile::tempdir().unwrap();
    let mut db = open(&home.path().join("state.sqlite3"));
    let a = seal("complete", "application/octet-stream", b"complete").unwrap();
    let b = seal(
        "partial",
        "application/octet-stream",
        &vec![1; CHUNK_BYTES + 1],
    )
    .unwrap();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let store = Objects::new(&tx, NOW).unwrap();
    for expiry in [0, NOW, NOW + MAX_RETENTION_SECONDS + 1, u64::MAX] {
        assert!(store.expect(a.grant(), expiry).is_err());
    }
    assert!(Objects::new(&tx, u64::MAX).is_err());
    store.stage(&a, EXPIRY).unwrap();
    store.expect(b.grant(), EXPIRY).unwrap();
    let a_id = &a.grant().descriptor().id;
    let b_id = &b.grant().descriptor().id;
    store.accept_chunk(b_id, 0, &b.chunks()[0]).unwrap();
    let later = Objects::new(&tx, NOW + INCOMPLETE_TTL_SECONDS).unwrap();
    assert!(later.status(b_id).is_err());
    assert!(later.grant(b_id).is_err());
    assert!(later.expect(b.grant(), EXPIRY).is_err());
    assert!(later.accept_chunk(b_id, 1, &b.chunks()[1]).is_err());
    assert!(later.read(a_id).is_ok());
    assert_eq!(later.reap().unwrap(), 1);
    assert_eq!(count(&tx, "file_chunks"), 1);
    let expired = Objects::new(&tx, EXPIRY).unwrap();
    assert!(expired.read(a_id).is_err());
    assert!(expired.upload_chunk(a_id, 0).is_err());
    assert!(expired.pending_uploads(a_id).is_err());
    assert!(expired.acknowledge_upload(a_id, 0).is_err());
    assert!(expired.retry_upload(a_id).is_err());
    assert_eq!(expired.reap().unwrap(), 1);
    assert_eq!(count(&tx, "file_objects"), 0);
    assert_eq!(count(&tx, "file_chunks"), 0);
    tx.commit().unwrap();
}

#[test]
fn schema_version_and_foreign_key_requirements_fail_closed() {
    let mut db = Connection::open_in_memory().unwrap();
    db.pragma_update(None, "foreign_keys", false).unwrap();
    assert!(file_objects::initialize(&mut db).is_err());
    db.pragma_update(None, "foreign_keys", true).unwrap();
    file_objects::initialize(&mut db).unwrap();
    db.execute("UPDATE file_object_schema SET version=2", [])
        .unwrap();
    assert!(file_objects::initialize(&mut db).is_err());
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(Objects::new(&tx, NOW).is_err());
}

#[test]
fn concurrent_writers_cannot_overbook_the_remaining_object_slot() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("state.sqlite3");
    let mut db = open(&path);
    {
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let store = Objects::new(&tx, NOW).unwrap();
        for _ in 0..MAX_OBJECTS - 1 {
            store
                .stage(
                    &seal("empty", "application/octet-stream", b"").unwrap(),
                    EXPIRY,
                )
                .unwrap();
        }
        tx.commit().unwrap();
    }
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let writers: Vec<_> = (0..2)
        .map(|_| {
            let mut db = open(&path);
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let sealed = seal("last", "application/octet-stream", b"last slot").unwrap();
                barrier.wait();
                let tx = db
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                if Objects::new(&tx, NOW)
                    .unwrap()
                    .stage(&sealed, EXPIRY)
                    .is_ok()
                {
                    tx.commit().unwrap();
                    true
                } else {
                    false
                }
            })
        })
        .collect();
    let accepted = writers
        .into_iter()
        .map(|w| usize::from(w.join().unwrap()))
        .sum::<usize>();
    assert_eq!(accepted, 1);
    assert_eq!(count(&db, "file_objects"), MAX_OBJECTS);
    assert_eq!(count(&db, "file_chunks"), MAX_OBJECTS);
}

#[test]
fn missing_saved_chunks_cannot_be_mistaken_for_a_completed_upload() {
    let home = tempfile::tempdir().unwrap();
    let mut db = open(&home.path().join("state.sqlite3"));
    let sealed = seal("empty", "application/octet-stream", b"").unwrap();
    let id = &sealed.grant().descriptor().id;
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let store = Objects::new(&tx, NOW).unwrap();
    store.stage(&sealed, EXPIRY).unwrap();
    tx.execute("DELETE FROM file_chunks WHERE object_id=?1", [id])
        .unwrap();
    assert!(store.read(id).is_err());
    assert!(store.pending_uploads(id).is_err());
    assert!(store.upload_chunk(id, 0).is_err());
    assert!(store.acknowledge_upload(id, 0).is_err());
    assert!(store.retry_upload(id).is_err());
    assert!(store.finish(id).is_err());
    store.stage(&sealed, EXPIRY).unwrap();
    assert_eq!(*store.read(id).unwrap(), b"");
    assert_eq!(store.pending_uploads(id).unwrap(), [0]);
    tx.commit().unwrap();
}
