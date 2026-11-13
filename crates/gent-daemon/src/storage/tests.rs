use super::*;
use rusqlite::{ErrorCode, TransactionBehavior};
use std::{fs, path::Path, process::Command, time::Duration};

fn number(db: &Connection, sql: &str) -> u64 {
    db.query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn full_transaction_rolls_back_and_freed_pages_are_reusable_after_reopen() {
    for page_size in [1024, 4096] {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("test.sqlite3");
        let mut db = Connection::open(&path).unwrap();
        db.pragma_update(None, "page_size", page_size).unwrap();
        configure_limit(&db, 256 * 1024).unwrap();
        db.execute_batch("CREATE TABLE data(id INTEGER PRIMARY KEY, body BLOB); INSERT INTO data VALUES(1,zeroblob(65536));").unwrap();
        let before = number(&db, "PRAGMA page_count");
        let tx = db.transaction().unwrap();
        tx.execute("UPDATE data SET body=X'01' WHERE id=1", [])
            .unwrap();
        let error = tx
            .execute("INSERT INTO data VALUES(2,zeroblob(524288))", [])
            .unwrap_err();
        assert_eq!(error.sqlite_error_code(), Some(ErrorCode::DiskFull));
        drop(tx);
        assert_eq!(
            number(&db, "SELECT length(body) FROM data WHERE id=1"),
            65536
        );
        assert_eq!(number(&db, "SELECT count(*) FROM data"), 1);
        assert_eq!(number(&db, "PRAGMA page_count"), before);
        assert!(fs::metadata(&path).unwrap().len() <= 256 * 1024);
        drop(db);
        let db = Connection::open(&path).unwrap();
        configure_limit(&db, 256 * 1024).unwrap();
        assert_eq!(number(&db, "PRAGMA max_page_count") * page_size, 256 * 1024);
        db.execute("DELETE FROM data", []).unwrap();
        assert!(number(&db, "PRAGMA freelist_count") > 0);
        db.execute("INSERT INTO data VALUES(3,zeroblob(65536))", [])
            .unwrap();
        assert_eq!(number(&db, "PRAGMA page_count"), before);
        let integrity: String = db
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
    }
}

#[test]
fn oversized_legacy_database_can_reuse_pages_but_cannot_grow() {
    let home = tempfile::tempdir().unwrap();
    let mut db = Connection::open(home.path().join("test.sqlite3")).unwrap();
    db.execute_batch("CREATE TABLE data(body BLOB); INSERT INTO data VALUES(zeroblob(524288));")
        .unwrap();
    let pages = number(&db, "PRAGMA page_count");
    configure_limit(&db, 64 * 1024).unwrap();
    assert_eq!(number(&db, "PRAGMA max_page_count"), pages);
    let tx = db.transaction().unwrap();
    assert_eq!(
        tx.execute("INSERT INTO data VALUES(zeroblob(524288))", [])
            .unwrap_err()
            .sqlite_error_code(),
        Some(ErrorCode::DiskFull)
    );
    drop(tx);
    db.execute_batch("DELETE FROM data; INSERT INTO data VALUES(zeroblob(524288));")
        .unwrap();
    assert_eq!(number(&db, "SELECT length(body) FROM data"), 524288);
    assert_eq!(number(&db, "PRAGMA page_count"), pages);
}

#[test]
fn pinned_reader_blocks_commits_without_accumulating_journal_history() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("test.sqlite3");
    let mut writer = Connection::open(&path).unwrap();
    configure_limit(&writer, 256 * 1024).unwrap();
    writer.busy_timeout(Duration::ZERO).unwrap();
    writer
        .execute_batch("CREATE TABLE data(value INTEGER); INSERT INTO data VALUES(1);")
        .unwrap();
    let reader = Connection::open(&path).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    assert_eq!(number(&reader, "SELECT value FROM data"), 1);
    for _ in 0..8 {
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute("UPDATE data SET value=2", []).unwrap();
        assert_eq!(
            tx.commit().unwrap_err().sqlite_error_code(),
            Some(ErrorCode::DatabaseBusy)
        );
        assert!(!home.path().join("test.sqlite3-wal").exists());
        assert!(!home.path().join("test.sqlite3-journal").exists());
        assert_eq!(number(&writer, "SELECT value FROM data"), 1);
    }
    reader.execute_batch("ROLLBACK").unwrap();
    writer.execute("UPDATE data SET value=2", []).unwrap();
    assert_eq!(number(&reader, "SELECT value FROM data"), 2);
}

#[test]
fn repeated_cache_spills_keep_only_current_transaction_before_images() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("test.sqlite3");
    let mut db = Connection::open(&path).unwrap();
    configure_limit(&db, 2 * 1024 * 1024).unwrap();
    db.execute_batch(
        "PRAGMA cache_size=4;
        CREATE TABLE data(id INTEGER PRIMARY KEY, generation INTEGER, body BLOB);
        WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<128)
        INSERT INTO data SELECT i,0,zeroblob(4096) FROM n;",
    )
    .unwrap();
    let tx = db.transaction().unwrap();
    let journal = home.path().join("test.sqlite3-journal");
    tx.execute("UPDATE data SET generation=1,body=zeroblob(4096)", [])
        .unwrap();
    let first_size = fs::metadata(&journal).unwrap().len();
    assert!(first_size > 0);
    let mut sizes = vec![first_size];
    for _ in 0..8 {
        tx.execute("UPDATE data SET body=zeroblob(4096)", [])
            .unwrap();
        sizes.push(fs::metadata(&journal).unwrap().len());
    }
    assert_eq!(sizes[4], sizes[8], "journal sizes: {sizes:?}");
    tx.rollback().unwrap();
    assert_eq!(number(&db, "SELECT sum(generation) FROM data"), 0);
    assert!(!journal.exists());
}

#[test]
fn live_wal_reader_prevents_conversion_without_losing_commits() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("test.sqlite3");
    let writer = Connection::open(&path).unwrap();
    writer
        .execute_batch(
            "PRAGMA journal_mode=WAL; CREATE TABLE data(value); INSERT INTO data VALUES(1);",
        )
        .unwrap();
    let reader = Connection::open(&path).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    assert_eq!(number(&reader, "SELECT value FROM data"), 1);
    writer.execute("UPDATE data SET value=2", []).unwrap();
    let candidate = Connection::open(&path).unwrap();
    candidate.busy_timeout(Duration::ZERO).unwrap();
    assert!(configure(&candidate).is_err());
    assert_eq!(number(&reader, "SELECT value FROM data"), 1);
    assert_eq!(number(&writer, "SELECT value FROM data"), 2);
    drop(reader);
    drop(writer);
    configure(&candidate).unwrap();
    assert_eq!(number(&candidate, "SELECT value FROM data"), 2);
    assert_eq!(usage(&candidate).unwrap()["journal_mode"], "delete");
    assert!(!home.path().join("test.sqlite3-wal").exists());
}

#[test]
fn abrupt_exit_recovers_committed_wal_and_hot_rollback_journal() {
    // The child exits without destructors so these are real recovery files.
    const CHILD: &str = "GENT_STORAGE_CRASH_TEST_PATH";
    if let Some(path) = std::env::var_os(CHILD) {
        let db = Connection::open(Path::new(&path)).unwrap();
        if std::env::var_os("GENT_STORAGE_CRASH_TEST_WAL").is_some() {
            db.execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
                CREATE TABLE data(body BLOB, generation INTEGER);
                INSERT INTO data VALUES(zeroblob(524288),1);
                BEGIN IMMEDIATE; UPDATE data SET generation=2;",
            )
            .unwrap();
        } else {
            configure(&db).unwrap();
            db.execute_batch(
                "PRAGMA cache_size=4; BEGIN IMMEDIATE;
                UPDATE data SET body=randomblob(524288),generation=2;",
            )
            .unwrap();
        }
        std::process::exit(0);
    }
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("test.sqlite3");
    for wal in [true, false] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "storage::tests::abrupt_exit_recovers_committed_wal_and_hot_rollback_journal",
                "--nocapture",
            ])
            .env(CHILD, &path);
        if wal {
            command.env("GENT_STORAGE_CRASH_TEST_WAL", "1");
        }
        assert!(command.output().unwrap().status.success());
        let auxiliary = home.path().join(if wal {
            "test.sqlite3-wal"
        } else {
            "test.sqlite3-journal"
        });
        assert!(fs::metadata(&auxiliary).unwrap().len() > 0);
        let db = Connection::open(&path).unwrap();
        configure(&db).unwrap();
        assert_eq!(number(&db, "SELECT generation FROM data"), 1);
        assert_eq!(number(&db, "SELECT body=zeroblob(524288) FROM data"), 1);
        assert!(!auxiliary.exists());
        assert_eq!(usage(&db).unwrap()["max_bytes"], MAX_DATABASE_BYTES);
    }
}
