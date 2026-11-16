use super::*;

#[test]
fn reopening_current_schema_does_not_write_or_force_another_durable_commit() {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let observer = open_database(home.path(), "mls.sqlite3").unwrap();
    let version = || {
        observer
            .pragma_query_value(None, "data_version", |r| r.get::<_, u64>(0))
            .unwrap()
    };
    let before = version();
    for _ in 0..4 {
        drop(open_database(home.path(), "mls.sqlite3").unwrap());
        assert_eq!(
            version(),
            before,
            "opening a current schema committed a write"
        );
    }
    // Schema checks still reject a lost security journal after initialization.
    observer
        .execute_batch("DROP TABLE invitation_attempts")
        .unwrap();
    assert!(open_database(home.path(), "mls.sqlite3").is_err());
}
