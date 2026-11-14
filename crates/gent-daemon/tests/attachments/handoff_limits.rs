use super::*;

fn imported(f: &mut Fixture) -> (AgentOp, String) {
    let request = f.source(0, "source.bin", b"private source bytes");
    let value = ok(f.call(0, request.clone()));
    (request, value["file"]["id"].as_str().unwrap().to_owned())
}

fn export(f: &mut Fixture, id: &str) -> Response {
    f.call(0, AgentOp::FileExport { file_id: id.into() })
}

fn paths(f: &Fixture, id: &str) -> (PathBuf, PathBuf) {
    let reservation: String = f
        .db()
        .query_row(
            "SELECT id FROM file_exports WHERE object_id=?1",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    let dir = f
        .home
        .path()
        .join("files")
        .join(&f.agents[0])
        .join("inbox")
        .join(id);
    (
        dir.join("source.bin"),
        dir.join(format!(".gent-export-{reservation}.tmp")),
    )
}

fn fail_publication(f: &Fixture) {
    f.db()
        .execute_batch(
            "CREATE TRIGGER fail_export BEFORE INSERT ON file_handoffs WHEN NEW.slot<>''
        BEGIN SELECT RAISE(ABORT,'injected publication failure'); END;",
        )
        .unwrap();
}

fn expire(f: &Fixture) {
    f.db()
        .execute_batch("UPDATE file_exports SET expires_at=1,next_attempt=0;")
        .unwrap();
}

#[test]
fn quotas_reserve_before_writes_and_exact_handoff_retries_work_at_capacity() {
    let mut f = Fixture::new();
    let (import, id) = imported(&mut f);
    let file = ok(export(&mut f, &id));
    let (count, bytes) = (
        f.owner(OwnerOp::FilesStatus)["handoffs"]["max_copies"]
            .as_u64()
            .unwrap(),
        f.owner(OwnerOp::FilesStatus)["handoffs"]["max_bytes"]
            .as_u64()
            .unwrap(),
    );
    assert_eq!(count, 4096);
    assert_eq!(bytes, 512 * 1024 * 1024);
    // Fill the byte quota with a synthetic reservation, without allocating it.
    let used = f.owner(OwnerOp::FilesStatus)["handoffs"]["reserved_bytes"]
        .as_u64()
        .unwrap();
    f.db().execute("INSERT INTO file_exports(id,agent,object_id,name,digest,bytes,expires_at) VALUES('fixture',?1,'fixture','fixture','',?2,0)",
        rusqlite::params![f.agents[0],bytes-used]).unwrap();
    assert_eq!(ok(f.call(0, import.clone()))["file"]["id"], id);
    assert_eq!(ok(export(&mut f, &id))["path"], file["path"]);
    let request = f.source(0, "second.bin", b"another file");
    assert!(error(f.call(0, request.clone())).contains("plaintext handoff quota"));
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM file_imports", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
    // Deleting a successfully exported copy does not grant new capacity.
    fs::remove_file(file["path"].as_str().unwrap()).unwrap();
    assert!(error(export(&mut f, &id)).contains("plaintext handoff quota"));
    assert!(!PathBuf::from(file["path"].as_str().unwrap()).exists());
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM file_exports", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
    f.db()
        .execute("DELETE FROM file_exports WHERE id='fixture'", [])
        .unwrap();
    ok(f.call(0, request));
    ok(export(&mut f, &id));
    // A separate count limit also bounds zero-byte handoffs.
    f.db()
        .execute(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<4096)
        INSERT INTO file_exports(id,agent,object_id,name,digest,bytes,expires_at)
        SELECT 'fixture-'||i,?1,'fixture-'||i,'fixture','',0,0 FROM n",
            [&f.agents[0]],
        )
        .unwrap();
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(ok(export(&mut f, &id))["file"]["id"], id);
    let empty = f.source(0, "empty", b"");
    assert!(error(f.call(0, empty)).contains("plaintext handoff quota"));
    assert_eq!(ok(f.call(0, import))["file"]["id"], id);
}

#[test]
fn reservation_failure_creates_no_plaintext_and_pending_capacity_can_finish_when_full() {
    let mut f = Fixture::new();
    let (_, id) = imported(&mut f);
    f.db()
        .execute_batch(
            "CREATE TRIGGER fail_reserve BEFORE INSERT ON file_exports
        BEGIN SELECT RAISE(ABORT,'injected reservation failure'); END;",
        )
        .unwrap();
    assert!(error(export(&mut f, &id)).contains("reservation failure"));
    let dir = f
        .home
        .path()
        .join("files")
        .join(&f.agents[0])
        .join("inbox")
        .join(&id);
    assert!(!dir.exists());
    f.db().execute_batch("DROP TRIGGER fail_reserve").unwrap();
    fail_publication(&f);
    assert!(error(export(&mut f, &id)).contains("publication failure"));
    let (path, tmp) = paths(&f, &id);
    assert!(path.exists() && !tmp.exists());
    let usage = f.owner(OwnerOp::FilesStatus);
    assert_eq!(usage["exports"]["pending"], 1);
    assert_eq!(usage["handoffs"]["reserved_copies"], 2);
    let remaining = usage["handoffs"]["max_bytes"].as_u64().unwrap()
        - usage["handoffs"]["reserved_bytes"].as_u64().unwrap()
        + 1;
    f.db().execute("INSERT INTO file_exports(id,agent,object_id,name,digest,bytes,expires_at) VALUES('fixture',?1,'fixture','fixture','',?2,0)",rusqlite::params![f.agents[0],remaining]).unwrap();
    f.db().execute_batch("DROP TRIGGER fail_export").unwrap();
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(ok(export(&mut f, &id))["path"], json!(path));
    assert_eq!(
        f.owner(OwnerOp::FilesStatus)["handoffs"]["reserved_bytes"],
        512 * 1024 * 1024u64 + 1
    );
    assert_eq!(
        f.db()
            .query_row(
                "SELECT COUNT(*) FROM file_exports WHERE object_id=?1",
                [&id],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn unstamped_export_retries_use_one_temporary_file_and_preserve_changed_bytes() {
    let mut f = Fixture::new();
    let (_, id) = imported(&mut f);
    f.db()
        .execute_batch(
            "CREATE TRIGGER fail_stage BEFORE UPDATE OF stamp ON file_exports
        BEGIN SELECT RAISE(ABORT,'injected stage failure'); END;",
        )
        .unwrap();
    assert!(error(export(&mut f, &id)).contains("stage failure"));
    let (path, tmp) = paths(&f, &id);
    assert!(!path.exists());
    assert_eq!(fs::read(&tmp).unwrap(), b"private source bytes");
    let reservation = f.owner(OwnerOp::FilesStatus)["exports"]["attention"][0].clone();
    assert_eq!(reservation["ready"], false);
    fs::write(&tmp, b"user modified temporary").unwrap();
    f.db().execute_batch("DROP TRIGGER fail_stage").unwrap();
    f.store = Store::open(f.home.path()).unwrap();
    assert!(error(export(&mut f, &id)).contains("temporary file changed"));
    assert_eq!(fs::read(&tmp).unwrap(), b"user modified temporary");
    // Model an interrupted first write. Only a matching prefix may resume.
    fs::write(&tmp, b"private").unwrap();
    assert_eq!(ok(export(&mut f, &id))["path"], json!(path));
    assert_eq!(fs::read(path).unwrap(), b"private source bytes");
    assert!(!tmp.exists());
    assert_eq!(f.owner(OwnerOp::FilesStatus)["exports"]["pending"], 0);
}

#[test]
fn cleanup_recovers_failed_publication_commit_and_never_removes_changed_or_unverified_files() {
    let mut f = Fixture::new();
    let (_, id) = imported(&mut f);
    fail_publication(&f);
    assert!(error(export(&mut f, &id)).contains("publication failure"));
    let (path, _) = paths(&f, &id);
    expire(&f);
    assert_eq!(
        f.owner(OwnerOp::FilesClean { dry_run: true })["exports"]["removed"],
        1
    );
    assert!(path.exists());
    f.db()
        .execute_batch(
            "CREATE TRIGGER fail_cleanup BEFORE DELETE ON file_exports
        BEGIN SELECT RAISE(ABORT,'injected cleanup failure'); END;",
        )
        .unwrap();
    let key = config::read_private(&f.home.path().join("owner.key")).unwrap();
    assert!(
        error(f.store.handle(Request::Owner {
            credential: key,
            action: OwnerOp::FilesClean { dry_run: false }
        }))
        .contains("cleanup failure")
    );
    assert!(!path.exists());
    f.db()
        .execute_batch("DROP TRIGGER fail_cleanup; DROP TRIGGER fail_export;")
        .unwrap();
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(
        f.owner(OwnerOp::FilesClean { dry_run: false })["exports"]["missing"],
        1
    );
    assert_eq!(f.owner(OwnerOp::FilesStatus)["exports"]["pending"], 0);

    fail_publication(&f);
    assert!(error(export(&mut f, &id)).contains("publication failure"));
    let (path, _) = paths(&f, &id);
    fs::write(&path, b"user revision").unwrap();
    expire(&f);
    assert_eq!(
        f.owner(OwnerOp::FilesClean { dry_run: false })["exports"]["preserved"],
        1
    );
    assert_eq!(fs::read(path).unwrap(), b"user revision");
    assert_eq!(f.owner(OwnerOp::FilesStatus)["exports"]["pending"], 1);

    let mut f = Fixture::new();
    let (_, id) = imported(&mut f);
    f.db()
        .execute_batch(
            "CREATE TRIGGER fail_stage BEFORE UPDATE OF stamp ON file_exports
        BEGIN SELECT RAISE(ABORT,'injected stage failure'); END;",
        )
        .unwrap();
    assert!(error(export(&mut f, &id)).contains("stage failure"));
    let (_, tmp) = paths(&f, &id);
    expire(&f);
    assert_eq!(
        f.owner(OwnerOp::FilesClean { dry_run: false })["exports"]["preserved"],
        1
    );
    assert!(tmp.exists());
    fs::remove_file(tmp).unwrap();
    expire(&f);
    assert_eq!(
        f.owner(OwnerOp::FilesClean { dry_run: false })["exports"]["missing"],
        1
    );
}

#[test]
fn every_export_phase_rechecks_agent_revocation() {
    for stage in [false, true] {
        let mut f = Fixture::new();
        let (_, id) = imported(&mut f);
        let event = if stage { "UPDATE OF stamp" } else { "INSERT" };
        f.db()
            .execute_batch(&format!(
                "CREATE TRIGGER revoke_export AFTER {event} ON file_exports
            BEGIN UPDATE agents SET revoked=1 WHERE id=NEW.agent; END;"
            ))
            .unwrap();
        assert!(error(export(&mut f, &id)).contains("registration revoked"));
        let (path, tmp) = paths(&f, &id);
        assert!(!path.exists());
        assert_eq!(tmp.exists(), stage);
        assert_eq!(f.owner(OwnerOp::FilesStatus)["exports"]["pending"], 1);
    }
}

#[test]
fn reservation_metadata_cannot_change_the_reserved_file() {
    let mut f = Fixture::new();
    let (_, id) = imported(&mut f);
    fail_publication(&f);
    assert!(error(export(&mut f, &id)).contains("publication failure"));
    let (path, _) = paths(&f, &id);
    f.db()
        .execute_batch("DROP TRIGGER fail_export; UPDATE file_exports SET bytes=bytes-1;")
        .unwrap();
    assert!(error(export(&mut f, &id)).contains("reservation conflicts"));
    assert_eq!(fs::read(&path).unwrap(), b"private source bytes");
    f.db()
        .execute_batch("UPDATE file_exports SET bytes=bytes+1;")
        .unwrap();
    ok(export(&mut f, &id));
}

#[test]
fn export_quarantine_recovers_without_overwriting_replacements_or_restoring_unknown_names() {
    for changed in [false, true] {
        let mut f = Fixture::new();
        let (_, id) = imported(&mut f);
        fail_publication(&f);
        assert!(error(export(&mut f, &id)).contains("publication failure"));
        let (path, _) = paths(&f, &id);
        let reservation: String = f
            .db()
            .query_row("SELECT id FROM file_exports", [], |r| r.get(0))
            .unwrap();
        let quarantine = path.with_file_name(format!(".gent-clean-{reservation}.tmp"));
        fs::rename(&path, &quarantine).unwrap();
        fs::write(&path, b"replacement").unwrap();
        if changed {
            fs::write(&quarantine, b"edited in quarantine").unwrap();
        }
        expire(&f);
        f.store = Store::open(f.home.path()).unwrap();
        let cleaned = f.owner(OwnerOp::FilesClean { dry_run: false });
        assert_eq!(
            cleaned["exports"][if changed { "preserved" } else { "removed" }],
            1
        );
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        assert_eq!(quarantine.exists(), changed);
        if changed {
            assert_eq!(fs::read(quarantine).unwrap(), b"edited in quarantine");
        }
    }
}

#[test]
fn export_cleanup_is_bounded_and_version_twelve_handoffs_survive_upgrade() {
    let mut f = Fixture::new();
    let (request, id) = imported(&mut f);
    let before = f.owner(OwnerOp::FilesStatus)["handoffs"]["recorded_bytes"].clone();
    f.db()
        .execute_batch("DROP TABLE file_exports; PRAGMA user_version=12;")
        .unwrap();
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(
        f.owner(OwnerOp::FilesStatus)["handoffs"]["recorded_bytes"],
        before
    );
    assert_eq!(ok(f.call(0, request))["file"]["id"], id);
    assert_eq!(
        f.db()
            .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap(),
        21
    );
    fail_publication(&f);
    for _ in 0..10 {
        let (_, id) = imported(&mut f);
        assert!(error(export(&mut f, &id)).contains("publication failure"));
    }
    expire(&f);
    assert_eq!(
        f.owner(OwnerOp::FilesClean { dry_run: true })["exports"]["removed"],
        8
    );
    assert_eq!(f.owner(OwnerOp::FilesStatus)["exports"]["pending"], 10);
    assert_eq!(
        f.owner(OwnerOp::FilesClean { dry_run: false })["exports"]["removed"],
        8
    );
    assert_eq!(
        f.owner(OwnerOp::FilesClean { dry_run: false })["exports"]["removed"],
        2
    );
    assert_eq!(f.owner(OwnerOp::FilesStatus)["exports"]["pending"], 0);
}
