use super::*;

fn expire(f: &Fixture) {
    f.db()
        .execute_batch(
            "UPDATE file_objects SET expires_at=1;
        UPDATE file_handoffs SET expires_at=1,next_attempt=0;",
        )
        .unwrap();
}
fn imported(f: &mut Fixture, name: &str) -> (AgentOp, String, PathBuf) {
    let operation = f.source(0, name, b"private source");
    let value = ok(f.call(0, operation.clone()));
    let path = f
        .home
        .path()
        .join("files")
        .join(&f.agents[0])
        .join("outbox")
        .join(name);
    (
        operation,
        value["file"]["id"].as_str().unwrap().into(),
        path,
    )
}
fn clean(f: &mut Fixture, dry_run: bool) -> Value {
    f.owner(OwnerOp::FilesClean { dry_run })
}

#[test]
fn expiry_preview_and_cleanup_preserve_messages_and_retry_tombstones() {
    let mut f = Fixture::new();
    let (import, id, path) = imported(&mut f, "private-name.bin");
    let send = f.send(1, vec![id.clone()]);
    let sent = ok(f.call(0, send.clone()));
    let file = f.inbox(1).remove(0).attachments.remove(0).id;
    let exported = ok(f.call(1, AgentOp::FileExport { file_id: file }));
    let export = PathBuf::from(exported["path"].as_str().unwrap());
    let status = f.owner(OwnerOp::FilesStatus);
    assert_eq!(status["objects"]["count"], 2);
    assert_eq!(status["handoffs"]["tracked_copies"], 2);
    assert!(!status.to_string().contains("private-name"));
    assert!(!status.to_string().contains("private source"));
    assert!(matches!(
        f.store.handle(Request::Owner {
            credential: f.keys[0].clone(),
            action: OwnerOp::FilesStatus
        }),
        Response::Error(_)
    ));
    assert!(
        serde_json::from_value::<AgentOp>(json!({"op":"files_clean","dry_run":false})).is_err()
    );
    expire(&f);
    let before = f.owner(OwnerOp::FilesStatus);
    let preview = clean(&mut f, true);
    assert_eq!(preview["handoffs_removed"], 2);
    assert_eq!(preview["expired_objects"], 2);
    assert_eq!(f.owner(OwnerOp::FilesStatus), before);
    assert!(path.exists() && export.exists());
    let done = clean(&mut f, false);
    assert_eq!(done["handoffs_removed"], 2);
    assert!(!path.exists() && !export.exists());
    let status = f.owner(OwnerOp::FilesStatus);
    assert_eq!(status["objects"]["count"], 0);
    assert_eq!(status["handoffs"]["tracked_copies"], 0);
    assert_eq!(status["retained_import_retries"], 1);
    assert_eq!(status["retained_messages"], 1);
    f.store = Store::open(f.home.path()).unwrap();
    // An identical message retry still returns its original ID after file expiry.
    assert_eq!(ok(f.call(0, send))["message_id"], sent["message_id"]);
    fs::write(&path, b"private source").unwrap();
    assert_eq!(error(f.call(0, import)), "file unavailable");
    assert_eq!(f.owner(OwnerOp::FilesStatus)["objects"]["count"], 0);
}

#[test]
fn changed_replaced_linked_and_untracked_files_survive_cleanup() {
    let mut f = Fixture::new();
    let (_, _, changed) = imported(&mut f, "changed");
    let (_, _, replaced) = imported(&mut f, "replaced");
    let (_, _, link) = imported(&mut f, "link");
    let (_, _, hard) = imported(&mut f, "hard");
    let (_, _, unchanged) = imported(&mut f, "unchanged");
    let outside = f.home.path().join("outside");
    fs::write(&outside, b"keep outside").unwrap();
    fs::write(&changed, b"new user content").unwrap();
    // Preserve a replaced inode even if its bytes are the original bytes.
    fs::rename(&replaced, replaced.with_extension("saved")).unwrap();
    fs::write(&replaced, b"private source").unwrap();
    fs::remove_file(&link).unwrap();
    symlink(&outside, &link).unwrap();
    fs::hard_link(&hard, hard.with_extension("saved")).unwrap();
    let untracked = changed.with_file_name("not-imported");
    fs::write(&untracked, b"not tracked").unwrap();
    expire(&f);
    let result = clean(&mut f, false);
    assert_eq!(
        result["handoffs_removed"],
        1,
        "{result}; {}",
        f.owner(OwnerOp::FilesStatus)
    );
    assert_eq!(result["handoffs_preserved"], 2);
    assert_eq!(result["handoffs_blocked"], 2);
    assert!(!unchanged.exists());
    assert_eq!(fs::read(changed).unwrap(), b"new user content");
    assert_eq!(fs::read(replaced).unwrap(), b"private source");
    assert_eq!(fs::read(link).unwrap(), b"keep outside");
    assert_eq!(fs::read(hard).unwrap(), b"private source");
    assert_eq!(fs::read(outside).unwrap(), b"keep outside");
    assert!(untracked.exists());
    let status = f.owner(OwnerOp::FilesStatus);
    assert_eq!(status["attention"].as_array().unwrap().len(), 4);
    assert_eq!(clean(&mut f, false)["handoffs_checked"], 0);
}

#[test]
fn interrupted_cleanup_recovers_without_touching_a_new_original_path() {
    let mut f = Fixture::new();
    let (_, _, path) = imported(&mut f, "original");
    let id: String = f
        .db()
        .query_row("SELECT id FROM file_handoffs", [], |r| r.get(0))
        .unwrap();
    let recovery = path.with_file_name(format!(".gent-clean-{id}.tmp"));
    expire(&f);
    fs::rename(&path, &recovery).unwrap();
    fs::write(&path, b"new host file").unwrap();
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(clean(&mut f, true)["handoffs_removed"], 1);
    assert!(recovery.exists());
    f.store.maintain().unwrap();
    assert!(!recovery.exists());
    assert_eq!(fs::read(&path).unwrap(), b"new host file");
    assert_eq!(
        f.owner(OwnerOp::FilesStatus)["handoffs"]["tracked_copies"],
        0
    );

    let (_, _, path) = imported(&mut f, "modified-recovery");
    let id: String = f
        .db()
        .query_row("SELECT id FROM file_handoffs", [], |r| r.get(0))
        .unwrap();
    let recovery = path.with_file_name(format!(".gent-clean-{id}.tmp"));
    expire(&f);
    fs::rename(&path, &recovery).unwrap();
    fs::write(&recovery, b"changed while daemon stopped").unwrap();
    fs::write(&path, b"replacement").unwrap();
    assert_eq!(clean(&mut f, false)["handoffs_preserved"], 1);
    assert_eq!(
        fs::read(&recovery).unwrap(),
        b"changed while daemon stopped"
    );
    assert_eq!(fs::read(&path).unwrap(), b"replacement");
    assert_eq!(
        f.owner(OwnerOp::FilesStatus)["attention"][0]["recovery_path"],
        json!(recovery)
    );
    fs::remove_file(&path).unwrap();
    f.db()
        .execute("UPDATE file_handoffs SET next_attempt=0", [])
        .unwrap();
    assert_eq!(clean(&mut f, false)["handoffs_preserved"], 1);
    assert!(!recovery.exists());
    assert_eq!(fs::read(&path).unwrap(), b"changed while daemon stopped");

    let mut f = Fixture::new();
    let (_, _, path) = imported(&mut f, "collision");
    let id: String = f
        .db()
        .query_row("SELECT id FROM file_handoffs", [], |r| r.get(0))
        .unwrap();
    let recovery = path.with_file_name(format!(".gent-clean-{id}.tmp"));
    fs::rename(&path, path.with_extension("saved")).unwrap();
    fs::write(&recovery, b"unrelated file at recovery name").unwrap();
    expire(&f);
    assert_eq!(clean(&mut f, false)["handoffs_preserved"], 1);
    assert!(!path.exists());
    assert_eq!(
        fs::read(&recovery).unwrap(),
        b"unrelated file at recovery name"
    );
}

#[test]
fn filesystem_deletion_recovers_after_database_rollback() {
    let mut f = Fixture::new();
    let (_, _, path) = imported(&mut f, "rollback");
    expire(&f);
    f.db()
        .execute_batch(
            "CREATE TRIGGER fail_handoff_delete BEFORE DELETE ON file_handoffs
        BEGIN SELECT RAISE(ABORT,'injected retention failure'); END;",
        )
        .unwrap();
    let credential = config::read_private(&f.home.path().join("owner.key")).unwrap();
    assert!(
        error(f.store.handle(Request::Owner {
            credential,
            action: OwnerOp::FilesClean { dry_run: false }
        }))
        .contains("injected retention failure")
    );
    assert!(!path.exists());
    assert_eq!(f.owner(OwnerOp::FilesStatus)["objects"]["count"], 1);
    f.db()
        .execute_batch("DROP TRIGGER fail_handoff_delete")
        .unwrap();
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(clean(&mut f, false)["handoffs_missing"], 1);
    assert_eq!(f.owner(OwnerOp::FilesStatus)["objects"]["count"], 0);
}

#[test]
fn reimport_extends_handoff_deadline_and_cleanup_is_bounded() {
    let mut f = Fixture::new();
    let (mut import, _, path) = imported(&mut f, "reused");
    f.db()
        .execute("UPDATE file_handoffs SET expires_at=1", [])
        .unwrap();
    if let AgentOp::FileImport { request_id, .. } = &mut import {
        *request_id = Uuid::now_v7().to_string();
    }
    ok(f.call(0, import));
    assert_eq!(
        f.owner(OwnerOp::FilesStatus)["handoffs"]["tracked_copies"],
        1
    );
    assert_eq!(clean(&mut f, false)["handoffs_checked"], 0);
    assert!(path.exists());
    for i in 0..10 {
        imported(&mut f, &format!("batch-{i}"));
    }
    expire(&f);
    assert_eq!(clean(&mut f, false)["handoffs_checked"], 8);
    assert_eq!(clean(&mut f, false)["handoffs_checked"], 3);
    assert_eq!(clean(&mut f, false)["handoffs_checked"], 0);
}

#[test]
fn directory_substitution_and_uncommitted_exports_remain_untouched() {
    let mut f = Fixture::new();
    let (_, id, path) = imported(&mut f, "source");
    f.db()
        .execute_batch(
            "CREATE TRIGGER fail_handoff_insert BEFORE INSERT ON file_handoffs
        BEGIN SELECT RAISE(ABORT,'injected handoff failure'); END;",
        )
        .unwrap();
    assert!(
        error(f.call(
            0,
            AgentOp::FileExport {
                file_id: id.clone()
            }
        ))
        .contains("injected handoff failure")
    );
    let export = f
        .home
        .path()
        .join("files")
        .join(&f.agents[0])
        .join("inbox")
        .join(&id)
        .join("source");
    assert!(export.exists());
    f.db()
        .execute_batch("DROP TRIGGER fail_handoff_insert")
        .unwrap();
    let outbox = path.parent().unwrap();
    let saved = outbox.with_file_name("saved-outbox");
    fs::rename(outbox, &saved).unwrap();
    symlink(&saved, outbox).unwrap();
    expire(&f);
    assert_eq!(clean(&mut f, false)["handoffs_blocked"], 1);
    assert_eq!(fs::read(saved.join("source")).unwrap(), b"private source");
    // Files created before ledger commit (or by an older version) are untracked.
    assert_eq!(fs::read(export).unwrap(), b"private source");
}
