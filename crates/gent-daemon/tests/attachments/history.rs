use super::*;
use gent_daemon::store::now;

fn next(f: &mut Fixture, agent: usize) -> String {
    ok(f.call(agent, AgentOp::RequestIds { count: 1 }))["request_ids"][0]
        .as_str()
        .unwrap()
        .into()
}
fn advance(f: &mut Fixture, timestamp: i64) {
    f.db()
        .execute("UPDATE request_clock SET floor=?1", [timestamp])
        .unwrap();
    f.owner(OwnerOp::Renew);
}
fn send(f: &mut Fixture, text: &str) -> AgentOp {
    AgentOp::Send {
        recipient: f.agents[1].clone(),
        request_id: next(f, 0),
        text: text.into(),
        files: vec![],
        file_ids: vec![],
    }
}
fn clean(f: &mut Fixture, dry_run: bool) -> Value {
    f.owner(OwnerOp::HistoryClean { dry_run })
}

#[test]
fn expiry_removes_whole_exchanges_and_retries_cannot_recreate_them_after_restart() {
    let mut f = Fixture::new();
    let start = now();
    let import = f.source(0, "source", b"private original");
    let imported = ok(f.call(0, import.clone()));
    let mut first = send(&mut f, "private old message");
    if let AgentOp::Send { file_ids, .. } = &mut first {
        file_ids.push(imported["file"]["id"].as_str().unwrap().into());
    }
    let sent = ok(f.call(0, first.clone()));
    let reply = AgentOp::Reply {
        message_id: sent["message_id"].as_str().unwrap().into(),
        request_id: next(&mut f, 1),
        text: "private reply".into(),
        files: vec![],
        file_ids: vec![],
    };
    ok(f.call(1, reply.clone()));
    advance(&mut f, start + 9 * 86400);
    let live = send(&mut f, "live message");
    let live_id = ok(f.call(0, live.clone()))["message_id"].clone();
    f.owner(OwnerOp::FilesClean { dry_run: false });
    let preview = clean(&mut f, true);
    assert_eq!(preview["messages_removed"], 2);
    assert_eq!(preview["import_retries_removed"], 1);
    assert_eq!(f.owner(OwnerOp::HistoryStatus)["messages"], 3);
    assert_eq!(clean(&mut f, false)["messages_removed"], 2);
    assert_eq!(f.owner(OwnerOp::HistoryStatus)["messages"], 1);
    assert_eq!(f.owner(OwnerOp::HistoryStatus)["import_retry_records"], 0);
    assert!(error(f.call(0, first.clone())).contains("request_id expired"));
    assert!(matches!(f.call(1, reply), Response::Error(_)));
    let folders = ok(f.call(0, AgentOp::FilePaths));
    fs::write(
        PathBuf::from(folders["import_directory"].as_str().unwrap()).join("source"),
        b"private original",
    )
    .unwrap();
    assert!(error(f.call(0, import)).contains("request_id expired"));
    assert_eq!(ok(f.call(0, live.clone()))["message_id"], live_id);
    f.store = Store::open(f.home.path()).unwrap();
    assert!(error(f.call(0, first)).contains("request_id expired"));
    assert_eq!(ok(f.call(0, live))["message_id"], live_id);
    assert!(
        f.db()
            .prepare("PRAGMA foreign_key_check")
            .unwrap()
            .query([])
            .unwrap()
            .next()
            .unwrap()
            .is_none()
    );
    assert_eq!(clean(&mut f, false)["messages_removed"], 0);
}

#[test]
fn pruning_rolls_back_atomically_and_preserves_fragment_cancellation_progress() {
    let mut f = Fixture::new();
    let action = send(&mut f, "private queued payload");
    let id = ok(f.call(0, action))["message_id"]
        .as_str()
        .unwrap()
        .to_string();
    let event = Uuid::new_v4().to_string();
    f.db()
        .execute(
            "INSERT INTO network_events(id,peer,body,offset,subject) VALUES(?1,?2,?3,262144,?4)",
            rusqlite::params![
                event,
                Uuid::new_v4().to_string(),
                b"private queued payload",
                id
            ],
        )
        .unwrap();
    advance(&mut f, now() + 9 * 86400);
    f.db().execute_batch("CREATE TRIGGER fail_retire BEFORE DELETE ON exchanges BEGIN SELECT RAISE(ABORT,'injected history failure'); END;").unwrap();
    let credential = config::read_private(&f.home.path().join("owner.key")).unwrap();
    assert!(
        error(f.store.handle(Request::Owner {
            credential,
            action: OwnerOp::HistoryClean { dry_run: false }
        }))
        .contains("injected history failure")
    );
    assert_eq!(f.owner(OwnerOp::HistoryStatus)["messages"], 1);
    let body: Vec<u8> = f
        .db()
        .query_row(
            "SELECT body FROM network_events WHERE id=?1",
            [&event],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(body, b"private queued payload");
    f.db().execute_batch("DROP TRIGGER fail_retire").unwrap();
    assert_eq!(clean(&mut f, false)["outbound_events_cancelled"], 1);
    let (body, offset, cancelled, subject): (Vec<u8>, i64, bool, Option<String>) = f
        .db()
        .query_row(
            "SELECT body,offset,cancelled,subject FROM network_events WHERE id=?1",
            [&event],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert!(body.is_empty() && cancelled && subject.is_none());
    assert_eq!(offset, 262144);
}

#[test]
fn accepted_legacy_ids_retry_during_migration_then_stay_rejected_after_pruning() {
    let mut f = Fixture::new();
    let action = send(&mut f, "legacy content");
    let sent = ok(f.call(0, action.clone()));
    let old = Uuid::new_v4().to_string();
    // The fingerprint excludes request ID. Reconstruct a genuine legacy root
    // with its original sender-scoped ID, as an older version stored it.
    let mut message = f.inbox(1).remove(0);
    let fingerprint: String = f
        .db()
        .query_row("SELECT fingerprint FROM messages", [], |r| r.get(0))
        .unwrap();
    message.id = gent_daemon::messages::message_id(&f.agents[0], &old).unwrap();
    message.exchange_id = message.id.clone();
    message.created_at = now() - 9 * 86400;
    message.expires_at = message.created_at + 86400;
    let db = f.db();
    db.execute(
        "DELETE FROM messages WHERE id=?1",
        [sent["message_id"].as_str().unwrap()],
    )
    .unwrap();
    db.execute("DELETE FROM exchanges", []).unwrap();
    db.execute(
        "INSERT INTO exchanges VALUES(?1,?2,?3,?4,1)",
        rusqlite::params![
            message.id,
            message.sender,
            message.recipient,
            message.expires_at
        ],
    )
    .unwrap();
    db.execute("INSERT INTO messages(id,sender,recipient,request_id,fingerprint,payload) VALUES(?1,?2,?3,?4,?5,?6)",
        rusqlite::params![message.id,message.sender,message.recipient,old,fingerprint,serde_json::to_string(&message).unwrap()]).unwrap();
    let mut legacy = action;
    if let AgentOp::Send { request_id, .. } = &mut legacy {
        *request_id = old;
    }
    assert_eq!(ok(f.call(0, legacy.clone()))["message_id"], message.id);
    assert_eq!(clean(&mut f, false)["legacy_exchanges_deferred"], 1);
    let until: i64 = f
        .db()
        .query_row("SELECT legacy_until FROM request_clock", [], |r| r.get(0))
        .unwrap();
    advance(&mut f, until + 1);
    assert_eq!(clean(&mut f, false)["messages_removed"], 1);
    assert!(error(f.call(0, legacy)).contains("UUIDv7"));
}

#[test]
fn expired_relay_turns_and_selections_retire_without_reactivating_old_requests() {
    let mut f = Fixture::new();
    let grant = Uuid::new_v4().to_string();
    f.owner(OwnerOp::Configure {
        request_id: Uuid::new_v4().to_string(),
        edit: ConfigurationEdit::GrantRelay {
            grant_id: grant,
            intermediary: f.agents[0].clone(),
            target: f.agents[1].clone(),
            lifetime_seconds: 3600,
        },
    });
    let attach = AgentOp::RelayAttach {
        target: f.agents[1].clone(),
        request_id: next(&mut f, 0),
    };
    let attached = ok(f.call(0, attach.clone()));
    let turn = AgentOp::RelaySend {
        attachment_id: attached["attachment"]["id"].as_str().unwrap().into(),
        request_id: next(&mut f, 0),
        text: "relay".into(),
        files: vec![],
        file_ids: vec![],
    };
    let sent = ok(f.call(0, turn));
    let reply = AgentOp::RelayRespond {
        turn_id: sent["turn_id"].as_str().unwrap().into(),
        request_id: next(&mut f, 1),
        text: "done".into(),
        files: vec![],
        file_ids: vec![],
        outcome: RelayResponseKind::Complete,
    };
    ok(f.call(1, reply));
    advance(&mut f, now() + 9 * 86400);
    let result = clean(&mut f, false);
    assert_eq!(result["messages_removed"], 2);
    assert_eq!(result["relay_attachments_removed"], 1);
    assert!(error(f.call(0, attach)).contains("request_id expired"));
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM relay_turns", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn cleanup_batches_do_not_remove_live_work_and_request_generation_is_bounded() {
    let mut f = Fixture::new();
    let generated = ok(f.call(0, AgentOp::RequestIds { count: 32 }));
    let ids = generated["request_ids"].as_array().unwrap();
    assert_eq!(
        ids.iter()
            .map(Value::to_string)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        32
    );
    assert!(matches!(
        f.call(0, AgentOp::RequestIds { count: 33 }),
        Response::Error(_)
    ));
    for _ in 0..11 {
        let action = send(&mut f, "batch");
        ok(f.call(0, action));
    }
    advance(&mut f, now() + 9 * 86400);
    assert_eq!(clean(&mut f, true)["more_exchanges_due"], 3);
    assert_eq!(clean(&mut f, false)["exchanges_removed"], 8);
    assert_eq!(clean(&mut f, false)["exchanges_removed"], 3);
    assert_eq!(clean(&mut f, false)["exchanges_removed"], 0);
}

#[test]
fn full_quotas_allow_exact_retries_and_failed_new_work_leaves_no_objects_or_exchanges() {
    let mut f = Fixture::new();
    let import = f.source(0, "source", b"quota proof");
    let imported = ok(f.call(0, import.clone()));
    let action = f.send(1, vec![imported["file"]["id"].as_str().unwrap().into()]);
    let sent = ok(f.call(0, action.clone()));
    let db = f.db();
    // Fill the admission counters without thousands of encrypted file copies.
    db.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<8191)
        INSERT INTO messages(id,sender,recipient,request_id,fingerprint,payload)
        SELECT 'quota-'||i,sender,recipient,'quota-'||i,fingerprint,'{}' FROM n,messages WHERE id=?1",
        [sent["message_id"].as_str().unwrap()]).unwrap();
    db.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<16383)
        INSERT INTO file_imports(agent,request_id,fingerprint,object_id,retire_after)
        SELECT agent,'quota-'||i,fingerprint,object_id,retire_after FROM n,file_imports WHERE request_id=?1",
        [match &import { AgentOp::FileImport{request_id,..} => request_id, _ => unreachable!() }]).unwrap();
    assert_eq!(
        ok(f.call(0, action.clone()))["message_id"],
        sent["message_id"]
    );
    assert_eq!(ok(f.call(0, import.clone()))["file"], imported["file"]);
    let snapshot = || {
        db.query_row(
            "SELECT (SELECT COUNT(*) FROM file_objects),
        (SELECT COUNT(*) FROM exchanges),(SELECT COUNT(*) FROM agent_files),
        (SELECT COUNT(*) FROM file_handoffs)",
            [],
            |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, u64>(2)?,
                    r.get::<_, u64>(3)?,
                ))
            },
        )
        .unwrap()
    };
    let before = snapshot();
    let mut new_send = action;
    if let AgentOp::Send { request_id, .. } = &mut new_send {
        *request_id = next(&mut f, 0);
    }
    assert!(error(f.call(0, new_send.clone())).contains("message history quota"));
    let mut new_import = import;
    if let AgentOp::FileImport { request_id, .. } = &mut new_import {
        *request_id = next(&mut f, 0);
    }
    assert!(error(f.call(0, new_import.clone())).contains("file import retry quota"));
    assert_eq!(snapshot(), before);
    db.execute("DELETE FROM messages WHERE id LIKE 'quota-%'", [])
        .unwrap();
    db.execute(
        "DELETE FROM file_imports WHERE request_id LIKE 'quota-%'",
        [],
    )
    .unwrap();
    ok(f.call(0, new_send));
    ok(f.call(0, new_import));
}

#[test]
fn old_import_schema_migrates_and_live_retry_ids_do_not_starve_expired_records() {
    let mut f = Fixture::new();
    let live = next(&mut f, 0);
    let issued = Uuid::parse_str(&live)
        .unwrap()
        .get_timestamp()
        .unwrap()
        .to_unix()
        .0 as i64;
    let old = Uuid::new_v7(uuid::Timestamp::from_unix(
        uuid::NoContext,
        (issued - 86400) as u64,
        0,
    ))
    .to_string();
    let legacy = Uuid::new_v4().to_string();
    let db = f.db();
    db.execute_batch(
        "DROP INDEX file_import_retention; ALTER TABLE file_imports DROP COLUMN retire_after;",
    )
    .unwrap();
    for request in [&live, &old, &legacy] {
        db.execute(
            "INSERT INTO file_imports VALUES(?1,?2,'fingerprint','missing')",
            rusqlite::params![f.agents[0], request],
        )
        .unwrap();
    }
    f.store = Store::open(f.home.path()).unwrap();
    for (request, deadline) in [(&live, issued + 86400), (&old, issued), (&legacy, 0)] {
        assert_eq!(
            db.query_row(
                "SELECT retire_after FROM file_imports WHERE request_id=?1",
                [request],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            deadline
        );
    }
    assert_eq!(clean(&mut f, false)["import_retries_removed"], 2);
    for _ in 0..300 {
        let request = Uuid::new_v7(uuid::Timestamp::from_unix(
            uuid::NoContext,
            issued as u64,
            0,
        ))
        .to_string();
        db.execute(
            "INSERT INTO file_imports VALUES(?1,?2,'fingerprint','missing',?3)",
            rusqlite::params![f.agents[0], request, issued + 86400],
        )
        .unwrap();
    }
    for _ in 0..257 {
        db.execute(
            "INSERT INTO file_imports VALUES(?1,?2,'fingerprint','missing',0)",
            rusqlite::params![f.agents[0], Uuid::new_v4().to_string()],
        )
        .unwrap();
    }
    assert_eq!(clean(&mut f, false)["import_retries_removed"], 256);
    assert_eq!(clean(&mut f, false)["import_retries_removed"], 1);
    assert_eq!(clean(&mut f, false)["import_retries_removed"], 0);
    assert_eq!(f.owner(OwnerOp::HistoryStatus)["import_retry_records"], 301);
    advance(&mut f, issued + 86400);
    assert_eq!(clean(&mut f, false)["import_retries_removed"], 256);
    assert_eq!(clean(&mut f, false)["import_retries_removed"], 45);
}
