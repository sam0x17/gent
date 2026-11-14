use gent_daemon::{
    config,
    store::{Store, now},
};
use gent_protocol::{work::WorkResolution, *};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt};
use uuid::Uuid;

fn ok(response: Response) -> Value {
    match response {
        Response::Ok(v) => v,
        Response::Error(e) => panic!("{e}"),
    }
}
fn error(response: Response) -> String {
    match response {
        Response::Error(e) => e,
        Response::Ok(v) => panic!("unexpected success: {v}"),
    }
}
fn begin(id: &str, revision: u64) -> AgentOp {
    AgentOp::WorkBegin {
        message_id: id.into(),
        expect_revision: revision,
        description: "write reviewed output".into(),
    }
}
fn complete(id: &str, revision: u64) -> AgentOp {
    AgentOp::WorkComplete {
        message_id: id.into(),
        expect_revision: revision,
        note: "checked output digest".into(),
    }
}
fn reconcile(id: &str, revision: u64, resolution: WorkResolution) -> OwnerOp {
    OwnerOp::WorkReconcile {
        message_id: id.into(),
        expect_revision: revision,
        resolution,
        note: format!("reviewed host state at revision {revision}"),
    }
}
struct Fixture {
    home: tempfile::TempDir,
    store: Store,
    owner: String,
    keys: [String; 3],
    agents: [String; 3],
}
impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        config::initialize(home.path(), "work-test").unwrap();
        let owner = config::read_private(&home.path().join("owner.key")).unwrap();
        let mut store = Store::open(home.path()).unwrap();
        let keys = std::array::from_fn(|_| config::secret());
        let agents = std::array::from_fn(|i| {
            ok(store.handle(Request::Agent {
                credential: keys[i].clone(),
                action: AgentOp::Register {
                    name: format!("agent-{i}"),
                    provider: "generic".into(),
                },
            }))["agent"]["id"]
                .as_str()
                .unwrap()
                .into()
        });
        let mut f = Self {
            home,
            store,
            owner,
            keys,
            agents,
        };
        let mut policy = config::load(f.home.path()).unwrap().policy;
        policy.rules = [Permission::Enumerate, Permission::Send, Permission::Receive]
            .map(|permission| Rule {
                actor: Selector::All,
                peer: Selector::All,
                permission,
                effect: Effect::Allow,
            })
            .into();
        ok(f.owner(OwnerOp::SetPolicy { policy }));
        f
    }
    fn agent(&mut self, i: usize, action: AgentOp) -> Response {
        self.store.handle(Request::Agent {
            credential: self.keys[i].clone(),
            action,
        })
    }
    fn owner(&mut self, action: OwnerOp) -> Response {
        self.store.handle(Request::Owner {
            credential: self.owner.clone(),
            action,
        })
    }
    fn db(&self) -> Connection {
        Connection::open(self.home.path().join("state.sqlite3")).unwrap()
    }
    fn send(&mut self) -> String {
        ok(self.agent(
            0,
            AgentOp::Send {
                recipient: self.agents[1].clone(),
                request_id: Uuid::now_v7().to_string(),
                text: "authorized fixture request".into(),
                files: vec![],
                file_ids: vec![],
            },
        ))["message_id"]
            .as_str()
            .unwrap()
            .into()
    }
    fn show(&mut self, id: &str) -> Value {
        ok(self.owner(OwnerOp::WorkShow {
            message_id: id.into(),
        }))
    }
    fn restart(&mut self) {
        self.store = Store::open(self.home.path()).unwrap();
    }
    fn turn(&mut self) -> String {
        ok(self.owner(OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit: ConfigurationEdit::GrantRelay {
                grant_id: Uuid::new_v4().to_string(),
                intermediary: self.agents[0].clone(),
                target: self.agents[1].clone(),
                lifetime_seconds: 3600,
            },
        }));
        let attach = ok(self.agent(
            0,
            AgentOp::RelayAttach {
                target: self.agents[1].clone(),
                request_id: Uuid::now_v7().to_string(),
            },
        ));
        ok(self.agent(
            0,
            AgentOp::RelaySend {
                attachment_id: attach["attachment"]["id"].as_str().unwrap().into(),
                request_id: Uuid::now_v7().to_string(),
                text: "relay fixture".into(),
                files: vec![],
                file_ids: vec![],
            },
        ))["turn_id"]
            .as_str()
            .unwrap()
            .into()
    }
}

#[test]
fn lost_responses_restart_acknowledgment_and_owner_retry_keep_one_attempt() {
    let mut f = Fixture::new();
    let id = f.send();
    assert!(
        ok(f.agent(
            1,
            AgentOp::WorkStatus {
                message_id: id.clone()
            }
        ))["record"]
            .is_null()
    );
    let started = ok(f.agent(1, begin(&id, 0)));
    assert_eq!(started["started_now"], true);
    assert_eq!(started["execution_verified"], false);
    ok(f.agent(
        1,
        AgentOp::Ack {
            message_id: id.clone(),
        },
    ));
    f.restart();
    let repeat = ok(f.agent(1, begin(&id, 0)));
    assert_eq!(repeat["record"], started["record"]);
    assert_eq!(repeat["started_now"], false);
    error(f.agent(1, begin(&id, 1)));
    let action = reconcile(&id, 1, WorkResolution::RetryApproved);
    let approved = ok(f.owner(action.clone()));
    assert_eq!(ok(f.owner(action)), approved);
    error(f.agent(1, complete(&id, 2)));
    error(f.agent(1, begin(&id, 0)));
    assert_eq!(ok(f.agent(1, begin(&id, 2)))["record"]["attempts"], 2);
    assert_eq!(ok(f.agent(1, begin(&id, 2)))["started_now"], false);
    error(f.agent(1, complete(&id, 1)));
    let done = ok(f.agent(1, complete(&id, 3)));
    f.restart();
    assert_eq!(ok(f.agent(1, complete(&id, 3))), done);
    error(f.agent(
        1,
        AgentOp::WorkComplete {
            message_id: id.clone(),
            expect_revision: 3,
            note: "different".into(),
        },
    ));
    error(f.agent(1, begin(&id, 0)));
    assert_eq!(f.show(&id)["events"].as_array().unwrap().len(), 4);
    assert_eq!(ok(f.agent(0, AgentOp::Inbox)), json!([]));
    assert_eq!(ok(f.owner(OwnerOp::HistoryStatus))["messages"], 1);
}

#[test]
fn concurrent_connections_can_start_only_once() {
    let mut f = Fixture::new();
    let id = f.send();
    let mut other = Store::open(f.home.path()).unwrap();
    let key = f.keys[1].clone();
    let action = begin(&id, 0);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let peer_barrier = barrier.clone();
    let thread = std::thread::spawn(move || {
        peer_barrier.wait();
        ok(other.handle(Request::Agent {
            credential: key,
            action,
        }))
    });
    barrier.wait();
    let a = ok(f.agent(1, begin(&id, 0)));
    let b = thread.join().unwrap();
    assert_ne!(a["started_now"], b["started_now"]);
    assert_eq!(a["record"], b["record"]);
    assert_eq!(f.show(&id)["events"].as_array().unwrap().len(), 1);
}

#[test]
fn recipient_policy_revocation_and_source_fingerprint_gate_agent_access() {
    let mut f = Fixture::new();
    let id = f.send();
    for i in [0, 2] {
        error(f.agent(i, begin(&id, 0)));
        error(f.agent(
            i,
            AgentOp::WorkStatus {
                message_id: id.clone(),
            },
        ));
    }
    ok(f.agent(1, begin(&id, 0)));
    error(f.agent(2, complete(&id, 1)));
    let mut policy = config::load(f.home.path()).unwrap().policy;
    let allowed = policy.clone();
    policy.rules.clear();
    ok(f.owner(OwnerOp::SetPolicy { policy }));
    error(f.agent(1, begin(&id, 0)));
    error(f.agent(1, complete(&id, 1)));
    error(f.owner(reconcile(&id, 1, WorkResolution::RetryApproved)));
    ok(f.owner(OwnerOp::SetPolicy { policy: allowed }));
    let db = f.db();
    let original: String = db
        .query_row("SELECT payload FROM messages WHERE id=?1", [&id], |r| {
            r.get(0)
        })
        .unwrap();
    db.execute(
        "UPDATE messages SET payload=json_set(payload,'$.text','changed') WHERE id=?1",
        [&id],
    )
    .unwrap();
    error(f.agent(1, begin(&id, 0)));
    error(f.agent(1, complete(&id, 1)));
    error(f.agent(
        1,
        AgentOp::WorkStatus {
            message_id: id.clone(),
        },
    ));
    db.execute(
        "UPDATE messages SET payload=?2 WHERE id=?1",
        params![id, original],
    )
    .unwrap();
    ok(f.owner(OwnerOp::Revoke {
        agent_id: f.agents[1].clone(),
    }));
    error(f.agent(1, complete(&id, 1)));
    error(f.owner(reconcile(&id, 1, WorkResolution::RetryApproved)));
    ok(f.owner(reconcile(&id, 1, WorkResolution::Abandoned)));
}

#[test]
fn expired_source_cleanup_preserves_owner_evidence_without_retry_authority() {
    let mut f = Fixture::new();
    let id = f.send();
    ok(f.agent(1, begin(&id, 0)));
    f.db()
        .execute("UPDATE request_clock SET floor=?1", [now() + 9 * 86400])
        .unwrap();
    // Owner evidence remains readable under stale authority, but a new retry
    // approval must wait for valid signed node authority and source access.
    assert_eq!(f.show(&id)["record"]["state"], "started");
    error(f.owner(reconcile(&id, 1, WorkResolution::RetryApproved)));
    ok(f.owner(OwnerOp::Renew));
    error(f.agent(1, complete(&id, 1)));
    error(f.owner(reconcile(&id, 1, WorkResolution::RetryApproved)));
    assert_eq!(
        ok(f.owner(OwnerOp::HistoryClean { dry_run: false }))["messages_removed"],
        1
    );
    f.restart();
    assert_eq!(f.show(&id)["record"]["state"], "started");
    assert_eq!(
        ok(f.owner(OwnerOp::WorkList {
            after_message_id: None
        }))["entries"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    error(f.agent(1, begin(&id, 0)));
    error(f.owner(reconcile(&id, 1, WorkResolution::RetryApproved)));
    assert_eq!(
        ok(f.owner(reconcile(&id, 1, WorkResolution::Completed)))["record"]["state"],
        "completed"
    );
}

#[test]
fn relay_queue_cancellation_and_final_outcome_gate_new_attempts() {
    let mut f = Fixture::new();
    let first = f.turn();
    let second = f.turn();
    error(f.agent(1, begin(&second, 0)));
    ok(f.agent(1, begin(&first, 0)));
    let cancel = ok(f.agent(
        0,
        AgentOp::RelayCancel {
            turn_id: first.clone(),
            request_id: Uuid::now_v7().to_string(),
        },
    ));
    error(f.agent(1, begin(cancel["message_id"].as_str().unwrap(), 0)));
    assert_eq!(ok(f.agent(1, begin(&first, 0)))["started_now"], false);
    error(f.owner(reconcile(&first, 1, WorkResolution::RetryApproved)));
    // An already recorded attempt can report its checked outcome after a cancel request.
    ok(f.agent(1, complete(&first, 1)));
    assert_eq!(ok(f.agent(1, AgentOp::RelayNext))["request"]["id"], first);
    let response = ok(f.agent(
        1,
        AgentOp::RelayRespond {
            turn_id: first.clone(),
            request_id: Uuid::now_v7().to_string(),
            text: "checked outcome".into(),
            files: vec![],
            file_ids: vec![],
            outcome: RelayResponseKind::Complete,
        },
    ));
    error(f.agent(0, begin(response["message_id"].as_str().unwrap(), 0)));
    error(f.owner(reconcile(&first, 2, WorkResolution::RetryApproved)));
    assert_eq!(ok(f.agent(1, begin(&second, 0)))["started_now"], true);
    let third = f.turn();
    ok(f.agent(
        0,
        AgentOp::RelayCancel {
            turn_id: third.clone(),
            request_id: Uuid::now_v7().to_string(),
        },
    ));
    error(f.agent(1, begin(&third, 0)));
}

#[test]
fn failing_event_write_rolls_back_creation_completion_and_owner_reconciliation() {
    let mut f = Fixture::new();
    let id = f.send();
    let db = f.db();
    let fail = "CREATE TRIGGER fail_work BEFORE INSERT ON work_events BEGIN SELECT RAISE(ABORT,'injected work failure'); END;";
    db.execute_batch(fail).unwrap();
    assert!(error(f.agent(1, begin(&id, 0))).contains("injected work failure"));
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM work_entries", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
    db.execute_batch("DROP TRIGGER fail_work").unwrap();
    ok(f.agent(1, begin(&id, 0)));
    let before = f.show(&id);
    db.execute_batch(fail).unwrap();
    error(f.agent(1, complete(&id, 1)));
    error(f.owner(reconcile(&id, 1, WorkResolution::RetryApproved)));
    assert_eq!(f.show(&id), before);
    db.execute_batch("DROP TRIGGER fail_work").unwrap();
    ok(f.agent(1, complete(&id, 1)));
}

#[test]
fn revision_limit_reserves_start_and_completion_and_rejects_stale_approval() {
    let mut f = Fixture::new();
    let id = f.send();
    ok(f.agent(1, begin(&id, 0)));
    for revision in 1..61 {
        ok(f.owner(reconcile(&id, revision, WorkResolution::Completed)));
    }
    assert_eq!(f.show(&id)["record"]["revision"], 61);
    ok(f.owner(reconcile(&id, 61, WorkResolution::RetryApproved)));
    error(f.owner(reconcile(&id, 62, WorkResolution::RetryApproved)));
    error(f.owner(reconcile(&id, 60, WorkResolution::RetryApproved)));
    assert_eq!(ok(f.agent(1, begin(&id, 62)))["started_now"], true);
    ok(f.agent(1, complete(&id, 63)));
    assert_eq!(f.show(&id)["events"].as_array().unwrap().len(), 64);
    error(f.owner(reconcile(&id, 64, WorkResolution::Abandoned)));
    assert_eq!(f.show(&id)["record"]["revision"], 64);
}

#[test]
fn corrupt_history_or_records_cannot_be_used_to_start_or_complete_work() {
    for corrupt in [
        "DELETE FROM work_events WHERE revision=1",
        "UPDATE work_events SET payload=json_set(payload,'$.actor','peer') WHERE revision=1",
        "UPDATE work_entries SET payload=json_set(payload,'$.attempts',0)",
        "UPDATE work_entries SET payload=json_set(payload,'$.revision',18446744073709551615)",
        "UPDATE work_entries SET payload=json_set(payload,'$.message_sha256','invalid')",
    ] {
        let mut f = Fixture::new();
        let id = f.send();
        ok(f.agent(1, begin(&id, 0)));
        ok(f.owner(reconcile(&id, 1, WorkResolution::RetryApproved)));
        f.db().execute_batch(corrupt).unwrap();
        f.restart();
        error(f.agent(1, begin(&id, 2)));
        error(f.agent(1, complete(&id, 2)));
        error(f.owner(reconcile(&id, 2, WorkResolution::Completed)));
        error(f.owner(OwnerOp::WorkShow { message_id: id }));
    }
}

#[test]
fn missing_schema_is_refused_and_legacy_initialization_is_atomic() {
    for corrupt in [
        "DROP TABLE work_events",
        "DROP TABLE work_entries",
        "DELETE FROM metadata WHERE key='work_journal_version'",
        "UPDATE metadata SET value='2' WHERE key='work_journal_version'",
    ] {
        let f = Fixture::new();
        f.db().execute_batch(corrupt).unwrap();
        assert!(Store::open(f.home.path()).is_err());
    }
    let mut f = Fixture::new();
    let id = f.send();
    let db = f.db();
    db.execute_batch("DROP TABLE work_events; DROP TABLE work_entries; DELETE FROM metadata WHERE key='work_journal_version';
        CREATE TRIGGER fail_version BEFORE INSERT ON metadata WHEN NEW.key='work_journal_version' BEGIN SELECT RAISE(ABORT,'injected migration failure'); END;").unwrap();
    assert!(Store::open(f.home.path()).is_err());
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name LIKE 'work_%'",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        0
    );
    db.execute_batch("DROP TRIGGER fail_version").unwrap();
    f.restart();
    assert!(ok(f.agent(1, AgentOp::WorkStatus { message_id: id }))["record"].is_null());
}

#[test]
fn admission_caps_preserve_completion_space_and_paginate_owner_records() {
    let mut f = Fixture::new();
    let id = f.send();
    let other = f.send();
    ok(f.agent(1, begin(&id, 0)));
    let db = f.db();
    // Bulk occupancy fixture: complete, internally consistent one-attempt
    // journals. Source messages are intentionally absent, as after cleanup.
    let mut record = f.show(&id)["record"].clone();
    record["state"] = json!("completed");
    record["revision"] = json!(2);
    let first = f.show(&id)["events"][0].clone();
    let last = json!({"revision":2,"state":"completed","attempts":1,"actor":"agent","note":"checked fixture","at":first["at"]});
    db.execute(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<4095)
        INSERT INTO work_entries SELECT printf('00000000-0000-4000-8000-%012d',i),?1,
        json_set(?2,'$.message_id',printf('00000000-0000-4000-8000-%012d',i)) FROM n",
        params![f.agents[1], record.to_string()],
    )
    .unwrap();
    for (revision, event) in [(1, first), (2, last)] {
        db.execute("INSERT INTO work_events SELECT message_id,?1,?2 FROM work_entries WHERE message_id!=?3",
            params![revision, event.to_string(), id]).unwrap();
    }
    assert!(error(f.agent(1, begin(&other, 0))).contains("capacity"));
    assert!(
        ok(f.agent(
            1,
            AgentOp::WorkStatus {
                message_id: other.clone()
            }
        ))["record"]
            .is_null()
    );
    let page = ok(f.owner(OwnerOp::WorkList {
        after_message_id: None,
    }));
    assert_eq!(page["entries"].as_array().unwrap().len(), 50);
    assert_eq!(page["has_more"], true);
    let cursor = page["next_after"].as_str().unwrap();
    let next = ok(f.owner(OwnerOp::WorkList {
        after_message_id: Some(cursor.into()),
    }));
    assert!(next["entries"][0]["record"]["message_id"].as_str().unwrap() > cursor);
    // Complete the original while all record slots are occupied.
    ok(f.agent(1, complete(&id, 1)));
    // Fill the event quota with valid owner outcome reports on those records.
    let updated = f.show(&id)["record"]["updated_at"].as_i64().unwrap();
    let final_event = json!({"revision":16,"state":"completed","attempts":1,"actor":"owner","note":"reviewed fixture","at":updated});
    db.execute("WITH RECURSIVE n(i) AS (SELECT 3 UNION ALL SELECT i+1 FROM n WHERE i<16)
        INSERT INTO work_events SELECT message_id,i,json_set(?1,'$.revision',i) FROM work_entries,n",
        [final_event.to_string()]).unwrap();
    db.execute(
        "UPDATE work_entries SET payload=json_set(payload,'$.revision',16,'$.updated_at',?1)",
        [updated],
    )
    .unwrap();
    let refused = error(f.owner(reconcile(&id, 16, WorkResolution::RetryApproved)));
    assert!(refused.contains("capacity"), "{refused}");
    assert_eq!(f.show(&id)["record"]["revision"], 16);
    // Leave exactly three event slots: owner approval reserves two, start
    // consumes one, and completion consumes the remaining reserved slot.
    db.execute("DELETE FROM work_events WHERE message_id='00000000-0000-4000-8000-000000000001' AND revision>13", []).unwrap();
    db.execute("UPDATE work_entries SET payload=json_set(payload,'$.revision',13) WHERE message_id='00000000-0000-4000-8000-000000000001'", []).unwrap();
    ok(f.owner(reconcile(&id, 16, WorkResolution::RetryApproved)));
    assert_eq!(ok(f.agent(1, begin(&id, 17)))["started_now"], true);
    ok(f.agent(1, complete(&id, 18)));
    error(f.owner(reconcile(&id, 19, WorkResolution::Completed)));
    assert_eq!(f.show(&id)["record"]["revision"], 19);
}

#[test]
fn invalid_ids_text_and_changed_begin_arguments_leave_no_new_attempt() {
    let mut f = Fixture::new();
    let id = f.send();
    for invalid in [
        "not-an-id",
        "00000000-0000-0000-0000-000000000000",
        &id.to_uppercase(),
    ] {
        error(f.agent(1, begin(invalid, 0)));
    }
    for description in [" ".into(), "é".repeat(513)] {
        error(f.agent(
            1,
            AgentOp::WorkBegin {
                message_id: id.clone(),
                expect_revision: 0,
                description,
            },
        ));
    }
    error(f.agent(1, begin(&id, u64::MAX)));
    assert!(
        ok(f.agent(
            1,
            AgentOp::WorkStatus {
                message_id: id.clone()
            }
        ))["record"]
            .is_null()
    );
    ok(f.agent(1, begin(&id, 0)));
    error(f.agent(
        1,
        AgentOp::WorkBegin {
            message_id: id.clone(),
            expect_revision: 0,
            description: "changed work".into(),
        },
    ));
    for note in [" ".into(), "é".repeat(1025)] {
        error(f.agent(
            1,
            AgentOp::WorkComplete {
                message_id: id.clone(),
                expect_revision: 1,
                note,
            },
        ));
    }
    error(f.agent(1, complete(&id, u64::MAX)));
    assert_eq!(f.show(&id)["record"]["revision"], 1);
    // JSON escaping can expand valid bounded input sixfold.
    ok(f.agent(
        1,
        AgentOp::WorkComplete {
            message_id: id,
            expect_revision: 1,
            note: "\u{0001}".repeat(2048),
        },
    ));
}
