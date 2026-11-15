use gent_daemon::{config, store::Store};
use gent_protocol::{wake::WakeTarget, *};
use rusqlite::{Connection, params};
use serde_json::Value;
use std::sync::{Arc, Barrier};
use std::{fs, os::unix::fs::PermissionsExt};
use uuid::Uuid;

fn ok(response: Response) -> Value {
    match response {
        Response::Ok(value) => value,
        Response::Error(error) => panic!("{error}"),
    }
}
fn error(response: Response) -> String {
    match response {
        Response::Error(error) => error,
        Response::Ok(value) => panic!("unexpected success: {value}"),
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
        config::initialize(home.path(), "wake-test").unwrap();
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
        let policy = Policy {
            rules: [Permission::Enumerate, Permission::Send, Permission::Receive]
                .map(|permission| Rule {
                    actor: Selector::All,
                    peer: Selector::All,
                    permission,
                    effect: Effect::Allow,
                })
                .into(),
            ..Default::default()
        };
        ok(f.owner(OwnerOp::SetPolicy { policy }));
        f
    }
    fn agent(&mut self, index: usize, action: AgentOp) -> Response {
        self.store.handle(Request::Agent {
            credential: self.keys[index].clone(),
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
                text: "private request content".into(),
                files: vec![],
                file_ids: vec![],
            },
        ))["message_id"]
            .as_str()
            .unwrap()
            .into()
    }
    fn claim(message: &str) -> AgentOp {
        AgentOp::WakeClaim {
            message_id: message.into(),
            attempt_id: Uuid::new_v4().to_string(),
            target: WakeTarget::Codex {
                thread_id: Uuid::now_v7().to_string(),
            },
        }
    }
    fn show(&mut self, message: &str) -> Value {
        ok(self.owner(OwnerOp::WakeShow {
            message_id: message.into(),
        }))
    }
    fn submitted(message: &str, claim: &Value) -> AgentOp {
        AgentOp::WakeSubmitted {
            message_id: message.into(),
            attempt_id: claim["record"]["attempt_id"].as_str().unwrap().into(),
            submission_id: Uuid::now_v7().to_string(),
        }
    }
    fn advance(&self, seconds: i64) {
        self.db()
            .execute("UPDATE request_clock SET floor=floor+?1", [seconds])
            .unwrap();
    }
    fn count(&self) -> u64 {
        self.db()
            .query_row("SELECT COUNT(*) FROM wake_dispatches", [], |r| r.get(0))
            .unwrap()
    }
}

#[test]
fn lost_claim_response_never_reissues_submission_permission() {
    let mut f = Fixture::new();
    let message = f.send();
    let pending = ok(f.agent(1, AgentOp::WakePending));
    assert_eq!(pending["pending"][0]["message_id"], message);
    assert!(!pending.to_string().contains("private request content"));
    f.db()
        .execute("UPDATE agents SET last_seen=1 WHERE id=?1", [&f.agents[1]])
        .unwrap();
    let claim = Fixture::claim(&message);
    let first = ok(f.agent(1, claim.clone()));
    assert_eq!(first["may_submit"], true);
    assert_eq!(first["record"]["state"], "uncertain");
    f.store = Store::open(f.home.path()).unwrap();
    let repeated = ok(f.agent(1, claim.clone()));
    assert_eq!(repeated["may_submit"], false);
    assert_eq!(repeated["record"], first["record"]);
    assert!(
        ok(f.agent(1, AgentOp::WakePending))["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(error(f.agent(1, Fixture::claim(&message))).contains("already claimed"));
    let mut changed = claim;
    if let AgentOp::WakeClaim { target, .. } = &mut changed {
        *target = WakeTarget::Codex {
            thread_id: Uuid::now_v7().to_string(),
        };
    }
    assert!(error(f.agent(1, changed)).contains("already claimed"));
    let submitted = Fixture::submitted(&message, &first);
    let outcome = ok(f.agent(1, submitted.clone()));
    f.advance(6);
    assert_eq!(ok(f.agent(1, submitted)), outcome);
    assert!(error(f.agent(1, Fixture::submitted(&message, &first))).contains("does not match"));
    let seen: i64 = f
        .db()
        .query_row(
            "SELECT last_seen FROM agents WHERE id=?1",
            [&f.agents[1]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        seen, 1,
        "host adapter traffic must not make a model look active"
    );
    assert_eq!(f.count(), 1);
}

#[test]
fn inbox_observation_and_host_ack_are_independent_of_message_receipts_and_work() {
    let mut f = Fixture::new();
    let message = f.send();
    let claim = ok(f.agent(1, Fixture::claim(&message)));
    f.advance(6);
    let inbox = ok(f.agent(1, AgentOp::Inbox));
    assert_eq!(inbox[0]["id"], message);
    let observed = f.show(&message);
    assert_eq!(observed["state"], "uncertain");
    assert!(observed["inbox_seen_at"].is_i64());
    assert!(observed["submission_id"].is_null());
    assert_eq!(inbox[0]["acknowledged"], false);
    assert!(
        error(f.owner(OwnerOp::WorkShow {
            message_id: message.clone()
        }))
        .contains("not recorded")
    );
    f.advance(6);
    let submitted = ok(f.agent(1, Fixture::submitted(&message, &claim)));
    assert_eq!(submitted["inbox_seen_at"], observed["inbox_seen_at"]);
    assert_eq!(submitted["state"], "submitted");
    ok(f.agent(1, AgentOp::Inbox));
    assert_eq!(f.show(&message), submitted);
    ok(f.agent(
        1,
        AgentOp::Ack {
            message_id: message.clone(),
        },
    ));
    assert_eq!(f.show(&message), submitted);
}

#[test]
fn permissions_revocation_and_acknowledgment_gate_new_claims() {
    let mut f = Fixture::new();
    let claimed = f.send();
    let request = Fixture::claim(&claimed);
    let first = ok(f.agent(1, request.clone()));
    let fresh = f.send();
    assert!(
        ok(f.agent(2, AgentOp::WakePending))["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(error(f.agent(2, request.clone())).contains("unavailable"));
    assert!(error(f.agent(2, Fixture::submitted(&claimed, &first))).contains("unavailable"));
    let acknowledged = f.send();
    ok(f.agent(
        1,
        AgentOp::Ack {
            message_id: acknowledged.clone(),
        },
    ));
    assert!(error(f.agent(1, Fixture::claim(&acknowledged))).contains("unavailable"));
    ok(f.owner(OwnerOp::SetPolicy {
        policy: Policy::default(),
    }));
    assert!(
        ok(f.agent(1, AgentOp::WakePending))["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(error(f.agent(1, Fixture::claim(&fresh))).contains("unavailable"));
    assert_eq!(ok(f.agent(1, request.clone()))["may_submit"], false);
    // Recording an already attempted submission does not require renewed peer access.
    ok(f.agent(1, Fixture::submitted(&claimed, &first)));
    ok(f.owner(OwnerOp::Revoke {
        agent_id: f.agents[1].clone(),
    }));
    assert!(error(f.agent(1, request)).contains("revoked"));
    assert_eq!(f.count(), 1);
}

#[test]
fn concurrent_claimants_get_one_permission_and_failed_commits_grant_none() {
    let mut f = Fixture::new();
    let message = f.send();
    let claim = Fixture::claim(&message);
    f.db().execute_batch("CREATE TRIGGER reject_wake BEFORE INSERT ON wake_dispatches BEGIN SELECT RAISE(ABORT,'fixture insert failure'); END;").unwrap();
    assert!(error(f.agent(1, claim.clone())).contains("fixture insert failure"));
    assert_eq!(f.count(), 0);
    f.db().execute_batch("DROP TRIGGER reject_wake").unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let mut store = Store::open(f.home.path()).unwrap();
        let barrier = barrier.clone();
        let credential = f.keys[1].clone();
        let action = claim.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            ok(store.handle(Request::Agent { credential, action }))
        }));
    }
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|w| w.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results.iter().filter(|r| r["may_submit"] == true).count(),
        1
    );
    assert_eq!(results[0]["record"], results[1]["record"]);
    f.db().execute_batch("CREATE TRIGGER reject_wake_update BEFORE UPDATE ON wake_dispatches BEGIN SELECT RAISE(ABORT,'fixture update failure'); END;").unwrap();
    let submitted = Fixture::submitted(&message, &results[0]);
    assert!(error(f.agent(1, submitted.clone())).contains("fixture update failure"));
    assert_eq!(f.show(&message)["state"], "uncertain");
    f.db()
        .execute_batch("DROP TRIGGER reject_wake_update")
        .unwrap();
    assert_eq!(ok(f.agent(1, claim))["may_submit"], false);
    ok(f.agent(1, submitted));
}

#[test]
fn claim_budgets_preserve_pending_messages_and_survive_restart() {
    let mut f = Fixture::new();
    for index in 0..12 {
        let message = f.send();
        let claim = Fixture::claim(&message);
        if index > 0 {
            assert!(error(f.agent(1, claim.clone())).contains("budget"));
            f.advance(5);
        }
        ok(f.agent(1, claim));
    }
    let message = f.send();
    f.advance(5);
    f.store = Store::open(f.home.path()).unwrap();
    assert!(error(f.agent(1, Fixture::claim(&message))).contains("budget"));
    assert_eq!(f.count(), 12);
    assert_eq!(
        ok(f.agent(1, AgentOp::WakePending))["pending"][0]["message_id"],
        message
    );
    f.advance(3600);
    ok(f.agent(1, Fixture::claim(&message)));
    assert_eq!(f.count(), 13);
}

#[test]
fn storage_limits_and_corrupt_journal_fail_without_recreating_dispatch_permission() {
    let mut f = Fixture::new();
    let message = f.send();
    let first = ok(f.agent(1, Fixture::claim(&message)));
    let mut db = f.db();
    let tx = db.transaction().unwrap();
    for _ in 1..16_384 {
        let mut record = first["record"].clone();
        record["message_id"] = Uuid::now_v7().to_string().into();
        record["attempt_id"] = Uuid::new_v4().to_string().into();
        tx.execute("INSERT INTO wake_dispatches(message_id,agent,attempt_id,claimed_at,payload) VALUES(?1,?2,?3,?4,?5)",params![
            record["message_id"].as_str().unwrap(),record["agent"].as_str().unwrap(),record["attempt_id"].as_str().unwrap(),
            record["claimed_at"].as_i64().unwrap(),record.to_string()]).unwrap();
    }
    tx.commit().unwrap();
    let next = f.send();
    assert!(error(f.agent(1, Fixture::claim(&next))).contains("full"));
    let page = ok(f.owner(OwnerOp::WakeList {
        after_message_id: None,
    }));
    assert_eq!(page["entries"].as_array().unwrap().len(), 50);
    assert_eq!(page["has_more"], true);
    assert!(
        db.execute(
            "UPDATE wake_dispatches SET payload=?1 WHERE message_id=?2",
            params!["x".repeat(2049), message]
        )
        .is_err()
    );
    db.execute(
        "UPDATE wake_dispatches SET payload='{}' WHERE message_id=?1",
        [&message],
    )
    .unwrap();
    assert!(
        !error(f.owner(OwnerOp::WakeShow {
            message_id: message
        }))
        .is_empty()
    );
    db.execute("DROP TABLE wake_dispatches", []).unwrap();
    assert!(Store::open(f.home.path()).is_err());
}

#[test]
fn node_budget_counts_other_agents_and_expired_messages_never_get_claims() {
    let mut f = Fixture::new();
    let expired = f.send();
    f.db()
        .execute(
            "UPDATE messages SET payload=json_set(payload,'$.expires_at',0) WHERE id=?1",
            [&expired],
        )
        .unwrap();
    assert!(error(f.agent(1, Fixture::claim(&expired))).contains("unavailable"));
    assert!(
        ok(f.agent(1, AgentOp::WakePending))["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let message = f.send();
    let first = ok(f.agent(1, Fixture::claim(&message)));
    let mut db = f.db();
    let tx = db.transaction().unwrap();
    // Populate other agents' retained claims through real accounting columns.
    for _ in 1..120 {
        let mut record = first["record"].clone();
        record["message_id"] = Uuid::now_v7().to_string().into();
        record["attempt_id"] = Uuid::new_v4().to_string().into();
        record["agent"] = f.agents[2].clone().into();
        tx.execute("INSERT INTO wake_dispatches(message_id,agent,attempt_id,claimed_at,payload) VALUES(?1,?2,?3,?4,?5)",params![
            record["message_id"].as_str().unwrap(),record["agent"].as_str().unwrap(),record["attempt_id"].as_str().unwrap(),
            record["claimed_at"].as_i64().unwrap(),record.to_string()]).unwrap();
    }
    tx.commit().unwrap();
    let next = f.send();
    f.advance(5);
    assert!(error(f.agent(1, Fixture::claim(&next))).contains("budget"));
    assert_eq!(f.count(), 120);
    assert_eq!(
        ok(f.agent(1, AgentOp::WakePending))["pending"][0]["message_id"],
        next
    );
    f.advance(3600);
    ok(f.agent(1, Fixture::claim(&next)));
}
