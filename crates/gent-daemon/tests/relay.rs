use gent_daemon::{
    config,
    store::{Store, now},
};
use gent_protocol::*;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt};
use uuid::Uuid;

fn ok(response: Response) -> Value {
    match response {
        Response::Ok(value) => value,
        Response::Error(error) => panic!("{error}"),
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
    fn start_turn(&mut self, target: usize) -> (String, AgentOp, String) {
        let attached = ok(self.agent(0, self.attach(target)));
        let id = attached["attachment"]["id"].as_str().unwrap().to_owned();
        let send = AgentOp::RelaySend {
            file_ids: vec![],
            attachment_id: id.clone(),
            request_id: Uuid::now_v7().to_string(),
            text: "  exact user text\n".into(),
            files: vec![FilePart {
                name: "reference.txt".into(),
                media_type: "text/plain".into(),
                data_base64: "aGVsbG8=".into(),
            }],
        };
        let turn = ok(self.agent(0, send.clone()))["turn_id"]
            .as_str()
            .unwrap()
            .to_owned();
        (id, send, turn)
    }
    fn turn(&mut self, turn: &str) -> Value {
        ok(self.agent(
            0,
            AgentOp::RelayTurnStatus {
                turn_id: turn.into(),
                after_message_id: None,
            },
        ))
    }
    fn respond(turn: &str, outcome: RelayResponseKind) -> AgentOp {
        AgentOp::RelayRespond {
            file_ids: vec![],
            turn_id: turn.into(),
            request_id: Uuid::now_v7().to_string(),
            text: "target response".into(),
            files: vec![],
            outcome,
        }
    }
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        config::initialize(home.path(), "relay-test").unwrap();
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
        Self {
            home,
            store,
            owner,
            keys,
            agents,
        }
    }
    fn agent(&mut self, i: usize, action: AgentOp) -> Response {
        self.store.handle(Request::Agent {
            credential: self.keys[i].clone(),
            action,
        })
    }
    fn owner(&mut self, action: OwnerOp) -> Value {
        ok(self.store.handle(Request::Owner {
            credential: self.owner.clone(),
            action,
        }))
    }
    fn edit(&mut self, edit: ConfigurationEdit) -> Value {
        self.owner(OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit,
        })
    }
    fn grant(&mut self, target: usize, ttl: u64) -> String {
        let id = Uuid::new_v4().to_string();
        let edit = ConfigurationEdit::GrantRelay {
            grant_id: id.clone(),
            intermediary: self.agents[0].clone(),
            target: self.agents[target].clone(),
            lifetime_seconds: ttl,
        };
        assert_eq!(self.edit(edit)["state"], "applied");
        id
    }
    // Recreate a persisted attachment from the old daemon, including its signed bound.
    fn legacy_attachment(&mut self, action: AgentOp, grant: &str) -> Value {
        let attached = ok(self.agent(0, action));
        let expiry = self.current_policy().relay_grants[grant].expires_at;
        self.db().execute(
            "UPDATE relay_attachments SET payload=json_set(payload,'$.grant_id',?1,'$.expires_at',?2) WHERE id=?3",
            rusqlite::params![grant, expiry, attached["attachment"]["id"].as_str().unwrap()],
        ).unwrap();
        self.store = Store::open(self.home.path()).unwrap();
        self.status(None)
    }
    fn policy(&mut self, policy: Policy) {
        self.owner(OwnerOp::SetPolicy { policy });
    }
    fn current_policy(&self) -> Policy {
        config::load(self.home.path()).unwrap().policy
    }
    fn allow(&mut self) {
        let mut policy = self.current_policy();
        policy.rules = [Permission::Enumerate, Permission::Send, Permission::Receive]
            .map(|permission| Rule {
                actor: Selector::All,
                peer: Selector::All,
                permission,
                effect: Effect::Allow,
            })
            .into();
        self.policy(policy);
    }
    fn attach(&self, target: usize) -> AgentOp {
        AgentOp::RelayAttach {
            target: self.agents[target].clone(),
            request_id: Uuid::now_v7().to_string(),
        }
    }
    fn status(&mut self, id: Option<&str>) -> Value {
        ok(self.agent(
            0,
            AgentOp::RelayStatus {
                attachment_id: id.map(str::to_owned),
            },
        ))
    }
    fn db(&self) -> Connection {
        Connection::open(self.home.path().join("state.sqlite3")).unwrap()
    }
}

#[test]
fn turns_preserve_content_attribution_and_pending_work_through_switch_and_restart() {
    let mut f = Fixture::new();
    let (attachment, send, turn) = f.start_turn(1);
    let next = ok(f.agent(1, AgentOp::RelayNext));
    assert_eq!(next["request"]["id"], turn);
    assert_eq!(next["request"]["text"], "  exact user text\n");
    assert_eq!(next["request"]["files"][0]["data_base64"], "aGVsbG8=");
    ok(f.agent(
        1,
        AgentOp::Ack {
            message_id: turn.clone(),
        },
    ));
    assert_eq!(ok(f.agent(1, AgentOp::Inbox)), json!([]));
    assert_eq!(f.turn(&turn)["state"], "pending");
    assert_eq!(ok(f.agent(1, AgentOp::RelayNext))["request"]["id"], turn);
    assert!(matches!(
        f.agent(
            1,
            AgentOp::Reply {
                file_ids: vec![],
                message_id: turn.clone(),
                request_id: Uuid::now_v7().to_string(),
                text: "bypass completion protocol".into(),
                files: vec![]
            }
        ),
        Response::Error(_)
    ));
    assert!(matches!(
        f.agent(
            2,
            AgentOp::RelayTurnStatus {
                turn_id: turn.clone(),
                after_message_id: None
            }
        ),
        Response::Error(_)
    ));
    assert!(matches!(
        f.agent(2, Fixture::respond(&turn, RelayResponseKind::Complete)),
        Response::Error(_)
    ));
    let other = ok(f.agent(0, f.attach(2)));
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(ok(f.agent(0, send.clone()))["duplicate"], true);
    let mut changed = send.clone();
    if let AgentOp::RelaySend { text, .. } = &mut changed {
        text.push('!');
    }
    assert!(matches!(f.agent(0, changed.clone()), Response::Error(_)));
    if let AgentOp::RelaySend { request_id, .. } = &mut changed {
        *request_id = Uuid::now_v7().to_string();
    }
    assert!(matches!(f.agent(0, changed), Response::Error(_)));
    let progress = Fixture::respond(&turn, RelayResponseKind::Progress);
    ok(f.agent(1, progress.clone()));
    assert_eq!(f.turn(&turn)["state"], "pending");
    let final_action = Fixture::respond(&turn, RelayResponseKind::Complete);
    let completed = ok(f.agent(1, final_action.clone()));
    assert_eq!(ok(f.agent(1, final_action))["duplicate"], true);
    assert_eq!(ok(f.agent(1, progress))["duplicate"], true);
    assert!(matches!(
        f.agent(1, Fixture::respond(&turn, RelayResponseKind::Progress)),
        Response::Error(_)
    ));
    let status = f.turn(&turn);
    assert_eq!(status["state"], "completed");
    assert_eq!(status["target"]["id"], f.agents[1]);
    assert_eq!(status["relay"]["attachment_id"], attachment);
    assert_eq!(status["final_message_id"], completed["message_id"]);
    assert_eq!(status["responses"].as_array().unwrap().len(), 2);
    assert_eq!(f.status(None)["attachment"], other["attachment"]);
    assert_eq!(ok(f.agent(1, AgentOp::RelayNext)), Value::Null);
}

#[test]
fn multiple_intermediaries_share_one_durable_target_queue_and_cancellation_is_explicit() {
    let mut f = Fixture::new();
    let (attachment, _, first) = f.start_turn(1);
    let attach = ok(f.agent(2, f.attach(1)));
    let second = ok(f.agent(
        2,
        AgentOp::RelaySend {
            file_ids: vec![],
            attachment_id: attach["attachment"]["id"].as_str().unwrap().into(),
            request_id: Uuid::now_v7().to_string(),
            text: "second intermediary".into(),
            files: vec![],
        },
    ))["turn_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let inbox = ok(f.agent(1, AgentOp::Inbox));
    assert_eq!(inbox.as_array().unwrap().len(), 1);
    assert_eq!(inbox[0]["id"], first);
    assert!(matches!(
        f.agent(1, Fixture::respond(&second, RelayResponseKind::Complete)),
        Response::Error(_)
    ));
    assert!(matches!(
        f.agent(1, Fixture::respond(&first, RelayResponseKind::Cancelled)),
        Response::Error(_)
    ));
    ok(f.agent(
        0,
        AgentOp::RelayDetach {
            attachment_id: attachment,
        },
    ));
    assert_eq!(
        ok(f.agent(1, AgentOp::RelayNext))["cancel_requested"],
        false
    );
    let cancel = AgentOp::RelayCancel {
        turn_id: first.clone(),
        request_id: Uuid::now_v7().to_string(),
    };
    ok(f.agent(0, cancel.clone()));
    assert_eq!(f.turn(&first)["state"], "pending");
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(ok(f.agent(1, AgentOp::RelayNext))["cancel_requested"], true);
    ok(f.agent(1, Fixture::respond(&first, RelayResponseKind::Cancelled)));
    assert_eq!(ok(f.agent(0, cancel))["duplicate"], true);
    assert_eq!(f.turn(&first)["state"], "completed");
    assert_eq!(f.turn(&first)["responses"][0]["relay"]["kind"], "cancelled");
    assert_eq!(ok(f.agent(1, AgentOp::RelayNext))["request"]["id"], second);
}

#[test]
fn relay_turn_and_final_reply_commit_atomically_with_retry_records() {
    let mut f = Fixture::new();
    let attached = ok(f.agent(0, f.attach(1)));
    let send = AgentOp::RelaySend {
        file_ids: vec![],
        attachment_id: attached["attachment"]["id"].as_str().unwrap().into(),
        request_id: Uuid::now_v7().to_string(),
        text: "atomic turn".into(),
        files: vec![],
    };
    f.db().execute_batch("CREATE TRIGGER fail_turn BEFORE INSERT ON relay_turns BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(matches!(f.agent(0, send.clone()), Response::Error(_)));
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        0
    );
    f.db().execute_batch("DROP TRIGGER fail_turn;").unwrap();
    let turn = ok(f.agent(0, send))["turn_id"].as_str().unwrap().to_owned();
    let reply = Fixture::respond(&turn, RelayResponseKind::Complete);
    f.db().execute_batch("CREATE TRIGGER fail_finish BEFORE UPDATE ON relay_turns BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(matches!(f.agent(1, reply.clone()), Response::Error(_)));
    assert_eq!(f.turn(&turn)["responses"], json!([]));
    assert_eq!(f.turn(&turn)["state"], "pending");
    f.db().execute_batch("DROP TRIGGER fail_finish;").unwrap();
    ok(f.agent(1, reply.clone()));
    assert_eq!(ok(f.agent(1, reply))["duplicate"], true);
    assert_eq!(f.turn(&turn)["responses"].as_array().unwrap().len(), 1);
}

#[test]
fn response_pages_preserve_files_and_revocation_hides_stored_content() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let mut f = Fixture::new();
    let (_, _, turn) = f.start_turn(1);
    let data = STANDARD.encode(vec![0xa5; MAX_FILE_BYTES]);
    for index in 0..3 {
        ok(f.agent(
            1,
            AgentOp::RelayRespond {
                file_ids: vec![],
                turn_id: turn.clone(),
                request_id: Uuid::now_v7().to_string(),
                text: format!("image {index}"),
                files: vec![FilePart {
                    name: "image.png".into(),
                    media_type: "image/png".into(),
                    data_base64: data.clone(),
                }],
                outcome: RelayResponseKind::Progress,
            },
        ));
    }
    let page = f.turn(&turn);
    assert_eq!(page["responses"].as_array().unwrap().len(), 2);
    assert_eq!(page["responses"][0]["files"][0]["data_base64"], data);
    assert_eq!(page["has_more"], true);
    let next = ok(f.agent(
        0,
        AgentOp::RelayTurnStatus {
            turn_id: turn.clone(),
            after_message_id: Some(page["next_after"].as_str().unwrap().into()),
        },
    ));
    assert_eq!(next["responses"].as_array().unwrap().len(), 1);
    assert_eq!(next["has_more"], false);
    let saved = f.current_policy();
    let mut restricted = saved.clone();
    restricted.rules.push(Rule {
        actor: Selector::Agent(f.agents[0].clone()),
        peer: Selector::Agent(f.agents[1].clone()),
        permission: Permission::Receive,
        effect: Effect::Deny,
    });
    f.policy(restricted);
    // Status must not leak response text/files when only receiving is denied.
    assert_eq!(f.turn(&turn)["responses"], json!([]));
    let mut restricted = saved.clone();
    restricted.rules.push(Rule {
        actor: Selector::Agent(f.agents[0].clone()),
        peer: Selector::Agent(f.agents[1].clone()),
        permission: Permission::Send,
        effect: Effect::Deny,
    });
    f.policy(restricted);
    assert_eq!(f.turn(&turn)["state"], "blocked");
    assert_eq!(f.turn(&turn)["responses"], json!([]));
    assert_eq!(ok(f.agent(1, AgentOp::RelayNext)), Value::Null);
    f.policy(saved);
    assert_eq!(ok(f.agent(1, AgentOp::RelayNext))["request"]["id"], turn);
    assert_eq!(f.turn(&turn)["responses"].as_array().unwrap().len(), 2);
    let mut policy = f.current_policy();
    policy.rules.clear();
    f.policy(policy);
    assert_eq!(f.turn(&turn), json!({"turn_id":turn,"state":"unavailable"}));
}

#[test]
fn relay_history_recovers_turn_ids_and_response_budget_reserves_completion() {
    let mut f = Fixture::new();
    let (attachment, _, first) = f.start_turn(1);
    for _ in 0..50 {
        ok(f.agent(
            0,
            AgentOp::RelaySend {
                file_ids: vec![],
                attachment_id: attachment.clone(),
                request_id: Uuid::now_v7().to_string(),
                text: "follow-up".into(),
                files: vec![],
            },
        ));
    }
    f.store = Store::open(f.home.path()).unwrap();
    let history = ok(f.agent(
        0,
        AgentOp::RelayTurns {
            after_turn_id: None,
        },
    ));
    assert_eq!(history["turns"].as_array().unwrap().len(), 50);
    assert_eq!(history["turns"][0]["turn_id"], first);
    assert_eq!(history["has_more"], true);
    let rest = ok(f.agent(
        0,
        AgentOp::RelayTurns {
            after_turn_id: Some(history["next_after"].as_str().unwrap().into()),
        },
    ));
    assert_eq!(rest["turns"].as_array().unwrap().len(), 1);
    assert_eq!(rest["has_more"], false);
    assert!(matches!(
        f.agent(
            2,
            AgentOp::RelayTurns {
                after_turn_id: Some(first.clone())
            }
        ),
        Response::Error(_)
    ));
    for _ in 0..15 {
        ok(f.agent(1, Fixture::respond(&first, RelayResponseKind::Progress)));
    }
    assert!(matches!(
        f.agent(1, Fixture::respond(&first, RelayResponseKind::Progress)),
        Response::Error(_)
    ));
    ok(f.agent(
        0,
        AgentOp::RelayCancel {
            turn_id: first.clone(),
            request_id: Uuid::now_v7().to_string(),
        },
    ));
    assert!(matches!(
        f.agent(
            0,
            AgentOp::RelayCancel {
                turn_id: first.clone(),
                request_id: Uuid::now_v7().to_string()
            }
        ),
        Response::Error(_)
    ));
    ok(f.agent(1, Fixture::respond(&first, RelayResponseKind::Cancelled)));
    assert_eq!(f.turn(&first)["responses"].as_array().unwrap().len(), 16);
    assert_ne!(ok(f.agent(1, AgentOp::RelayNext))["request"]["id"], first);
}

#[test]
fn temporary_permission_block_does_not_let_later_turns_overtake_the_head() {
    let mut f = Fixture::new();
    let (_, _, first) = f.start_turn(1);
    let attachment = ok(f.agent(2, f.attach(1)))["attachment"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(f.agent(
        2,
        AgentOp::RelaySend {
            file_ids: vec![],
            attachment_id: attachment,
            request_id: Uuid::now_v7().to_string(),
            text: "later".into(),
            files: vec![],
        },
    ));
    let saved = f.current_policy();
    let mut blocked = saved.clone();
    blocked.rules.push(Rule {
        actor: Selector::Agent(f.agents[0].clone()),
        peer: Selector::Agent(f.agents[1].clone()),
        permission: Permission::Send,
        effect: Effect::Deny,
    });
    f.policy(blocked);
    assert_eq!(ok(f.agent(1, AgentOp::RelayNext)), Value::Null);
    assert_eq!(ok(f.agent(1, AgentOp::Inbox)), json!([]));
    assert_eq!(f.turn(&first)["state"], "blocked");
    f.policy(saved);
    assert_eq!(ok(f.agent(1, AgentOp::RelayNext))["request"]["id"], first);
}

#[test]
fn relay_selection_is_open_by_default_and_obeys_explicit_restrictions() {
    let mut f = Fixture::new();
    f.policy(Policy::default());
    assert!(matches!(f.agent(0, f.attach(1)), Response::Error(_)));
    assert!(matches!(
        f.agent(
            0,
            AgentOp::Send {
                file_ids: vec![],
                recipient: f.agents[1].clone(),
                request_id: Uuid::now_v7().to_string(),
                text: "grant is not permission".into(),
                files: vec![]
            }
        ),
        Response::Error(_)
    ));
    f.allow();
    assert_eq!(ok(f.agent(0, f.attach(2)))["state"], "attached");
    for (actor, peer, permission) in [
        (0, 1, Permission::Enumerate),
        (1, 0, Permission::Enumerate),
        (0, 1, Permission::Send),
        (1, 0, Permission::Receive),
    ] {
        let mut policy = f.current_policy();
        policy.rules.push(Rule {
            actor: Selector::Agent(f.agents[actor].clone()),
            peer: Selector::Agent(f.agents[peer].clone()),
            permission,
            effect: Effect::Deny,
        });
        f.policy(policy);
        assert!(matches!(f.agent(0, f.attach(1)), Response::Error(_)));
        f.allow();
    }
    let attached = ok(f.agent(0, f.attach(1)));
    assert_eq!(attached["state"], "attached");
    assert_eq!(attached["attachment"]["security_mode"], "local_daemon");
    assert_eq!(attached["supports_turns"], true);
    assert!(attached["attachment"].get("grant_id").is_none());
    assert!(attached["attachment"].get("expires_at").is_none());
    assert!(f.current_policy().relay_grants.is_empty());
    assert_eq!(ok(f.agent(1, AgentOp::Inbox)), json!([]));
}

#[test]
fn retries_switches_and_explicit_detach_survive_restart_without_changing_target() {
    let mut f = Fixture::new();
    let first = f.attach(1);
    let a = ok(f.agent(0, first.clone()));
    let id = a["attachment"]["id"].as_str().unwrap();
    assert_eq!(ok(f.agent(0, first.clone())), a);
    let mut changed = first.clone();
    if let AgentOp::RelayAttach { target, .. } = &mut changed {
        *target = f.agents[2].clone();
    }
    assert!(matches!(f.agent(0, changed), Response::Error(_)));
    let b = ok(f.agent(0, f.attach(2)));
    assert_eq!(ok(f.agent(0, first.clone()))["state"], "detached");
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(f.status(None)["attachment"], b["attachment"]);
    assert_eq!(
        ok(f.agent(
            0,
            AgentOp::RelayDetach {
                attachment_id: id.into()
            }
        ))["state"],
        "detached"
    );
    assert_eq!(f.status(None)["attachment"], b["attachment"]);
    assert_eq!(ok(f.agent(0, first))["state"], "detached");
    let id = b["attachment"]["id"].as_str().unwrap().to_owned();
    ok(f.agent(0, AgentOp::RelayDetach { attachment_id: id }));
    assert_eq!(f.status(None), Value::Null);
}

#[test]
fn attachments_are_isolated_and_hidden_targets_disappear_from_status() {
    let mut f = Fixture::new();
    let a = ok(f.agent(0, f.attach(1)));
    let id = a["attachment"]["id"].as_str().unwrap();
    for action in [
        AgentOp::RelayStatus {
            attachment_id: Some(id.into()),
        },
        AgentOp::RelayDetach {
            attachment_id: id.into(),
        },
    ] {
        assert!(matches!(f.agent(2, action), Response::Error(_)));
    }
    let mut policy = f.current_policy();
    policy.rules.push(Rule {
        actor: Selector::Agent(f.agents[0].clone()),
        peer: Selector::Agent(f.agents[1].clone()),
        permission: Permission::Send,
        effect: Effect::Deny,
    });
    f.policy(policy);
    assert_eq!(f.status(None)["state"], "blocked");
    let mut policy = f.current_policy();
    policy.rules.push(Rule {
        actor: Selector::Agent(f.agents[0].clone()),
        peer: Selector::Agent(f.agents[1].clone()),
        permission: Permission::Enumerate,
        effect: Effect::Deny,
    });
    f.policy(policy);
    assert_eq!(
        f.status(Some(id)),
        json!({"attachment_id":id,"state":"unavailable","supports_turns":true})
    );
    let detached = ok(f.agent(
        0,
        AgentOp::RelayDetach {
            attachment_id: id.into(),
        },
    ));
    assert_eq!(
        detached,
        json!({"attachment_id":id,"state":"unavailable","supports_turns":true})
    );
}

#[test]
fn legacy_grant_revocation_stays_effective_but_new_selections_need_no_grant() {
    let mut f = Fixture::new();
    let grant = f.grant(1, 3600);
    let action = f.attach(1);
    let a = f.legacy_attachment(action.clone(), &grant);
    assert_eq!(
        f.edit(ConfigurationEdit::RevokeRelay {
            grant_id: grant.clone()
        })["state"],
        "applied"
    );
    assert_eq!(f.status(None)["state"], "revoked");
    assert_eq!(ok(f.agent(0, action))["state"], "revoked");
    let b = ok(f.agent(0, f.attach(1)));
    assert_eq!(b["state"], "attached");
    assert_ne!(a["attachment"]["id"], b["attachment"]["id"]);
    assert_eq!(
        f.edit(ConfigurationEdit::GrantRelay {
            grant_id: grant,
            intermediary: f.agents[0].clone(),
            target: f.agents[1].clone(),
            lifetime_seconds: 3600
        })["state"],
        "rejected"
    );
}

#[test]
fn failed_switch_rolls_back_previous_selection_and_retry_record() {
    let mut f = Fixture::new();
    let a = ok(f.agent(0, f.attach(1)));
    let switch = f.attach(2);
    f.db().execute_batch("CREATE TRIGGER fail_relay_insert BEFORE INSERT ON relay_attachments BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(matches!(f.agent(0, switch.clone()), Response::Error(_)));
    assert_eq!(f.status(None)["attachment"], a["attachment"]);
    f.db()
        .execute_batch("DROP TRIGGER fail_relay_insert;")
        .unwrap();
    let b = ok(f.agent(0, switch));
    assert_eq!(b["state"], "attached");
    assert_ne!(a["attachment"]["id"], b["attachment"]["id"]);
}

#[test]
fn legacy_expiry_is_preserved_without_limiting_new_selections() {
    let mut f = Fixture::new();
    // Keep ample time to attach even on slow CI. Wait only until the signed
    // boundary; no production API accepts a caller-controlled clock.
    let grant = f.grant(1, 2);
    let action = f.attach(1);
    let a = f.legacy_attachment(action.clone(), &grant);
    let expiry = a["attachment"]["expires_at"].as_i64().unwrap();
    let sent = ok(f.agent(
        0,
        AgentOp::RelaySend {
            file_ids: vec![],
            attachment_id: a["attachment"]["id"].as_str().unwrap().into(),
            request_id: Uuid::now_v7().to_string(),
            text: "expires with grant".into(),
            files: vec![],
        },
    ));
    let turn = sent["turn_id"].as_str().unwrap();
    while now() < expiry {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(f.status(None)["state"], "expired");
    assert_eq!(ok(f.agent(0, action))["state"], "expired");
    assert_eq!(ok(f.agent(0, f.attach(1)))["state"], "attached");
    assert_eq!(f.turn(turn)["state"], "expired");
    assert_eq!(ok(f.agent(1, AgentOp::RelayNext)), Value::Null);
    assert!(matches!(
        f.agent(1, Fixture::respond(turn, RelayResponseKind::Complete)),
        Response::Error(_)
    ));
}

#[test]
fn legacy_turn_retries_survive_restart_and_revocation_does_not_revive_work() {
    let mut f = Fixture::new();
    let grant = f.grant(1, 3600);
    let action = f.attach(1);
    let attachment = f.legacy_attachment(action, &grant);
    let send = AgentOp::RelaySend {
        attachment_id: attachment["attachment"]["id"].as_str().unwrap().into(),
        request_id: Uuid::now_v7().to_string(),
        text: "existing turn".into(),
        files: vec![],
        file_ids: vec![],
    };
    let turn = ok(f.agent(0, send.clone()))["turn_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let root = ok(f.agent(1, AgentOp::RelayNext));
    assert_eq!(root["request"]["relay"]["grant_id"], grant);
    let wire = serde_json::to_string(&root["request"]).unwrap();
    let message: Message = serde_json::from_str(&wire).unwrap();
    assert_eq!(json!(message), root["request"]);
    ok(f.agent(1, Fixture::respond(&turn, RelayResponseKind::Progress)));
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(ok(f.agent(0, send))["duplicate"], true);
    f.edit(ConfigurationEdit::RevokeRelay { grant_id: grant });
    assert_eq!(f.turn(&turn)["state"], "revoked");
    assert_eq!(f.turn(&turn)["responses"], json!([]));
    assert_eq!(ok(f.agent(1, AgentOp::RelayNext)), Value::Null);
    // Selecting again must neither reauthorize nor replay an old accepted turn.
    let (_, _, new_turn) = f.start_turn(1);
    assert_eq!(
        ok(f.agent(1, AgentOp::RelayNext))["request"]["id"],
        new_turn
    );
    assert_eq!(f.turn(&turn)["state"], "revoked");
}
