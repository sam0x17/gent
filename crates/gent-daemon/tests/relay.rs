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
            request_id: Uuid::new_v4().to_string(),
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
fn relay_selection_needs_both_owner_grant_and_ordinary_permissions() {
    let mut f = Fixture::new();
    f.grant(1, 3600);
    assert!(matches!(f.agent(0, f.attach(1)), Response::Error(_)));
    assert!(matches!(
        f.agent(
            0,
            AgentOp::Send {
                recipient: f.agents[1].clone(),
                request_id: Uuid::new_v4().to_string(),
                text: "grant is not permission".into(),
                files: vec![]
            }
        ),
        Response::Error(_)
    ));
    f.allow();
    assert!(matches!(f.agent(0, f.attach(2)), Response::Error(_)));
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
    assert_eq!(attached["supports_turns"], false);
    assert_eq!(ok(f.agent(1, AgentOp::Inbox)), json!([]));
}

#[test]
fn retries_switches_and_explicit_detach_survive_restart_without_changing_target() {
    let mut f = Fixture::new();
    f.allow();
    f.grant(1, 3600);
    f.grant(2, 3600);
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
    f.allow();
    f.grant(1, 3600);
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
        json!({"attachment_id":id,"state":"unavailable","supports_turns":false})
    );
    let detached = ok(f.agent(
        0,
        AgentOp::RelayDetach {
            attachment_id: id.into(),
        },
    ));
    assert_eq!(
        detached,
        json!({"attachment_id":id,"state":"unavailable","supports_turns":false})
    );
}

#[test]
fn revoked_grants_cannot_revive_an_attachment_even_after_a_new_grant() {
    let mut f = Fixture::new();
    f.allow();
    let grant = f.grant(1, 3600);
    let action = f.attach(1);
    let a = ok(f.agent(0, action.clone()));
    assert_eq!(
        f.edit(ConfigurationEdit::RevokeRelay {
            grant_id: grant.clone()
        })["state"],
        "applied"
    );
    assert_eq!(f.status(None)["state"], "revoked");
    f.grant(1, 3600);
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
    f.allow();
    f.grant(1, 3600);
    f.grant(2, 3600);
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
fn expired_grant_blocks_new_selection_and_expires_persisted_selection() {
    let mut f = Fixture::new();
    f.allow();
    // Keep ample time to attach even on slow CI. Wait only until the signed
    // boundary; no production API accepts a caller-controlled clock.
    f.grant(1, 2);
    let action = f.attach(1);
    let a = ok(f.agent(0, action.clone()));
    let expiry = a["attachment"]["expires_at"].as_i64().unwrap();
    while now() < expiry {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(f.status(None)["state"], "expired");
    assert_eq!(ok(f.agent(0, action))["state"], "expired");
    assert!(matches!(f.agent(0, f.attach(1)), Response::Error(_)));
}
