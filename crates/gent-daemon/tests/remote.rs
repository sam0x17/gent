#[path = "support/relay.rs"]
mod relay;
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gent_daemon::{
    config,
    pairing::{self, Peer},
    store::Store,
    sync,
};
use gent_protocol::{
    AgentOp, Effect, FilePart, OwnerOp, PairingOp, Permission, Policy, Request, Response, Rule,
    Selector,
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::task::JoinHandle;
use uuid::Uuid;

struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn ok(response: Response) -> Value {
    match response {
        Response::Ok(value) => value,
        Response::Error(error) => panic!("{error}"),
    }
}
struct OwnerPeer {
    store: Arc<Mutex<Store>>,
    credential: String,
    cluster: String,
}
impl Peer for OwnerPeer {
    async fn call(&mut self, action: PairingOp) -> Result<Value> {
        match self.store.lock().unwrap().handle(Request::Owner {
            credential: self.credential.clone(),
            action: OwnerOp::Pair {
                cluster_id: self.cluster.clone(),
                action,
            },
        }) {
            Response::Ok(value) => Ok(value),
            Response::Error(error) => anyhow::bail!(error),
        }
    }
}
struct Pair {
    homes: [tempfile::TempDir; 2],
    stores: [Arc<Mutex<Store>>; 2],
    owners: [String; 2],
    agents: [String; 2],
    keys: [String; 2],
    tasks: [Option<Task>; 2],
}
impl Pair {
    async fn new(relay: &relay::RelayServer) -> Self {
        let homes: [tempfile::TempDir; 2] = std::array::from_fn(|_| {
            let temp = tempfile::tempdir().unwrap();
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            temp
        });
        let mut cfg = config::initialize(homes[0].path(), "remote").unwrap();
        cfg.relay = Some(config::RelayConfig {
            endpoint: relay.endpoint.clone(),
            credential_file: "relay.key".into(),
        });
        config::write_private(&homes[0].path().join("relay.key"), relay.token.as_bytes()).unwrap();
        config::save(homes[0].path(), &cfg).unwrap();
        let source = Arc::new(Mutex::new(Store::open(homes[0].path()).unwrap()));
        let owner = config::read_private(&homes[0].path().join("owner.key")).unwrap();
        let mut peer = OwnerPeer {
            store: source.clone(),
            credential: owner,
            cluster: cfg.cluster.id.clone(),
        };
        pairing::join(
            homes[1].path(),
            pairing::Options {
                cluster: &cfg.cluster.id,
                name: "peer",
                relay_endpoint: None,
            },
            &mut peer,
        )
        .await
        .unwrap();
        let target = Arc::new(Mutex::new(Store::open(homes[1].path()).unwrap()));
        let stores = [source, target];
        let keys = std::array::from_fn(|_| config::secret());
        let owners = std::array::from_fn(|i| {
            config::read_private(&homes[i].path().join("owner.key")).unwrap()
        });
        let agents = std::array::from_fn(|i| {
            ok(stores[i].lock().unwrap().handle(Request::Agent {
                credential: keys[i].clone(),
                action: AgentOp::Register {
                    name: format!("private-agent-{i}"),
                    provider: "arbitrary-mcp-host".into(),
                },
            }))["agent"]["id"]
                .as_str()
                .unwrap()
                .to_owned()
        });
        let tasks =
            std::array::from_fn(|i| Some(Task(sync::start(stores[i].clone()).unwrap().unwrap())));
        let pair = Self {
            homes,
            stores,
            owners,
            agents,
            keys,
            tasks,
        };
        pair.wait(|| {
            pair.owner(0, OwnerOp::Agents).as_array().unwrap().len() == 2
                && pair.owner(1, OwnerOp::Agents).as_array().unwrap().len() == 2
        })
        .await;
        pair
    }
    fn owner(&self, node: usize, action: OwnerOp) -> Value {
        ok(self.stores[node].lock().unwrap().handle(Request::Owner {
            credential: self.owners[node].clone(),
            action,
        }))
    }
    fn agent(&self, node: usize, action: AgentOp) -> Response {
        self.stores[node].lock().unwrap().handle(Request::Agent {
            credential: self.keys[node].clone(),
            action,
        })
    }
    async fn wait(&self, mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(25), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("remote delivery timed out");
    }
    fn policy(&self) -> Policy {
        let mut policy = Policy::default();
        for (a, b, p) in [
            (0, 1, Permission::Enumerate),
            (1, 0, Permission::Enumerate),
            (0, 1, Permission::Send),
            (1, 0, Permission::Receive),
        ] {
            policy.rules.push(Rule {
                actor: Selector::Agent(self.agents[a].clone()),
                peer: Selector::Agent(self.agents[b].clone()),
                permission: p,
                effect: Effect::Allow,
            });
        }
        policy
    }
    async fn allow(&self) {
        let revision = self.owner(
            0,
            OwnerOp::SetPolicy {
                policy: self.policy(),
            },
        )["revision"]
            .as_u64()
            .unwrap();
        self.wait(|| {
            config::load(self.homes[1].path()).unwrap().applied_revision == Some(revision)
        })
        .await;
    }
    fn send(&self, text: &str, files: Vec<FilePart>, request: &str) -> AgentOp {
        AgentOp::Send {
            recipient: self.agents[1].clone(),
            request_id: request.into(),
            text: text.into(),
            files,
        }
    }
    fn reopen(&mut self, node: usize) {
        self.tasks[node].take();
        self.stores[node] = Arc::new(Mutex::new(Store::open(self.homes[node].path()).unwrap()));
        self.tasks[node] = Some(Task(
            sync::start(self.stores[node].clone()).unwrap().unwrap(),
        ));
    }
}

#[tokio::test]
async fn remote_images_scoped_replies_and_authenticated_receipts_survive_restart() {
    let relay = relay::RelayServer::start().await;
    let mut pair = Pair::new(&relay).await;
    assert_eq!(ok(pair.agent(0, AgentOp::Agents)), json!([]));
    assert_eq!(ok(pair.agent(1, AgentOp::Agents)), json!([]));
    assert!(matches!(
        pair.agent(0, pair.send("hidden", vec![], &Uuid::new_v4().to_string())),
        Response::Error(_)
    ));
    pair.allow().await;
    let bytes = vec![0xc5; 1024 * 1024];
    let file = FilePart {
        name: "visual.png".into(),
        media_type: "image/png".into(),
        data_base64: STANDARD.encode(&bytes),
    };
    let request = Uuid::new_v4().to_string();
    let action = pair.send("private-visual-review", vec![file.clone()], &request);
    let sent = ok(pair.agent(0, action.clone()));
    assert_eq!(ok(pair.agent(0, action))["message_id"], sent["message_id"]);
    pair.wait(|| {
        !ok(pair.agent(1, AgentOp::Inbox))
            .as_array()
            .unwrap()
            .is_empty()
    })
    .await;
    pair.reopen(1);
    let inbox = ok(pair.agent(1, AgentOp::Inbox));
    assert_eq!(inbox.as_array().unwrap().len(), 1);
    assert_eq!(inbox[0]["text"], "private-visual-review");
    assert_eq!(
        STANDARD
            .decode(inbox[0]["files"][0]["data_base64"].as_str().unwrap())
            .unwrap(),
        bytes
    );
    assert!(matches!(
        pair.agent(
            1,
            AgentOp::Send {
                recipient: pair.agents[0].clone(),
                request_id: Uuid::new_v4().to_string(),
                text: "unsolicited".into(),
                files: vec![]
            }
        ),
        Response::Error(_)
    ));
    let message = sent["message_id"].as_str().unwrap().to_owned();
    ok(pair.agent(
        1,
        AgentOp::Reply {
            message_id: message.clone(),
            request_id: Uuid::new_v4().to_string(),
            text: "scoped feedback".into(),
            files: vec![],
        },
    ));
    pair.wait(|| {
        !ok(pair.agent(0, AgentOp::Inbox))
            .as_array()
            .unwrap()
            .is_empty()
    })
    .await;
    assert_eq!(ok(pair.agent(0, AgentOp::Inbox))[0]["reply_to"], message);
    ok(pair.agent(
        1,
        AgentOp::Ack {
            message_id: message.clone(),
        },
    ));
    pair.wait(|| {
        ok(pair.agent(
            0,
            AgentOp::MessageStatus {
                message_id: message.clone(),
            },
        ))["state"]
            == "delivered"
    })
    .await;
    for packet in relay.data.lock().unwrap().values().flatten() {
        assert!(packet.len() <= 1024 * 1024);
        let wire = String::from_utf8_lossy(packet);
        assert!(!wire.contains("private-visual-review") && !wire.contains("private-agent"));
    }
}

#[tokio::test]
async fn queued_remote_work_and_directory_tombstones_obey_newer_permissions() {
    let relay = relay::RelayServer::start().await;
    let mut pair = Pair::new(&relay).await;
    pair.allow().await;
    pair.tasks[1].take();
    relay.mode.store(1, std::sync::atomic::Ordering::SeqCst);
    let sent = ok(pair.agent(
        0,
        pair.send("offline-work", vec![], &Uuid::new_v4().to_string()),
    ));
    let mut policy = pair.policy();
    policy.rules.push(Rule {
        actor: Selector::Agent(pair.agents[1].clone()),
        peer: Selector::Agent(pair.agents[0].clone()),
        permission: Permission::Receive,
        effect: Effect::Deny,
    });
    let revision = pair.owner(0, OwnerOp::SetPolicy { policy })["revision"]
        .as_u64()
        .unwrap();
    relay.mode.store(0, std::sync::atomic::Ordering::SeqCst);
    pair.reopen(1);
    pair.wait(|| config::load(pair.homes[1].path()).unwrap().applied_revision == Some(revision))
        .await;
    assert_eq!(ok(pair.agent(1, AgentOp::Inbox)), json!([]));
    assert_eq!(
        ok(pair.agent(
            0,
            AgentOp::MessageStatus {
                message_id: sent["message_id"].as_str().unwrap().into()
            }
        ))["state"],
        "revoked"
    );
    pair.owner(
        1,
        OwnerOp::Revoke {
            agent_id: pair.agents[1].clone(),
        },
    );
    pair.wait(|| {
        pair.owner(0, OwnerOp::Agents)
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["id"] == pair.agents[1] && a["revoked"] == true)
    })
    .await;
    assert_eq!(ok(pair.agent(0, AgentOp::Agents)), json!([]));
}

fn edit(label: &str) -> gent_protocol::ConfigurationEdit {
    gent_protocol::ConfigurationEdit::Policy {
        policy: Policy {
            groups: std::collections::BTreeMap::from([(label.into(), vec![])]),
            ..Default::default()
        },
    }
}
fn request_status(pair: &Pair, node: usize, id: &str) -> Value {
    pair.owner(
        node,
        OwnerOp::ConfigurationRequests {
            request_id: Some(id.into()),
        },
    )
}

#[tokio::test]
async fn relay_grant_proposals_sync_and_revoke_persistent_cross_node_selection() {
    use gent_protocol::ConfigurationEdit;
    let relay = relay::RelayServer::start().await;
    let mut pair = Pair::new(&relay).await;
    pair.allow().await;
    // Wait for directory announcements before the owner resolves grant endpoints.
    pair.wait(|| ok(pair.agent(0, AgentOp::Agents)).as_array().unwrap().len() == 1)
        .await;
    let grant = Uuid::new_v4().to_string();
    let proposal = OwnerOp::Configure {
        request_id: grant.clone(),
        edit: ConfigurationEdit::GrantRelay {
            grant_id: grant.clone(),
            intermediary: pair.agents[0].clone(),
            target: pair.agents[1].clone(),
            lifetime_seconds: 3600,
        },
    };
    assert_eq!(pair.owner(1, proposal.clone())["state"], "queued");
    pair.wait(|| request_status(&pair, 1, &grant)["state"] == "applied")
        .await;
    assert_eq!(pair.owner(1, proposal)["state"], "applied");
    for home in &pair.homes {
        assert!(
            config::load(home.path())
                .unwrap()
                .policy
                .relay_grants
                .contains_key(&grant)
        );
    }
    let attach = AgentOp::RelayAttach {
        target: pair.agents[1].clone(),
        request_id: Uuid::new_v4().to_string(),
    };
    let attached = ok(pair.agent(0, attach.clone()));
    assert_eq!(attached["state"], "attached");
    assert_eq!(
        attached["attachment"]["security_mode"],
        "encrypted_daemon_link"
    );
    pair.reopen(0);
    assert_eq!(
        ok(pair.agent(
            0,
            AgentOp::RelayStatus {
                attachment_id: None
            }
        ))["attachment"],
        attached["attachment"]
    );
    let revoke = Uuid::new_v4().to_string();
    pair.owner(
        1,
        OwnerOp::Configure {
            request_id: revoke.clone(),
            edit: ConfigurationEdit::RevokeRelay {
                grant_id: grant.clone(),
            },
        },
    );
    pair.wait(|| request_status(&pair, 1, &revoke)["state"] == "applied")
        .await;
    assert_eq!(ok(pair.agent(0, attach))["state"], "revoked");
    for node in 0..2 {
        let grants = pair.owner(node, OwnerOp::RelayGrants);
        assert_eq!(grants["grants"], json!({}));
        assert_eq!(grants["retired"], json!([grant]));
    }
}
#[tokio::test]
async fn offline_configuration_requests_survive_restart_and_later_acceptance_wins() {
    let relay = relay::RelayServer::start().await;
    let mut pair = Pair::new(&relay).await;
    pair.tasks[0].take();
    let id = Uuid::new_v4().to_string();
    let action = OwnerOp::Configure {
        request_id: id.clone(),
        edit: edit("offline-proposal"),
    };
    assert_eq!(pair.owner(1, action.clone())["state"], "queued");
    assert!(
        !config::load(pair.homes[1].path())
            .unwrap()
            .policy
            .groups
            .contains_key("offline-proposal")
    );
    pair.reopen(1);
    assert_eq!(request_status(&pair, 1, &id)["state"], "queued");
    let earlier = pair.owner(
        0,
        OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit: edit("accepted-before-offline-request"),
        },
    )["revision"]
        .as_u64()
        .unwrap();
    pair.reopen(0);
    pair.wait(|| request_status(&pair, 1, &id)["state"] == "applied")
        .await;
    assert_eq!(request_status(&pair, 1, &id)["revision"], earlier + 1);
    for home in &pair.homes {
        assert!(
            config::load(home.path())
                .unwrap()
                .policy
                .groups
                .contains_key("offline-proposal")
        );
    }
    let after = pair.owner(
        0,
        OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit: edit("newest"),
        },
    )["revision"]
        .as_u64()
        .unwrap();
    pair.wait(|| config::load(pair.homes[1].path()).unwrap().applied_revision == Some(after))
        .await;
    assert_eq!(pair.owner(1, action)["revision"], earlier + 1);
    assert_eq!(
        pair.owner(0, OwnerOp::Status)["authority"]["revision"],
        after
    );
    assert!(
        config::load(pair.homes[1].path())
            .unwrap()
            .policy
            .groups
            .contains_key("newest")
    );
    assert!(matches!(
        pair.stores[1].lock().unwrap().handle(Request::Owner {
            credential: pair.owners[1].clone(),
            action: OwnerOp::Configure {
                request_id: id,
                edit: edit("conflicting-retry")
            }
        }),
        Response::Error(_)
    ));
    for packet in relay.data.lock().unwrap().values().flatten() {
        assert!(!String::from_utf8_lossy(packet).contains("offline-proposal"));
    }
}

#[tokio::test]
async fn revoked_configuration_grant_rejects_pending_edit_without_blocking_later_work() {
    let relay = relay::RelayServer::start().await;
    let mut pair = Pair::new(&relay).await;
    let node = config::load(pair.homes[1].path()).unwrap().node.id;
    pair.tasks[1].take();
    let id = Uuid::new_v4().to_string();
    pair.owner(
        1,
        OwnerOp::Configure {
            request_id: id.clone(),
            edit: edit("must-not-apply"),
        },
    );
    let revoked = pair.owner(
        0,
        OwnerOp::DelegateConfiguration {
            node_id: node.clone(),
            allow: false,
        },
    )["revision"]
        .as_u64()
        .unwrap();
    pair.reopen(1);
    pair.wait(|| request_status(&pair, 1, &id)["state"] == "rejected")
        .await;
    assert_eq!(
        pair.owner(0, OwnerOp::Status)["authority"]["revision"],
        revoked
    );
    assert!(
        !config::load(pair.homes[0].path())
            .unwrap()
            .policy
            .groups
            .contains_key("must-not-apply")
    );
    assert!(matches!(
        pair.stores[1].lock().unwrap().handle(Request::Owner {
            credential: pair.owners[1].clone(),
            action: OwnerOp::DelegateConfiguration {
                node_id: node.clone(),
                allow: true
            }
        }),
        Response::Error(_)
    ));
    let granted = pair.owner(
        0,
        OwnerOp::DelegateConfiguration {
            node_id: node.clone(),
            allow: true,
        },
    )["revision"]
        .as_u64()
        .unwrap();
    pair.wait(|| config::load(pair.homes[1].path()).unwrap().applied_revision == Some(granted))
        .await;
    let rename = Uuid::new_v4().to_string();
    pair.owner(
        1,
        OwnerOp::Configure {
            request_id: rename.clone(),
            edit: gent_protocol::ConfigurationEdit::RenameNode {
                name: "new-peer-name".into(),
            },
        },
    );
    pair.wait(|| request_status(&pair, 1, &rename)["state"] == "applied")
        .await;
    assert_eq!(config::load(pair.homes[1].path()).unwrap().node.id, node);
    assert_eq!(
        config::load(pair.homes[1].path()).unwrap().node.name,
        "new-peer-name"
    );
    assert_eq!(request_status(&pair, 1, &id)["state"], "rejected");
    assert!(matches!(
        pair.stores[1].lock().unwrap().handle(Request::Owner {
            credential: pair.keys[1].clone(),
            action: OwnerOp::Configure {
                request_id: Uuid::new_v4().to_string(),
                edit: edit("agent-escalation")
            }
        }),
        Response::Error(_)
    ));
}
