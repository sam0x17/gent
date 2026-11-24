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

#[tokio::test]
async fn response_required_request_crosses_nodes_and_replies_complete_the_original_turn() {
    let relay = relay::RelayServer::start().await;
    let pair = Pair::new(&relay).await;
    pair.allow().await;
    let send = AgentOp::RequestReply {
        recipient: pair.agents[1].clone(),
        request_id: Uuid::now_v7().to_string(),
        text: "hello across nodes".into(),
        files: vec![],
        file_ids: vec![],
    };
    let sent = ok(pair.agent(0, send.clone()));
    let id = sent["message_id"].as_str().unwrap().to_owned();
    pair.wait(|| {
        !ok(pair.agent(1, AgentOp::Inbox))
            .as_array()
            .unwrap()
            .is_empty()
    })
    .await;
    ok(pair.agent(
        1,
        AgentOp::Ack {
            message_id: id.clone(),
        },
    ));
    let reply = AgentOp::Reply {
        message_id: id.clone(),
        request_id: Uuid::now_v7().to_string(),
        text: "remote answer".into(),
        files: vec![],
        file_ids: vec![],
    };
    let response = ok(pair.agent(1, reply.clone()));
    pair.wait(|| {
        ok(pair.agent(
            0,
            AgentOp::RelayTurnStatus {
                turn_id: id.clone(),
                after_message_id: None,
            },
        ))["state"]
            == "completed"
    })
    .await;
    let status = ok(pair.agent(
        0,
        AgentOp::RelayTurnStatus {
            turn_id: id.clone(),
            after_message_id: None,
        },
    ));
    assert_eq!(status["responses"][0]["text"], "remote answer");
    assert_eq!(ok(pair.agent(0, send))["message_id"], id);
    assert_eq!(
        ok(pair.agent(1, reply))["message_id"],
        response["message_id"]
    );
}

#[tokio::test]
async fn diagnostics_distinguish_relay_contact_failed_streams_and_recovery() {
    use std::sync::atomic::Ordering;
    let relay = relay::RelayServer::start().await;
    let pair = Pair::new(&relay).await;
    pair.wait(|| {
        pair.owner(0, OwnerOp::Diagnose)["relay"]["health"]["last_success_at"].is_number()
    })
    .await;
    relay.mode.store(1, Ordering::SeqCst);
    let _ = relay.notices.send(relay::Notice::Close);
    pair.wait(|| {
        pair.owner(0, OwnerOp::Diagnose)["relay"]["health"]["retrying_streams"]
            .as_u64()
            .unwrap_or(0)
            > 0
    })
    .await;
    let failed = pair.owner(0, OwnerOp::Diagnose);
    assert!(failed["relay"]["health"]["last_failure_at"].is_number());
    assert!(!failed.to_string().contains(&relay.token));
    relay.mode.store(0, Ordering::SeqCst);
    pair.wait(|| {
        let h = &pair.owner(0, OwnerOp::Diagnose)["relay"]["health"];
        h["retrying_streams"] == 0 && h["notifications_connected"] == true
    })
    .await;
    assert!(pair.owner(0, OwnerOp::Diagnose)["relay"]["health"]["last_success_at"].is_number());
}
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
        Self::configured(&relay.endpoint, &relay.token).await
    }
    async fn configured(endpoint: &str, token: &str) -> Self {
        let homes: [tempfile::TempDir; 2] = std::array::from_fn(|_| {
            let temp = tempfile::tempdir().unwrap();
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            temp
        });
        let mut cfg = config::initialize(homes[0].path(), "remote").unwrap();
        // Retain explicit allowlist coverage alongside blacklist mesh tests.
        cfg.policy = Policy::default();
        cfg.relay = Some(config::RelayConfig {
            endpoint: endpoint.into(),
            credential_file: "relay.key".into(),
        });
        config::write_private(&homes[0].path().join("relay.key"), token.as_bytes()).unwrap();
        config::save(homes[0].path(), &cfg).unwrap();
        gent_daemon::entitlements::grant_test(homes[0].path(), &cfg);
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
                replace_node: None,
                cluster: &cfg.cluster.id,
                name: "peer",
                relay_endpoint: None,
            },
            &mut peer,
        )
        .await
        .unwrap();
        gent_daemon::entitlements::grant_test(
            homes[1].path(),
            &config::load(homes[1].path()).unwrap(),
        );
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
            file_ids: vec![],
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
        pair.agent(0, pair.send("hidden", vec![], &Uuid::now_v7().to_string())),
        Response::Error(_)
    ));
    pair.allow().await;
    let bytes = vec![0xc5; 1024 * 1024];
    let file = FilePart {
        name: "visual.png".into(),
        media_type: "image/png".into(),
        data_base64: STANDARD.encode(&bytes),
    };
    let request = Uuid::now_v7().to_string();
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
                file_ids: vec![],
                recipient: pair.agents[0].clone(),
                request_id: Uuid::now_v7().to_string(),
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
            file_ids: vec![],
            message_id: message.clone(),
            request_id: Uuid::now_v7().to_string(),
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
        pair.send("offline-work", vec![], &Uuid::now_v7().to_string()),
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
async fn legacy_grant_proposals_sync_without_restricting_new_cross_node_selection() {
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
        request_id: Uuid::now_v7().to_string(),
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
    assert_eq!(ok(pair.agent(0, attach))["state"], "attached");
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

fn import_file(pair: &Pair, bytes: &[u8]) -> String {
    let folders = ok(pair.agent(0, AgentOp::FilePaths));
    fs::write(
        std::path::Path::new(folders["import_directory"].as_str().unwrap())
            .join("private-render.bin"),
        bytes,
    )
    .unwrap();
    ok(pair.agent(
        0,
        AgentOp::FileImport {
            request_id: Uuid::now_v7().to_string(),
            name: "private-render.bin".into(),
            media_type: "application/x-gent-private-image".into(),
        },
    ))["file"]["id"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn attached_message(pair: &Pair, id: &str) -> AgentOp {
    AgentOp::Send {
        recipient: pair.agents[1].clone(),
        request_id: Uuid::now_v7().to_string(),
        text: "attachment visual review".into(),
        files: vec![],
        file_ids: vec![id.into()],
    }
}
fn file_ready(pair: &Pair, node: usize, id: &str) -> bool {
    matches!(pair.agent(node,AgentOp::FileStatus {file_id:id.into()}),Response::Ok(v) if v["state"]=="ready")
}
async fn receive_file(pair: &Pair, node: usize) -> String {
    pair.wait(|| {
        !ok(pair.agent(node, AgentOp::Inbox))
            .as_array()
            .unwrap()
            .is_empty()
    })
    .await;
    let inbox = ok(pair.agent(node, AgentOp::Inbox));
    let id = inbox[0]["attachments"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    pair.wait(|| file_ready(pair, node, &id)).await;
    id
}
fn exported(pair: &Pair, node: usize, id: &str) -> Vec<u8> {
    let result = ok(pair.agent(node, AgentOp::FileExport { file_id: id.into() }));
    fs::read(result["path"].as_str().unwrap()).unwrap()
}
#[tokio::test]
async fn automatic_attachment_dispatch_recovers_storage_loss_restart_and_rechecks_revocation() {
    use std::sync::atomic::Ordering;
    let relay = relay::RelayServer::start().await;
    let mut pair = Pair::new(&relay).await;
    pair.allow().await;
    let bytes = vec![0x83; 2 * 1024 * 1024 + 7];
    let source = import_file(&pair, &bytes);
    pair.tasks[1].take();
    relay.mode.store(1, Ordering::SeqCst);
    let action = attached_message(&pair, &source);
    let sent = ok(pair.agent(0, action.clone()));
    pair.reopen(0);
    relay.mode.store(0, Ordering::SeqCst);
    pair.wait(|| {
        relay.data.lock().unwrap().iter().any(|(k, v)| {
            k.starts_with("objects/") && v.len() == 10 && v[1..].iter().all(|b| !b.is_empty())
        })
    })
    .await;
    // Erase relay ciphertext while keeping the sender's durable uploaded flags.
    relay
        .data
        .lock()
        .unwrap()
        .retain(|k, _| !k.starts_with("objects/"));
    pair.reopen(0);
    pair.wait(|| {
        relay
            .data
            .lock()
            .unwrap()
            .keys()
            .any(|k| k.starts_with("objects/"))
    })
    .await;
    pair.reopen(1);
    let id = receive_file(&pair, 1).await;
    assert_ne!(id, source);
    assert_eq!(exported(&pair, 1, &id), bytes);
    assert_eq!(ok(pair.agent(0, action))["message_id"], sent["message_id"]);
    let inbox = ok(pair.agent(1, AgentOp::Inbox));
    let reply = AgentOp::Reply {
        message_id: inbox[0]["id"].as_str().unwrap().into(),
        request_id: Uuid::now_v7().to_string(),
        text: "review result".into(),
        files: vec![],
        file_ids: vec![id.clone()],
    };
    ok(pair.agent(1, reply.clone()));
    pair.reopen(1);
    let returned = receive_file(&pair, 0).await;
    assert_ne!(returned, id);
    assert_eq!(exported(&pair, 0, &returned), bytes);
    assert_eq!(ok(pair.agent(1, reply))["duplicate"], true);
    // Inspect every opaque mailbox packet and object; private metadata remains at endpoints.
    for entry in relay.data.lock().unwrap().values() {
        for bytes in entry {
            for private in [
                "private-render.bin",
                "application/x-gent-private-image",
                "attachment visual review",
            ] {
                assert!(
                    !bytes
                        .windows(private.len())
                        .any(|w| w == private.as_bytes())
                );
            }
        }
    }
    let revision = pair.owner(
        0,
        OwnerOp::SetPolicy {
            policy: Policy::default(),
        },
    )["revision"]
        .as_u64()
        .unwrap();
    pair.wait(|| config::load(pair.homes[1].path()).unwrap().applied_revision == Some(revision))
        .await;
    assert!(matches!(
        pair.agent(1, AgentOp::FileExport { file_id: id }),
        Response::Error(_)
    ));
    assert!(matches!(
        pair.agent(0, AgentOp::FileExport { file_id: returned }),
        Response::Error(_)
    ));
}

#[tokio::test]
#[ignore = "requires local Wrangler and GENT_TEST_RELAY_TOKEN_FILE"]
async fn wrangler_dispatches_agent_attachments_with_native_files_and_restart() {
    let endpoint = std::env::var("GENT_TEST_RELAY_URL").unwrap();
    let token = config::read_private(std::path::Path::new(
        &std::env::var("GENT_TEST_RELAY_TOKEN_FILE").unwrap(),
    ))
    .unwrap();
    let mut pair = Pair::configured(&endpoint, &token).await;
    pair.allow().await;
    let bytes: Vec<_> = (0..gent_protocol::file_objects::MAX_FILE_BYTES)
        .map(|i| (i * 31 + 7) as u8)
        .collect();
    let source = import_file(&pair, &bytes);
    pair.tasks[1].take();
    let action = attached_message(&pair, &source);
    let sent = ok(pair.agent(0, action.clone()));
    pair.reopen(0);
    pair.reopen(1);
    // 32 MiB debug crypto plus actual R2 writes can take longer than small tests.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    let received = loop {
        let inbox = ok(pair.agent(1, AgentOp::Inbox));
        if let Some(id) = inbox
            .get(0)
            .and_then(|m| m["attachments"][0]["id"].as_str())
            && file_ready(&pair, 1, id)
        {
            break id.to_owned();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "large agent attachment timed out"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    pair.reopen(1);
    assert_eq!(exported(&pair, 1, &received), bytes);
    assert_eq!(ok(pair.agent(0, action))["message_id"], sent["message_id"]);
    let inbox = ok(pair.agent(1, AgentOp::Inbox));
    let reply = AgentOp::Reply {
        message_id: inbox[0]["id"].as_str().unwrap().into(),
        request_id: Uuid::now_v7().to_string(),
        text: "verified complete image".into(),
        files: vec![],
        file_ids: vec![received.clone()],
    };
    ok(pair.agent(1, reply));
    pair.reopen(1);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    let returned = loop {
        let inbox = ok(pair.agent(0, AgentOp::Inbox));
        if let Some(id) = inbox
            .get(0)
            .and_then(|m| m["attachments"][0]["id"].as_str())
            && file_ready(&pair, 0, id)
        {
            break id.to_owned();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "large forwarded file timed out"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_ne!(received, returned);
    assert_eq!(exported(&pair, 0, &returned), bytes);
    if let Ok(root) = std::env::var("GENT_AGENT_FILE_PROOF_ROOT") {
        for task in &mut pair.tasks {
            task.take();
        }
        for (i, home) in pair.homes.iter().enumerate() {
            let path = std::path::Path::new(&root).join(format!("node-{i}"));
            config::private_dir(&path).unwrap();
            // SQLite's backup is taken while the Store mutex excludes mutations.
            // VACUUM INTO avoids depending on uncheckpointed WAL files.
            let _guard = pair.stores[i].lock().unwrap();
            let db = rusqlite::Connection::open(home.path().join("state.sqlite3")).unwrap();
            db.execute(
                "VACUUM INTO ?1",
                [path.join("state.sqlite3").to_str().unwrap()],
            )
            .unwrap();
            fs::set_permissions(
                path.join("state.sqlite3"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        config::write_private(&std::path::Path::new(&root).join("report.json"),&serde_json::to_vec(&json!({"sent":sent,"source":source,"received":received,"returned":returned,"bytes":bytes.len()})).unwrap()).unwrap();
        println!("Retained agent attachment evidence in {root}");
    }
}

#[tokio::test]
async fn configuration_sync_continues_while_object_requests_are_stalled() {
    use std::sync::atomic::Ordering;
    let relay = relay::RelayServer::start().await;
    let pair = Pair::new(&relay).await;
    pair.allow().await;
    let source = import_file(&pair, b"file server stall");
    relay.mode.store(6, Ordering::SeqCst);
    ok(pair.agent(0, attached_message(&pair, &source)));
    pair.wait(|| relay.data.lock().unwrap().contains_key("blocked-object"))
        .await;
    // The file HTTP call remains in flight for six seconds. Ordinary signed
    // configuration must propagate without awaiting it or consuming its retries.
    let revision = pair.owner(
        0,
        OwnerOp::SetPolicy {
            policy: Policy::default(),
        },
    )["revision"]
        .as_u64()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while config::load(pair.homes[1].path()).unwrap().applied_revision != Some(revision) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("file transfer blocked configuration sync");
    assert!(
        ok(pair.agent(1, AgentOp::Inbox))
            .as_array()
            .unwrap()
            .is_empty()
    );
}
