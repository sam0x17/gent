use super::*;
use gent_crypto::NodeIdentity;
use std::time::Duration;
use uuid::Uuid;

use super::test_support::Pair;

impl Pair {
    fn owner(&mut self, action: OwnerOp) -> Value {
        self.parent
            .execute(Request::Owner {
                credential: config::read_private(&self.homes[0].path().join("owner.key")).unwrap(),
                action,
            })
            .unwrap()
    }

    fn prepare(&mut self) {
        self.owner(OwnerOp::PrepareHostedNode {
            node_id: self.child.identity.node.id().into(),
            home: self.homes[1].path().into(),
        });
    }

    fn activate(&mut self) {
        self.prepare();
        let result = self.owner(OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit: ConfigurationEdit::HostNode {
                node_id: self.child.identity.node.id().into(),
                parent: self.parent.identity.node.id().into(),
            },
        });
        assert_eq!(result["state"], "applied", "{result}");
        self.state = self.parent.identity.state(&self.parent.db).unwrap();
    }

    fn call(&mut self, index: usize, action: AgentOp) -> Result<Value> {
        let request = if index == 0 {
            Request::Agent {
                credential: self.keys[index].clone(),
                action,
            }
        } else {
            Request::HostedAgent {
                node_id: self.child.identity.node.id().into(),
                gateway_credential: config::read_private(&self.homes[1].path().join("owner.key"))?,
                credential: self.keys[index].clone(),
                action,
            }
        };
        self.parent.execute(request)
    }

    fn policy(&mut self, rules: Vec<Rule>) {
        self.owner(OwnerOp::SetPolicy {
            policy: Policy {
                rules,
                ..Default::default()
            },
        });
    }
}

fn send(recipient: &str) -> AgentOp {
    AgentOp::Send {
        recipient: recipient.into(),
        request_id: Uuid::now_v7().to_string(),
        text: "isolated hosted fixture".into(),
        files: vec![],
        file_ids: vec![],
    }
}

fn visible(directory: &Value, id: &str) -> bool {
    directory
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["agent"]["id"] == id || entry["id"] == id)
}

fn rules(peer: Selector) -> Vec<Rule> {
    [Permission::Enumerate, Permission::Send, Permission::Receive]
        .map(|permission| Rule {
            actor: Selector::All,
            peer: peer.clone(),
            permission,
            effect: Effect::Allow,
        })
        .into()
}

#[test]
fn preparation_is_retryable_and_signed_activation_preserves_identity_and_shared_directory() {
    let mut pair = Pair::new();
    assert!(pair.call(1, AgentOp::Identity).is_err());
    pair.prepare();
    assert!(pair.call(1, AgentOp::Identity).is_err());
    let config = config::load_for_runtime(pair.homes[1].path()).unwrap();
    assert_eq!(
        config.hosted_parent().unwrap().unwrap().node_id,
        pair.parent.identity.node.id()
    );
    assert!(Store::open(pair.homes[1].path()).is_err());
    // Preparation retry occurs after the child is fenced. It uses the saved
    // migration journal rather than attempting to reopen an independent Store.
    pair.prepare();
    pair.activate();
    for i in 0..3 {
        let identity = pair.call(i, AgentOp::Identity).unwrap();
        assert_eq!(identity["agent"]["id"], pair.agents[i]);
        assert_eq!(
            identity["agent"]["node_id"],
            if i == 0 {
                pair.parent.identity.node.id()
            } else {
                pair.child.identity.node.id()
            }
        );
        let directory = pair.call(i, AgentOp::Agents).unwrap();
        for id in &pair.agents {
            assert!(visible(&directory, id), "{directory}");
        }
    }
    assert_eq!(
        pair.state
            .transport_host(pair.child.identity.node.id())
            .unwrap(),
        pair.parent.identity.node.id()
    );
    assert_eq!(
        pair.parent
            .db
            .query_row("SELECT COUNT(*) FROM hosted_nodes", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn failed_preparation_preserves_child_config_and_signed_mapping_until_retry() {
    let mut pair = Pair::new();
    let config_before = std::fs::read(config::path(pair.homes[1].path())).unwrap();
    let checkpoint = pair
        .parent
        .identity
        .state(&pair.parent.db)
        .unwrap()
        .checkpoint()
        .clone();
    pair.parent.db.execute_batch("CREATE TRIGGER fail_migration BEFORE INSERT ON agents BEGIN SELECT RAISE(ABORT,'fixture failure'); END").unwrap();
    let request = || Request::Owner {
        credential: config::read_private(&pair.homes[0].path().join("owner.key")).unwrap(),
        action: OwnerOp::PrepareHostedNode {
            node_id: pair.child.identity.node.id().into(),
            home: pair.homes[1].path().into(),
        },
    };
    assert!(pair.parent.execute(request()).is_err());
    assert_eq!(
        std::fs::read(config::path(pair.homes[1].path())).unwrap(),
        config_before
    );
    assert_eq!(
        pair.parent
            .identity
            .state(&pair.parent.db)
            .unwrap()
            .checkpoint(),
        &checkpoint
    );
    assert_eq!(
        pair.parent
            .db
            .query_row("SELECT COUNT(*) FROM hosted_nodes", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    pair.parent
        .db
        .execute_batch("DROP TRIGGER fail_migration")
        .unwrap();
    pair.activate();
    let committed = pair
        .parent
        .identity
        .state(&pair.parent.db)
        .unwrap()
        .checkpoint()
        .clone();
    let config_after = std::fs::read(config::path(pair.homes[1].path())).unwrap();
    let child_key = pair.homes[1].path().join("owner.key");
    let saved = config::read_private(&child_key).unwrap();
    config::write_private(&child_key, config::secret().as_bytes()).unwrap();
    let result = pair.parent.execute(Request::Owner {
        credential: config::read_private(&pair.homes[0].path().join("owner.key")).unwrap(),
        action: OwnerOp::PrepareHostedNode {
            node_id: pair.child.identity.node.id().into(),
            home: pair.homes[1].path().into(),
        },
    });
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("migration identity changed")
    );
    assert_eq!(
        std::fs::read(config::path(pair.homes[1].path())).unwrap(),
        config_after
    );
    assert_eq!(
        pair.parent
            .identity
            .state(&pair.parent.db)
            .unwrap()
            .checkpoint(),
        &committed
    );
    config::write_private(&child_key, saved.as_bytes()).unwrap();
    pair.prepare();
    pair.call(1, AgentOp::Identity).unwrap();
}

#[test]
fn hosted_scope_rejects_native_sibling_gateway_and_wrong_parent_credentials() {
    let mut pair = Pair::new();
    pair.activate();
    let home = tempfile::tempdir().unwrap();
    let sibling = NodeIdentity::generate().unwrap();
    let tx = pair.parent.db.unchecked_transaction().unwrap();
    let state = pair.parent.identity.state(&tx).unwrap();
    let enrollment = sibling
        .request_enrollment(state.anchor(), state.checkpoint(), "sibling", now() as u64)
        .unwrap();
    let update = state
        .enroll(
            &*pair.parent.identity.signing_owner(&tx).unwrap(),
            &enrollment,
            enrollment.fingerprint().unwrap(),
            now() as u64,
        )
        .unwrap();
    let state = pair.parent.identity.apply(&tx, update).unwrap();
    tx.commit().unwrap();
    let sibling_home = home.path().join("sibling");
    runtime::install_joined(&sibling_home, &sibling, &state).unwrap();
    pair.owner(OwnerOp::PrepareHostedNode {
        node_id: sibling.id().into(),
        home: sibling_home.clone(),
    });
    assert_eq!(
        pair.owner(OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit: ConfigurationEdit::HostNode {
                node_id: sibling.id().into(),
                parent: pair.parent.identity.node.id().into()
            }
        })["state"],
        "applied"
    );
    let sibling_key = config::secret();
    let sibling_gateway = config::read_private(&sibling_home.join("owner.key")).unwrap();
    pair.parent
        .execute(Request::HostedAgent {
            node_id: sibling.id().into(),
            gateway_credential: sibling_gateway.clone(),
            credential: sibling_key.clone(),
            action: AgentOp::Register {
                name: "sibling-chat".into(),
                provider: "test".into(),
            },
        })
        .unwrap();
    let gateway = config::read_private(&pair.homes[1].path().join("owner.key")).unwrap();
    let parent_node = pair.parent.identity.node.id().to_owned();
    for (node, key, gateway) in [
        (
            pair.child.identity.node.id(),
            pair.keys[0].clone(),
            gateway.clone(),
        ),
        (pair.child.identity.node.id(), sibling_key, gateway.clone()),
        (
            pair.child.identity.node.id(),
            pair.keys[1].clone(),
            config::secret(),
        ),
        (parent_node.as_str(), pair.keys[0].clone(), gateway.clone()),
        (sibling.id(), pair.keys[1].clone(), sibling_gateway),
    ] {
        assert!(
            pair.parent
                .execute(Request::HostedAgent {
                    node_id: node.into(),
                    gateway_credential: gateway,
                    credential: key,
                    action: AgentOp::Identity
                })
                .is_err()
        );
    }
    assert!(
        pair.parent
            .execute(Request::Agent {
                credential: pair.keys[1].clone(),
                action: AgentOp::Identity
            })
            .is_err()
    );
    for action in [
        AgentOp::FilePaths,
        AgentOp::FileImport {
            request_id: Uuid::now_v7().to_string(),
            name: "fixture".into(),
            media_type: "text/plain".into(),
        },
        AgentOp::FileExport {
            file_id: Uuid::new_v4().to_string(),
        },
    ] {
        assert!(
            pair.call(1, action)
                .unwrap_err()
                .to_string()
                .contains("local filesystem tools are unavailable")
        );
    }
    let other_home = home.path().join("other-parent");
    config::initialize(&other_home, "other-cluster").unwrap();
    let mut other = Store::open(&other_home).unwrap();
    assert!(
        other
            .execute(Request::HostedAgent {
                node_id: pair.child.identity.node.id().into(),
                gateway_credential: gateway,
                credential: pair.keys[1].clone(),
                action: AgentOp::Identity
            })
            .is_err()
    );
}

#[test]
fn native_and_hosted_send_reply_ack_and_dedupe_survive_parent_restart() {
    let mut pair = Pair::new();
    pair.activate();
    let native_send = send(&pair.agents[1]);
    let first = pair.call(0, native_send.clone()).unwrap();
    let id = first["message_id"].as_str().unwrap().to_owned();
    assert_eq!(
        pair.call(1, AgentOp::Inbox).unwrap()[0]["sender"],
        pair.agents[0]
    );
    pair.call(
        1,
        AgentOp::Ack {
            message_id: id.clone(),
        },
    )
    .unwrap();
    let reply = AgentOp::Reply {
        message_id: id,
        request_id: Uuid::now_v7().to_string(),
        text: "hosted reply".into(),
        files: vec![],
        file_ids: vec![],
    };
    let answered = pair.call(1, reply.clone()).unwrap();
    assert_eq!(
        pair.call(0, AgentOp::Inbox).unwrap()[0]["sender"],
        pair.agents[1]
    );
    let hosted_send = send(&pair.agents[0]);
    let second = pair.call(1, hosted_send.clone()).unwrap();
    let home = pair.homes[0].path().to_owned();
    drop(pair.parent);
    pair.parent = Store::open(&home).unwrap();
    for (who, action, expected) in [
        (0, native_send, first),
        (1, reply, answered),
        (1, hosted_send, second),
    ] {
        let retry = pair.call(who, action).unwrap();
        assert_eq!(retry["message_id"], expected["message_id"]);
        assert_eq!(retry["duplicate"], true);
    }
    assert_eq!(
        pair.parent
            .db
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        3
    );
}

#[test]
fn signed_node_policies_and_same_node_continue_using_logical_identity() {
    let mut pair = Pair::new();
    let mut policy = rules(Selector::All);
    for permission in [Permission::Enumerate, Permission::Send] {
        policy.push(Rule {
            actor: Selector::Node(pair.child.identity.node.id().into()),
            peer: Selector::Node(pair.parent.identity.node.id().into()),
            permission,
            effect: Effect::Deny,
        });
    }
    pair.policy(policy);
    pair.activate();
    assert!(!visible(
        &pair.call(1, AgentOp::Agents).unwrap(),
        &pair.agents[0]
    ));
    assert!(pair.call(1, send(&pair.agents[0].clone())).is_err());
    assert!(visible(
        &pair.call(1, AgentOp::Agents).unwrap(),
        &pair.agents[2]
    ));
    let mut policy = rules(Selector::All);
    policy.push(Rule {
        actor: Selector::Node(pair.parent.identity.node.id().into()),
        peer: Selector::Node(pair.child.identity.node.id().into()),
        permission: Permission::Send,
        effect: Effect::Deny,
    });
    pair.policy(policy);
    assert!(pair.call(0, send(&pair.agents[1].clone())).is_err());
    pair.policy(rules(Selector::SameNode));
    assert!(!visible(
        &pair.call(0, AgentOp::Agents).unwrap(),
        &pair.agents[1]
    ));
    assert!(!visible(
        &pair.call(1, AgentOp::Agents).unwrap(),
        &pair.agents[0]
    ));
    assert!(visible(
        &pair.call(1, AgentOp::Agents).unwrap(),
        &pair.agents[2]
    ));
    assert!(pair.call(1, send(&pair.agents[0].clone())).is_err());
    pair.call(1, send(&pair.agents[2].clone())).unwrap();
}

#[test]
fn hosted_chat_admin_requires_an_exact_owner_grant_and_cannot_exceed_it() {
    use gent_protocol::administration::{PermissionChange, RuleDecision};
    let mut pair = Pair::new();
    pair.activate();
    let grant = Uuid::new_v4().to_string();
    let change = PermissionChange {
        grant_id: grant.clone(),
        actor: pair.agents[0].clone(),
        peer: pair.agents[2].clone(),
        permission: Permission::Send,
        decision: RuleDecision::Deny,
    };
    let action = |change: PermissionChange| AgentOp::PermissionApply {
        request_id: Uuid::now_v7().to_string(),
        changes: vec![change],
    };
    assert!(pair.call(1, action(change.clone())).is_err());
    assert_eq!(
        pair.owner(OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit: ConfigurationEdit::GrantPermissionAdmin {
                grant_id: grant,
                administrator: pair.agents[1].clone(),
                actor: Selector::Agent(pair.agents[0].clone()),
                peer: Selector::Agent(pair.agents[2].clone()),
                permissions: vec![Permission::Send],
                lifetime_seconds: 3600,
                selector_rules: false,
            },
        })["state"],
        "applied"
    );
    // Delegation authorizes the exact relationship, not the logical node or
    // arbitrary peers served by the same native parent.
    let mut wrong = change.clone();
    wrong.peer = pair.agents[1].clone();
    assert!(pair.call(1, action(wrong)).is_err());
    assert!(pair.call(2, action(change.clone())).is_err());
    pair.call(
        1,
        AgentOp::PermissionPreview {
            changes: vec![change.clone()],
        },
    )
    .unwrap();
    let applied = pair.call(1, action(change)).unwrap();
    assert_eq!(applied["state"], "applied", "{applied}");
    assert!(pair.call(0, send(&pair.agents[2].clone())).is_err());
    pair.call(0, send(&pair.agents[1].clone())).unwrap();
}

async fn socket_ready(home: &Path) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !home.join("daemon.sock").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unix_proxy_scopes_json_and_binary_file_uploads_and_drains_shutdown() {
    let mut pair = Pair::new();
    pair.activate();
    let child_node = pair.child.identity.node.id().to_owned();
    let gateway = config::read_private(&pair.homes[1].path().join("owner.key")).unwrap();
    drop(pair.parent);
    drop(pair.child);
    let (parent_stop, parent_shutdown) = tokio::sync::oneshot::channel();
    let parent_home = pair.homes[0].path().to_owned();
    let parent = tokio::spawn(async move {
        crate::run_until(&parent_home, async {
            let _ = parent_shutdown.await;
        })
        .await
    });
    socket_ready(pair.homes[0].path()).await;
    let (child_stop, child_shutdown) = tokio::sync::oneshot::channel();
    let child_home = pair.homes[1].path().to_owned();
    let child = tokio::spawn(async move {
        crate::hosted::run(&child_home, async {
            let _ = child_shutdown.await;
        })
        .await
    });
    socket_ready(pair.homes[1].path()).await;
    assert!(crate::DaemonLock::acquire(pair.homes[1].path()).is_err());
    let identity = crate::request(
        pair.homes[1].path(),
        Request::Agent {
            credential: pair.keys[1].clone(),
            action: AgentOp::Identity,
        },
    )
    .await
    .unwrap();
    assert_eq!(identity["agent"]["id"], pair.agents[1]);
    let directory = crate::request(
        pair.homes[1].path(),
        Request::Agent {
            credential: pair.keys[1].clone(),
            action: AgentOp::Agents,
        },
    )
    .await
    .unwrap();
    assert!(visible(&directory, &pair.agents[0]));
    assert!(
        crate::request(
            pair.homes[1].path(),
            Request::Agent {
                credential: pair.keys[0].clone(),
                action: AgentOp::Identity
            }
        )
        .await
        .is_err()
    );
    assert!(
        crate::request(
            pair.homes[0].path(),
            Request::Agent {
                credential: pair.keys[1].clone(),
                action: AgentOp::Identity
            }
        )
        .await
        .is_err()
    );
    let bytes = b"binary\0upload through real hosted IPC\n";
    let file = gent_protocol::file_objects::IncomingFile {
        request_id: Uuid::now_v7().to_string(),
        source_id: "a".repeat(64),
        name: "fixture.bin".into(),
        media_type: "application/octet-stream".into(),
    };
    let uploaded = crate::receive_file(
        pair.homes[1].path(),
        pair.keys[1].clone(),
        file.clone(),
        bytes,
    )
    .await
    .unwrap();
    let file_id = uploaded["file"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        crate::receive_file(pair.homes[1].path(), pair.keys[1].clone(), file, bytes)
            .await
            .unwrap()["file"]["id"],
        file_id
    );
    let chunk = crate::request(
        pair.homes[1].path(),
        Request::Agent {
            credential: pair.keys[1].clone(),
            action: AgentOp::FileRead {
                file_id: file_id.clone(),
                chunk_index: 0,
            },
        },
    )
    .await
    .unwrap();
    assert_eq!(
        STANDARD
            .decode(chunk["data_base64"].as_str().unwrap())
            .unwrap(),
        bytes
    );
    assert!(
        crate::request(
            pair.homes[0].path(),
            Request::Agent {
                credential: pair.keys[0].clone(),
                action: AgentOp::FileRead {
                    file_id: file_id.clone(),
                    chunk_index: 0
                }
            }
        )
        .await
        .is_err()
    );
    assert!(
        crate::receive_file(
            pair.homes[1].path(),
            pair.keys[0].clone(),
            gent_protocol::file_objects::IncomingFile {
                request_id: Uuid::now_v7().to_string(),
                source_id: "b".repeat(64),
                name: "denied".into(),
                media_type: "text/plain".into()
            },
            b"denied"
        )
        .await
        .is_err()
    );
    // Send the header and body together so BufReader can prefetch binary bytes.
    // The proxy must forward those buffered bytes exactly once to the parent.
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let buffered_file = gent_protocol::file_objects::IncomingFile {
        request_id: Uuid::now_v7().to_string(),
        source_id: "c".repeat(64),
        name: "buffered.bin".into(),
        media_type: "application/octet-stream".into(),
    };
    let mut frame = serde_json::to_vec(&Request::Agent {
        credential: pair.keys[1].clone(),
        action: AgentOp::FileReceive {
            file: buffered_file,
            byte_length: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        },
    })
    .unwrap();
    frame.push(b'\n');
    frame.extend_from_slice(bytes);
    let mut socket = tokio::net::UnixStream::connect(pair.homes[1].path().join("daemon.sock"))
        .await
        .unwrap();
    socket.write_all(&frame).await.unwrap();
    socket.shutdown().await.unwrap();
    let mut socket = BufReader::new(socket);
    let mut final_result = Value::Null;
    for expected in ["upload", "ready"] {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), socket.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        let Response::Ok(value) = serde_json::from_str(&line).unwrap() else {
            panic!("buffered upload rejected");
        };
        assert_eq!(value["state"], expected);
        final_result = value;
    }
    let buffered_id = final_result["file"]["id"].as_str().unwrap().to_owned();
    let read = crate::request(
        pair.homes[1].path(),
        Request::Agent {
            credential: pair.keys[1].clone(),
            action: AgentOp::FileRead {
                file_id: buffered_id.clone(),
                chunk_index: 0,
            },
        },
    )
    .await
    .unwrap();
    assert_eq!(
        STANDARD
            .decode(read["data_base64"].as_str().unwrap())
            .unwrap(),
        bytes
    );
    assert!(
        crate::request(
            pair.homes[1].path(),
            Request::Agent {
                credential: pair.keys[2].clone(),
                action: AgentOp::FileRead {
                    file_id: buffered_id,
                    chunk_index: 0
                }
            }
        )
        .await
        .is_err()
    );
    drop(socket);
    // Stop accepting new connections while a binary upload is admitted but
    // unfinished. The proxy must drain that connection and its final response.
    let drain_file = gent_protocol::file_objects::IncomingFile {
        request_id: Uuid::now_v7().to_string(),
        source_id: "d".repeat(64),
        name: "draining.bin".into(),
        media_type: "application/octet-stream".into(),
    };
    let mut header = serde_json::to_vec(&Request::Agent {
        credential: pair.keys[1].clone(),
        action: AgentOp::FileReceive {
            file: drain_file,
            byte_length: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        },
    })
    .unwrap();
    header.push(b'\n');
    let socket = tokio::net::UnixStream::connect(pair.homes[1].path().join("daemon.sock"))
        .await
        .unwrap();
    let mut socket = BufReader::new(socket);
    socket.get_mut().write_all(&header).await.unwrap();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), socket.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let Response::Ok(admission) = serde_json::from_str(&line).unwrap() else {
        panic!("draining upload rejected");
    };
    assert_eq!(admission["state"], "upload");
    child_stop.send(()).unwrap();
    socket.get_mut().write_all(bytes).await.unwrap();
    socket.get_mut().shutdown().await.unwrap();
    line.clear();
    tokio::time::timeout(Duration::from_secs(5), socket.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let Response::Ok(completed) = serde_json::from_str(&line).unwrap() else {
        panic!("draining upload incomplete");
    };
    assert_eq!(completed["state"], "ready");
    drop(socket);
    tokio::time::timeout(Duration::from_secs(5), child)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    parent_stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), parent)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!pair.homes[1].path().join("daemon.sock").exists());
    let _lock = crate::DaemonLock::acquire(pair.homes[1].path()).unwrap();
    let mut store = Store::open(pair.homes[0].path()).unwrap();
    let chunk = store
        .execute(Request::HostedAgent {
            node_id: child_node,
            gateway_credential: gateway,
            credential: pair.keys[1].clone(),
            action: AgentOp::FileRead {
                file_id,
                chunk_index: 0,
            },
        })
        .unwrap();
    assert_eq!(
        STANDARD
            .decode(chunk["data_base64"].as_str().unwrap())
            .unwrap(),
        bytes
    );
}
