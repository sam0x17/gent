use super::*;
use crate::pairing::{self, Peer};
use std::os::unix::fs::PermissionsExt;

struct OwnerPeer<'a>(&'a mut Store, String);
impl Peer for OwnerPeer<'_> {
    async fn call(&mut self, action: PairingOp) -> Result<Value> {
        self.0.execute(Request::Owner {
            credential: self.1.clone(),
            action: OwnerOp::Pair {
                cluster_id: self.0.config.cluster.id.clone(),
                action,
            },
        })
    }
}
struct Pair {
    homes: [tempfile::TempDir; 2],
    stores: [Store; 2],
    keys: [String; 2],
    agents: [String; 2],
}
impl Pair {
    async fn new() -> Self {
        let homes = std::array::from_fn(|_| {
            let home = tempfile::tempdir().unwrap();
            std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            home
        });
        let mut cfg = config::initialize(homes[0].path(), "network-tests").unwrap();
        cfg.relay = Some(config::RelayConfig {
            endpoint: "https://relay.example".into(),
            credential_file: "relay.key".into(),
        });
        config::write_private(
            &homes[0].path().join("relay.key"),
            config::secret().as_bytes(),
        )
        .unwrap();
        config::save(homes[0].path(), &cfg).unwrap();
        let mut owner = Store::open(homes[0].path()).unwrap();
        let credential = config::read_private(&homes[0].path().join("owner.key")).unwrap();
        pairing::join(
            homes[1].path(),
            pairing::Options {
                cluster: &cfg.cluster.id,
                name: "joined",
                relay_endpoint: None,
            },
            &mut OwnerPeer(&mut owner, credential),
        )
        .await
        .unwrap();
        let joined = Store::open(homes[1].path()).unwrap();
        let mut stores = [owner, joined];
        let keys = std::array::from_fn(|_| config::secret());
        let agents = std::array::from_fn(|i| {
            stores[i]
                .execute(Request::Agent {
                    credential: keys[i].clone(),
                    action: AgentOp::Register {
                        name: format!("agent-{i}"),
                        provider: "test".into(),
                    },
                })
                .unwrap()["agent"]["id"]
                .as_str()
                .unwrap()
                .to_owned()
        });
        let mut pair = Self {
            homes,
            stores,
            keys,
            agents,
        };
        pair.pump();
        pair.policy(true);
        pair.pump();
        pair
    }
    fn agent(&mut self, i: usize, action: AgentOp) -> Result<Value> {
        self.stores[i].execute(Request::Agent {
            credential: self.keys[i].clone(),
            action,
        })
    }
    fn policy(&mut self, allow: bool) {
        let mut policy = Policy::default();
        if allow {
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
        }
        self.stores[0]
            .execute(Request::Owner {
                credential: config::read_private(&self.homes[0].path().join("owner.key")).unwrap(),
                action: OwnerOp::SetPolicy { policy },
            })
            .unwrap();
    }
    fn send(&mut self, files: Vec<FilePart>) -> Result<Value> {
        self.agent(
            0,
            AgentOp::Send {
                recipient: self.agents[1].clone(),
                request_id: Uuid::new_v4().to_string(),
                text: "private work".into(),
                files,
            },
        )
    }
    fn group(&self) -> Vec<u8> {
        self.stores[0]
            .db
            .query_row("SELECT outgoing FROM network_links", [], |r| r.get(0))
            .unwrap()
    }
    fn pump(&mut self) {
        for _ in 0..100 {
            let mut progressed = false;
            for i in 0..2 {
                let streams = self.stores[i].sync_streams().unwrap();
                for stream in streams.into_iter().filter(|s| s.outgoing) {
                    let group = &stream.group;
                    let packet = if stream.configuration {
                        self.stores[i].sync_prepare(group).unwrap();
                        let next = self.stores[1 - i].sync_next(group).unwrap();
                        self.stores[i].sync_outgoing(group, next).unwrap()
                    } else {
                        self.stores[i].data_prepare(group).unwrap();
                        let next = self.stores[1 - i].data_next(group).unwrap();
                        self.stores[i].data_outgoing(group, next).unwrap()
                    };
                    if let Some(packet) = packet {
                        if stream.configuration {
                            self.stores[1 - i].sync_receive(&packet).unwrap();
                        } else {
                            self.stores[1 - i].data_receive(&packet).unwrap();
                        }
                        progressed = true;
                    }
                }
            }
            if !progressed {
                return;
            }
        }
        panic!("transport failed to drain");
    }
    fn reopen(&mut self, i: usize) {
        self.stores[i] = Store::open(self.homes[i].path()).unwrap();
    }
}

#[tokio::test]
async fn failed_enqueue_rolls_back_message_and_retry_preserves_ciphertext_after_cursor_failure() {
    let mut pair = Pair::new().await;
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_enqueue BEFORE INSERT ON network_events BEGIN SELECT RAISE(ABORT,'disk failure'); END;").unwrap();
    assert!(pair.send(vec![]).is_err());
    let count: usize = pair.stores[0]
        .db
        .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_enqueue;")
        .unwrap();
    pair.send(vec![]).unwrap();
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_cursor BEFORE DELETE ON network_events BEGIN SELECT RAISE(ABORT,'disk failure'); END;").unwrap();
    let group = pair.group();
    let next = pair.stores[1].data_next(&group).unwrap();
    assert!(pair.stores[0].data_prepare(&group).is_err());
    let packet = pair.stores[0].data_outgoing(&group, next).unwrap().unwrap();
    pair.reopen(0);
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_cursor;")
        .unwrap();
    pair.stores[0].data_prepare(&group).unwrap();
    assert_eq!(
        packet.encode().unwrap(),
        pair.stores[0]
            .data_outgoing(&group, next)
            .unwrap()
            .unwrap()
            .encode()
            .unwrap()
    );
    pair.pump();
    assert_eq!(
        pair.agent(1, AgentOp::Inbox)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        pair.stores[0]
            .data_outgoing(&group, next + 1)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn failed_recipient_import_keeps_decrypted_record_until_transaction_can_commit() {
    let mut pair = Pair::new().await;
    pair.send(vec![]).unwrap();
    let group = pair.group();
    let next = pair.stores[1].data_next(&group).unwrap();
    pair.stores[0].data_prepare(&group).unwrap();
    let packet = pair.stores[0].data_outgoing(&group, next).unwrap().unwrap();
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_import BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT,'disk failure'); END;").unwrap();
    assert!(pair.stores[1].data_receive(&packet).is_err());
    assert_eq!(pair.agent(1, AgentOp::Inbox).unwrap(), json!([]));
    pair.reopen(1);
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_import;")
        .unwrap();
    assert_eq!(pair.stores[1].data_next(&group).unwrap(), next + 1);
    pair.stores[1].data_receive(&packet).unwrap();
    assert_eq!(
        pair.agent(1, AgentOp::Inbox)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn partially_encrypted_file_is_cancelled_and_next_allowed_message_can_progress() {
    let mut pair = Pair::new().await;
    let cancelled = pair
        .send(vec![FilePart {
            name: "screenshot.png".into(),
            media_type: "image/png".into(),
            data_base64: STANDARD.encode(vec![7; 1024 * 1024]),
        }])
        .unwrap();
    let group = pair.group();
    let next = pair.stores[1].data_next(&group).unwrap();
    pair.stores[0].data_prepare(&group).unwrap();
    let packet = pair.stores[0].data_outgoing(&group, next).unwrap().unwrap();
    pair.stores[1].data_receive(&packet).unwrap();
    assert_eq!(pair.agent(1, AgentOp::Inbox).unwrap(), json!([]));
    pair.policy(false);
    pair.pump();
    let pending: usize = pair.stores[1]
        .db
        .query_row("SELECT COUNT(*) FROM network_partial", [], |r| r.get(0))
        .unwrap();
    assert_eq!(pending, 0);
    pair.reopen(0);
    pair.policy(true);
    pair.pump();
    assert_eq!(
        pair.agent(
            0,
            AgentOp::MessageStatus {
                message_id: cancelled["message_id"].as_str().unwrap().into(),
            }
        )
        .unwrap()["state"],
        "revoked"
    );
    let sent = pair.send(vec![]).unwrap();
    pair.pump();
    let inbox = pair.agent(1, AgentOp::Inbox).unwrap();
    assert_eq!(inbox.as_array().unwrap().len(), 1);
    assert_eq!(inbox[0]["id"], sent["message_id"]);
}

#[tokio::test]
async fn enrolled_peer_cannot_claim_unknown_foreign_agent_or_forge_reply_or_receipt() {
    let mut pair = Pair::new().await;
    let store = &pair.stores[0];
    let tx = store.db.unchecked_transaction().unwrap();
    let state = store.identity.state(&tx).unwrap();
    let session = store.network_session(&tx, state);
    let peer = pair.stores[1].identity.node.id();
    let mut registration = pair.stores[1]
        .network_session(
            &pair.stores[1].db,
            pair.stores[1].identity.state(&pair.stores[1].db).unwrap(),
        )
        .registration(&pair.agents[1])
        .unwrap();
    registration.id =
        gent_crypto::agent_id(store.identity.node.id(), registration.nonce.unwrap()).unwrap();
    assert!(session.import_registration(peer, &registration).is_err());
    tx.rollback().unwrap();

    let sent = pair.send(vec![]).unwrap();
    pair.pump();
    let store = &pair.stores[1];
    let tx = store.db.unchecked_transaction().unwrap();
    let session = store.network_session(&tx, store.identity.state(&tx).unwrap());
    let mut message = session
        .message(sent["message_id"].as_str().unwrap())
        .unwrap();
    assert!(
        session
            .import_event(
                pair.stores[0].identity.node.id(),
                Event::Receipt {
                    message_id: message.id.clone(),
                    delivered: true
                }
            )
            .is_err()
    );
    let sender = pair.stores[0]
        .network_session(
            &pair.stores[0].db,
            pair.stores[0].identity.state(&pair.stores[0].db).unwrap(),
        )
        .registration(&pair.agents[0])
        .unwrap();
    let request = Uuid::new_v4().to_string();
    message.id = messages::message_id(&sender.id, &request).unwrap();
    message.reply_to = Some(Uuid::new_v4().to_string());
    assert!(
        session
            .import_event(
                pair.stores[0].identity.node.id(),
                Event::Message {
                    sender: Box::new(sender),
                    request_id: request,
                    message
                }
            )
            .is_err()
    );
    tx.rollback().unwrap();
    assert_eq!(
        pair.agent(1, AgentOp::Inbox)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn message_waits_for_missing_configuration_before_delivery() {
    let mut pair = Pair::new().await;
    pair.policy(false);
    pair.pump();
    pair.policy(true);
    let sent = pair.send(vec![]).unwrap();
    let group = pair.group();
    let next = pair.stores[1].data_next(&group).unwrap();
    pair.stores[0].data_prepare(&group).unwrap();
    let packet = pair.stores[0].data_outgoing(&group, next).unwrap().unwrap();
    pair.stores[1].data_receive(&packet).unwrap();
    assert_eq!(pair.agent(1, AgentOp::Inbox).unwrap(), json!([]));
    pair.reopen(1);
    pair.pump();
    assert_eq!(
        pair.agent(1, AgentOp::Inbox).unwrap()[0]["id"],
        sent["message_id"]
    );
}

#[tokio::test]
async fn remote_exchange_budget_stays_bounded_when_both_nodes_queue_replies() {
    let mut pair = Pair::new().await;
    let initial = pair.send(vec![]).unwrap();
    pair.pump();
    let reply = |message: &Value| AgentOp::Reply {
        message_id: message["message_id"].as_str().unwrap().into(),
        request_id: Uuid::new_v4().to_string(),
        text: "response".into(),
        files: vec![],
    };
    let first_reply = pair.agent(1, reply(&initial)).unwrap();
    pair.pump();
    for _ in 0..15 {
        pair.agent(0, reply(&first_reply)).unwrap();
        pair.agent(1, reply(&initial)).unwrap();
    }
    assert!(pair.agent(0, reply(&first_reply)).is_err());
    assert!(pair.agent(1, reply(&initial)).is_err());
    pair.pump();
    for store in &pair.stores {
        let count: u32 = store
            .db
            .query_row(
                "SELECT count FROM exchanges WHERE id=?1",
                [initial["exchange_id"].as_str().unwrap()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, MAX_EXCHANGE_MESSAGES);
    }
}
