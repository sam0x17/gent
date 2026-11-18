use super::*;
use crate::pairing::{self, Peer};
use std::os::unix::fs::PermissionsExt;

#[path = "administration_tests.rs"]
mod administration_tests;
#[path = "configuration_storage_tests.rs"]
mod configuration_storage_tests;
#[path = "group_administration_tests.rs"]
mod group_administration_tests;
#[path = "node_invite_tests.rs"]
mod node_invite_tests;
#[path = "owner_handoff_tests.rs"]
mod owner_handoff_tests;
#[path = "presence_tests.rs"]
mod presence_tests;
#[path = "registration_tests.rs"]
mod registration_tests;
#[path = "retention_tests.rs"]
mod retention_tests;
#[path = "retries.rs"]
mod retries;

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
    fn relay_attach(&mut self) -> String {
        self.agent(
            0,
            AgentOp::RelayAttach {
                target: self.agents[1].clone(),
                request_id: Uuid::now_v7().to_string(),
            },
        )
        .unwrap()["attachment"]["id"]
            .as_str()
            .unwrap()
            .into()
    }
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
                replace_node: None,
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
                file_ids: vec![],
                recipient: self.agents[1].clone(),
                request_id: Uuid::now_v7().to_string(),
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
    fn retire_history(&mut self, i: usize) -> Value {
        // Advance request admission/retention only. MLS still uses the real
        // wall clock and its existing signed authority during these tests.
        self.stores[i]
            .db
            .execute("UPDATE request_clock SET floor=?1", [now() + 9 * 86400])
            .unwrap();
        self.stores[i]
            .execute(Request::Owner {
                credential: config::read_private(&self.homes[i].path().join("owner.key")).unwrap(),
                action: OwnerOp::HistoryClean { dry_run: false },
            })
            .unwrap()
    }
}

#[tokio::test]
async fn retired_partial_message_cancels_after_restart_even_if_fragment_cursor_rolled_back() {
    for failed_cursor in [false, true] {
        let mut pair = Pair::new().await;
        pair.send(vec![FilePart {
            name: "partial.png".into(),
            media_type: "image/png".into(),
            data_base64: STANDARD.encode(vec![7; 1024 * 1024]),
        }])
        .unwrap();
        let group = pair.group();
        let next = pair.stores[1].data_next(&group).unwrap();
        if failed_cursor {
            pair.stores[0].db.execute_batch("CREATE TRIGGER fail_offset BEFORE UPDATE OF offset ON network_events BEGIN SELECT RAISE(ABORT,'injected offset failure'); END;").unwrap();
            assert!(pair.stores[0].data_prepare(&group).is_err());
            pair.stores[0]
                .db
                .execute_batch("DROP TRIGGER fail_offset;")
                .unwrap();
        } else {
            pair.stores[0].data_prepare(&group).unwrap();
        }
        let packet = pair.stores[0].data_outgoing(&group, next).unwrap().unwrap();
        pair.stores[1].data_receive(&packet).unwrap();
        let receipt = pair.stores[1].transport_receipt(&group, false).unwrap();
        pair.stores[0]
            .transport_confirm(&group, false, Some(&receipt))
            .unwrap();
        let retained: bool = pair.stores[0]
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM stream_outbox WHERE group_id=?1 AND sequence=?2)",
                params![&group, next],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(retained, failed_cursor);
        assert_eq!(
            pair.stores[1]
                .db
                .query_row("SELECT COUNT(*) FROM network_partial", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
        let cleaned = pair.retire_history(0);
        assert_eq!(cleaned["messages_removed"], 1);
        assert_eq!(cleaned["outbound_events_cancelled"], 1);
        let offset: usize = pair.stores[0].db.query_row("SELECT offset FROM network_events WHERE cancelled=1 AND length(body)=0 AND subject IS NULL",[],|r|r.get(0)).unwrap();
        assert_eq!(offset, if failed_cursor { 0 } else { FRAGMENT_BYTES });
        pair.reopen(0);
        pair.reopen(1);
        pair.stores[0].db.execute_batch("CREATE TRIGGER fail_cancel BEFORE DELETE ON network_events BEGIN SELECT RAISE(ABORT,'cancel cursor failure'); END;").unwrap();
        assert!(pair.stores[0].data_prepare(&group).is_err());
        let cancel = pair.stores[0]
            .data_outgoing(&group, next + 1)
            .unwrap()
            .unwrap();
        pair.stores[1].data_receive(&cancel).unwrap();
        let receipt = pair.stores[1].transport_receipt(&group, false).unwrap();
        pair.stores[0]
            .transport_confirm(&group, false, Some(&receipt))
            .unwrap();
        pair.stores[0]
            .db
            .execute_batch("DROP TRIGGER fail_cancel")
            .unwrap();
        pair.pump();
        pair.stores[0]
            .transport_confirm(&group, false, Some(&receipt))
            .unwrap();
        assert_eq!(
            pair.stores[0]
                .db
                .query_row(
                    "SELECT COUNT(*) FROM transport_requests WHERE group_id=?1",
                    [&group],
                    |r| r.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            pair.stores[1]
                .db
                .query_row("SELECT COUNT(*) FROM network_partial", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            pair.stores[0]
                .db
                .query_row("SELECT COUNT(*) FROM network_events", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            0
        );
        assert_eq!(pair.agent(1, AgentOp::Inbox).unwrap(), json!([]));
    }
}

#[tokio::test]
async fn late_authenticated_receipt_after_pruning_does_not_stall_stream() {
    let mut pair = Pair::new().await;
    let id = pair.send(vec![]).unwrap()["message_id"]
        .as_str()
        .unwrap()
        .to_owned();
    pair.pump();
    pair.agent(
        1,
        AgentOp::Ack {
            message_id: id.clone(),
        },
    )
    .unwrap();
    assert_eq!(pair.retire_history(0)["messages_removed"], 1);
    pair.reopen(0);
    pair.pump();
    assert_eq!(
        pair.stores[0]
            .db
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT COUNT(*) FROM network_events", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn pruned_remote_request_cannot_return_with_original_or_rewritten_timestamps() {
    let mut pair = Pair::new().await;
    pair.send(vec![]).unwrap();
    let body: Vec<u8> = pair.stores[0]
        .db
        .query_row(
            "SELECT body FROM network_events WHERE subject IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    pair.pump();
    assert_eq!(pair.retire_history(1)["messages_removed"], 1);
    let state = pair.stores[1].identity.state(&pair.stores[1].db).unwrap();
    let renewal = state
        .renew(
            &pair.stores[0]
                .identity
                .signing_owner(&pair.stores[0].db)
                .unwrap(),
            (now() + 9 * 86400) as u64,
        )
        .unwrap();
    pair.stores[1]
        .identity
        .apply(&pair.stores[1].db, renewal)
        .unwrap();
    pair.reopen(1);
    let peer = pair.stores[0].identity.node.id().to_owned();
    for rewrite in [false, true] {
        let mut record: Record = serde_json::from_slice(&body).unwrap();
        if rewrite {
            if let Event::Message { message, .. } = &mut record.event {
                message.created_at = now() + 9 * 86400;
                message.expires_at = message.created_at + EXCHANGE_TTL_SECONDS;
            } else {
                panic!("expected message");
            }
        }
        let store = &pair.stores[1];
        let tx = store.db.unchecked_transaction().unwrap();
        let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
        session.import_event(&peer, record.event).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            store
                .db
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT COUNT(*) FROM network_events", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn remote_relay_replies_cannot_strip_or_substitute_authenticated_turn_context() {
    let mut pair = Pair::new().await;
    let attachment = pair.relay_attach();
    let turn = pair
        .agent(
            0,
            AgentOp::RelaySend {
                file_ids: vec![],
                attachment_id: attachment,
                request_id: Uuid::now_v7().to_string(),
                text: "original turn".into(),
                files: vec![],
            },
        )
        .unwrap()["turn_id"]
        .as_str()
        .unwrap()
        .to_owned();
    pair.pump();
    let target = &pair.stores[1];
    let target_session =
        target.network_session(&target.db, target.identity.state(&target.db).unwrap());
    let registration = target_session.registration(&pair.agents[1]).unwrap();
    let root = target_session.message(&turn).unwrap();
    for attack in 0..4 {
        let store = &pair.stores[0];
        let tx = store.db.unchecked_transaction().unwrap();
        let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
        let request = Uuid::now_v7().to_string();
        let mut message = root.clone();
        message.id = messages::message_id(&pair.agents[1], &request).unwrap();
        message.sender.clone_from(&root.recipient);
        message.recipient.clone_from(&root.sender);
        message.reply_to = Some(root.id.clone());
        message.relay.as_mut().unwrap().kind = RelayMessageKind::Complete;
        match attack {
            0 => message.relay = None,
            1 => message.relay.as_mut().unwrap().attachment_id = Uuid::new_v4().to_string(),
            2 => message.relay.as_mut().unwrap().turn_id = Uuid::new_v4().to_string(),
            _ => message.reply_to = Some(Uuid::new_v4().to_string()),
        }
        assert!(
            session
                .import_event(
                    pair.stores[1].identity.node.id(),
                    Event::Message {
                        attachments: vec![],
                        sender: Box::new(registration.clone()),
                        request_id: request,
                        message,
                    }
                )
                .is_err()
        );
        tx.rollback().unwrap();
    }
    let response = AgentOp::RelayRespond {
        file_ids: vec![],
        turn_id: turn.clone(),
        request_id: Uuid::now_v7().to_string(),
        text: "verified reply".into(),
        files: vec![],
        outcome: RelayResponseKind::Complete,
    };
    pair.agent(1, response).unwrap();
    pair.pump();
    let status = pair
        .agent(
            0,
            AgentOp::RelayTurnStatus {
                turn_id: turn,
                after_message_id: None,
            },
        )
        .unwrap();
    assert_eq!(status["state"], "completed");
    assert_eq!(status["responses"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn crossed_cancellation_and_completion_do_not_reopen_or_lose_a_remote_turn() {
    let mut pair = Pair::new().await;
    let attachment = pair.relay_attach();
    let send = AgentOp::RelaySend {
        file_ids: vec![],
        attachment_id: attachment.clone(),
        request_id: Uuid::now_v7().to_string(),
        text: "work".into(),
        files: vec![],
    };
    let turn = pair.agent(0, send.clone()).unwrap()["turn_id"]
        .as_str()
        .unwrap()
        .to_owned();
    pair.pump();
    pair.agent(
        0,
        AgentOp::RelayDetach {
            attachment_id: attachment,
        },
    )
    .unwrap();
    let cancel = AgentOp::RelayCancel {
        turn_id: turn.clone(),
        request_id: Uuid::now_v7().to_string(),
    };
    pair.agent(0, cancel.clone()).unwrap();
    let response = AgentOp::RelayRespond {
        file_ids: vec![],
        turn_id: turn.clone(),
        request_id: Uuid::now_v7().to_string(),
        text: "already finished".into(),
        files: vec![],
        outcome: RelayResponseKind::Complete,
    };
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_relay_outbox BEFORE INSERT ON network_events BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(pair.agent(1, response.clone()).is_err());
    assert_eq!(
        pair.agent(1, AgentOp::RelayNext).unwrap()["request"]["id"],
        turn
    );
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_relay_outbox;")
        .unwrap();
    pair.agent(1, response.clone()).unwrap();
    pair.reopen(0);
    pair.reopen(1);
    pair.pump();
    let status = pair
        .agent(
            0,
            AgentOp::RelayTurnStatus {
                turn_id: turn.clone(),
                after_message_id: None,
            },
        )
        .unwrap();
    assert_eq!(status["state"], "completed");
    assert_eq!(status["cancel_requested"], true);
    assert_eq!(status["responses"][0]["relay"]["kind"], "complete");
    assert_eq!(pair.agent(1, AgentOp::RelayNext).unwrap(), Value::Null);
    assert_eq!(pair.agent(0, send).unwrap()["duplicate"], true);
    assert_eq!(pair.agent(0, cancel).unwrap()["duplicate"], true);
    assert_eq!(pair.agent(1, response).unwrap()["duplicate"], true);
    pair.pump();
    assert_eq!(pair.agent(1, AgentOp::Inbox).unwrap(), json!([]));
}

#[tokio::test]
async fn permission_denial_blocks_relay_turns_before_encryption_and_before_target_work() {
    let mut pair = Pair::new().await;
    let attachment = pair.relay_attach();
    let first = pair
        .agent(
            0,
            AgentOp::RelaySend {
                file_ids: vec![],
                attachment_id: attachment.clone(),
                request_id: Uuid::now_v7().to_string(),
                text: "accepted earlier".into(),
                files: vec![],
            },
        )
        .unwrap()["turn_id"]
        .as_str()
        .unwrap()
        .to_owned();
    pair.pump();
    assert_eq!(
        pair.agent(1, AgentOp::RelayNext).unwrap()["request"]["id"],
        first
    );
    let queued = pair
        .agent(
            0,
            AgentOp::RelaySend {
                file_ids: vec![],
                attachment_id: attachment,
                request_id: Uuid::now_v7().to_string(),
                text: "must not encrypt".into(),
                files: vec![],
            },
        )
        .unwrap()["turn_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut policy = pair.stores[0].config.policy.clone();
    policy.rules.push(Rule {
        actor: Selector::Agent(pair.agents[0].clone()),
        peer: Selector::Agent(pair.agents[1].clone()),
        permission: Permission::Send,
        effect: Effect::Deny,
    });
    pair.stores[0]
        .execute(Request::Owner {
            credential: config::read_private(&pair.homes[0].path().join("owner.key")).unwrap(),
            action: OwnerOp::Configure {
                request_id: Uuid::new_v4().to_string(),
                edit: ConfigurationEdit::Policy { policy },
            },
        })
        .unwrap();
    pair.pump();
    assert_eq!(pair.agent(1, AgentOp::RelayNext).unwrap(), Value::Null);
    assert_eq!(pair.agent(1, AgentOp::Inbox).unwrap(), json!([]));
    assert_eq!(
        pair.agent(
            0,
            AgentOp::RelayTurnStatus {
                turn_id: queued.clone(),
                after_message_id: None
            }
        )
        .unwrap()["state"],
        "revoked"
    );
    assert!(
        !pair.stores[1]
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE id=?1)",
                [queued],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
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
async fn joined_runtime_clears_conservative_legacy_join_pins_without_changing_authority() {
    let mut pair = Pair::new().await;
    let before = pair.stores[1]
        .identity
        .state(&pair.stores[1].db)
        .unwrap()
        .checkpoint()
        .clone();
    pair.stores[1]
        .db
        .execute_batch("DROP TABLE authority_join_pins; PRAGMA user_version=5;")
        .unwrap();
    pair.reopen(1);
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT COUNT(*) FROM authority_join_pins", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        pair.stores[1]
            .identity
            .state(&pair.stores[1].db)
            .unwrap()
            .checkpoint(),
        &before
    );
}

#[tokio::test]
async fn queued_message_uses_retained_authority_digest_after_full_history_compaction() {
    let mut pair = Pair::new().await;
    let sent = pair.send(vec![]).unwrap();
    let revision = pair.stores[0]
        .identity
        .state(&pair.stores[0].db)
        .unwrap()
        .checkpoint()
        .revision;
    let edit = Uuid::new_v4().to_string();
    pair.owner(
        1,
        OwnerOp::Configure {
            request_id: edit.clone(),
            edit: ConfigurationEdit::RenameNode {
                name: "delayed-result".into(),
            },
        },
    )
    .unwrap();
    let request_group: Vec<u8> = pair.stores[1]
        .db
        .query_row("SELECT outgoing FROM network_links", [], |r| r.get(0))
        .unwrap();
    let next = pair.stores[0].data_next(&request_group).unwrap();
    pair.stores[1].data_prepare(&request_group).unwrap();
    let request = pair.stores[1]
        .data_outgoing(&request_group, next)
        .unwrap()
        .unwrap();
    pair.stores[0].data_receive(&request).unwrap();
    for _ in 0..80 {
        let store = &pair.stores[0];
        let tx = store.db.unchecked_transaction().unwrap();
        let state = store.identity.state(&tx).unwrap();
        store
            .identity
            .apply(
                &tx,
                state
                    .renew(&store.identity.signing_owner(&tx).unwrap(), now() as u64)
                    .unwrap(),
            )
            .unwrap();
        tx.commit().unwrap();
    }
    // Deliver only configuration, leaving the old queued message untouched.
    let streams = pair.stores[0].sync_streams().unwrap();
    for entry in streams
        .into_iter()
        .filter(|s| s.outgoing && s.configuration)
    {
        loop {
            pair.stores[0].sync_prepare(&entry.group).unwrap();
            let next = pair.stores[1].sync_next(&entry.group).unwrap();
            let Some(packet) = pair.stores[0].sync_outgoing(&entry.group, next).unwrap() else {
                break;
            };
            pair.stores[1].sync_receive(&packet).unwrap();
        }
    }
    for store in &pair.stores {
        while {
            let tx = store.db.unchecked_transaction().unwrap();
            let (n, _) = encrypted::history::clean(&tx, false).unwrap();
            tx.commit().unwrap();
            n > 0
        } {}
    }
    assert!(
        !pair.stores[1]
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_history WHERE revision=?1)",
                [revision],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    pair.reopen(1);
    pair.pump();
    assert_eq!(
        pair.owner(
            1,
            OwnerOp::ConfigurationRequests {
                request_id: Some(edit)
            }
        )
        .unwrap()["state"],
        "applied"
    );
    assert_eq!(
        pair.agent(1, AgentOp::Inbox).unwrap()[0]["id"],
        sent["message_id"]
    );
}

#[tokio::test]
async fn checkpoints_preserve_pending_send_cursors_and_do_not_acknowledge_agents() {
    let mut pair = Pair::new().await;
    let sent = pair.send(vec![]).unwrap();
    let group = pair.group();
    let next = pair.stores[1].data_next(&group).unwrap();
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_cursor BEFORE DELETE ON network_events BEGIN SELECT RAISE(ABORT,'injected cursor'); END;").unwrap();
    assert!(pair.stores[0].data_prepare(&group).is_err());
    let packet = pair.stores[0].data_outgoing(&group, next).unwrap().unwrap();
    pair.stores[1].data_receive(&packet).unwrap();
    let receipt = pair.stores[1].transport_receipt(&group, false).unwrap();
    pair.stores[0]
        .transport_confirm(&group, false, Some(&receipt))
        .unwrap();
    let retained: Vec<u8> = pair.stores[0]
        .db
        .query_row(
            "SELECT packet FROM stream_outbox WHERE group_id=?1 AND sequence=?2",
            params![&group, next],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(retained, packet.encode().unwrap());
    // Storage confirmation is independent of Gent's agent-level inbox/ack.
    assert_eq!(
        pair.agent(1, AgentOp::Inbox)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    pair.reopen(0);
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_cursor")
        .unwrap();
    pair.stores[0].data_prepare(&group).unwrap();
    pair.stores[0]
        .transport_confirm(&group, false, Some(&receipt))
        .unwrap();
    let retained: Option<Vec<u8>> = pair.stores[0]
        .db
        .query_row(
            "SELECT packet FROM stream_outbox WHERE group_id=?1 AND sequence=?2",
            params![&group, next],
            |r| r.get(0),
        )
        .optional()
        .unwrap();
    assert!(retained.is_none());
    pair.pump();
    assert_eq!(
        pair.agent(1, AgentOp::Inbox).unwrap()[0]["id"],
        sent["message_id"]
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
    let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
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
    let request = Uuid::now_v7().to_string();
    message.id = messages::message_id(&sender.id, &request).unwrap();
    message.reply_to = Some(Uuid::new_v4().to_string());
    assert!(
        session
            .import_event(
                pair.stores[0].identity.node.id(),
                Event::Message {
                    attachments: vec![],
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
        file_ids: vec![],
        message_id: message["message_id"].as_str().unwrap().into(),
        request_id: Uuid::now_v7().to_string(),
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

impl Pair {
    fn owner(&mut self, i: usize, action: OwnerOp) -> Result<Value> {
        self.stores[i].execute(Request::Owner {
            credential: config::read_private(&self.homes[i].path().join("owner.key"))?,
            action,
        })
    }
}
#[tokio::test]
async fn configuration_proposal_revision_and_result_recover_atomically_after_storage_failures() {
    let mut pair = Pair::new().await;
    let id = Uuid::new_v4().to_string();
    let action = OwnerOp::Configure {
        request_id: id.clone(),
        edit: ConfigurationEdit::RenameNode {
            name: "renamed-remotely".into(),
        },
    };
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_proposal BEFORE INSERT ON network_events BEGIN SELECT RAISE(ABORT,'disk failure'); END;").unwrap();
    assert!(pair.owner(1, action.clone()).is_err());
    assert!(
        pair.owner(
            1,
            OwnerOp::ConfigurationRequests {
                request_id: Some(id.clone())
            }
        )
        .is_err()
    );
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_proposal;")
        .unwrap();
    assert_eq!(pair.owner(1, action.clone()).unwrap()["state"], "queued");
    let before = pair.stores[0]
        .identity
        .state(&pair.stores[0].db)
        .unwrap()
        .checkpoint()
        .clone();
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_result BEFORE INSERT ON configuration_edits BEGIN SELECT RAISE(ABORT,'disk failure'); END;").unwrap();
    let group: Vec<u8> = pair.stores[1]
        .db
        .query_row("SELECT outgoing FROM network_links", [], |r| r.get(0))
        .unwrap();
    let next = pair.stores[0].data_next(&group).unwrap();
    pair.stores[1].data_prepare(&group).unwrap();
    let packet = pair.stores[1].data_outgoing(&group, next).unwrap().unwrap();
    assert!(pair.stores[0].data_receive(&packet).is_err());
    assert_eq!(
        pair.stores[0]
            .identity
            .state(&pair.stores[0].db)
            .unwrap()
            .checkpoint(),
        &before
    );
    pair.reopen(0);
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_result;")
        .unwrap();
    pair.stores[0].data_next(&group).unwrap();
    pair.pump();
    let result = pair
        .owner(
            1,
            OwnerOp::ConfigurationRequests {
                request_id: Some(id.clone()),
            },
        )
        .unwrap();
    assert_eq!(result["revision"], before.revision + 1);
    assert_eq!(
        pair.owner(1, action).unwrap()["revision"],
        result["revision"]
    );
    assert_eq!(
        config::load(pair.homes[1].path()).unwrap().node.name,
        "renamed-remotely"
    );
    assert_eq!(
        pair.stores[0]
            .identity
            .state(&pair.stores[0].db)
            .unwrap()
            .checkpoint()
            .revision,
        before.revision + 1
    );
}

#[tokio::test]
async fn configuration_results_require_the_original_writer_request_and_verified_revision() {
    let mut pair = Pair::new().await;
    let id = Uuid::new_v4();
    let edit = ConfigurationEdit::RenameNode {
        name: "pending".into(),
    };
    pair.owner(
        1,
        OwnerOp::Configure {
            request_id: id.to_string(),
            edit,
        },
    )
    .unwrap();
    let store = &pair.stores[1];
    let tx = store.db.unchecked_transaction().unwrap();
    let state = store.identity.state(&tx).unwrap();
    let fingerprint: String = tx
        .query_row(
            "SELECT fingerprint FROM configuration_edits WHERE origin=?1 AND id=?2",
            params![store.identity.node.id(), id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    let session = store.network_session(&tx, state.clone());
    let mut checkpoint = state.checkpoint().clone();
    checkpoint.state_hash[0] ^= 1;
    assert!(
        session
            .import_configuration_result(
                pair.stores[0].identity.node.id(),
                id,
                &fingerprint,
                crate::messages::EditResult::Applied { checkpoint }
            )
            .is_err()
    );
    assert!(
        session
            .import_configuration_result(
                store.identity.node.id(),
                id,
                &fingerprint,
                crate::messages::EditResult::Rejected {
                    reason: "forged".into()
                }
            )
            .is_err()
    );
    assert!(
        session
            .import_configuration_result(
                pair.stores[0].identity.node.id(),
                id,
                "wrong request digest",
                crate::messages::EditResult::Rejected {
                    reason: "forged".into()
                }
            )
            .is_err()
    );
    tx.rollback().unwrap();
    assert_eq!(
        pair.owner(
            1,
            OwnerOp::ConfigurationRequests {
                request_id: Some(id.to_string())
            }
        )
        .unwrap()["state"],
        "queued"
    );
    pair.pump();
    assert_eq!(
        pair.owner(
            1,
            OwnerOp::ConfigurationRequests {
                request_id: Some(id.to_string())
            }
        )
        .unwrap()["state"],
        "applied"
    );
}

#[tokio::test]
async fn attachment_grants_reject_substitution_and_downloads_resume_with_current_authority() {
    let mut pair = Pair::new().await;
    let paths = pair.agent(0, AgentOp::FilePaths).unwrap();
    let bytes = vec![0x91; gent_crypto::files::CHUNK_BYTES * 2 + 7];
    std::fs::write(
        std::path::Path::new(paths["import_directory"].as_str().unwrap()).join("native.bin"),
        &bytes,
    )
    .unwrap();
    let imported = pair
        .agent(
            0,
            AgentOp::FileImport {
                request_id: Uuid::now_v7().to_string(),
                name: "native.bin".into(),
                media_type: "application/octet-stream".into(),
            },
        )
        .unwrap();
    let sent = pair
        .agent(
            0,
            AgentOp::Send {
                recipient: pair.agents[1].clone(),
                request_id: Uuid::now_v7().to_string(),
                text: "file review".into(),
                files: vec![],
                file_ids: vec![imported["file"]["id"].as_str().unwrap().into()],
            },
        )
        .unwrap();
    let message_id = sent["message_id"].as_str().unwrap();
    let body: Vec<u8> = pair.stores[0]
        .db
        .query_row(
            "SELECT body FROM network_events WHERE subject=?1",
            [message_id],
            |r| r.get(0),
        )
        .unwrap();
    let record: Record = serde_json::from_slice(&body).unwrap();
    let id = match &record.event {
        Event::Message { message, .. } => message.attachments[0].id.clone(),
        _ => panic!(),
    };
    // Message publication waits for all object chunks; a restart preserves the job.
    pair.pump();
    assert!(
        pair.agent(1, AgentOp::Inbox)
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty()
    );
    pair.reopen(0);
    let job = pair.stores[0].file_transfer(&id).unwrap().unwrap();
    assert_eq!(job.missing, vec![0, 1, 2]);
    let chunks: Vec<_> = (0..3)
        .map(|i| pair.stores[0].file_upload(&id, i).unwrap())
        .collect();
    pair.stores[0].file_uploaded(&id, &[0, 1, 2]).unwrap();
    // A forged grant for the same visible descriptor must be rejected, including
    // duplicate messages after the original object has expired/reaped.
    for attack in 0..4 {
        let mut wire: serde_json::Value = serde_json::from_slice(&body).unwrap();
        match attack {
            0 => {
                wire["event"]["attachments"] = json!([]);
            }
            1 => {
                wire["event"]["attachments"][0]["manifest"]["expires_at"] = json!(1);
            }
            2 => {
                wire["event"]["message"]["attachments"][0]["name"] = json!("substituted.bin");
            }
            _ => {
                wire["event"]["attachments"][0]["manifest"]["chunks"][0]["bytes"] = json!(17);
            }
        }
        let forged: Record = serde_json::from_value(wire).unwrap();
        let store = &pair.stores[1];
        let tx = store.db.unchecked_transaction().unwrap();
        let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
        assert!(
            session
                .import_event(pair.stores[0].identity.node.id(), forged.event)
                .is_err()
        );
        tx.rollback().unwrap();
    }
    pair.pump();
    let status = pair
        .agent(
            1,
            AgentOp::FileStatus {
                file_id: id.clone(),
            },
        )
        .unwrap();
    assert_eq!(status["state"], "pending");
    pair.stores[1].file_received(&id, 0, &chunks[0]).unwrap();
    pair.reopen(1);
    assert_eq!(
        pair.stores[1].file_transfer(&id).unwrap().unwrap().missing,
        vec![1, 2]
    );
    let mut bad = chunks[1].clone();
    bad[0] ^= 1;
    assert!(pair.stores[1].file_received(&id, 1, &bad).is_err());
    pair.stores[1].file_received(&id, 1, &chunks[1]).unwrap();
    pair.stores[1].file_received(&id, 2, &chunks[2]).unwrap();
    let exported = pair
        .agent(
            1,
            AgentOp::FileExport {
                file_id: id.clone(),
            },
        )
        .unwrap();
    assert_eq!(
        std::fs::read(exported["path"].as_str().unwrap()).unwrap(),
        bytes
    );
    let mut wire: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let grant = &mut wire["event"]["attachments"][0]["grant"];
    let mut secret: serde_json::Value =
        serde_json::from_slice(&STANDARD.decode(grant.as_str().unwrap()).unwrap()).unwrap();
    secret["key"][0] = json!(secret["key"][0].as_u64().unwrap() ^ 1);
    *grant = json!(STANDARD.encode(serde_json::to_vec(&secret).unwrap()));
    for reaped in [false, true] {
        let store = &pair.stores[1];
        let tx = store.db.unchecked_transaction().unwrap();
        if reaped {
            tx.execute("DELETE FROM file_objects WHERE id=?1", [&id])
                .unwrap();
        }
        let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
        let changed: Record = serde_json::from_value(wire.clone()).unwrap();
        assert!(
            session
                .import_event(pair.stores[0].identity.node.id(), changed.event)
                .unwrap_err()
                .to_string()
                .contains("conflicting remote file grants")
        );
        tx.rollback().unwrap();
    }
    pair.policy(false);
    pair.pump();
    assert!(pair.stores[0].file_upload(&id, 0).is_err());
    assert!(pair.stores[1].file_transfer(&id).is_err());
    assert!(pair.stores[1].file_received(&id, 0, &chunks[0]).is_err());
    assert!(pair.agent(1, AgentOp::FileExport { file_id: id }).is_err());
}
