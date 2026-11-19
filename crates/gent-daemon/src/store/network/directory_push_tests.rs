use super::*;
use crate::messages::directory::Snapshot;

pub(super) fn snapshot(store: &Store) -> Snapshot {
    let tx = store.db.unchecked_transaction().unwrap();
    let value = store
        .network_session(&tx, store.identity.state(&tx).unwrap())
        .directory_snapshot()
        .unwrap();
    tx.commit().unwrap();
    value
}

pub(super) fn forget(store: &Store, id: &str) {
    for table in ["agent_activity", "network_origins"] {
        store
            .db
            .execute(&format!("DELETE FROM {table} WHERE agent=?1"), [id])
            .unwrap();
    }
    store
        .db
        .execute("DELETE FROM agents WHERE id=?1", [id])
        .unwrap();
}

pub(super) fn negotiate(pair: &mut Pair) {
    for store in &mut pair.stores {
        store.presence_tick().unwrap();
    }
    pair.pump();
}

fn heartbeat(pair: &mut Pair, from: usize) {
    pair.stores[from]
        .db
        .execute("UPDATE node_presence SET next_probe_at=0", [])
        .unwrap();
    pair.stores[from].presence_tick().unwrap();
}

#[tokio::test]
async fn failed_optional_repair_does_not_roll_back_an_incoming_message() {
    let mut pair = Pair::new().await;
    let extra = pair.stores[1]
        .execute(Request::Agent {
            credential: config::secret(),
            action: AgentOp::Register {
                name: "another chat".into(),
                provider: "test".into(),
            },
        })
        .unwrap()["agent"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    pair.pump();
    negotiate(&mut pair);
    forget(&pair.stores[0], &extra);
    pair.stores[1]
        .db
        .execute_batch(
            "CREATE TRIGGER reject_optional_repair BEFORE INSERT ON network_events
        WHEN json_extract(CAST(NEW.body AS TEXT),'$.event.envelope.step')='push'
        BEGIN SELECT RAISE(ABORT,'injected repair failure'); END;",
        )
        .unwrap();
    let sent = pair.send(vec![]).unwrap();
    pair.pump();
    let inbox = pair.agent(1, AgentOp::Inbox).unwrap();
    assert_eq!(inbox.as_array().unwrap().len(), 1);
    assert_eq!(inbox[0]["id"], sent["message_id"]);
    assert!(
        pair.stores[1]
            .db
            .query_row("SELECT error IS NOT NULL FROM directory_push", [], |r| r
                .get::<_, bool>(
                0
            ))
            .unwrap()
    );
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER reject_optional_repair")
        .unwrap();
    pair.stores[1].directory_tick().unwrap();
    pair.pump();
    assert_eq!(
        snapshot(&pair.stores[0]).root,
        snapshot(&pair.stores[1]).root
    );
}

#[tokio::test]
async fn push_repairs_revocations_and_keeps_chat_visibility_restrictions() {
    let mut pair = Pair::new().await;
    negotiate(&mut pair);
    let id = pair.agents[0].clone();
    let credential = config::read_private(&pair.homes[0].path().join("owner.key")).unwrap();
    pair.stores[0]
        .execute(Request::Owner {
            credential,
            action: OwnerOp::Revoke {
                agent_id: id.clone(),
            },
        })
        .unwrap();
    pair.pump();
    pair.stores[1]
        .db
        .execute("UPDATE agents SET revoked=0 WHERE id=?1", [&id])
        .unwrap();
    pair.stores[1]
        .db
        .execute(
            "UPDATE network_origins SET generation=1 WHERE agent=?1",
            [&id],
        )
        .unwrap();
    heartbeat(&mut pair, 1);
    pair.pump();
    assert!(
        pair.stores[1]
            .db
            .query_row("SELECT revoked FROM agents WHERE id=?1", [&id], |r| r
                .get::<_, bool>(0))
            .unwrap()
    );
    assert!(
        !pair
            .agent(1, AgentOp::Agents)
            .unwrap()
            .to_string()
            .contains(&id)
    );
    assert_eq!(
        snapshot(&pair.stores[0]).root,
        snapshot(&pair.stores[1]).root
    );
}

#[tokio::test]
async fn ordinary_traffic_pushes_a_missing_manual_chat_without_a_probe() {
    let mut pair = Pair::with_preexisting_chat(true).await;
    negotiate(&mut pair);
    let id = pair.agents[0].clone();
    forget(&pair.stores[1], &id);
    pair.agent(
        1,
        AgentOp::Rename {
            name: "ordinary-rename".into(),
            expected_generation: 1,
        },
    )
    .unwrap();
    let bytes: Vec<u8> = pair.stores[1]
        .db
        .query_row(
            "SELECT body FROM network_events ORDER BY rowid LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let record: Record = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record.version, crate::messages::wire::CURRENT);
    assert!(record.directory.is_some());
    assert!(matches!(record.event, Event::Registration { .. }));
    pair.pump();
    assert_eq!(
        snapshot(&pair.stores[0]).root,
        snapshot(&pair.stores[1]).root
    );
    assert!(
        pair.agent(1, AgentOp::Agents)
            .unwrap()
            .to_string()
            .contains(&id)
    );
    for store in &pair.stores {
        assert_eq!(
            store
                .db
                .query_row("SELECT COUNT(*) FROM network_events", [], |r| r
                    .get::<_, usize>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .db
                .query_row("SELECT COUNT(*) FROM directory_sync", [], |r| r
                    .get::<_, usize>(0))
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn push_pages_are_bounded_resumable_and_do_not_loop() {
    let mut pair = Pair::new().await;
    let mut ids = Vec::new();
    for i in 0..80 {
        let value = pair.stores[0]
            .execute(Request::Agent {
                credential: config::secret(),
                action: AgentOp::Register {
                    name: format!("history-{i}"),
                    provider: "test".into(),
                },
            })
            .unwrap();
        ids.push(value["agent"]["id"].as_str().unwrap().to_owned());
    }
    pair.pump();
    negotiate(&mut pair);
    for id in &ids {
        forget(&pair.stores[1], id);
    }
    heartbeat(&mut pair, 1);
    pair.pump();
    pair.reopen(0);
    pair.reopen(1);
    for _ in 0..12 {
        for store in &mut pair.stores {
            store.directory_tick().unwrap();
        }
        for store in &pair.stores {
            let bytes = store
                .db
                .prepare("SELECT body FROM network_events")
                .unwrap()
                .query_map([], |r| r.get::<_, Vec<u8>>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            for body in bytes {
                let record: Record = serde_json::from_slice(&body).unwrap();
                if let Event::Directory { envelope } = record.event
                    && let crate::messages::directory::Envelope::Push { chats } = *envelope
                {
                    assert!(chats.len() <= crate::messages::directory::PUSH_LIMIT);
                }
            }
        }
        pair.pump();
        if snapshot(&pair.stores[0]).root == snapshot(&pair.stores[1]).root {
            break;
        }
    }
    assert_eq!(snapshot(&pair.stores[0]).root.count, 82);
    assert_eq!(
        snapshot(&pair.stores[0]).root,
        snapshot(&pair.stores[1]).root
    );
    let before = snapshot(&pair.stores[0]);
    for _ in 0..3 {
        heartbeat(&mut pair, 1);
        pair.pump();
    }
    assert_eq!(before, snapshot(&pair.stores[0]));
    assert_eq!(pair.agent(1, AgentOp::Inbox).unwrap(), json!([]));
}

#[tokio::test]
async fn sequence_persists_and_activity_does_not_rebuild_the_tree() {
    let mut pair = Pair::new().await;
    let initial = snapshot(&pair.stores[0]);
    pair.stores[0]
        .db
        .execute("UPDATE agents SET last_seen=last_seen+1", [])
        .unwrap();
    pair.stores[0].db.execute_batch("CREATE TRIGGER reject_rebuild BEFORE UPDATE ON directory_snapshot WHEN NEW.dirty=0 BEGIN SELECT RAISE(ABORT,'unexpected rebuild'); END;").unwrap();
    assert_eq!(snapshot(&pair.stores[0]), initial);
    pair.reopen(0);
    assert_eq!(snapshot(&pair.stores[0]), initial);
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER reject_rebuild")
        .unwrap();
    pair.agent(
        0,
        AgentOp::Rename {
            name: "changed".into(),
            expected_generation: 1,
        },
    )
    .unwrap();
    let renamed = snapshot(&pair.stores[0]);
    assert_eq!(renamed.sequence, initial.sequence + 1);
    assert_ne!(renamed.root, initial.root);
    pair.reopen(0);
    assert_eq!(snapshot(&pair.stores[0]), renamed);
}

#[tokio::test]
async fn equal_sequences_never_hide_divergence_and_failed_push_rolls_back() {
    let mut pair = Pair::new().await;
    negotiate(&mut pair);
    let original = snapshot(&pair.stores[0]);
    forget(&pair.stores[1], &pair.agents[0]);
    let mut remote = snapshot(&pair.stores[1]);
    remote.sequence = original.sequence;
    let peer = pair.stores[1].identity.node.id();
    let store = &pair.stores[0];
    store.db.execute_batch("CREATE TRIGGER reject_push BEFORE INSERT ON network_events BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    {
        let tx = store.db.unchecked_transaction().unwrap();
        let session = store.network_session(&tx, store.identity.state(&tx).unwrap());
        session
            .receive_directory_snapshot(peer, remote.clone())
            .unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        store
            .db
            .query_row("SELECT COUNT(*) FROM network_events", [], |r| r
                .get::<_, usize>(0))
            .unwrap(),
        0
    );
    assert!(
        !store
            .db
            .query_row(
                "SELECT complete FROM directory_push WHERE peer=?1",
                [peer],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    store.db.execute_batch("DROP TRIGGER reject_push").unwrap();
    {
        let tx = store.db.unchecked_transaction().unwrap();
        let session = store.network_session(&tx, store.identity.state(&tx).unwrap());
        session
            .receive_directory_snapshot(peer, remote.clone())
            .unwrap();
        // An identical incoming snapshot cannot enqueue another copy.
        session.receive_directory_snapshot(peer, remote).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        store
            .db
            .query_row("SELECT COUNT(*) FROM network_events", [], |r| r
                .get::<_, usize>(0))
            .unwrap(),
        1
    );
    pair.pump();
    assert_eq!(
        snapshot(&pair.stores[0]).root,
        snapshot(&pair.stores[1]).root
    );
}
