use super::*;
use crate::messages::directory::{Envelope, Reply, Summary};

#[tokio::test]
async fn directory_rejects_tampering_and_another_carriers_chats() {
    let mut pair = Pair::new().await;
    negotiate(&mut pair);
    let id = pair.agents[0].clone();
    forget(&pair, 1, &id);
    pair.stores[1].directory_tick().unwrap();
    deliver(&mut pair, 1);
    let bytes: Vec<u8> = pair.stores[0]
        .db
        .query_row(
            "SELECT body FROM network_events ORDER BY rowid LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut record: Record = serde_json::from_slice(&bytes).unwrap();
    if let Event::Directory { envelope } = &mut record.event {
        if let Envelope::Reply {
            result: Reply::Leaves { chats },
            ..
        } = envelope.as_mut()
        {
            chats[0].name = "tampered".into();
        } else {
            panic!("expected leaves");
        }
    }
    {
        let store = &pair.stores[1];
        let tx = store.db.unchecked_transaction().unwrap();
        let result = store
            .network_session(&tx, store.identity.state(&tx).unwrap())
            .import_event(pair.stores[0].identity.node.id(), record.event);
        assert!(result.unwrap_err().to_string().contains("leaf hash"));
    }
    // A valid tree from node 0 cannot be presented by node 1 as its own tree.
    pair.stores[0].directory_tick().unwrap();
    let progress: Vec<u8> = pair.stores[0]
        .db
        .query_row("SELECT progress FROM directory_sync", [], |r| r.get(0))
        .unwrap();
    let round = Uuid::parse_str(
        serde_json::from_slice::<Value>(&progress).unwrap()["round"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mut record: Record = serde_json::from_slice(&bytes).unwrap();
    if let Event::Directory { envelope } = &mut record.event
        && let Envelope::Reply { round: value, .. } = envelope.as_mut()
    {
        *value = round;
    }
    {
        let store = &pair.stores[0];
        let tx = store.db.unchecked_transaction().unwrap();
        assert!(
            store
                .network_session(&tx, store.identity.state(&tx).unwrap())
                .import_event(pair.stores[1].identity.node.id(), record.event)
                .is_err()
        );
    }
    pair.pump();
    assert_eq!(status(&pair, 1)["state"], "matched");
}

#[tokio::test]
async fn directory_changed_snapshot_finishes_then_retries_and_converges() {
    let mut pair = Pair::new().await;
    for i in 0..32 {
        pair.stores[0]
            .execute(Request::Agent {
                credential: config::secret(),
                action: AgentOp::Register {
                    name: format!("history-{i}"),
                    provider: "test".into(),
                },
            })
            .unwrap();
    }
    pair.pump();
    negotiate(&mut pair);
    forget(&pair, 1, &pair.agents[0]);
    pair.stores[1].directory_tick().unwrap();
    deliver(&mut pair, 1);
    deliver(&mut pair, 0);
    pair.agent(
        0,
        AgentOp::Rename {
            name: "new coordinator".into(),
            expected_generation: 1,
        },
    )
    .unwrap();
    pair.pump();
    assert_eq!(status(&pair, 1)["state"], "changed");
    due(&pair, 1);
    check(&mut pair);
    assert_eq!(status(&pair, 1)["state"], "matched");
}

fn negotiate(pair: &mut Pair) {
    for store in &mut pair.stores {
        store.presence_tick().unwrap();
    }
    pair.pump();
}

fn forget(pair: &Pair, index: usize, id: &str) {
    // Simulate a lost directory entry after transport and announcement dedup
    // have already committed. Never reset encrypted stream state.
    let db = &pair.stores[index].db;
    db.execute("DELETE FROM agent_activity WHERE agent=?1", [id])
        .unwrap();
    db.execute("DELETE FROM network_origins WHERE agent=?1", [id])
        .unwrap();
    db.execute("DELETE FROM agents WHERE id=?1", [id]).unwrap();
}

fn check(pair: &mut Pair) {
    for store in &mut pair.stores {
        store.directory_tick().unwrap();
    }
    pair.pump();
}

fn status(pair: &Pair, index: usize) -> Value {
    pair.stores[index].synchronization_status().unwrap()["directory"]["peers"][0].clone()
}

fn due(pair: &Pair, index: usize) {
    pair.stores[index]
        .db
        .execute("UPDATE directory_sync SET next_check=0", [])
        .unwrap();
}

fn deliver(pair: &mut Pair, from: usize) -> Option<Event> {
    let group: Vec<u8> = pair.stores[from]
        .db
        .query_row("SELECT outgoing FROM network_links", [], |r| r.get(0))
        .unwrap();
    let next = pair.stores[1 - from].data_next(&group).unwrap();
    let record: Option<Vec<u8>> = pair.stores[from]
        .db
        .query_row(
            "SELECT body FROM network_events WHERE peer=?1 ORDER BY rowid LIMIT 1",
            [pair.stores[1 - from].identity.node.id()],
            |r| r.get(0),
        )
        .optional()
        .unwrap();
    pair.stores[from].data_prepare(&group).unwrap();
    if let Some(packet) = pair.stores[from].data_outgoing(&group, next).unwrap() {
        pair.stores[1 - from].data_receive(&packet).unwrap();
    }
    record.map(|b| serde_json::from_slice::<Record>(&b).unwrap().event)
}

#[tokio::test]
async fn directory_repairs_manual_registration_from_before_join_after_restart() {
    let mut pair = Pair::with_preexisting_chat(true).await;
    let id = pair.agents[0].clone();
    assert!(
        pair.agent(1, AgentOp::Agents)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["id"] == id && a["name"] == "coordinator")
    );
    negotiate(&mut pair);
    forget(&pair, 1, &id);
    assert!(pair.stores[1].directory_tick().unwrap());
    let before: usize = pair.stores[1]
        .db
        .query_row("SELECT count(*) FROM network_events", [], |r| r.get(0))
        .unwrap();
    pair.reopen(1);
    for _ in 0..5 {
        assert!(!pair.stores[1].directory_tick().unwrap());
    }
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT count(*) FROM network_events", [], |r| r
                .get::<_, usize>(0))
            .unwrap(),
        before
    );
    pair.pump();
    assert!(
        pair.agent(1, AgentOp::Agents)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["id"] == id && a["name"] == "coordinator")
    );
    assert_eq!(status(&pair, 1)["state"], "matched");
    assert_eq!(status(&pair, 1)["verified_chats"], 1);
    // A second check exchanges only roots, with no registration payload.
    due(&pair, 1);
    pair.stores[1].directory_tick().unwrap();
    assert!(matches!(
        deliver(&mut pair, 1),
        Some(Event::Directory { .. })
    ));
    assert!(
        matches!(deliver(&mut pair, 0), Some(Event::Directory { envelope }) if matches!(*envelope, Envelope::Reply { result: Reply::Equal, .. }))
    );
}

#[tokio::test]
async fn directory_only_transfers_the_differing_branch_and_preserves_visibility() {
    let mut pair = Pair::new().await;
    for i in 0..72 {
        pair.stores[0]
            .execute(Request::Agent {
                credential: config::secret(),
                action: AgentOp::Register {
                    name: format!("discovered-{i}"),
                    provider: "test".into(),
                },
            })
            .unwrap();
    }
    pair.pump();
    negotiate(&mut pair);
    let id = pair.agents[0].clone();
    forget(&pair, 1, &id);
    pair.stores[1].directory_tick().unwrap();
    let mut leaves = 0;
    let mut branches = 0;
    for _ in 0..50 {
        deliver(&mut pair, 1);
        if let Some(Event::Directory { envelope }) = deliver(&mut pair, 0) {
            match *envelope {
                Envelope::Reply {
                    result: Reply::Leaves { chats },
                    ..
                } => leaves += chats.len(),
                Envelope::Reply {
                    result: Reply::Branch { .. },
                    ..
                } => branches += 1,
                _ => {}
            }
        }
        if status(&pair, 1)["state"] == "matched" {
            break;
        }
    }
    assert_eq!(status(&pair, 1)["state"], "matched");
    assert_eq!(status(&pair, 1)["verified_chats"], 73);
    assert!(branches > 0 && leaves > 0 && leaves <= 16);
    // Merkle repair changes neither chat visibility rules nor the inbox.
    let mut policy = pair.stores[0].config.policy.clone();
    policy.rules.push(Rule {
        actor: Selector::All,
        peer: Selector::Agent(id.clone()),
        permission: Permission::Enumerate,
        effect: Effect::Deny,
    });
    pair.stores[0]
        .execute(Request::Owner {
            credential: config::read_private(&pair.homes[0].path().join("owner.key")).unwrap(),
            action: OwnerOp::SetPolicy { policy },
        })
        .unwrap();
    pair.pump();
    due(&pair, 1);
    check(&mut pair);
    assert!(
        !pair
            .agent(1, AgentOp::Agents)
            .unwrap()
            .to_string()
            .contains(&id)
    );
    assert_eq!(pair.agent(1, AgentOp::Inbox).unwrap(), json!([]));
}

#[tokio::test]
async fn directory_repairs_missed_renames_and_revocations_without_resurrecting_chats() {
    let mut pair = Pair::new().await;
    negotiate(&mut pair);
    let id = pair.agents[0].clone();
    pair.agent(
        0,
        AgentOp::Rename {
            name: "coordinator".into(),
            expected_generation: 1,
        },
    )
    .unwrap();
    pair.pump();
    pair.stores[1]
        .db
        .execute("UPDATE agents SET name='old-name' WHERE id=?1", [&id])
        .unwrap();
    pair.stores[1]
        .db
        .execute(
            "UPDATE network_origins SET generation=1 WHERE agent=?1",
            [&id],
        )
        .unwrap();
    check(&mut pair);
    assert_eq!(status(&pair, 1)["state"], "matched");
    assert!(
        pair.agent(1, AgentOp::Agents)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["name"] == "coordinator")
    );
    pair.stores[0]
        .execute(Request::Owner {
            credential: config::read_private(&pair.homes[0].path().join("owner.key")).unwrap(),
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
            "UPDATE network_origins SET generation=2 WHERE agent=?1",
            [&id],
        )
        .unwrap();
    due(&pair, 1);
    check(&mut pair);
    assert_eq!(status(&pair, 1)["state"], "matched");
    assert!(
        pair.stores[1]
            .db
            .query_row("SELECT revoked FROM agents WHERE id=?1", [&id], |r| r
                .get::<_, bool>(0))
            .unwrap()
    );
}

#[tokio::test]
async fn directory_waits_for_supported_wire_and_reports_extras_without_deleting() {
    let mut pair = Pair::new().await;
    for store in &mut pair.stores {
        assert!(!store.directory_tick().unwrap());
    }
    negotiate(&mut pair);
    // A version 2 peer can still exchange messages, but receives no tree events.
    pair.stores[0]
        .db
        .execute("UPDATE wire_peers SET version=2", [])
        .unwrap();
    assert!(!pair.stores[0].directory_tick().unwrap());
    let id = pair.agents[0].clone();
    forget(&pair, 0, &id);
    pair.stores[1].directory_tick().unwrap();
    pair.pump();
    assert_eq!(status(&pair, 1)["state"], "different");
    assert!(
        pair.agent(1, AgentOp::Agents)
            .unwrap()
            .to_string()
            .contains(&id)
    );
}

#[tokio::test]
async fn directory_rolls_back_failed_repairs_and_ignores_unrelated_rounds() {
    let mut pair = Pair::new().await;
    negotiate(&mut pair);
    let id = pair.agents[0].clone();
    forget(&pair, 1, &id);
    pair.stores[1].directory_tick().unwrap();
    deliver(&mut pair, 1);
    let bytes: Vec<u8> = pair.stores[0]
        .db
        .query_row(
            "SELECT body FROM network_events ORDER BY rowid LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let store = &pair.stores[1];
    let peer = pair.stores[0].identity.node.id();
    let original: Vec<u8> = store
        .db
        .query_row("SELECT progress FROM directory_sync", [], |r| r.get(0))
        .unwrap();
    {
        let tx = store.db.unchecked_transaction().unwrap();
        store
            .network_session(&tx, store.identity.state(&tx).unwrap())
            .import_event(
                peer,
                Event::Directory {
                    envelope: Box::new(Envelope::Reply {
                        round: Uuid::new_v4(),
                        prefix: "".into(),
                        root: Summary {
                            hash: [0; 32],
                            count: 0,
                        },
                        result: Reply::Equal,
                    }),
                },
            )
            .unwrap();
        tx.commit().unwrap();
    }
    store.db.execute_batch("CREATE TRIGGER fail_directory BEFORE UPDATE ON directory_sync BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    {
        let tx = store.db.unchecked_transaction().unwrap();
        let result = store
            .network_session(&tx, store.identity.state(&tx).unwrap())
            .import_event(
                peer,
                serde_json::from_slice::<Record>(&bytes).unwrap().event,
            );
        assert!(result.is_err());
    }
    assert_eq!(
        store
            .db
            .query_row("SELECT progress FROM directory_sync", [], |r| r
                .get::<_, Vec<u8>>(0))
            .unwrap(),
        original
    );
    assert!(
        !store
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM agents WHERE id=?1)",
                [&id],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    store
        .db
        .execute_batch("DROP TRIGGER fail_directory;")
        .unwrap();
    pair.reopen(1);
    pair.pump();
    assert_eq!(status(&pair, 1)["state"], "matched");
}
