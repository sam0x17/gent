use super::directory_push_tests::{forget, negotiate, snapshot};
use super::*;

#[tokio::test]
async fn unchanged_directory_is_short_and_v4_still_gets_a_complete_frontier() {
    let mut pair = Pair::new().await;
    negotiate(&mut pair);
    // First V5 traffic advertises the full view after capability negotiation.
    pair.send(vec![]).unwrap();
    pair.pump();
    pair.send(vec![]).unwrap();
    let body: Vec<u8> = pair.stores[0].db.query_row("SELECT body FROM network_events WHERE json_extract(CAST(body AS TEXT),'$.event.kind')='message'", [], |r| r.get(0)).unwrap();
    let record: Record = serde_json::from_slice(&body).unwrap();
    assert_eq!(record.version, 5);
    let directory = record.directory.unwrap();
    assert!(directory.incarnation.is_some());
    assert!(directory.frontier.is_empty());
    pair.pump();
    pair.stores[0]
        .db
        .execute("UPDATE wire_peers SET version=4", [])
        .unwrap();
    pair.send(vec![]).unwrap();
    let body: Vec<u8> = pair.stores[0].db.query_row("SELECT body FROM network_events WHERE json_extract(CAST(body AS TEXT),'$.event.kind')='message'", [], |r| r.get(0)).unwrap();
    let record: Record = serde_json::from_slice(&body).unwrap();
    assert_eq!(record.version, 4);
    let directory = record.directory.unwrap();
    assert!(directory.incarnation.is_none());
    assert!(!directory.frontier.is_empty());
    pair.pump();
    assert_eq!(
        pair.agent(1, AgentOp::Inbox)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[tokio::test]
async fn unknown_short_root_and_restored_sequence_repair_without_acknowledgement_loop() {
    let mut pair = Pair::new().await;
    negotiate(&mut pair);
    forget(&pair.stores[1], &pair.agents[0]);
    let mut remote = snapshot(&pair.stores[1]);
    remote.incarnation = Some(Uuid::new_v4());
    remote.sequence = 1;
    remote.frontier.clear();
    let peer = pair.stores[1].identity.node.id().to_owned();
    let store = &pair.stores[0];
    let original_root = snapshot(store).root;
    let tx = store.db.unchecked_transaction().unwrap();
    let session = store.network_session(&tx, store.identity.state(&tx).unwrap());
    // Simulate restoring a database after a much newer summary was observed.
    let mut before = remote.clone();
    before.sequence = 100;
    before.root = original_root;
    session.receive_directory_snapshot(&peer, before).unwrap();
    for _ in 0..10 {
        session
            .receive_directory_snapshot(&peer, remote.clone())
            .unwrap();
    }
    tx.commit().unwrap();
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
    for store in &pair.stores {
        assert_eq!(
            store
                .db
                .query_row("SELECT COUNT(*) FROM network_events", [], |r| r
                    .get::<_, usize>(0))
                .unwrap(),
            0
        );
    }
}
