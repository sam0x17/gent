use super::directory_push_tests::{forget, negotiate, snapshot};
use super::*;

#[tokio::test]
async fn only_a_matching_peer_snapshot_suppresses_the_periodic_frontier_after_reopen() {
    let mut pair = Pair::new().await;
    let peer = pair.stores[1].identity.node.id().to_owned();
    let mut remote = snapshot(&pair.stores[1]);
    remote.incarnation = Some(Uuid::new_v4());
    remote.frontier.clear();
    {
        let store = &pair.stores[0];
        let tx = store.db.unchecked_transaction().unwrap();
        let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
        let first = session.outgoing_directory(&peer, 6, false).unwrap();
        assert!(!first.frontier.is_empty());
        assert_eq!(first.root, remote.root);
        session.directory_admitted(&peer, &first).unwrap();
        session.timestamp += 300;
        assert_eq!(session.outgoing_directory(&peer, 6, false).unwrap(), first);
        session.receive_directory_snapshot(&peer, remote).unwrap();
        tx.commit().unwrap();
    }
    pair.reopen(0);
    let store = &pair.stores[0];
    let tx = store.db.unchecked_transaction().unwrap();
    let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
    session.timestamp += 3600;
    for version in [5, 6] {
        let short = session.outgoing_directory(&peer, version, false).unwrap();
        let full = session.outgoing_directory(&peer, version, true).unwrap();
        assert!(short.frontier.is_empty());
        assert!(!full.frontier.is_empty());
        assert_eq!(short.root, full.root);
        assert_eq!(short.incarnation, full.incarnation);
        assert_eq!(short.sequence, full.sequence);
    }
    assert!(
        !session
            .outgoing_directory(&peer, 4, false)
            .unwrap()
            .frontier
            .is_empty()
    );
}

#[tokio::test]
async fn changed_incarnations_and_rolled_back_sequences_require_a_new_frontier() {
    let pair = Pair::new().await;
    let store = &pair.stores[0];
    let peer = pair.stores[1].identity.node.id();
    let mut remote = snapshot(&pair.stores[1]);
    remote.frontier.clear();
    let replacement = Uuid::new_v4();
    let tx = store.db.unchecked_transaction().unwrap();
    let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
    // The peer is replaced, then restored within that same incarnation.
    for (incarnation, sequence) in [(Uuid::new_v4(), 100), (replacement, 100), (replacement, 1)] {
        remote.incarnation = Some(incarnation);
        remote.sequence = sequence;
        session
            .receive_directory_snapshot(peer, remote.clone())
            .unwrap();
        let full = session.outgoing_directory(peer, 6, false).unwrap();
        assert!(!full.frontier.is_empty());
        session.directory_admitted(peer, &full).unwrap();
        session
            .receive_directory_snapshot(peer, remote.clone())
            .unwrap();
        session.timestamp += 301;
        assert!(
            session
                .outgoing_directory(peer, 6, false)
                .unwrap()
                .frontier
                .is_empty()
        );
    }
    tx.execute(
        "UPDATE directory_incarnation SET id=?1",
        [Uuid::new_v4().to_string()],
    )
    .unwrap();
    session
        .receive_directory_snapshot(peer, remote.clone())
        .unwrap();
    assert!(
        !session
            .outgoing_directory(peer, 6, false)
            .unwrap()
            .frontier
            .is_empty()
    );
    let original = session.directory_snapshot().unwrap();
    let mut newer = original.clone();
    newer.sequence += 1;
    tx.execute(
        "UPDATE directory_snapshot SET view=?1",
        [serde_json::to_vec(&newer).unwrap()],
    )
    .unwrap();
    let full = session.outgoing_directory(peer, 6, false).unwrap();
    assert!(!full.frontier.is_empty());
    session.directory_admitted(peer, &full).unwrap();
    session.receive_directory_snapshot(peer, remote).unwrap();
    // Restore an older local snapshot with the same content and incarnation.
    tx.execute(
        "UPDATE directory_snapshot SET view=?1",
        [serde_json::to_vec(&original).unwrap()],
    )
    .unwrap();
    assert!(
        !session
            .outgoing_directory(peer, 6, false)
            .unwrap()
            .frontier
            .is_empty()
    );
}

#[tokio::test]
async fn rollback_at_the_same_divergent_root_restarts_a_completed_push() {
    let mut pair = Pair::new().await;
    negotiate(&mut pair);
    let peer = pair.stores[1].identity.node.id();
    forget(&pair.stores[1], &pair.agents[0]);
    let mut remote = snapshot(&pair.stores[1]);
    remote.incarnation = Some(Uuid::new_v4());
    remote.sequence = 100;
    let store = &pair.stores[0];
    let tx = store.db.unchecked_transaction().unwrap();
    let session = store.network_session(&tx, store.identity.state(&tx).unwrap());
    session
        .receive_directory_snapshot(peer, remote.clone())
        .unwrap();
    // The one-page repair was sent, but the remote has restored its older view.
    assert_eq!(
        tx.execute("DELETE FROM network_events WHERE peer=?1", [peer])
            .unwrap(),
        1
    );
    session
        .receive_directory_snapshot(peer, remote.clone())
        .unwrap();
    assert!(
        !tx.prepare("SELECT 1 FROM network_events WHERE peer=?1")
            .unwrap()
            .exists([peer])
            .unwrap()
    );
    remote.sequence = 1;
    session.receive_directory_snapshot(peer, remote).unwrap();
    let body: Vec<u8> = tx
        .query_row(
            "SELECT body FROM network_events WHERE peer=?1",
            [peer],
            |r| r.get(0),
        )
        .unwrap();
    let record: Record = serde_json::from_slice(&body).unwrap();
    assert!(!record.directory.unwrap().frontier.is_empty());
    let Event::Directory { envelope } = record.event else {
        panic!("expected directory repair")
    };
    let crate::messages::directory::Envelope::Push { chats } = *envelope else {
        panic!("expected push")
    };
    assert!(chats.iter().any(|chat| chat.id == pair.agents[0]));
}

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
    assert_eq!(record.version, crate::messages::wire::CURRENT);
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
    let queued: Vec<u8> = store
        .db
        .query_row("SELECT body FROM network_events", [], |r| r.get(0))
        .unwrap();
    let record: Record = serde_json::from_slice(&queued).unwrap();
    assert!(!record.directory.unwrap().frontier.is_empty());
    assert!(matches!(record.event, Event::Directory { envelope }
        if matches!(*envelope, crate::messages::directory::Envelope::Push { ref chats } if chats.is_empty())));
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
