use super::*;

#[test]
fn only_committed_receiver_heads_retire_a_prefix_and_preserve_offline_suffix() {
    let w = World::new();
    let origin = w.stream(0, &[1]);
    let group = origin.group();
    let ids: Vec<_> = (0..4).map(|_| Uuid::new_v4()).collect();
    let packets: Vec<_> = ids
        .iter()
        .map(|id| w.endpoint(0).send(group, *id, b"private", w.now).unwrap())
        .collect();
    let origin_receipt = w.endpoint(1).receipt(group, w.now).unwrap();
    assert_eq!(origin_receipt.sequence(), 0);
    // Staged ciphertext and gaps do not authorize deletion.
    w.endpoint(1).stage(&packets[1], w.now).unwrap();
    assert_eq!(w.endpoint(1).receipt(group, w.now).unwrap(), origin_receipt);
    w.endpoint(1).stage(&packets[0], w.now).unwrap();
    w.endpoint(1).drain(group, 2, w.now).unwrap();
    let receipt = w.endpoint(1).receipt(group, w.now).unwrap();
    assert_eq!(receipt.sequence(), 2);
    // Forged identity, wrong digest, ahead-of-writer and cross-stream receipts fail closed.
    for invalid in [
        w.nodes[2]
            .sign_stream_receipt(group, 2, packets[1].digest().unwrap())
            .unwrap(),
        w.nodes[1].sign_stream_receipt(group, 2, [9; 32]).unwrap(),
        w.nodes[1].sign_stream_receipt(group, 5, [9; 32]).unwrap(),
        w.nodes[1]
            .sign_stream_receipt(b"unknown", 2, packets[1].digest().unwrap())
            .unwrap(),
    ] {
        assert!(
            w.endpoint(0)
                .confirm(&invalid, w.nodes[1].id(), w.now)
                .is_err()
        );
    }
    assert!(
        w.endpoint(0)
            .confirm(&receipt, w.nodes[2].id(), w.now)
            .is_err()
    );
    assert!(w.endpoint(0).receipt(group, w.now).is_err());
    assert_eq!(w.endpoint(0).confirmed_next(group).unwrap(), 0);
    assert_eq!(
        w.endpoint(0).outbox(group, None, 8, w.now).unwrap().len(),
        5
    );
    // A failed cleanup transaction must also roll back confirmation.
    w.db(0).execute_batch("CREATE TRIGGER fail_retire BEFORE UPDATE OF packet ON stream_outbox BEGIN SELECT RAISE(ABORT,'injected retirement'); END;").unwrap();
    assert!(
        w.endpoint(0)
            .confirm(&receipt, w.nodes[1].id(), w.now)
            .is_err()
    );
    assert_eq!(w.endpoint(0).confirmed_next(group).unwrap(), 0);
    w.db(0).execute_batch("DROP TRIGGER fail_retire").unwrap();
    w.endpoint(0)
        .confirm(&receipt, w.nodes[1].id(), w.now)
        .unwrap();
    assert_eq!(w.endpoint(0).confirmed_next(group).unwrap(), 3);
    assert_eq!(
        w.endpoint(0).storage_status().unwrap()["outgoing"]["data"]["packets"],
        3
    );
    assert_eq!(
        w.endpoint(0).outbox(group, Some(2), 8, w.now).unwrap(),
        packets[2..]
    );
    assert!(w.endpoint(0).outbox(group, Some(0), 8, w.now).is_err());
    assert!(
        w.endpoint(0)
            .send(group, ids[0], b"private", w.now)
            .unwrap_err()
            .to_string()
            .contains("retired")
    );
    assert_eq!(
        w.endpoint(0)
            .send(group, ids[3], b"private", w.now)
            .unwrap(),
        packets[3]
    );
    assert_eq!(w.raw(0).outbox(0, 8).unwrap().len(), 3);
    // A stale authenticated checkpoint cannot roll back the retained floor.
    w.endpoint(0)
        .confirm(&origin_receipt, w.nodes[1].id(), w.now)
        .unwrap();
    assert_eq!(
        w.endpoint(0).confirmed_receipt(group, w.now).unwrap(),
        Some(receipt)
    );
    for packet in &packets[2..] {
        w.endpoint(1).stage(packet, w.now).unwrap();
        w.endpoint(1).drain(group, 1, w.now).unwrap();
    }
    assert_eq!(w.endpoint(1).inbox(group, 0, 8).unwrap().len(), 4);
    assert_eq!(w.endpoint(0).status(group, w.now).unwrap().head, 4);
}

#[test]
fn version_four_upgrade_preserves_unconfirmed_history() {
    let w = World::new();
    let origin = w.stream(0, &[1]);
    let packet = w
        .endpoint(0)
        .send(origin.group(), Uuid::new_v4(), b"offline", w.now)
        .unwrap();
    w.db(0)
        .execute_batch("DROP TABLE stream_confirmed; PRAGMA user_version=4;")
        .unwrap();
    assert_eq!(
        w.endpoint(0)
            .outbox(origin.group(), Some(0), 8, w.now)
            .unwrap(),
        vec![packet]
    );
    assert_eq!(w.endpoint(0).confirmed_next(origin.group()).unwrap(), 0);
    assert_eq!(
        w.db(0)
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        10
    );
}

#[test]
fn group_receipts_and_revoked_readers_cannot_retire_other_members_history() {
    let w = World::new();
    let origin = w.stream(0, &[1, 2]);
    assert!(w.endpoint(1).receipt(origin.group(), w.now).is_err());
    let forged = w.nodes[1]
        .sign_stream_receipt(origin.group(), 0, origin.digest().unwrap())
        .unwrap();
    assert!(
        w.endpoint(0)
            .confirm(&forged, w.nodes[1].id(), w.now)
            .is_err()
    );
    let origin = w.stream(0, &[1]);
    let receipt = w.endpoint(1).receipt(origin.group(), w.now).unwrap();
    let revoked = w
        .state
        .revoke_node(&w.owner, w.nodes[1].id(), w.now)
        .unwrap();
    w.endpoint(0).apply_authority(&[revoked]).unwrap();
    assert!(
        w.endpoint(0)
            .confirm(&receipt, w.nodes[1].id(), w.now)
            .is_err()
    );
}

#[test]
fn retirement_is_bounded_and_keeps_retry_tombstones() {
    let w = World::new();
    let origin = w.stream(0, &[1]);
    let group = origin.group();
    let mut packets = vec![];
    for _ in 0..270 {
        let p = w
            .endpoint(0)
            .send(group, Uuid::new_v4(), b"durable", w.now)
            .unwrap();
        w.endpoint(1).stage(&p, w.now).unwrap();
        w.endpoint(1).drain(group, 1, w.now).unwrap();
        packets.push(p);
    }
    let receipt = w.endpoint(1).receipt(group, w.now).unwrap();
    w.endpoint(0)
        .confirm(&receipt, w.nodes[1].id(), w.now)
        .unwrap();
    assert_eq!(
        w.endpoint(0).storage_status().unwrap()["retired_packet_tombstones"],
        256
    );
    let preview = w.endpoint(0).clean_storage(true).unwrap();
    assert_eq!(preview["retained_packets_removed"], 14);
    assert_eq!(
        w.endpoint(0).storage_status().unwrap()["retired_packet_tombstones"],
        256
    );
    w.endpoint(0).clean_storage(false).unwrap();
    assert_eq!(
        w.endpoint(0).storage_status().unwrap()["retired_packet_tombstones"],
        270
    );
    assert_eq!(
        w.endpoint(0).storage_status().unwrap()["outgoing"]["data"]["packets"],
        1
    );
}
