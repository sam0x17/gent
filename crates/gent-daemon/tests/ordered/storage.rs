use super::*;
use gent_daemon::encrypted::ordered::storage::RECENT_PACKETS;

fn count(db: &Connection, table: &str) -> u64 {
    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn offline_packets_and_retries_survive_compaction_while_replay_evidence_stays_bounded() {
    let w = World::new();
    let origin = w.stream(0, &[1]);
    let group = origin.group();
    let mut packets = vec![];
    let mut requests = vec![];
    for i in 1..=150 {
        let request = Uuid::new_v4();
        let body = format!("offline packet {i}");
        if i == 130 {
            w.db(0).execute_batch("CREATE TRIGGER fail_trim BEFORE DELETE ON stream_seen BEGIN SELECT RAISE(ABORT,'injected trim'); END;").unwrap();
            assert!(
                w.endpoint(0)
                    .send(group, request, body.as_bytes(), w.now)
                    .is_err()
            );
            assert_eq!(w.endpoint(0).status(group, w.now).unwrap().head, 129);
            assert_eq!(count(&w.db(0), "stream_outbox"), 130);
            w.db(0).execute_batch("DROP TRIGGER fail_trim;").unwrap();
        }
        packets.push(
            w.endpoint(0)
                .send(group, request, body.as_bytes(), w.now)
                .unwrap(),
        );
        requests.push((request, body));
    }
    let status = w.endpoint(0).storage_status().unwrap();
    assert_eq!(status["duplicate_bytes"], 0);
    assert_eq!(status["outgoing"]["data"]["packets"], 151);
    assert_eq!(status["accepted_digests"], RECENT_PACKETS + 1);
    // Reopening on each call models restart; retained packets still cover an
    // offline peer's entire missing prefix, beyond the replay evidence window.
    let mut fetched = w.endpoint(0).outbox(group, Some(0), 128, w.now).unwrap();
    fetched.extend(w.endpoint(0).outbox(group, Some(128), 128, w.now).unwrap());
    assert_eq!(fetched, packets);
    for (i, packet) in packets.iter().enumerate() {
        w.endpoint(1).stage(packet, w.now).unwrap();
        if i == 129 {
            w.db(1).execute_batch("CREATE TRIGGER fail_trim BEFORE DELETE ON receipts BEGIN SELECT RAISE(ABORT,'injected receipt trim'); END;").unwrap();
            assert!(w.endpoint(1).drain(group, 1, w.now).is_err());
            assert_eq!(w.endpoint(1).status(group, w.now).unwrap().head, 129);
            assert_eq!(count(&w.db(1), "inbox"), 129);
            w.db(1).execute_batch("DROP TRIGGER fail_trim;").unwrap();
        }
        assert_eq!(w.endpoint(1).drain(group, 1, w.now).unwrap().len(), 1);
    }
    assert_eq!(count(&w.db(1), "receipts"), RECENT_PACKETS + 1);
    assert_eq!(count(&w.db(1), "stream_seen"), RECENT_PACKETS + 1);
    assert_eq!(count(&w.db(1), "inbox"), 150);
    let receiver = w.endpoint(1).status(group, w.now).unwrap();
    assert_eq!(receiver.retired_through, 22);
    assert_eq!(
        w.endpoint(1).stage(&packets[0], w.now).unwrap(),
        Staged::Retired
    );
    assert_eq!(
        w.endpoint(1).stage(&packets[149], w.now).unwrap(),
        Staged::Duplicate
    );
    assert_eq!(
        w.endpoint(1).stage(&origin, w.now).unwrap(),
        Staged::Duplicate
    );
    let old_fork = w.nodes[0]
        .sign_stream_packet(group, 1, origin.digest().unwrap(), b"unknown old history")
        .unwrap();
    assert_eq!(
        w.endpoint(1).stage(&old_fork, w.now).unwrap(),
        Staged::Retired
    );
    let wrong_key = w.nodes[2]
        .sign_stream_packet(group, 1, origin.digest().unwrap(), b"forged")
        .unwrap();
    assert!(w.endpoint(1).stage(&wrong_key, w.now).is_err());
    let recent_fork = w.nodes[0]
        .sign_stream_packet(group, 150, packets[148].digest().unwrap(), b"fork")
        .unwrap();
    assert!(w.endpoint(1).stage(&recent_fork, w.now).is_err());
    for i in [0, 149] {
        let (id, body) = &requests[i];
        assert_eq!(
            w.endpoint(0)
                .send(group, *id, body.as_bytes(), w.now)
                .unwrap(),
            packets[i]
        );
        assert!(w.endpoint(0).send(group, *id, b"changed", w.now).is_err());
    }
    assert_eq!(
        w.raw(0).outbox(0, 2).unwrap()[1].1.bytes,
        packets[0].ciphertext()
    );
    // No receipt hash remains for packet 1. Its consumed MLS generation still
    // cannot be decrypted again at a new position signed by the real writer.
    let relabeled = w.nodes[0]
        .sign_stream_packet(group, 151, receiver.digest, packets[0].ciphertext())
        .unwrap();
    w.endpoint(1).stage(&relabeled, w.now).unwrap();
    assert!(w.endpoint(1).drain(group, 1, w.now).is_err());
    assert_eq!(w.endpoint(1).status(group, w.now).unwrap().head, 150);
    assert_eq!(count(&w.db(1), "inbox"), 150);
    assert!(
        w.raw(1)
            .receive(group, packets[0].ciphertext(), w.now)
            .is_err()
    );
}

#[test]
fn data_quota_preserves_exact_retries_and_configuration_reserve_and_rolls_back_crypto() {
    let w = World::new();
    let request = Uuid::new_v4();
    let (origin, packages) = w.invite(0, &[1], request);
    let group = origin.group();
    w.endpoint(1)
        .join(
            &origin,
            w.nodes[0].id(),
            &[w.nodes[0].id(), w.nodes[1].id()],
            w.now,
        )
        .unwrap();
    w.db(0)
        .execute(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<65535)
        INSERT INTO stream_outbox SELECT 'quota-'||i,?1,i,X'01' FROM n",
            [group],
        )
        .unwrap();
    let send = Uuid::new_v4();
    let error = w
        .endpoint(0)
        .send(group, send, b"after space available", w.now)
        .unwrap_err();
    assert!(error.to_string().contains("data transport history quota"));
    assert_eq!(w.endpoint(0).status(group, w.now).unwrap().head, 0);
    assert_eq!(count(&w.db(0), "outbox"), 1);
    assert_eq!(
        w.endpoint(0)
            .create(request, &[(w.nodes[1].id(), &packages[0])], w.now)
            .unwrap(),
        origin
    );
    let kp = w.endpoint(1).key_package(Uuid::new_v4(), w.now).unwrap();
    let config = w
        .endpoint(0)
        .create_configuration(&w.owner, Uuid::new_v4(), (w.nodes[1].id(), &kp), w.now)
        .unwrap();
    w.endpoint(0)
        .rotate_configuration(config.packet.group(), Uuid::new_v4(), w.now)
        .unwrap();
    assert_eq!(
        w.endpoint(0).storage_status().unwrap()["outgoing"]["configuration"]["packets"],
        2
    );
    w.db(0)
        .execute("DELETE FROM stream_outbox WHERE id LIKE 'quota-%'", [])
        .unwrap();
    w.db(0)
        .execute(
            "WITH RECURSIVE n(i) AS (VALUES(2) UNION ALL SELECT i+1 FROM n WHERE i<65535)
        INSERT INTO stream_outbox SELECT 'config-quota-'||i,?1,i,X'01' FROM n",
            [config.packet.group()],
        )
        .unwrap();
    let update = w
        .endpoint(0)
        .authority_state()
        .unwrap()
        .renew(&w.owner, w.now + 1)
        .unwrap();
    w.endpoint(0).apply_authority(&[update]).unwrap();
    let configuration_request = Uuid::new_v4();
    let revision: u64 = w
        .db(0)
        .query_row(
            "SELECT revision FROM configuration_streams WHERE group_id=?1",
            [config.packet.group()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        w.endpoint(0)
            .next_configuration(config.packet.group(), configuration_request, w.now + 1)
            .unwrap_err()
            .to_string()
            .contains("configuration transport history quota")
    );
    assert_eq!(
        w.db(0)
            .query_row(
                "SELECT revision FROM configuration_streams WHERE group_id=?1",
                [config.packet.group()],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        revision
    );
    assert_eq!(count(&w.db(0), "outbox"), 3);
    let packet = w
        .endpoint(0)
        .send(group, send, b"after space available", w.now + 1)
        .unwrap();
    w.endpoint(1).stage(&packet, w.now + 1).unwrap();
    assert_eq!(w.endpoint(1).drain(group, 1, w.now + 1).unwrap().len(), 1);
    w.db(0)
        .execute(
            "DELETE FROM stream_outbox WHERE id LIKE 'config-quota-%'",
            [],
        )
        .unwrap();
    assert!(
        w.endpoint(0)
            .next_configuration(config.packet.group(), configuration_request, w.now + 1)
            .unwrap()
            .is_some()
    );
}

#[test]
fn version_three_compaction_is_bounded_atomic_and_keeps_raw_receipts_and_exact_bytes() {
    let w = World::new();
    let origin = w.stream(0, &[1]);
    let mut packets = vec![origin.clone()];
    for _ in 0..10 {
        let packet = w
            .endpoint(0)
            .send(origin.group(), Uuid::new_v4(), b"legacy bytes", w.now)
            .unwrap();
        w.endpoint(1).stage(&packet, w.now).unwrap();
        w.endpoint(1).drain(origin.group(), 1, w.now).unwrap();
        packets.push(packet);
    }
    for packet in &packets {
        w.db(0).execute("UPDATE outbox SET bytes=?1 WHERE id IN (SELECT id FROM stream_outbox WHERE group_id=?2 AND sequence=?3)",
            rusqlite::params![packet.ciphertext(),packet.group(),packet.sequence()]).unwrap();
    }
    for i in [0, 1] {
        w.db(i).execute_batch("DROP INDEX receipt_stream_sequence; ALTER TABLE receipts DROP COLUMN stream_sequence; PRAGMA user_version=3;").unwrap();
    }
    w.db(1)
        .execute("INSERT INTO receipts VALUES(X'01',X'ff')", [])
        .unwrap();
    let mut sender = w.endpoint(0);
    let mut receiver = w.endpoint(1);
    assert_eq!(
        w.db(0)
            .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap(),
        9
    );
    let preview = sender.clean_storage(true).unwrap();
    assert_eq!(preview["duplicate_copies_compacted"], 8);
    assert_eq!(sender.storage_status().unwrap()["duplicate_copies"], 11);
    w.db(0).execute_batch("CREATE TRIGGER fail_copy BEFORE UPDATE OF bytes ON outbox WHEN OLD.sequence=2 BEGIN SELECT RAISE(ABORT,'injected compact'); END;").unwrap();
    assert!(sender.clean_storage(false).is_err());
    assert_eq!(sender.storage_status().unwrap()["duplicate_copies"], 11);
    w.db(0).execute_batch("DROP TRIGGER fail_copy;").unwrap();
    // Refuse a mismatched duplicate rather than discarding potential evidence.
    w.db(0)
        .execute("UPDATE outbox SET bytes=X'ff' WHERE sequence=1", [])
        .unwrap();
    assert!(sender.clean_storage(false).is_err());
    w.db(0)
        .execute(
            "UPDATE outbox SET bytes=?1 WHERE sequence=1",
            [origin.ciphertext()],
        )
        .unwrap();
    assert_eq!(
        sender.clean_storage(false).unwrap()["duplicate_copies_compacted"],
        8
    );
    assert_eq!(
        sender.clean_storage(false).unwrap()["duplicate_copies_compacted"],
        3
    );
    assert_eq!(
        sender.clean_storage(false).unwrap()["duplicate_copies_compacted"],
        0
    );
    assert_eq!(
        sender.outbox(origin.group(), None, 128, w.now).unwrap(),
        packets
    );
    assert_eq!(
        w.raw(0)
            .outbox(0, 128)
            .unwrap()
            .iter()
            .map(|(_, p)| p.bytes.clone())
            .collect::<Vec<_>>(),
        packets
            .iter()
            .map(|p| p.ciphertext().to_vec())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        receiver.clean_storage(true).unwrap()["wire_receipts_removed"],
        11
    );
    assert_eq!(count(&w.db(1), "receipts"), 12);
    assert_eq!(
        receiver.clean_storage(false).unwrap()["wire_receipts_removed"],
        11
    );
    assert_eq!(count(&w.db(1), "receipts"), 1);
    assert_eq!(
        receiver.stage(&packets[1], w.now).unwrap(),
        Staged::Duplicate
    );
    assert_eq!(receiver.status(origin.group(), w.now).unwrap().head, 10);
}

#[test]
fn configuration_replay_evidence_retires_without_losing_expired_lease_recovery() {
    let w = World::new();
    let kp = w.endpoint(1).key_package(Uuid::new_v4(), w.now).unwrap();
    let invitation = w
        .endpoint(0)
        .create_configuration(&w.owner, Uuid::new_v4(), (w.nodes[1].id(), &kp), w.now)
        .unwrap();
    w.endpoint(1)
        .join_configuration(&invitation, w.now)
        .unwrap();
    let group = invitation.packet.group();
    let mut first = None;
    for i in 1..=130 {
        let now = w.now + i;
        let update = w
            .endpoint(0)
            .authority_state()
            .unwrap()
            .renew(&w.owner, now)
            .unwrap();
        w.endpoint(0).apply_authority(&[update]).unwrap();
        let packet = w
            .endpoint(0)
            .next_configuration(group, Uuid::new_v4(), now)
            .unwrap()
            .unwrap();
        if first.is_none() {
            first = Some(packet.clone());
        }
        w.endpoint(1).stage_configuration(&packet, now).unwrap();
        w.endpoint(1).drain_configuration(group, 1, now).unwrap();
    }
    assert_eq!(count(&w.db(1), "receipts"), RECENT_PACKETS + 1);
    let expired = w.now + gent_crypto::MAX_STATE_LIFETIME + 1000;
    assert!(
        w.endpoint(1)
            .authority_state()
            .unwrap()
            .require_fresh(expired)
            .is_err()
    );
    assert_eq!(
        w.endpoint(1)
            .stage_configuration(&first.unwrap(), expired)
            .unwrap(),
        Staged::Retired
    );
    let update = w
        .endpoint(0)
        .authority_state()
        .unwrap()
        .renew(&w.owner, expired)
        .unwrap();
    w.endpoint(0).apply_authority(&[update]).unwrap();
    let packet = w
        .endpoint(0)
        .next_configuration(group, Uuid::new_v4(), expired)
        .unwrap()
        .unwrap();
    w.endpoint(1).stage_configuration(&packet, expired).unwrap();
    w.endpoint(1)
        .drain_configuration(group, 1, expired)
        .unwrap();
    w.endpoint(1)
        .authority_state()
        .unwrap()
        .require_fresh(expired)
        .unwrap();
}
