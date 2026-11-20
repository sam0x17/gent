use super::*;
use gent_crypto::stream::Packet;

#[tokio::test]
async fn confirmed_priority_message_keeps_its_retry_until_its_own_cursor_commits() {
    let mut pair = Pair::new().await;
    pair.stores[0]
        .execute(Request::Agent {
            credential: config::secret(),
            action: AgentOp::Register {
                name: "queued-registration".into(),
                provider: "test".into(),
            },
        })
        .unwrap();
    let sent = pair.send(vec![]).unwrap();
    let group = pair.group();
    let next = pair.stores[1].data_next(&group).unwrap();
    let event = queue::next_id(&pair.stores[0].db, pair.stores[1].identity.node.id())
        .unwrap()
        .unwrap();
    let earlier: bool = pair.stores[0]
        .db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM network_events WHERE rowid<e.rowid AND peer=e.peer)
         FROM network_events e WHERE id=?1 AND subject=?2",
            params![event, sent["message_id"].as_str().unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(earlier);
    pair.stores[0].db.execute_batch(
        "CREATE TRIGGER fail_cursor BEFORE DELETE ON network_events BEGIN SELECT RAISE(ABORT,'cursor failure'); END;"
    ).unwrap();
    assert!(pair.stores[0].data_prepare(&group).is_err());
    let packet = pair.stores[0].data_outgoing(&group, next).unwrap().unwrap();
    let request = pair.packet_request(&packet);
    pair.stores[1].data_receive(&packet).unwrap();
    let receipt = pair.stores[1].transport_receipt(&group, false).unwrap();
    pair.stores[0]
        .transport_confirm(&group, false, Some(&receipt))
        .unwrap();
    assert_eq!(pair.retry_rows(request), [1, 1, 1, 0]);

    pair.reopen(0);
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_cursor")
        .unwrap();
    pair.stores[0].data_prepare(&group).unwrap();
    assert_eq!(
        pair.endpoint(0).status(&group, now() as u64).unwrap().head,
        packet.sequence()
    );
    assert_eq!(pair.retry_rows(request), [0; 4]);
    let inbox = pair.agent(1, AgentOp::Inbox).unwrap();
    assert_eq!(inbox.as_array().unwrap().len(), 1);
    assert_eq!(inbox[0]["id"], sent["message_id"]);
}

#[tokio::test]
async fn allocated_retirement_is_batched_and_preview_preserves_every_retry_association() {
    let pair = Pair::new().await;
    let group = pair.group();
    let receipt = pair.endpoint(1).receipt(&group, now() as u64).unwrap();
    pair.endpoint(0)
        .confirm(&receipt, pair.stores[1].identity.node.id(), now() as u64)
        .unwrap();
    let mut ids = vec![];
    for _ in 0..270 {
        let event = Uuid::new_v4();
        let body = serde_json::to_vec(&Frame::Cancel {
            version: 1,
            id: event,
        })
        .unwrap();
        let packet = pair
            .endpoint(0)
            .send_checked(
                &group,
                (event, 0, true),
                &body,
                false,
                now() as u64,
                |_, _| Ok(()),
            )
            .unwrap();
        ids.push(pair.packet_request(&packet));
        pair.endpoint(1).stage(&packet, now() as u64).unwrap();
        pair.endpoint(1).drain(&group, 1, now() as u64).unwrap();
    }
    let latest = pair.endpoint(1).receipt(&group, now() as u64).unwrap();
    // Applying the ACK retires one bounded prefix. Reading its durable value,
    // replaying it, or receiving an older signed ACK cannot start another pass.
    for received in [Some(&latest), None, Some(&latest), Some(&receipt)] {
        let confirmed = pair.stores[0]
            .transport_confirm(&group, false, received)
            .unwrap()
            .unwrap();
        assert_eq!(confirmed, latest);
    }
    for id in &ids[..256] {
        assert_eq!(pair.retry_rows(*id), [0; 4]);
    }
    for id in &ids[256..] {
        assert_eq!(pair.retry_rows(*id), [1, 1, 1, 0]);
    }
    let preview = pair.endpoint(0).clean_storage(true).unwrap();
    assert_eq!(preview["transport_requests_removed"], 14);
    for id in &ids[256..] {
        assert_eq!(pair.retry_rows(*id), [1, 1, 1, 0]);
    }
    let cleaned = pair.endpoint(0).clean_storage(false).unwrap();
    assert_eq!(cleaned["transport_requests_removed"], 14);
    for id in &ids {
        assert_eq!(pair.retry_rows(*id), [0; 4]);
    }
    let status = pair.endpoint(0).storage_status().unwrap();
    assert_eq!(status["outgoing"]["data"]["retry_records"], 1);
    assert_eq!(status["retired_packet_tombstones"], 0);
}

impl Pair {
    fn endpoint(&self, i: usize) -> OrderedEndpoint<'_> {
        OrderedEndpoint::open_runtime(self.homes[i].path(), &self.stores[i].identity.node).unwrap()
    }

    fn packet_request(&self, packet: &Packet) -> Uuid {
        let id: String = self.stores[0]
            .db
            .query_row(
                "SELECT id FROM stream_outbox WHERE group_id=?1 AND sequence=?2",
                params![packet.group(), packet.sequence()],
                |r| r.get(0),
            )
            .unwrap();
        Uuid::parse_str(&id).unwrap()
    }

    fn retry_rows(&self, request: Uuid) -> [u64; 4] {
        [
            "outbox",
            "stream_outbox",
            "transport_requests",
            "configuration_requests",
        ]
        .map(|table| {
            self.stores[0]
                .db
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE id=?1"),
                    [request.to_string()],
                    |r| r.get(0),
                )
                .unwrap()
        })
    }

    fn first_frame(&self) -> (Uuid, Vec<u8>) {
        let (id, body): (String, Vec<u8>) = self.stores[0]
            .db
            .query_row(
                "SELECT id,body FROM network_events ORDER BY rowid LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let id = Uuid::parse_str(&id).unwrap();
        let frame = Frame::Part {
            version: 1,
            id,
            digest: Sha256::digest(&body).into(),
            total: body.len(),
            offset: 0,
            data: STANDARD.encode(&body[..body.len().min(FRAGMENT_BYTES)]),
        };
        (id, serde_json::to_vec(&frame).unwrap())
    }
}

#[tokio::test]
async fn allocated_requests_survive_offline_restarts_then_cannot_be_reused_after_confirmation() {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    pair.send(vec![]).unwrap();
    let group = pair.group();
    let (event, frame) = pair.first_frame();
    let next = pair.stores[1].data_next(&group).unwrap();
    pair.stores[0].data_prepare(&group).unwrap();
    let packet = pair.stores[0].data_outgoing(&group, next).unwrap().unwrap();
    let request = pair.packet_request(&packet);
    assert_eq!(request.get_version_num(), 7);
    assert_eq!(pair.retry_rows(request), [1, 1, 1, 0]);
    pair.reopen(0);
    assert_eq!(
        pair.endpoint(0)
            .send(&group, request, &frame, now() as u64)
            .unwrap(),
        packet
    );
    assert!(
        pair.endpoint(0)
            .send(&group, request, b"changed", now() as u64)
            .is_err()
    );
    pair.endpoint(0).clean_storage(false).unwrap();
    assert_eq!(pair.retry_rows(request), [1, 1, 1, 0]);
    pair.stores[1].data_receive(&packet).unwrap();
    let receipt = pair.stores[1].transport_receipt(&group, false).unwrap();
    pair.stores[0]
        .transport_confirm(&group, false, Some(&receipt))
        .unwrap();
    assert_eq!(pair.retry_rows(request), [0; 4]);
    // A second dispatcher holding an old queue snapshot cannot allocate fresh
    // ciphertext for the already completed fragment after its ID was forgotten.
    assert!(
        pair.endpoint(0)
            .send_checked(
                &group,
                (event, 0, false),
                &frame,
                false,
                now() as u64,
                |db, _| { check_cursor(db, &group, (event, 0, false)) }
            )
            .is_err()
    );
    pair.reopen(0);
    let before = pair.endpoint(0).status(&group, now() as u64).unwrap().head;
    // The timestamp is not an admission window. Moving the call's clock backward
    // cannot authorize this ID, nor can switching operation kinds.
    let timestamp = now() as u64;
    for clock in [timestamp + 1, timestamp] {
        for body in [&frame[..], &b"changed"[..]] {
            assert!(
                pair.endpoint(0)
                    .send(&group, request, body, clock)
                    .unwrap_err()
                    .to_string()
                    .contains("retired")
            );
        }
        assert!(pair.endpoint(0).rotate(&group, request, clock).is_err());
        assert!(
            pair.endpoint(0)
                .remove_revoked(&group, request, clock)
                .is_err()
        );
        assert!(pair.endpoint(0).key_package(request, clock).is_err());
    }
    let kp = pair
        .endpoint(1)
        .key_package(Uuid::new_v4(), timestamp)
        .unwrap();
    assert!(
        pair.endpoint(0)
            .create(
                request,
                &[(pair.stores[1].identity.node.id(), &kp)],
                timestamp
            )
            .is_err()
    );
    assert_eq!(
        pair.endpoint(0).status(&group, timestamp).unwrap().head,
        before
    );
    assert_eq!(pair.retry_rows(request), [0; 4]);
    pair.send(vec![]).unwrap();
    pair.pump();
    assert_eq!(
        pair.agent(1, AgentOp::Inbox)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn failed_packet_commit_rolls_back_allocation_ratchet_and_queue_progress() {
    let mut pair = Pair::new().await;
    pair.send(vec![]).unwrap();
    let group = pair.group();
    let before = pair.endpoint(0).status(&group, now() as u64).unwrap().head;
    let count = || {
        pair.stores[0]
            .db
            .query_row("SELECT COUNT(*) FROM transport_requests", [], |r| {
                r.get::<_, u64>(0)
            })
            .unwrap()
    };
    let allocated = count();
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_packet BEFORE INSERT ON stream_outbox BEGIN SELECT RAISE(ABORT,'packet failure'); END;").unwrap();
    assert!(pair.stores[0].data_prepare(&group).is_err());
    assert_eq!(
        pair.stores[0]
            .db
            .query_row("SELECT COUNT(*) FROM transport_requests", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        allocated
    );
    assert_eq!(
        pair.endpoint(0).status(&group, now() as u64).unwrap().head,
        before
    );
    pair.reopen(0);
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_packet")
        .unwrap();
    pair.pump();
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
async fn version_six_pending_deterministic_fragment_reuses_legacy_ciphertext_and_tombstone() {
    let mut pair = Pair::new().await;
    pair.send(vec![]).unwrap();
    let group = pair.group();
    let (event, frame) = pair.first_frame();
    let request = messages::packet_id(event, 0, false);
    let packet = pair
        .endpoint(0)
        .send(&group, request, &frame, now() as u64)
        .unwrap();
    // Reproduce an old encryption commit followed by a crash before cursor commit.
    pair.stores[0]
        .db
        .execute_batch("DROP TABLE transport_requests; PRAGMA user_version=6;")
        .unwrap();
    pair.reopen(0);
    // A newly queued heartbeat must not replace the already encrypted legacy
    // first fragment, even though its saved offset is still zero.
    pair.stores[0].presence_tick().unwrap();
    pair.stores[0].data_prepare(&group).unwrap();
    assert_eq!(
        pair.endpoint(0).status(&group, now() as u64).unwrap().head,
        packet.sequence()
    );
    assert_eq!(
        pair.endpoint(0)
            .send(&group, request, &frame, now() as u64)
            .unwrap(),
        packet
    );
    assert_eq!(pair.retry_rows(request), [1, 1, 0, 0]);
    pair.stores[1].data_receive(&packet).unwrap();
    let receipt = pair.stores[1].transport_receipt(&group, false).unwrap();
    pair.stores[0]
        .transport_confirm(&group, false, Some(&receipt))
        .unwrap();
    assert_eq!(pair.retry_rows(request), [1, 1, 0, 0]);
    assert!(
        pair.endpoint(0)
            .send(&group, request, &frame, now() as u64)
            .unwrap_err()
            .to_string()
            .contains("retired")
    );
}

#[tokio::test]
async fn configuration_allocations_commit_and_retire_atomically_and_cannot_publish_twice() {
    let mut pair = Pair::new().await;
    pair.policy(true);
    let group = pair.stores[0]
        .sync_streams()
        .unwrap()
        .into_iter()
        .find(|s| s.outgoing && s.configuration)
        .unwrap()
        .group;
    let next = pair.stores[1].sync_next(&group).unwrap();
    let before: u64 = pair.stores[0]
        .db
        .query_row("SELECT COUNT(*) FROM transport_requests", [], |r| r.get(0))
        .unwrap();
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_config BEFORE INSERT ON configuration_requests BEGIN SELECT RAISE(ABORT,'configuration failure'); END;").unwrap();
    assert!(pair.stores[0].sync_prepare(&group).is_err());
    assert_eq!(
        pair.stores[0]
            .db
            .query_row("SELECT COUNT(*) FROM transport_requests", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        before
    );
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_config")
        .unwrap();
    pair.stores[0].sync_prepare(&group).unwrap();
    let packet = pair.stores[0].sync_outgoing(&group, next).unwrap().unwrap();
    let request = pair.packet_request(&packet);
    assert_eq!(pair.retry_rows(request), [1; 4]);
    pair.reopen(0);
    assert_eq!(
        pair.endpoint(0)
            .next_configuration(&group, request, now() as u64)
            .unwrap(),
        Some(packet.clone())
    );
    pair.stores[1].sync_receive(&packet).unwrap();
    let receipt = pair.stores[1].transport_receipt(&group, true).unwrap();
    let prior = pair.endpoint(0).confirmed_next(&group).unwrap();
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_forget BEFORE DELETE ON transport_requests BEGIN SELECT RAISE(ABORT,'retirement failure'); END;").unwrap();
    assert!(
        pair.stores[0]
            .transport_confirm(&group, true, Some(&receipt))
            .is_err()
    );
    assert_eq!(pair.retry_rows(request), [1; 4]);
    assert_eq!(pair.endpoint(0).confirmed_next(&group).unwrap(), prior);
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_forget")
        .unwrap();
    pair.stores[0]
        .transport_confirm(&group, true, Some(&receipt))
        .unwrap();
    assert_eq!(pair.retry_rows(request), [0; 4]);
    pair.policy(true);
    assert!(
        pair.endpoint(0)
            .next_configuration(&group, request, now() as u64)
            .unwrap_err()
            .to_string()
            .contains("retired")
    );
    assert_eq!(
        pair.endpoint(0)
            .configuration_status(&group, now() as u64)
            .unwrap()
            .head,
        packet.sequence()
    );
    pair.pump();
}
