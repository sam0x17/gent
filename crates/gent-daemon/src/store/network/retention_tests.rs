use super::*;

fn count(pair: &Pair, node: usize, table: &str) -> u64 {
    pair.stores[node]
        .db
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

fn clean(pair: &mut Pair, node: usize, dry_run: bool) -> Result<Value> {
    pair.stores[node].execute(Request::Owner {
        credential: config::read_private(&pair.homes[node].path().join("owner.key")).unwrap(),
        action: OwnerOp::HistoryClean { dry_run },
    })
}

#[tokio::test]
async fn retired_wake_claim_cannot_return_through_remote_replay_or_timestamp_rewriting() {
    let mut pair = Pair::new().await;
    let message = pair.send(vec![]).unwrap()["message_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let body: Vec<u8> = pair.stores[0]
        .db
        .query_row(
            "SELECT body FROM network_events WHERE subject=?1",
            [&message],
            |r| r.get(0),
        )
        .unwrap();
    pair.pump();
    let attempt = Uuid::new_v4().to_string();
    let claim = AgentOp::WakeClaim {
        message_id: message.clone(),
        attempt_id: attempt.clone(),
        target: gent_protocol::wake::WakeTarget::Codex {
            thread_id: Uuid::new_v4().to_string(),
        },
    };
    assert_eq!(pair.agent(1, claim.clone()).unwrap()["may_submit"], true);
    pair.agent(1, AgentOp::Inbox).unwrap();
    pair.agent(
        1,
        AgentOp::WakeSubmitted {
            message_id: message,
            attempt_id: attempt,
            submission_id: Uuid::new_v4().to_string(),
        },
    )
    .unwrap();
    assert_eq!(pair.retire_history(1)["messages_removed"], 1);
    let credential = config::read_private(&pair.homes[1].path().join("owner.key")).unwrap();
    assert_eq!(
        pair.stores[1]
            .execute(Request::Owner {
                credential,
                action: OwnerOp::WakeClean { dry_run: false },
            })
            .unwrap()["records_removed"],
        1
    );
    let state = pair.stores[1].identity.state(&pair.stores[1].db).unwrap();
    // retire_history advances the durable clock once. Using a later wall-clock
    // read here can issue authority one second ahead of that frozen clock on
    // a slower runner, failing before the replay check is reached.
    let timestamp: i64 = pair.stores[1]
        .db
        .query_row(
            "SELECT floor FROM request_clock WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let renewal = state
        .renew(
            &pair.stores[0]
                .identity
                .signing_owner(&pair.stores[0].db)
                .unwrap(),
            timestamp as u64,
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
            let Event::Message { message, .. } = &mut record.event else {
                panic!()
            };
            message.created_at = timestamp;
            message.expires_at = message.created_at + EXCHANGE_TTL_SECONDS;
        }
        let store = &pair.stores[1];
        let tx = store.db.unchecked_transaction().unwrap();
        store
            .network_session(&tx, store.identity.state(&tx).unwrap())
            .import_event(&peer, record.event)
            .unwrap();
        tx.commit().unwrap();
        assert_eq!(count(&pair, 1, "messages"), 0);
        assert_eq!(count(&pair, 1, "wake_dispatches"), 0);
        assert!(
            pair.agent(1, claim.clone())
                .unwrap_err()
                .to_string()
                .contains("unavailable")
        );
        assert_eq!(
            pair.agent(1, AgentOp::WakePending).unwrap()["pending"],
            json!([])
        );
    }
}

#[tokio::test]
async fn legacy_negative_receipts_outlive_the_complete_upgrade_admission_grace() {
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
    let mut record: Record = serde_json::from_slice(&body).unwrap();
    let Event::Message {
        sender,
        request_id,
        message,
        ..
    } = &mut record.event
    else {
        panic!()
    };
    *request_id = Uuid::new_v4().to_string();
    message.id = messages::message_id(&sender.id, request_id).unwrap();
    message.exchange_id = message.id.clone();
    message.created_at = now() - 9 * 86400;
    message.expires_at = message.created_at + EXCHANGE_TTL_SECONDS;
    let replay = serde_json::to_vec(&record).unwrap();
    let peer = pair.stores[0].identity.node.id().to_owned();
    {
        let store = &pair.stores[1];
        let tx = store.db.unchecked_transaction().unwrap();
        store
            .network_session(&tx, store.identity.state(&tx).unwrap())
            .import_event(&peer, record.event)
            .unwrap();
        tx.commit().unwrap();
    }
    pair.pump();
    let until: i64 = pair.stores[1]
        .db
        .query_row("SELECT legacy_until FROM request_clock", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        pair.stores[1]
            .db
            .query_row(
                "SELECT retire_after FROM network_sent WHERE traffic='data'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        until + history::RETENTION
    );
    pair.stores[1]
        .db
        .execute("UPDATE request_clock SET floor=?1", [until - 1])
        .unwrap();
    assert_eq!(
        clean(&mut pair, 1, false).unwrap()["sent_event_retries_removed"],
        0
    );
    assert_eq!(count(&pair, 1, "network_sent"), 1);
    assert_eq!(pair.retire_history(1)["sent_event_retries_removed"], 1);
    let store = &pair.stores[1];
    let tx = store.db.unchecked_transaction().unwrap();
    let record: Record = serde_json::from_slice(&replay).unwrap();
    store
        .network_session(&tx, store.identity.state(&tx).unwrap())
        .import_event(&peer, record.event)
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(count(&pair, 1, "network_events"), 0);
}

#[tokio::test]
async fn full_data_retry_quota_rolls_back_acknowledgment_but_remote_configuration_still_progresses()
{
    let mut pair = Pair::new().await;
    let sent = pair.send(vec![]).unwrap();
    let message = sent["message_id"].as_str().unwrap().to_owned();
    pair.pump();
    pair.stores[1].db.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<131072)
        INSERT INTO network_sent(id,traffic,retire_after) SELECT 'quota-'||x,'data',9223372036854775807 FROM n;").unwrap();
    assert!(
        pair.agent(
            1,
            AgentOp::Ack {
                message_id: message.clone()
            }
        )
        .unwrap_err()
        .to_string()
        .contains("retry quota")
    );
    assert_eq!(
        pair.agent(1, AgentOp::Inbox)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let request = Uuid::new_v4().to_string();
    let credential = config::read_private(&pair.homes[1].path().join("owner.key")).unwrap();
    pair.stores[1]
        .execute(Request::Owner {
            credential: credential.clone(),
            action: OwnerOp::Configure {
                request_id: request.clone(),
                edit: ConfigurationEdit::RenameNode {
                    name: "control-capacity".into(),
                },
            },
        })
        .unwrap();
    pair.pump();
    let result = pair.stores[1]
        .execute(Request::Owner {
            credential,
            action: OwnerOp::ConfigurationRequests {
                request_id: Some(request),
            },
        })
        .unwrap();
    assert_eq!(result["state"], "applied");
    pair.stores[1]
        .db
        .execute("DELETE FROM network_sent WHERE id LIKE 'quota-%'", [])
        .unwrap();
    pair.agent(
        1,
        AgentOp::Ack {
            message_id: message.clone(),
        },
    )
    .unwrap();
    pair.pump();
    assert_eq!(
        pair.agent(
            0,
            AgentOp::MessageStatus {
                message_id: message
            }
        )
        .unwrap()["state"],
        "delivered"
    );
}

#[tokio::test]
async fn announcement_capacity_preserves_existing_generations_and_rolls_back_new_registrations() {
    let mut pair = Pair::new().await;
    pair.stores[0].db.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<65535)
        INSERT INTO network_announcements(peer,agent,generation) SELECT 'quota','agent-'||x,1 FROM n;").unwrap();
    let agents = count(&pair, 0, "agents");
    assert!(
        pair.stores[0]
            .execute(Request::Agent {
                credential: config::secret(),
                action: AgentOp::Register {
                    name: "over-capacity".into(),
                    provider: "test".into(),
                }
            })
            .unwrap_err()
            .to_string()
            .contains("announcement quota")
    );
    assert_eq!(count(&pair, 0, "agents"), agents);
    let store = &pair.stores[0];
    let tx = store.db.unchecked_transaction().unwrap();
    tx.execute(
        "UPDATE network_origins SET generation=generation+1 WHERE agent=?1",
        [&pair.agents[0]],
    )
    .unwrap();
    store
        .network_session(&tx, store.identity.state(&tx).unwrap())
        .announce(&pair.agents[0])
        .unwrap();
    tx.commit().unwrap();
    pair.pump();
    assert_eq!(count(&pair, 0, "network_announcements"), 65536);
    assert_eq!(count(&pair, 0, "network_sent"), 0);
}

#[tokio::test]
async fn message_and_receipt_retries_retire_atomically_without_requeue_after_clock_rollback() {
    let mut pair = Pair::new().await;
    let sent = pair.send(vec![]).unwrap();
    let body: Vec<u8> = pair.stores[0]
        .db
        .query_row(
            "SELECT body FROM network_events WHERE subject IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    pair.pump();
    for _ in 0..2 {
        pair.agent(
            1,
            AgentOp::Ack {
                message_id: sent["message_id"].as_str().unwrap().into(),
            },
        )
        .unwrap();
        pair.pump();
    }
    for node in 0..2 {
        assert_eq!(count(&pair, node, "network_sent"), 1);
        assert_eq!(
            clean(&mut pair, node, true).unwrap()["sent_event_retries_removed"],
            0
        );
        pair.stores[node]
            .db
            .execute("UPDATE request_clock SET floor=?1", [now() + 9 * 86400])
            .unwrap();
        assert_eq!(
            clean(&mut pair, node, true).unwrap()["sent_event_retries_removed"],
            1
        );
        assert_eq!(count(&pair, node, "network_sent"), 1);
        pair.stores[node].db.execute_batch("CREATE TRIGGER fail_retention BEFORE DELETE ON network_sent BEGIN SELECT RAISE(ABORT,'injected event cleanup'); END;").unwrap();
        assert!(clean(&mut pair, node, false).is_err());
        assert_eq!(count(&pair, node, "messages"), 1);
        assert_eq!(count(&pair, node, "network_sent"), 1);
        pair.stores[node]
            .db
            .execute_batch("DROP TRIGGER fail_retention")
            .unwrap();
        assert_eq!(
            clean(&mut pair, node, false).unwrap()["sent_event_retries_removed"],
            1
        );
        pair.reopen(node);
        assert_eq!(count(&pair, node, "network_sent"), 0);
    }
    // A stale producer with the real (now lower) clock still sees the committed
    // request clock. Original queue snapshots cannot create another packet.
    let record: Record = serde_json::from_slice(&body).unwrap();
    let Event::Message {
        request_id,
        message,
        ..
    } = record.event
    else {
        panic!()
    };
    let store = &pair.stores[0];
    let tx = store.db.unchecked_transaction().unwrap();
    let session = store.network_session(&tx, store.identity.state(&tx).unwrap());
    session
        .queue_message(pair.stores[1].identity.node.id(), &request_id, &message)
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(count(&pair, 0, "network_events"), 0);
    assert_eq!(count(&pair, 0, "network_sent"), 0);
}

#[tokio::test]
async fn denied_messages_cannot_recreate_receipts_after_their_retention_deadline() {
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
    pair.policy(false);
    pair.pump();
    let peer = pair.stores[0].identity.node.id().to_owned();
    for _ in 0..2 {
        let record: Record = serde_json::from_slice(&body).unwrap();
        let store = &pair.stores[1];
        let tx = store.db.unchecked_transaction().unwrap();
        let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
        session.import_event(&peer, record.event).unwrap();
        tx.commit().unwrap();
        pair.pump();
    }
    assert_eq!(count(&pair, 1, "network_sent"), 1);
    assert_eq!(pair.retire_history(1)["sent_event_retries_removed"], 1);
    pair.reopen(1);
    for rewrite in [false, true] {
        let mut record: Record = serde_json::from_slice(&body).unwrap();
        if rewrite && let Event::Message { message, .. } = &mut record.event {
            message.created_at = now() + 9 * 86400;
            message.expires_at = message.created_at + EXCHANGE_TTL_SECONDS;
        }
        let store = &pair.stores[1];
        let tx = store.db.unchecked_transaction().unwrap();
        let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
        session.import_event(&peer, record.event).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(count(&pair, 1, "network_events"), 0);
    assert_eq!(count(&pair, 1, "network_sent"), 0);
}

#[tokio::test]
async fn announcements_keep_one_generation_watermark_and_failed_enqueue_cannot_advance_it() {
    let mut pair = Pair::new().await;
    let peer = pair.stores[1].identity.node.id().to_owned();
    let agent = pair.agents[0].clone();
    let old = pair.stores[0]
        .network_session(
            &pair.stores[0].db,
            pair.stores[0].identity.state(&pair.stores[0].db).unwrap(),
        )
        .registration(&agent)
        .unwrap();
    let saved = || {
        pair.stores[0]
            .db
            .query_row(
                "SELECT generation FROM network_announcements WHERE peer=?1 AND agent=?2",
                params![peer, agent],
                |r| r.get::<_, u64>(0),
            )
            .unwrap()
    };
    let initial = saved();
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_announce BEFORE INSERT ON network_events BEGIN SELECT RAISE(ABORT,'injected announcement'); END;").unwrap();
    {
        let store = &pair.stores[0];
        let tx = store.db.unchecked_transaction().unwrap();
        tx.execute(
            "UPDATE network_origins SET generation=generation+1 WHERE agent=?1",
            [&agent],
        )
        .unwrap();
        assert!(
            store
                .network_session(&tx, store.identity.state(&tx).unwrap())
                .announce(&agent)
                .is_err()
        );
    }
    assert_eq!(saved(), initial);
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_announce")
        .unwrap();
    for _ in 0..20 {
        let store = &pair.stores[0];
        let tx = store.db.unchecked_transaction().unwrap();
        tx.execute(
            "UPDATE network_origins SET generation=generation+1 WHERE agent=?1",
            [&agent],
        )
        .unwrap();
        store
            .network_session(&tx, store.identity.state(&tx).unwrap())
            .announce(&agent)
            .unwrap();
        tx.commit().unwrap();
        pair.pump();
    }
    pair.reopen(0);
    assert_eq!(count(&pair, 0, "network_announcements"), 1);
    assert_eq!(count(&pair, 0, "network_sent"), 0);
    let store = &pair.stores[0];
    let tx = store.db.unchecked_transaction().unwrap();
    let session = store.network_session(&tx, store.identity.state(&tx).unwrap());
    session.announce(&agent).unwrap();
    session
        .queue(
            &peer,
            scoped_id(
                b"gent/registration-event/v1\0",
                &[
                    peer.as_bytes(),
                    agent.as_bytes(),
                    &old.generation.to_be_bytes(),
                ],
            ),
            Event::Registration { agent: old },
            None,
        )
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(count(&pair, 0, "network_events"), 0);
    assert_eq!(
        pair.stores[1]
            .db
            .query_row(
                "SELECT generation FROM network_origins WHERE agent=?1",
                [&agent],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        initial + 20
    );
}

#[tokio::test]
async fn version_seven_event_metadata_migration_keeps_legacy_sends_and_pending_cursors() {
    let mut pair = Pair::new().await;
    pair.send(vec![]).unwrap();
    pair.pump();
    pair.send(vec![]).unwrap();
    let group = pair.group();
    let next = pair.stores[1].data_next(&group).unwrap();
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_cursor BEFORE DELETE ON network_events BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(pair.stores[0].data_prepare(&group).is_err());
    let packet = pair.stores[0].data_outgoing(&group, next).unwrap().unwrap();
    pair.stores[0].db.execute_batch("DROP TRIGGER fail_cursor;
        DROP INDEX network_sent_retirement; DROP INDEX network_sent_traffic; DROP INDEX network_event_traffic;
        ALTER TABLE network_sent DROP COLUMN traffic; ALTER TABLE network_sent DROP COLUMN retire_after;
        ALTER TABLE network_events DROP COLUMN traffic; ALTER TABLE network_events DROP COLUMN retire_after;
        ALTER TABLE network_events DROP COLUMN announcement; DROP TABLE network_announcements; PRAGMA user_version=7;").unwrap();
    pair.reopen(0);
    pair.stores[0].data_prepare(&group).unwrap();
    assert_eq!(
        pair.stores[0].data_outgoing(&group, next).unwrap().unwrap(),
        packet
    );
    pair.pump();
    assert_eq!(count(&pair, 0, "network_sent"), 2);
    assert_eq!(pair.retire_history(0)["sent_event_retries_removed"], 0);
    assert_eq!(count(&pair, 0, "network_sent"), 2);
}
