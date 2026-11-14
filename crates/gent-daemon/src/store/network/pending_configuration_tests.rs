use super::*;

fn retained(pair: &Pair, id: &str) -> ConfigurationEdit {
    let store = &pair.stores[1];
    configuration::pending::load(&store.db, store.identity.node.id(), id).unwrap()
}

fn count(pair: &Pair) -> u64 {
    pair.stores[1]
        .db
        .query_row("SELECT COUNT(*) FROM configuration_pending", [], |r| {
            r.get(0)
        })
        .unwrap()
}

#[tokio::test]
async fn full_pending_policy_survives_transport_retirement_and_owner_downtime() {
    let mut pair = Pair::new().await;
    let id = Uuid::new_v4().to_string();
    let policy = Policy {
        rules: vec![
            Rule {
                actor: Selector::All,
                peer: Selector::All,
                permission: Permission::Enumerate,
                effect: Effect::Allow
            };
            2000
        ],
        ..Policy::default()
    };
    let edit = ConfigurationEdit::Policy { policy };
    let original = serde_json::to_vec(&edit).unwrap();
    assert!(original.len() > 128 * 1024);
    let candidate = prepare(&mut pair);
    issue(&mut pair, &candidate);
    let queued = configure(&mut pair, 1, &id, edit.clone()).unwrap();
    assert_eq!(queued["payload_retained"], true);
    let group: Vec<u8> = pair.stores[1]
        .db
        .query_row("SELECT outgoing FROM network_links", [], |r| r.get(0))
        .unwrap();
    let next = pair.stores[0].data_next(&group).unwrap();
    pair.stores[1].data_prepare(&group).unwrap();
    let packet = pair.stores[1].data_outgoing(&group, next).unwrap().unwrap();
    assert!(
        pair.stores[0]
            .data_receive(&packet)
            .unwrap_err()
            .to_string()
            .contains("signing is frozen")
    );
    let receipt = pair.stores[0].transport_receipt(&group, false).unwrap();
    pair.stores[1]
        .transport_confirm(&group, false, Some(&receipt))
        .unwrap();
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT COUNT(*) FROM network_events", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    pair.reopen(1);
    pair.stores[1].maintain().unwrap();
    assert_eq!(serde_json::to_vec(&retained(&pair, &id)).unwrap(), original);
    assert_eq!(configure(&mut pair, 1, &id, edit).unwrap(), queued);
    assert_eq!(count(&pair), 1);
}

#[tokio::test]
async fn result_commit_releases_payload_and_failed_release_preserves_the_pending_request() {
    let mut pair = Pair::new().await;
    let id = Uuid::new_v4().to_string();
    let edit = ConfigurationEdit::RenameNode {
        name: "retained-until-decision".into(),
    };
    configure(&mut pair, 1, &id, edit.clone()).unwrap();
    let origin = pair.stores[1].identity.node.id().to_owned();
    let result = crate::messages::EditResult::Rejected {
        reason: "test decision".into(),
    };
    let fingerprint = hash(&serde_json::to_string(&edit).unwrap());
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_release BEFORE DELETE ON configuration_pending BEGIN SELECT RAISE(ABORT,'release failure'); END;").unwrap();
    let writer = pair.stores[0].identity.node.id().to_owned();
    {
        let store = &pair.stores[1];
        let tx = store.db.unchecked_transaction().unwrap();
        let session = store.network_session(&tx, store.identity.state(&tx).unwrap());
        assert!(
            session
                .import_configuration_result(
                    &writer,
                    Uuid::parse_str(&id).unwrap(),
                    &fingerprint,
                    result
                )
                .is_err()
        );
        tx.rollback().unwrap();
    }
    assert_eq!(count(&pair), 1);
    assert!(
        pair.stores[1]
            .db
            .query_row(
                "SELECT result IS NULL FROM configuration_edits WHERE origin=?1 AND id=?2",
                params![origin, id],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_release;")
        .unwrap();
    pair.pump();
    assert_eq!(count(&pair), 0);
    assert_eq!(
        configure(&mut pair, 1, &id, edit).unwrap()["state"],
        "applied"
    );
    assert_eq!(count(&pair), 0);
    assert!(configuration::pending::load(&pair.stores[1].db, &origin, &id).is_err());
}

#[tokio::test]
async fn legacy_queue_and_full_edit_recover_without_changing_identity_or_fingerprint() {
    for full in [true, false] {
        let mut pair = Pair::new().await;
        let id = Uuid::new_v4().to_string();
        let edit = ConfigurationEdit::RenameNode {
            name: "legacy-payload".into(),
        };
        let queued = configure(&mut pair, 1, &id, edit.clone()).unwrap();
        pair.stores[1]
            .db
            .execute_batch("DROP TABLE configuration_pending; PRAGMA user_version=19;")
            .unwrap();
        if full {
            pair.stores[1]
                .db
                .execute(
                    "UPDATE configuration_edits SET edit=?1,compact=0 WHERE id=?2",
                    params![serde_json::to_vec(&edit).unwrap(), id],
                )
                .unwrap();
            pair.stores[1]
                .db
                .execute("DELETE FROM network_events", [])
                .unwrap();
        }
        pair.reopen(1);
        assert_eq!(
            serde_json::to_vec(&retained(&pair, &id)).unwrap(),
            serde_json::to_vec(&edit).unwrap()
        );
        assert_eq!(configure(&mut pair, 1, &id, edit).unwrap(), queued);
        assert_eq!(
            pair.stores[1]
                .db
                .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            23
        );
    }
}

#[tokio::test]
async fn missing_legacy_body_is_reported_and_exact_retry_repairs_it_without_reapplying() {
    let mut pair = Pair::new().await;
    let id = Uuid::new_v4().to_string();
    let edit = ConfigurationEdit::RenameNode {
        name: "repair-original".into(),
    };
    configure(&mut pair, 1, &id, edit.clone()).unwrap();
    pair.stores[1]
        .db
        .execute_batch("DELETE FROM configuration_pending; DELETE FROM network_events;")
        .unwrap();
    pair.reopen(1);
    let status = pair
        .owner(
            1,
            OwnerOp::ConfigurationRequests {
                request_id: Some(id.clone()),
            },
        )
        .unwrap();
    assert_eq!(status["payload_retained"], false);
    assert!(configure(&mut pair, 1, &id, ConfigurationEdit::Renew).is_err());
    assert_eq!(count(&pair), 0);
    let before = pair.stores[1]
        .identity
        .state(&pair.stores[1].db)
        .unwrap()
        .checkpoint()
        .clone();
    assert_eq!(
        configure(&mut pair, 1, &id, edit).unwrap()["payload_retained"],
        true
    );
    assert_eq!(
        pair.stores[1]
            .identity
            .state(&pair.stores[1].db)
            .unwrap()
            .checkpoint(),
        &before
    );
    pair.stores[1]
        .db
        .execute(
            "UPDATE configuration_pending SET body=?1",
            [br#"{"op":"renew"}"#.as_slice()],
        )
        .unwrap();
    let origin = pair.stores[1].identity.node.id();
    assert!(configuration::pending::load(&pair.stores[1].db, origin, &id).is_err());
    assert!(
        pair.owner(
            1,
            OwnerOp::ConfigurationRequests {
                request_id: Some(id)
            }
        )
        .is_err()
    );
    pair.stores[1]
        .db
        .execute_batch("DROP TABLE configuration_pending;")
        .unwrap();
    assert!(Store::open(pair.homes[1].path()).is_err());
}

#[tokio::test]
async fn payload_admission_failure_rolls_back_request_and_event_and_preserves_exact_retries() {
    let mut pair = Pair::new().await;
    let edit = ConfigurationEdit::RenameNode {
        name: "capacity".into(),
    };
    let first = Uuid::new_v4().to_string();
    let queued = configure(&mut pair, 1, &first, edit.clone()).unwrap();
    let db = Connection::open(pair.homes[1].path().join("state.sqlite3")).unwrap();
    db.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
    // Reserve all remaining slots without 4095 expensive network requests.
    db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4095) INSERT INTO configuration_pending SELECT 'quota',CAST(x AS TEXT),x'7b7d' FROM n", []).unwrap();
    assert_eq!(
        configure(&mut pair, 1, &first, edit.clone()).unwrap(),
        queued
    );
    let id = Uuid::new_v4().to_string();
    assert!(
        configure(&mut pair, 1, &id, edit.clone())
            .unwrap_err()
            .to_string()
            .contains("payload quota")
    );
    assert_eq!(
        pair.stores[1]
            .db
            .query_row(
                "SELECT COUNT(*) FROM configuration_edits WHERE id=?1",
                [&id],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
    db.execute("DELETE FROM configuration_pending WHERE origin='quota'", [])
        .unwrap();
    db.execute(
        "INSERT INTO configuration_pending VALUES('quota','bytes',zeroblob(2097152))",
        [],
    )
    .unwrap();
    db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<31) INSERT INTO configuration_pending SELECT 'quota',CAST(x AS TEXT),zeroblob(2097152) FROM n", []).unwrap();
    assert!(
        configure(&mut pair, 1, &id, edit.clone())
            .unwrap_err()
            .to_string()
            .contains("payload quota")
    );
    db.execute("DELETE FROM configuration_pending WHERE origin='quota'", [])
        .unwrap();
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_pending BEFORE INSERT ON configuration_pending BEGIN SELECT RAISE(ABORT,'pending failure'); END;").unwrap();
    assert!(configure(&mut pair, 1, &id, edit.clone()).is_err());
    assert_eq!(count(&pair), 1);
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_pending;")
        .unwrap();
    configure(&mut pair, 1, &id, edit).unwrap();
    pair.pump();
    assert_eq!(count(&pair), 0);
    assert_eq!(
        pair.stores[1]
            .db
            .query_row(
                "SELECT COUNT(*) FROM configuration_edits WHERE id=?1",
                [&id],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn bounded_recovery_skips_missing_bodies_and_capacity_never_blocks_startup() {
    let mut pair = Pair::new().await;
    let mut ids = Vec::new();
    for i in 0..10 {
        let id = Uuid::new_v4().to_string();
        configure(
            &mut pair,
            1,
            &id,
            ConfigurationEdit::RenameNode {
                name: format!("pending-{i}"),
            },
        )
        .unwrap();
        ids.push(id);
    }
    pair.stores[1]
        .db
        .execute("DELETE FROM configuration_pending", [])
        .unwrap();
    for id in &ids[..8] {
        pair.stores[1]
            .db
            .execute(
                "DELETE FROM network_events WHERE json_extract(body,'$.event.request_id')=?1",
                [id],
            )
            .unwrap();
    }
    pair.reopen(1);
    assert_eq!(count(&pair), 0);
    pair.stores[1].maintain().unwrap();
    assert_eq!(count(&pair), 2);
    for id in &ids[8..] {
        retained(&pair, id);
    }
    let db = Connection::open(pair.homes[1].path().join("state.sqlite3")).unwrap();
    db.execute_batch("PRAGMA foreign_keys=OFF; DELETE FROM configuration_pending;")
        .unwrap();
    db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO configuration_pending SELECT 'quota',CAST(x AS TEXT),x'7b7d' FROM n", []).unwrap();
    // Startup and receipt handling must remain possible when the payload cache
    // is full; otherwise old decisions could never release capacity.
    pair.reopen(1);
    pair.stores[1].maintain().unwrap();
    assert_eq!(count(&pair), 4096);
    db.execute("DELETE FROM configuration_pending WHERE origin='quota'", [])
        .unwrap();
    for _ in 0..3 {
        pair.stores[1].maintain().unwrap();
    }
    assert_eq!(count(&pair), 2);
    for id in &ids[8..] {
        retained(&pair, id);
    }
}
