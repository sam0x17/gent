use super::*;

fn edit(id: &str, name: &str) -> OwnerOp {
    OwnerOp::Configure {
        request_id: id.into(),
        edit: ConfigurationEdit::RenameNode { name: name.into() },
    }
}

fn count(pair: &Pair, i: usize, table: &str) -> u64 {
    pair.stores[i]
        .db
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[tokio::test]
async fn pending_large_policy_survives_legacy_migration_restart_and_exact_retries() {
    let mut pair = Pair::new().await;
    let id = Uuid::new_v4().to_string();
    let mut policy = pair.stores[0]
        .identity
        .state(&pair.stores[0].db)
        .unwrap()
        .state()
        .policy
        .clone();
    policy.rules.extend((0..2000).map(|_| Rule {
        actor: Selector::All,
        peer: Selector::All,
        permission: Permission::Enumerate,
        effect: Effect::Allow,
    }));
    let proposal = ConfigurationEdit::Policy { policy };
    let body = serde_json::to_vec(&proposal).unwrap();
    assert!(body.len() > 128 * 1024);
    let action = OwnerOp::Configure {
        request_id: id.clone(),
        edit: proposal,
    };
    let queued = pair.owner(1, action.clone()).unwrap();
    assert_eq!(queued["state"], "queued");
    let summary: Vec<u8> = pair.stores[1]
        .db
        .query_row(
            "SELECT edit FROM configuration_edits WHERE id=?1",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(summary.len() < 100);
    // Restore the on-disk v8 shape while its full proposal is still queued.
    pair.stores[1]
        .db
        .execute(
            "UPDATE configuration_edits SET edit=?1 WHERE id=?2",
            params![body, id],
        )
        .unwrap();
    pair.stores[1].db.execute_batch("DROP INDEX configuration_edits_format; ALTER TABLE configuration_edits DROP COLUMN compact; PRAGMA user_version=8;").unwrap();
    pair.reopen(1);
    pair.stores[1].maintain().unwrap();
    assert_eq!(
        pair.stores[1]
            .db
            .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap(),
        10
    );
    assert_eq!(
        pair.owner(1, OwnerOp::HistoryStatus).unwrap()["configuration_edits"]["legacy_records"],
        0
    );
    assert_eq!(pair.owner(1, action.clone()).unwrap(), queued);
    pair.reopen(0);
    pair.pump();
    let applied = pair.owner(1, action.clone()).unwrap();
    assert_eq!(applied["state"], "applied");
    for i in 0..2 {
        let (stored, compact): (Vec<u8>, bool) = pair.stores[i]
            .db
            .query_row(
                "SELECT edit,compact FROM configuration_edits WHERE id=?1",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored, summary);
        assert!(compact);
        pair.reopen(i);
    }
    assert_eq!(pair.owner(1, action).unwrap(), applied);
    assert!(
        pair.owner(1, edit(&id, "conflicting reuse"))
            .unwrap_err()
            .to_string()
            .contains("another edit")
    );
}

#[tokio::test]
async fn edit_quota_rolls_back_owner_revision_and_remote_import_until_capacity_is_available() {
    let mut pair = Pair::new().await;
    let before = pair.stores[0]
        .identity
        .state(&pair.stores[0].db)
        .unwrap()
        .checkpoint()
        .clone();
    let rows = count(&pair, 0, "configuration_edits");
    pair.stores[0]
        .db
        .execute(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1)
        INSERT INTO configuration_edits SELECT 'quota',CAST(x AS TEXT),'','',X'',X'',1 FROM n",
            [65536 - rows],
        )
        .unwrap();
    let id = Uuid::new_v4().to_string();
    let events = count(&pair, 0, "network_events");
    assert!(
        pair.owner(0, edit(&id, "owner-quota"))
            .unwrap_err()
            .to_string()
            .contains("edit history quota")
    );
    assert_eq!(
        pair.stores[0]
            .identity
            .state(&pair.stores[0].db)
            .unwrap()
            .checkpoint(),
        &before
    );
    assert_eq!(count(&pair, 0, "network_events"), events);
    assert!(
        pair.owner(
            0,
            OwnerOp::ConfigurationRequests {
                request_id: Some(id.clone())
            }
        )
        .is_err()
    );
    let action = edit(&id, "remote-quota");
    pair.owner(1, action.clone()).unwrap();
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
            .contains("edit history quota")
    );
    assert_eq!(
        pair.stores[0]
            .identity
            .state(&pair.stores[0].db)
            .unwrap()
            .checkpoint(),
        &before
    );
    assert_eq!(count(&pair, 0, "configuration_edits"), 65536);
    pair.stores[0]
        .db
        .execute("DELETE FROM configuration_edits WHERE origin='quota'", [])
        .unwrap();
    pair.reopen(0);
    pair.stores[0].data_next(&group).unwrap();
    pair.pump();
    let applied = pair.owner(1, action).unwrap();
    assert_eq!(applied["revision"], before.revision + 1);
    assert_eq!(count(&pair, 0, "configuration_edits"), rows + 1);
}

#[tokio::test]
async fn full_edit_log_allows_pending_result_completion_and_exact_retries() {
    let mut pair = Pair::new().await;
    let id = Uuid::new_v4().to_string();
    let action = edit(&id, "reserved-completion");
    let queued = pair.owner(1, action.clone()).unwrap();
    let usage = pair.owner(1, OwnerOp::HistoryStatus).unwrap()["configuration_edits"].clone();
    let capacity = usage["max_reserved_bytes"].as_u64().unwrap();
    let padding = capacity - usage["reserved_bytes"].as_u64().unwrap() - "quota".len() as u64;
    pair.stores[1]
        .db
        .execute(
            "INSERT INTO configuration_edits VALUES('quota','','','',zeroblob(?1),X'',1)",
            [padding],
        )
        .unwrap();
    assert_eq!(
        pair.owner(1, OwnerOp::HistoryStatus).unwrap()["configuration_edits"]["reserved_bytes"],
        capacity
    );
    pair.reopen(1);
    assert_eq!(pair.owner(1, action.clone()).unwrap(), queued);
    let events = count(&pair, 1, "network_events");
    assert!(
        pair.owner(1, edit(&Uuid::new_v4().to_string(), "overflow"))
            .unwrap_err()
            .to_string()
            .contains("edit history quota")
    );
    assert_eq!(count(&pair, 1, "network_events"), events);
    pair.pump();
    let applied = pair.owner(1, action.clone()).unwrap();
    assert_eq!(applied["state"], "applied");
    let after = pair.owner(1, OwnerOp::HistoryStatus).unwrap()["configuration_edits"].clone();
    assert_eq!(after["pending"], 0);
    assert!(after["reserved_bytes"].as_u64().unwrap() < capacity);
    // Over-limit legacy databases must still allow exact completed retries.
    pair.stores[1]
        .db
        .execute(
            "UPDATE configuration_edits SET edit=zeroblob(?1) WHERE origin='quota'",
            [capacity],
        )
        .unwrap();
    pair.reopen(1);
    assert_eq!(pair.owner(1, action).unwrap(), applied);
    assert!(pair.owner(1, edit(&id, "conflict")).is_err());
}
