use super::*;

#[test]
fn agent_administration_has_independent_record_pending_and_byte_limits() {
    let admin = Uuid::new_v4().to_string();
    let edit = ConfigurationEdit::AgentPermissions {
        administrator: admin.clone(),
        request_id: Uuid::now_v7().to_string(),
        changes: vec![],
    };
    let rule_edit = ConfigurationEdit::AgentPermissionRules {
        administrator: admin.clone(),
        request_id: Uuid::now_v7().to_string(),
        changes: vec![],
    };
    let summary = serde_json::to_vec(&Summary::from(&edit)).unwrap();
    let result = serde_json::to_vec(&EditResult::Rejected {
        reason: "\0".repeat(1000),
    })
    .unwrap();
    // Distinct caps must leave the ordinary owner's history budget available.
    for (rows, same_admin, pending, large) in [
        (1024, true, false, false),
        (64, true, true, false),
        (8192, false, false, false),
        (3000, false, false, true),
    ] {
        let db = database();
        db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1)
            INSERT INTO configuration_edits(origin,id,writer,fingerprint,edit,result,compact)
            SELECT 'seed',CAST(x AS TEXT),'writer','hash',
            CAST(json_set(CASE WHEN ?2 THEN ?3 ELSE json_set(?3,'$.administrator',CAST(x AS TEXT)) END,
                '$.op',CASE WHEN x%2=0 THEN 'agent_permissions' ELSE 'agent_permission_rules' END) AS BLOB),
            CASE WHEN ?4 THEN NULL ELSE ?5 END,1 FROM n",
            params![rows,same_admin,summary,pending,if large {result.as_slice()} else {b"{}"}]).unwrap();
        let before = status(&db).unwrap();
        assert!(insert(&db, "node", "agent-new", "writer", "hash", &edit, None).is_err());
        assert!(insert(&db, "node", "rules-new", "writer", "hash", &rule_edit, None).is_err());
        assert_eq!(status(&db).unwrap(), before);
        insert(
            &db,
            "node",
            "owner-new",
            "writer",
            "hash",
            &ConfigurationEdit::Renew,
            None,
        )
        .unwrap();
        assert_eq!(status(&db).unwrap()["records"], rows + 1);
    }
}

#[test]
fn compact_agent_audit_preserves_actor_request_and_changes_through_legacy_migration() {
    use gent_protocol::administration::*;
    let db = database();
    let edit = ConfigurationEdit::AgentPermissionRules {
        administrator: Uuid::new_v4().to_string(),
        request_id: Uuid::now_v7().to_string(),
        changes: vec![PermissionRuleChange {
            grant_id: Uuid::new_v4().to_string(),
            actor: Selector::Node(Uuid::new_v4().to_string()),
            peer: Selector::Group("workers".into()),
            permission: Permission::Send,
            decision: RuleDecision::Deny,
        }],
    };
    let body = serde_json::to_vec(&edit).unwrap();
    db.execute(
        "INSERT INTO configuration_edits VALUES('node','id','writer',?1,?2,NULL,0)",
        params![fingerprint(&edit).unwrap(), body],
    )
    .unwrap();
    let mut before = json!({});
    describe(&body, false, &mut before).unwrap();
    clean(&db, false).unwrap();
    let saved: Vec<u8> = db
        .query_row("SELECT edit FROM configuration_edits", [], |r| r.get(0))
        .unwrap();
    let mut after = json!({});
    describe(&saved, true, &mut after).unwrap();
    assert_eq!(before, after);
    assert!(after["administrator"].is_string());
    assert_eq!(after["changes"][0]["decision"], "deny");
    assert_eq!(after["selector_rules"], true);
}

fn database() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    schema(&db).unwrap();
    db
}

#[test]
fn migration_compacts_bounded_batches_without_changing_results_order_or_status() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE configuration_edits(origin TEXT NOT NULL,id TEXT NOT NULL,writer TEXT NOT NULL,fingerprint TEXT NOT NULL,edit BLOB NOT NULL,result BLOB,PRIMARY KEY(origin,id));").unwrap();
    let edits = [
        ConfigurationEdit::Policy {
            policy: Policy::default(),
        },
        ConfigurationEdit::Replace {
            cluster_name: "cluster".into(),
            node_name: "node".into(),
            policy: Policy::default(),
        },
        ConfigurationEdit::RenameNode {
            name: "机器".repeat(1000),
        },
        ConfigurationEdit::Renew,
        ConfigurationEdit::GrantRelay {
            grant_id: Uuid::new_v4().to_string(),
            intermediary: "a".into(),
            target: "b".into(),
            lifetime_seconds: 60,
        },
        ConfigurationEdit::RevokeRelay {
            grant_id: "invalid historical grant".into(),
        },
    ];
    let result = serde_json::to_vec(&EditResult::Rejected {
        reason: "historical result".into(),
    })
    .unwrap();
    for i in 0..10 {
        let edit = &edits[i % edits.len()];
        db.execute(
            "INSERT INTO configuration_edits VALUES('origin',?1,'writer',?2,?3,?4)",
            params![
                i.to_string(),
                fingerprint(edit).unwrap(),
                serde_json::to_vec(edit).unwrap(),
                if i % 2 == 0 { Some(&result) } else { None }
            ],
        )
        .unwrap();
    }
    schema(&db).unwrap();
    schema(&db).unwrap();
    assert_eq!(status(&db).unwrap()["legacy_records"], 10);
    let before = status(&db).unwrap();
    let dry = clean(&db, true).unwrap();
    assert_eq!(dry["records_compacted"], CLEAN_BATCH);
    assert_eq!(dry["more_due"], 2);
    assert_eq!(status(&db).unwrap(), before);
    assert_eq!(clean(&db, false).unwrap(), dry);
    assert_eq!(clean(&db, false).unwrap()["records_compacted"], 2);
    assert_eq!(clean(&db, false).unwrap()["records_compacted"], 0);
    for i in 0..10 {
        let (row, saved, body, completed, compact): (i64, String, Vec<u8>, Option<Vec<u8>>, bool) =
            db.query_row(
                "SELECT rowid,fingerprint,edit,result,compact FROM configuration_edits WHERE id=?1",
                [i.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        let edit = &edits[i % edits.len()];
        assert_eq!(row, i as i64 + 1);
        assert_eq!(saved, fingerprint(edit).unwrap());
        assert_eq!(
            completed,
            if i % 2 == 0 {
                Some(result.clone())
            } else {
                None
            }
        );
        assert!(compact);
        let mut old = json!({});
        let mut new = json!({});
        describe(&serde_json::to_vec(edit).unwrap(), false, &mut old).unwrap();
        describe(&body, true, &mut new).unwrap();
        assert_eq!(old, new);
    }
}

#[test]
fn corruption_or_write_failure_rolls_back_the_whole_compaction_batch() {
    let db = database();
    let edit = ConfigurationEdit::Policy {
        policy: Policy::default(),
    };
    let body = serde_json::to_vec(&edit).unwrap();
    for id in ["first", "second"] {
        db.execute("INSERT INTO configuration_edits(origin,id,writer,fingerprint,edit) VALUES('o',?1,'w',?2,?3)",
            params![id,fingerprint(&edit).unwrap(),body]).unwrap();
    }
    for corrupt in [true, false] {
        if corrupt {
            db.execute(
                "UPDATE configuration_edits SET fingerprint='wrong' WHERE id='second'",
                [],
            )
            .unwrap();
        } else {
            db.execute(
                "UPDATE configuration_edits SET fingerprint=?1 WHERE id='second'",
                [fingerprint(&edit).unwrap()],
            )
            .unwrap();
            db.execute_batch("CREATE TRIGGER fail_compaction BEFORE UPDATE ON configuration_edits WHEN OLD.id='second' BEGIN SELECT RAISE(ABORT,'disk full'); END;").unwrap();
        }
        let before = status(&db).unwrap();
        let tx = db.unchecked_transaction().unwrap();
        assert!(clean(&tx, false).is_err());
        tx.rollback().unwrap();
        assert_eq!(status(&db).unwrap(), before);
        assert_eq!(status(&db).unwrap()["legacy_records"], 2);
    }
}

#[test]
fn byte_quota_counts_utf8_and_reserves_an_encoded_result_before_admission() {
    let db = database();
    let edit = ConfigurationEdit::Renew;
    let digest = fingerprint(&edit).unwrap();
    let bytes = "机器".len()
        + 1
        + 1
        + digest.len()
        + serde_json::to_vec(&Summary::Renew).unwrap().len()
        + RESULT_RESERVE;
    // A compact historical row may have a large status field or legacy result.
    db.execute(
        "INSERT INTO configuration_edits VALUES('','','','',zeroblob(?1),X'',1)",
        [MAX_BYTES - bytes as u64 + 1],
    )
    .unwrap();
    assert!(
        insert(&db, "机器", "i", "w", &digest, &edit, None)
            .unwrap_err()
            .to_string()
            .contains("quota")
    );
    db.execute(
        "UPDATE configuration_edits SET edit=zeroblob(?1)",
        [MAX_BYTES - bytes as u64],
    )
    .unwrap();
    insert(&db, "机器", "i", "w", &digest, &edit, None).unwrap();
    let used = usage(&db).unwrap();
    assert_eq!(used.reserved, MAX_BYTES);
    assert_eq!(used.bytes + RESULT_RESERVE as u64, used.reserved);
    assert!(insert(&db, "o", "other", "w", &digest, &edit, Some(b"{}")).is_err());
}

#[test]
fn record_quota_is_independent_of_body_bytes() {
    let db = database();
    db.execute(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1)
        INSERT INTO configuration_edits SELECT '',CAST(x AS TEXT),'','',X'',X'',1 FROM n",
        [MAX_RECORDS - 1],
    )
    .unwrap();
    let edit = ConfigurationEdit::Renew;
    insert(
        &db,
        "o",
        "last",
        "w",
        &fingerprint(&edit).unwrap(),
        &edit,
        None,
    )
    .unwrap();
    assert_eq!(usage(&db).unwrap().records, MAX_RECORDS);
    assert!(usage(&db).unwrap().reserved < MAX_BYTES);
    assert!(
        insert(
            &db,
            "o",
            "overflow",
            "w",
            &fingerprint(&edit).unwrap(),
            &edit,
            None
        )
        .is_err()
    );
}

#[test]
fn rejection_bounds_allow_worst_case_json_escaping_and_preserve_utf8() {
    for reason in [
        "\0".repeat(2000),
        "é".repeat(700),
        "机".repeat(500),
        "short reason".into(),
    ] {
        let bounded = rejection_reason(reason.clone());
        assert!(bounded.len() <= MAX_REASON_BYTES);
        assert!(reason.starts_with(&bounded));
        let encoded = serde_json::to_vec(&EditResult::Rejected { reason: bounded }).unwrap();
        result_size(&encoded).unwrap();
    }
    assert!(result_size(&vec![0; RESULT_RESERVE + 1]).is_err());
}
