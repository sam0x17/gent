use super::*;

fn count(pair: &Pair, node: usize) -> u64 {
    pair.stores[node]
        .db
        .query_row("SELECT COUNT(*) FROM owner_readiness", [], |r| r.get(0))
        .unwrap()
}

#[tokio::test]
async fn new_signing_stop_requires_saved_authentic_readiness_and_exact_retries_survive_expiry() {
    let mut pair = Pair::new().await;
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let candidate = prepare(&mut pair);
    let id = &candidate.candidate.id;
    assert!(
        pair.stores[0]
            .authorize_owner_handoff(&keys[0], &candidate)
            .unwrap_err()
            .to_string()
            .contains("readiness must be recorded")
    );
    assert!(!status(&mut pair, 0)["signing_frozen"].as_bool().unwrap());
    assert!(
        pair.stores[1]
            .owner_handoff_readiness(&keys[1], id)
            .is_err()
    );
    assert_eq!(count(&pair, 1), 0);
    prepare_readiness(&mut pair, &candidate);
    let report = pair.stores[1]
        .owner_handoff_readiness(&keys[1], id)
        .unwrap();
    assert!(
        pair.stores[1]
            .owner_handoff_readiness(&pair.keys[1], id)
            .is_err()
    );
    assert!(
        pair.stores[0]
            .record_owner_readiness(&pair.keys[0], &candidate, &report)
            .is_err()
    );
    pair.stores[0]
        .db
        .execute("DELETE FROM owner_readiness", [])
        .unwrap();
    let mut corrupt = report.clone();
    corrupt.node_signature[0] ^= 1;
    assert!(
        pair.stores[0]
            .record_owner_readiness(&keys[0], &candidate, &corrupt)
            .is_err()
    );
    assert_eq!(count(&pair, 0), 0);
    assert!(
        pair.stores[0]
            .authorize_owner_handoff(&keys[0], &candidate)
            .is_err()
    );
    let group = report.readiness.peers[0].receipt.group();
    let wire: Vec<u8> = pair.stores[0]
        .db
        .query_row(
            "SELECT grant FROM owner_configuration_grants WHERE group_id=?1",
            [group],
            |r| r.get(0),
        )
        .unwrap();
    pair.stores[0]
        .db
        .execute(
            "UPDATE owner_configuration_grants SET grant=x'00' WHERE group_id=?1",
            [group],
        )
        .unwrap();
    assert!(
        pair.stores[0]
            .record_owner_readiness(&keys[0], &candidate, &report)
            .is_err()
    );
    pair.stores[0]
        .db
        .execute(
            "UPDATE owner_configuration_grants SET grant=?1 WHERE group_id=?2",
            params![wire, group],
        )
        .unwrap();
    pair.stores[0]
        .record_owner_readiness(&keys[0], &candidate, &report)
        .unwrap();
    pair.reopen(0);
    pair.reopen(1);
    let authorization = pair.stores[0]
        .authorize_owner_handoff(&keys[0], &candidate)
        .unwrap();
    for i in 0..2 {
        pair.stores[i]
            .db
            .execute(
                "UPDATE request_clock SET floor=?1",
                [candidate.candidate.expires_at + 1],
            )
            .unwrap();
        pair.reopen(i);
    }
    assert_eq!(
        pair.stores[1]
            .owner_handoff_readiness(&keys[1], id)
            .unwrap(),
        report
    );
    pair.stores[0]
        .record_owner_readiness(&keys[0], &candidate, &report)
        .unwrap();
    assert_eq!(
        pair.stores[0]
            .authorize_owner_handoff(&keys[0], &candidate)
            .unwrap(),
        authorization
    );
    assert_eq!(status(&mut pair, 0)["readiness"]["reports"], 1);
}

#[tokio::test]
async fn failed_readiness_commits_and_damaged_evidence_never_stop_the_source() {
    let mut pair = Pair::new().await;
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let candidate = prepare(&mut pair);
    prepare_readiness(&mut pair, &candidate);
    for store in &pair.stores {
        store.db.execute("DELETE FROM owner_readiness", []).unwrap();
    }
    let path = pair.homes[1]
        .path()
        .join("owner-candidates")
        .join(format!("{}.key", candidate.candidate.id));
    let secret = std::fs::read(&path).unwrap();
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_readiness BEFORE INSERT ON owner_readiness BEGIN SELECT RAISE(ABORT,'readiness failure'); END;").unwrap();
    assert!(
        pair.stores[1]
            .owner_handoff_readiness(&keys[1], &candidate.candidate.id)
            .unwrap_err()
            .to_string()
            .contains("readiness failure")
    );
    assert_eq!(count(&pair, 1), 0);
    assert_eq!(std::fs::read(path).unwrap(), secret);
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_readiness")
        .unwrap();
    let report = pair.stores[1]
        .owner_handoff_readiness(&keys[1], &candidate.candidate.id)
        .unwrap();
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_readiness BEFORE INSERT ON owner_readiness BEGIN SELECT RAISE(ABORT,'readiness failure'); END;").unwrap();
    assert!(
        pair.stores[0]
            .record_owner_readiness(&keys[0], &candidate, &report)
            .unwrap_err()
            .to_string()
            .contains("readiness failure")
    );
    assert_eq!(count(&pair, 0), 0);
    assert!(
        pair.stores[0]
            .authorize_owner_handoff(&keys[0], &candidate)
            .is_err()
    );
    pair.stores[0]
        .identity
        .signing_owner(&pair.stores[0].db)
        .unwrap();
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_readiness")
        .unwrap();
    pair.stores[0]
        .record_owner_readiness(&keys[0], &candidate, &report)
        .unwrap();
    pair.stores[0]
        .db
        .execute("UPDATE owner_readiness SET report=x'00'", [])
        .unwrap();
    assert!(
        pair.stores[0]
            .authorize_owner_handoff(&keys[0], &candidate)
            .is_err()
    );
    pair.stores[0]
        .identity
        .signing_owner(&pair.stores[0].db)
        .unwrap();
    pair.stores[0]
        .db
        .execute(
            "UPDATE owner_readiness SET report=?1",
            [report.encode().unwrap()],
        )
        .unwrap();
    pair.stores[0]
        .authorize_owner_handoff(&keys[0], &candidate)
        .unwrap();
}

#[tokio::test]
async fn expired_readiness_cannot_authorize_a_first_handoff_and_legacy_fences_survive_upgrade() {
    let mut pair = Pair::new().await;
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let candidate = prepare(&mut pair);
    prepare_readiness(&mut pair, &candidate);
    let base = pair.stores[0]
        .identity
        .state(&pair.stores[0].db)
        .unwrap()
        .checkpoint()
        .clone();
    pair.stores[0]
        .db
        .execute(
            "UPDATE request_clock SET floor=?1",
            [candidate.candidate.expires_at],
        )
        .unwrap();
    assert!(
        pair.stores[0]
            .authorize_owner_handoff(&keys[0], &candidate)
            .is_err()
    );
    assert_eq!(status(&mut pair, 0)["signing_frozen"], false);
    assert_eq!(
        pair.stores[0]
            .identity
            .state(&pair.stores[0].db)
            .unwrap()
            .checkpoint(),
        &base
    );
    // Restore the test clock, then model an issued schema-22 handoff whose
    // readiness was not part of that historical on-disk format.
    pair.stores[0]
        .db
        .execute("UPDATE request_clock SET floor=?1", [now()])
        .unwrap();
    let authorization = issue(&mut pair, &candidate);
    for i in 0..2 {
        pair.stores[i]
            .db
            .execute_batch("DROP TABLE owner_readiness; PRAGMA user_version=22;")
            .unwrap();
        pair.reopen(i);
        assert_eq!(count(&pair, i), 0);
    }
    assert_eq!(status(&mut pair, 0)["signing_frozen"], true);
    assert_eq!(
        pair.stores[0]
            .authorize_owner_handoff(&keys[0], &candidate)
            .unwrap(),
        authorization
    );
    pair.stores[1]
        .accept_owner_handoff(&keys[1], &candidate.candidate.id, &authorization)
        .unwrap();
    pair.stores[1]
        .activate_owner_handoff(&keys[1], &candidate.candidate.id)
        .unwrap();
    pair.pump();
    assert_eq!(
        pair.stores[0]
            .identity
            .state(&pair.stores[0].db)
            .unwrap()
            .owner_epoch(),
        1
    );
}

#[tokio::test]
async fn readiness_row_and_byte_limits_preserve_signing_and_existing_retries() {
    let mut pair = Pair::new().await;
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let candidate = prepare(&mut pair);
    prepare_readiness(&mut pair, &candidate);
    let report = pair.stores[1]
        .owner_handoff_readiness(&keys[1], &candidate.candidate.id)
        .unwrap();
    for byte_limit in [false, true] {
        for store in &pair.stores {
            store.db.execute("DELETE FROM owner_readiness", []).unwrap();
            if byte_limit {
                store.db.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<32) INSERT INTO owner_readiness SELECT printf('00000000-0000-4000-8000-%012x',x),0,x'',zeroblob(2097152),x'' FROM n;").unwrap();
            } else {
                store.db.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<64) INSERT INTO owner_readiness SELECT printf('00000000-0000-4000-8000-%012x',x),0,x'',x'',x'' FROM n;").unwrap();
            }
        }
        assert!(
            pair.stores[1]
                .owner_handoff_readiness(&keys[1], &candidate.candidate.id)
                .unwrap_err()
                .to_string()
                .contains("budget exhausted")
        );
        assert!(
            pair.stores[0]
                .record_owner_readiness(&keys[0], &candidate, &report)
                .unwrap_err()
                .to_string()
                .contains("budget exhausted")
        );
        pair.stores[0]
            .identity
            .signing_owner(&pair.stores[0].db)
            .unwrap();
    }
    for store in &pair.stores {
        store.db.execute("DELETE FROM owner_readiness", []).unwrap();
    }
    prepare_readiness(&mut pair, &candidate);
    let report = pair.stores[1]
        .owner_handoff_readiness(&keys[1], &candidate.candidate.id)
        .unwrap();
    for i in 0..2 {
        pair.stores[i].db.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<63) INSERT INTO owner_readiness SELECT printf('00000000-0000-4000-8000-%012x',x),0,x'',x'',x'' FROM n;").unwrap();
        pair.reopen(i);
    }
    assert_eq!(
        pair.stores[1]
            .owner_handoff_readiness(&keys[1], &candidate.candidate.id)
            .unwrap(),
        report
    );
    pair.stores[0]
        .record_owner_readiness(&keys[0], &candidate, &report)
        .unwrap();
    pair.stores[0]
        .authorize_owner_handoff(&keys[0], &candidate)
        .unwrap();
}
