use super::*;

fn renew(f: &Fixture) {
    let state = f.endpoint(0).authority_state().unwrap();
    f.endpoint(0)
        .apply_authority(&[state.renew(&f.owner, f.now).unwrap()])
        .unwrap();
}

fn clean(f: &Fixture, node: usize) {
    while f.endpoint(node).clean_storage(false).unwrap()["authority_records_compacted"]
        .as_u64()
        .unwrap()
        > 0
    {}
}

#[test]
fn publication_cursors_preserve_offline_history_and_compaction_keeps_fork_evidence() {
    let f = Fixture::new();
    let a = f.configuration(1);
    let b = f.configuration(1);
    let stalled = f.configuration(2);
    let mut first = vec![];
    let mut second = vec![];
    for _ in 0..80 {
        renew(&f);
        first.extend(f.publish_all(a.packet.group(), f.now));
        second.extend(f.publish_all(b.packet.group(), f.now));
    }
    clean(&f, 0);
    assert!(
        f.endpoint(0).storage_status().unwrap()["authority_history"]["full_records"]
            .as_u64()
            .unwrap()
            > 64
    );
    // Publication for one stalled reader must keep the signed suffix. Once that
    // reader is revoked, other readers recover from already encrypted packets.
    let state = f.endpoint(0).authority_state().unwrap();
    f.endpoint(0)
        .apply_authority(&[state.revoke_node(&f.owner, f.nodes[2].id(), f.now).unwrap()])
        .unwrap();
    first.extend(f.publish_all(a.packet.group(), f.now));
    second.extend(f.publish_all(b.packet.group(), f.now));
    assert!(
        f.endpoint(0)
            .next_configuration(stalled.packet.group(), Uuid::new_v4(), f.now)
            .is_err()
    );
    clean(&f, 0);
    assert_eq!(
        f.endpoint(0).storage_status().unwrap()["authority_history"]["full_records"],
        64
    );
    assert!(
        f.db(0)
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_digests WHERE revision=3)",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    for packet in &first {
        f.endpoint(1).stage_configuration(packet, f.now).unwrap();
        f.endpoint(1)
            .drain_configuration(packet.group(), 1, f.now)
            .unwrap();
    }
    clean(&f, 1);
    assert_eq!(
        f.endpoint(1).storage_status().unwrap()["authority_history"]["full_records"],
        64
    );
    assert!(
        !f.db(1)
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_history WHERE revision=3)",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    // An older duplicate stream still checks each accepted revision against its
    // saved digest. A conflicting digest cannot advance either MLS or authority.
    let digest: Vec<u8> = f
        .db(1)
        .query_row(
            "SELECT digest FROM authority_digests WHERE revision=3",
            [],
            |r| r.get(0),
        )
        .unwrap();
    f.db(1)
        .execute(
            "UPDATE authority_digests SET digest=zeroblob(32) WHERE revision=3",
            [],
        )
        .unwrap();
    f.endpoint(1)
        .stage_configuration(&second[0], f.now)
        .unwrap();
    assert!(
        f.endpoint(1)
            .drain_configuration(second[0].group(), 1, f.now)
            .is_err()
    );
    assert_eq!(
        f.endpoint(1)
            .configuration_status(second[0].group(), f.now)
            .unwrap()
            .head,
        0
    );
    f.db(1)
        .execute(
            "UPDATE authority_digests SET digest=?1 WHERE revision=3",
            [digest],
        )
        .unwrap();
    for packet in &second {
        f.endpoint(1).stage_configuration(packet, f.now).unwrap();
        f.endpoint(1)
            .drain_configuration(packet.group(), 1, f.now)
            .unwrap();
    }
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        f.endpoint(0).authority_state().unwrap().checkpoint()
    );
}

#[test]
fn expired_writer_can_publish_accepted_configuration_but_cannot_send_data_or_revive_a_reader() {
    let f = Fixture::new();
    let config = f.configuration(1);
    let data = f.data(0, 1);
    renew(&f);
    let expired = f.now + MAX_STATE_LIFETIME + 1;
    assert!(
        f.endpoint(0)
            .send(data.group(), Uuid::new_v4(), b"blocked", expired)
            .is_err()
    );
    assert!(
        f.endpoint(0)
            .next_configuration(data.group(), Uuid::new_v4(), expired)
            .is_err()
    );
    let packet = f
        .endpoint(0)
        .next_configuration(config.packet.group(), Uuid::new_v4(), expired)
        .unwrap()
        .unwrap();
    f.endpoint(1).stage_configuration(&packet, expired).unwrap();
    f.endpoint(1)
        .drain_configuration(packet.group(), 1, expired)
        .unwrap();
    assert!(
        f.endpoint(1)
            .authority_state()
            .unwrap()
            .require_fresh(expired)
            .is_err()
    );
    let state = f.endpoint(0).authority_state().unwrap();
    f.endpoint(0)
        .apply_authority(&[state
            .revoke_node(&f.owner, f.nodes[1].id(), expired)
            .unwrap()])
        .unwrap();
    assert!(
        f.endpoint(0)
            .next_configuration(config.packet.group(), Uuid::new_v4(), expired)
            .is_err()
    );
}

#[test]
fn partial_configuration_publication_keeps_its_full_record_until_the_last_fragment() {
    let f = Fixture::new();
    let c = f.configuration(1);
    let members: Vec<_> = (0..4096).map(|_| Uuid::new_v4().to_string()).collect();
    let mut policy = Policy::default();
    for i in 0..3 {
        policy.groups.insert(format!("large-{i}"), members.clone());
    }
    let update = f.state.set_policy(&f.owner, policy, f.now).unwrap();
    assert!(update.encode().unwrap().len() > MAX_FRAGMENT_BYTES);
    let revision = update.state.revision;
    f.endpoint(0).apply_authority(&[update]).unwrap();
    let first = f
        .endpoint(0)
        .next_configuration(c.packet.group(), Uuid::new_v4(), f.now)
        .unwrap()
        .unwrap();
    let state = f.endpoint(0).authority_state().unwrap();
    f.endpoint(0)
        .apply_authority(&[state
            .set_policy(&f.owner, Policy::default(), f.now)
            .unwrap()])
        .unwrap();
    for _ in 0..70 {
        renew(&f);
    }
    clean(&f, 0);
    assert!(
        f.db(0)
            .query_row(
                "SELECT length(state)>?1 FROM authority_history WHERE revision=?2",
                rusqlite::params![MAX_FRAGMENT_BYTES, revision],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    let mut packets = vec![first];
    packets.extend(f.publish_all(c.packet.group(), f.now));
    clean(&f, 0);
    assert!(
        !f.db(0)
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_history WHERE revision=?1)",
                [revision],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    for packet in packets {
        f.endpoint(1).stage_configuration(&packet, f.now).unwrap();
        f.endpoint(1)
            .drain_configuration(packet.group(), 1, f.now)
            .unwrap();
    }
    assert_eq!(
        f.endpoint(0).authority_state().unwrap().checkpoint(),
        f.endpoint(1).authority_state().unwrap().checkpoint()
    );
}

#[test]
fn history_compaction_is_bounded_transactional_and_detects_corrupt_records() {
    let f = Fixture::new();
    let c = f.configuration(1);
    for _ in 0..85 {
        renew(&f);
    }
    f.publish_all(c.packet.group(), f.now);
    // Simulate an older row without a precomputed accepted digest.
    f.db(0)
        .execute("DELETE FROM authority_digests WHERE revision=3", [])
        .unwrap();
    let before = f.endpoint(0).storage_status().unwrap();
    let preview = f.endpoint(0).clean_storage(true).unwrap();
    assert_eq!(preview["authority_records_compacted"], 8);
    assert!(preview["authority_bytes_removed"].as_u64().unwrap() > 0);
    assert_eq!(before, f.endpoint(0).storage_status().unwrap());
    f.db(0).execute_batch("CREATE TRIGGER fail_history BEFORE DELETE ON authority_history BEGIN SELECT RAISE(ABORT,'injected compaction'); END;").unwrap();
    assert!(f.endpoint(0).clean_storage(false).is_err());
    assert_eq!(before, f.endpoint(0).storage_status().unwrap());
    f.db(0).execute_batch("DROP TRIGGER fail_history").unwrap();
    let state: Vec<u8> = f
        .db(0)
        .query_row(
            "SELECT state FROM authority_history WHERE revision=3",
            [],
            |r| r.get(0),
        )
        .unwrap();
    f.db(0)
        .execute(
            "UPDATE authority_history SET state=X'00' WHERE revision=3",
            [],
        )
        .unwrap();
    assert!(f.endpoint(0).clean_storage(false).is_err());
    f.db(0)
        .execute(
            "UPDATE authority_history SET state=?1 WHERE revision=3",
            [state],
        )
        .unwrap();
    assert_eq!(
        f.endpoint(0).clean_storage(false).unwrap()["authority_records_compacted"],
        8
    );
    clean(&f, 0);
    assert_eq!(
        f.endpoint(0).storage_status().unwrap()["authority_history"]["full_records"],
        64
    );
    assert!(
        f.db(0)
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_digests WHERE revision=3)",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
}

#[test]
fn version_five_migration_protects_possible_interrupted_joins_and_quota_failure_rolls_back() {
    let f = Fixture::new();
    let c = f.configuration(1);
    for _ in 0..70 {
        renew(&f);
    }
    f.publish_all(c.packet.group(), f.now);
    f.db(0)
        .execute_batch(
            "DROP TABLE authority_digests; DROP TABLE authority_join_pins; PRAGMA user_version=5;",
        )
        .unwrap();
    let before = f.endpoint(0).authority_state().unwrap();
    clean(&f, 0);
    assert_eq!(
        f.endpoint(0).storage_status().unwrap()["authority_history"]["pending_join_pins"],
        2
    );
    assert!(
        f.endpoint(0).storage_status().unwrap()["authority_history"]["full_records"]
            .as_u64()
            .unwrap()
            >= 70
    );
    // Reserve the remaining slots without large allocations. High revisions are
    // deliberately outside the cleanup window; none may be mistaken for accepted state.
    let count: u64 = f
        .db(0)
        .query_row("SELECT COUNT(*) FROM authority_history", [], |r| r.get(0))
        .unwrap();
    f.db(0)
        .execute(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1)
        INSERT INTO authority_history SELECT 10000+i,X'00' FROM n",
            [8192 - count],
        )
        .unwrap();
    let next = before.renew(&f.owner, f.now).unwrap();
    assert!(
        f.endpoint(0)
            .apply_authority(std::slice::from_ref(&next))
            .unwrap_err()
            .to_string()
            .contains("history quota")
    );
    assert_eq!(
        f.endpoint(0).authority_state().unwrap().checkpoint(),
        before.checkpoint()
    );
    assert!(
        !f.db(0)
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_digests WHERE revision=?1)",
                [next.state.revision],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    f.db(0)
        .execute("DELETE FROM authority_history WHERE revision>10000", [])
        .unwrap();
    f.endpoint(0).apply_authority(&[next]).unwrap();
}
