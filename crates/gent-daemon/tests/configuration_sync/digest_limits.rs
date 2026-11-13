use super::*;

const LIMIT: u64 = 1_048_576;
const SYNTHETIC_START: u64 = 10_000_000;

fn fill(f: &Fixture, node: usize, total: u64) {
    let used =
        f.endpoint(node).storage_status().unwrap()["authority_history"]["accepted_revisions"]
            .as_u64()
            .unwrap();
    assert!(total > used);
    // Synthetic quota reservations avoid verifying a million signed fixtures.
    // Their high revisions are outside every stream exercised by these tests.
    f.db(node)
        .execute(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1)
        INSERT INTO authority_digests SELECT ?2+i,zeroblob(32) FROM n",
            rusqlite::params![total - used, SYNTHETIC_START],
        )
        .unwrap();
}

fn release_one(f: &Fixture, node: usize) {
    // Remove only a synthetic fixture reservation, never real verification data.
    assert_eq!(
        f.db(node)
            .execute(
                "DELETE FROM authority_digests WHERE revision=?1",
                [SYNTHETIC_START + 1]
            )
            .unwrap(),
        1
    );
}

#[test]
fn batched_authority_admission_rolls_back_every_revision_at_the_digest_limit() {
    let f = Fixture::new();
    let before = f.endpoint(0).authority_state().unwrap();
    let mut next = before.clone();
    let mut updates = vec![];
    for _ in 0..3 {
        let update = next.renew(&f.owner, f.now).unwrap();
        next.advance_history(std::slice::from_ref(&update)).unwrap();
        updates.push(update);
    }
    fill(&f, 0, LIMIT - 2);
    let history = f.endpoint(0).storage_status().unwrap()["authority_history"].clone();
    assert!(
        f.endpoint(0)
            .apply_authority(&updates)
            .unwrap_err()
            .to_string()
            .contains("accepted revision history quota")
    );
    assert_eq!(
        f.endpoint(0).authority_state().unwrap().checkpoint(),
        before.checkpoint()
    );
    assert_eq!(
        f.endpoint(0).storage_status().unwrap()["authority_history"],
        history
    );
    f.endpoint(0).apply_authority(&updates[..2]).unwrap();
    assert_eq!(
        f.endpoint(0).storage_status().unwrap()["authority_history"]["accepted_revisions"],
        LIMIT
    );
    assert!(f.endpoint(0).apply_authority(&updates[2..]).is_err());
    release_one(&f, 0);
    f.endpoint(0).apply_authority(&updates[2..]).unwrap();
    assert_eq!(
        f.endpoint(0).authority_state().unwrap().checkpoint(),
        next.checkpoint()
    );
}

#[test]
fn full_digest_history_preserves_duplicate_streams_and_buffers_unaccepted_revisions() {
    let f = Fixture::new();
    let first = f.configuration(1);
    let second = f.configuration(1);
    for _ in 0..70 {
        super::history::renew(&f);
    }
    let first_packets = f.publish_all(first.packet.group(), f.now);
    let second_packets = f.publish_all(second.packet.group(), f.now);
    for packet in first_packets {
        f.endpoint(1).stage_configuration(&packet, f.now).unwrap();
        f.endpoint(1)
            .drain_configuration(packet.group(), 1, f.now)
            .unwrap();
    }
    super::history::clean(&f, 1);
    assert_eq!(
        f.endpoint(1).storage_status().unwrap()["authority_history"]["full_records"],
        64
    );
    fill(&f, 1, LIMIT);
    for packet in second_packets {
        f.endpoint(1).stage_configuration(&packet, f.now).unwrap();
        f.endpoint(1)
            .drain_configuration(packet.group(), 1, f.now)
            .unwrap();
    }
    let before = f.endpoint(1).authority_state().unwrap();
    let head = f
        .endpoint(1)
        .configuration_status(first.packet.group(), f.now)
        .unwrap()
        .head;
    super::history::renew(&f);
    let packets = f.publish_all(first.packet.group(), f.now);
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    f.endpoint(1).stage_configuration(packet, f.now).unwrap();
    assert!(
        f.endpoint(1)
            .drain_configuration(packet.group(), 1, f.now)
            .unwrap_err()
            .to_string()
            .contains("accepted revision history quota")
    );
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        before.checkpoint()
    );
    assert_eq!(
        f.endpoint(1)
            .configuration_status(packet.group(), f.now)
            .unwrap()
            .head,
        head
    );
    assert_eq!(
        f.db(1)
            .query_row("SELECT COUNT(*) FROM stream_pending", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
    release_one(&f, 1);
    f.endpoint(1)
        .drain_configuration(packet.group(), 1, f.now)
        .unwrap();
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        f.endpoint(0).authority_state().unwrap().checkpoint()
    );
}

#[test]
fn full_digest_quota_does_not_block_publication_of_already_accepted_expired_history() {
    let f = Fixture::new();
    let c = f.configuration(1);
    super::history::renew(&f);
    fill(&f, 0, LIMIT);
    let state = f.endpoint(0).authority_state().unwrap();
    assert!(
        f.endpoint(0)
            .apply_authority(&[state.renew(&f.owner, f.now).unwrap()])
            .is_err()
    );
    let expired = f.now + MAX_STATE_LIFETIME + 1;
    let packets = f.publish_all(c.packet.group(), expired);
    assert!(!packets.is_empty());
    for packet in packets {
        f.endpoint(1).stage_configuration(&packet, expired).unwrap();
        f.endpoint(1)
            .drain_configuration(packet.group(), 1, expired)
            .unwrap();
    }
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        state.checkpoint()
    );
    assert!(
        f.endpoint(1)
            .authority_state()
            .unwrap()
            .require_fresh(expired)
            .is_err()
    );
}

#[test]
fn oversized_migration_can_compact_legacy_bodies_without_losing_reserved_evidence() {
    let f = Fixture::new();
    let stream = f.configuration(1);
    for _ in 0..70 {
        super::history::renew(&f);
    }
    f.publish_all(stream.packet.group(), f.now);
    f.db(0)
        .execute("DELETE FROM authority_digests WHERE revision=3", [])
        .unwrap();
    fill(&f, 0, LIMIT + 1);
    f.db(0).execute_batch("PRAGMA user_version=10").unwrap();
    let before = f.endpoint(0).storage_status().unwrap()["authority_history"].clone();
    assert_eq!(before["legacy_digest_reservations"], 1);
    let preview = f.endpoint(0).clean_storage(true).unwrap();
    assert!(preview["authority_records_compacted"].as_u64().unwrap() > 0);
    f.db(0).execute_batch("CREATE TRIGGER fail_compaction BEFORE DELETE ON authority_history BEGIN SELECT RAISE(ABORT,'disk failure'); END;").unwrap();
    assert!(f.endpoint(0).clean_storage(false).is_err());
    assert_eq!(
        f.endpoint(0).storage_status().unwrap()["authority_history"],
        before
    );
    f.db(0)
        .execute_batch("DROP TRIGGER fail_compaction")
        .unwrap();
    super::history::clean(&f, 0);
    let after = f.endpoint(0).storage_status().unwrap()["authority_history"].clone();
    assert_eq!(after["accepted_revisions"], LIMIT + 1);
    assert_eq!(after["legacy_digest_reservations"], 0);
    assert_eq!(after["full_records"], 64);
    let state = f.endpoint(0).authority_state().unwrap();
    assert!(
        f.endpoint(0)
            .apply_authority(&[state.renew(&f.owner, f.now).unwrap()])
            .is_err()
    );
}

#[test]
fn bootstrap_reserves_its_revision_before_creating_a_full_history_record() {
    let f = Fixture::new();
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut endpoint = OrderedEndpoint::open(home.path(), &f.nodes[2]).unwrap();
    let db = Connection::open(home.path().join("mls.sqlite3")).unwrap();
    db.execute(
        "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1)
        INSERT INTO authority_digests SELECT ?2+i,zeroblob(32) FROM n",
        rusqlite::params![LIMIT, SYNTHETIC_START],
    )
    .unwrap();
    assert!(
        endpoint
            .initialize(&f.state, f.now)
            .unwrap_err()
            .to_string()
            .contains("accepted revision history quota")
    );
    for table in ["authority", "authority_history"] {
        assert_eq!(
            db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    db.execute(
        "DELETE FROM authority_digests WHERE revision=?1",
        [SYNTHETIC_START + 1],
    )
    .unwrap();
    endpoint.initialize(&f.state, f.now).unwrap();
    assert_eq!(
        endpoint.authority_state().unwrap().checkpoint(),
        f.state.checkpoint()
    );
    assert_eq!(
        endpoint.storage_status().unwrap()["authority_history"]["accepted_revisions"],
        LIMIT
    );
}
