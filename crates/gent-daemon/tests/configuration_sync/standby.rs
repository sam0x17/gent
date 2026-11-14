use super::*;
use gent_crypto::{SignedConfigurationGrant, succession::SignedOwnerCandidate};
use gent_daemon::encrypted::ordered::configuration::standby::ConfigurationPreparation;

fn candidate(f: &Fixture) -> SignedOwnerCandidate {
    f.nodes[1]
        .prepare_owner_candidate(
            &f.state,
            &OwnerKey::generate().unwrap(),
            &Uuid::new_v4().to_string(),
            f.now,
        )
        .unwrap()
}
fn authorize(f: &Fixture, prepared: &ConfigurationPreparation) -> SignedConfigurationGrant {
    let grant = f
        .owner
        .authorize_standby_configuration_stream(
            &f.state,
            &prepared.candidate,
            prepared.packet.group(),
            prepared.packet.digest().unwrap(),
            &prepared.reader,
            f.now,
        )
        .unwrap();
    prepared.verify_grant(&grant).unwrap();
    grant
}
fn count(f: &Fixture, i: usize, table: &str) -> u64 {
    f.db(i)
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn standby_retries_survive_reopen_and_expiry_without_publishing_or_changing_roles() {
    let f = Fixture::new();
    let ordinary = f.configuration(2);
    let candidate = candidate(&f);
    let package = f.endpoint(2).key_package(Uuid::new_v4(), f.now).unwrap();
    let id = Uuid::new_v4();
    let prepare = |now| {
        f.endpoint(1)
            .prepare_standby_configuration(id, &candidate, (f.nodes[2].id(), &package), now)
            .unwrap()
    };
    let prepared = prepare(f.now);
    let group = prepared.packet.group();
    assert!(
        f.endpoint(1)
            .configuration_streams(f.now)
            .unwrap()
            .is_empty()
    );
    assert!(
        f.endpoint(1)
            .send(group, Uuid::new_v4(), b"no data", f.now)
            .is_err()
    );
    let grant = authorize(&f, &prepared);
    let invitation = f
        .endpoint(1)
        .install_standby_configuration(id, &grant, f.now)
        .unwrap();
    f.endpoint(2)
        .join_configuration(&invitation, f.now)
        .unwrap();
    let receipt = f.endpoint(2).receipt(group, f.now).unwrap();
    assert_eq!(receipt.sequence(), 0);
    f.endpoint(1)
        .confirm(&receipt, f.nodes[2].id(), f.now)
        .unwrap();
    assert_eq!(f.endpoint(1).confirmed_next(group).unwrap(), 1);
    assert!(
        f.endpoint(1)
            .configuration_streams(f.now)
            .unwrap()
            .is_empty()
    );
    assert_eq!(f.endpoint(2).configuration_streams(f.now).unwrap().len(), 2);
    assert!(
        f.endpoint(1)
            .next_configuration(group, Uuid::new_v4(), f.now)
            .is_err()
    );
    assert!(
        f.endpoint(1)
            .rotate_configuration(group, Uuid::new_v4(), f.now)
            .is_err()
    );
    let late = f.now + MAX_STATE_LIFETIME + 1;
    assert_eq!(prepare(late).packet, prepared.packet);
    assert_eq!(
        f.endpoint(1)
            .install_standby_configuration(id, &grant, late)
            .unwrap()
            .packet,
        prepared.packet
    );
    f.endpoint(2).join_configuration(&invitation, late).unwrap();
    f.endpoint(1)
        .confirm(&receipt, f.nodes[2].id(), late)
        .unwrap();
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        f.state.checkpoint()
    );
    assert!(
        f.endpoint(1)
            .prepare_standby_configuration(
                Uuid::new_v4(),
                &candidate,
                (f.nodes[2].id(), &package),
                late
            )
            .is_err()
    );
    let update = f.state.renew(&f.owner, f.now + 1).unwrap();
    f.endpoint(0).apply_authority(&[update]).unwrap();
    for packet in f.publish_all(ordinary.packet.group(), f.now + 1) {
        f.endpoint(2)
            .stage_configuration(&packet, f.now + 1)
            .unwrap();
        f.endpoint(2)
            .drain_configuration(packet.group(), 1, f.now + 1)
            .unwrap();
    }
    assert_eq!(
        f.endpoint(2)
            .authority_state()
            .unwrap()
            .checkpoint()
            .revision,
        f.state.checkpoint().revision + 1
    );
    f.endpoint(2).join_configuration(&invitation, late).unwrap();
    assert_eq!(count(&f, 1, "configuration_preparations"), 1);
}

#[test]
fn standby_requests_cannot_adopt_other_streams_and_failed_writes_are_atomic() {
    let f = Fixture::new();
    let candidate = candidate(&f);
    let package = f.endpoint(2).key_package(Uuid::new_v4(), f.now).unwrap();
    let id = Uuid::new_v4();
    let prepare = || {
        f.endpoint(1).prepare_standby_configuration(
            id,
            &candidate,
            (f.nodes[2].id(), &package),
            f.now,
        )
    };
    f.db(1).execute_batch("CREATE TRIGGER fail_preparation BEFORE INSERT ON configuration_preparations BEGIN SELECT RAISE(ABORT,'preparation failure'); END;").unwrap();
    assert!(prepare().is_err());
    for table in [
        "outbox",
        "streams",
        "stream_outbox",
        "configuration_preparations",
    ] {
        assert_eq!(count(&f, 1, table), 0);
    }
    f.db(1)
        .execute_batch("DROP TRIGGER fail_preparation")
        .unwrap();
    let prepared = prepare().unwrap();
    assert!(
        f.endpoint(1)
            .create(id, &[(f.nodes[2].id(), &package)], f.now)
            .is_err()
    );
    assert!(
        f.endpoint(1)
            .prepare_standby_configuration(id, &candidate, (f.nodes[0].id(), &package), f.now)
            .is_err()
    );
    assert!(
        f.endpoint(1)
            .prepare_standby_configuration(
                id,
                &candidate,
                (f.nodes[2].id(), b"different package"),
                f.now
            )
            .is_err()
    );
    let other = self::candidate(&f);
    assert!(
        f.endpoint(1)
            .prepare_standby_configuration(id, &other, (f.nodes[2].id(), &package), f.now)
            .is_err()
    );
    let data_id = Uuid::new_v4();
    f.endpoint(1)
        .create(data_id, &[(f.nodes[2].id(), &package)], f.now)
        .unwrap();
    assert!(
        f.endpoint(1)
            .prepare_standby_configuration(data_id, &candidate, (f.nodes[2].id(), &package), f.now)
            .is_err()
    );
    let grant = authorize(&f, &prepared);
    let mut forged = grant.clone();
    forged.grant.owner_candidate = None;
    assert!(
        f.endpoint(1)
            .install_standby_configuration(id, &forged, f.now)
            .is_err()
    );
    let wrong = f
        .owner
        .authorize_standby_configuration_stream(
            &f.state,
            &other,
            prepared.packet.group(),
            prepared.packet.digest().unwrap(),
            f.nodes[2].id(),
            f.now,
        )
        .unwrap();
    assert!(
        f.endpoint(1)
            .install_standby_configuration(id, &wrong, f.now)
            .is_err()
    );
    f.db(1).execute_batch("CREATE TRIGGER fail_grant BEFORE INSERT ON configuration_streams BEGIN SELECT RAISE(ABORT,'grant failure'); END;").unwrap();
    assert!(
        f.endpoint(1)
            .install_standby_configuration(id, &grant, f.now)
            .is_err()
    );
    assert_eq!(count(&f, 1, "configuration_streams"), 0);
    assert_eq!(prepare().unwrap().packet, prepared.packet);
    f.db(1).execute_batch("DROP TRIGGER fail_grant").unwrap();
    let invitation = f
        .endpoint(1)
        .install_standby_configuration(id, &grant, f.now)
        .unwrap();
    f.db(2).execute_batch("CREATE TRIGGER fail_grant BEFORE INSERT ON configuration_streams BEGIN SELECT RAISE(ABORT,'reader failure'); END;").unwrap();
    assert!(
        f.endpoint(2)
            .join_configuration(&invitation, f.now)
            .is_err()
    );
    assert_eq!(count(&f, 2, "streams"), 0);
    f.db(2).execute_batch("DROP TRIGGER fail_grant").unwrap();
    f.endpoint(2)
        .join_configuration(&invitation, f.now)
        .unwrap();
    assert!(
        f.endpoint(0)
            .join_configuration(&invitation, f.now)
            .is_err()
    );
    let revoked = f
        .state
        .revoke_node(&f.owner, f.nodes[2].id(), f.now + 1)
        .unwrap();
    f.endpoint(1).apply_authority(&[revoked]).unwrap();
    assert!(prepare().is_err());
    assert!(
        f.endpoint(1)
            .install_standby_configuration(id, &grant, f.now + 1)
            .is_err()
    );
}

#[test]
fn standby_receiver_rejects_authentic_updates_that_do_not_select_its_candidate() {
    let f = Fixture::new();
    let candidate = candidate(&f);
    let package = f.endpoint(2).key_package(Uuid::new_v4(), f.now).unwrap();
    let id = Uuid::new_v4();
    let prepared = f
        .endpoint(1)
        .prepare_standby_configuration(id, &candidate, (f.nodes[2].id(), &package), f.now)
        .unwrap();
    let invitation = f
        .endpoint(1)
        .install_standby_configuration(id, &authorize(&f, &prepared), f.now)
        .unwrap();
    f.endpoint(2)
        .join_configuration(&invitation, f.now)
        .unwrap();
    // Simulate an enrolled but misbehaving writer producing valid MLS traffic.
    // The independent receiver must enforce the standby binding itself.
    f.db(1)
        .execute(
            "UPDATE streams SET purpose='data' WHERE group_id=?1",
            [prepared.packet.group()],
        )
        .unwrap();
    let update = f
        .state
        .renew(&f.owner, f.now + 1)
        .unwrap()
        .encode()
        .unwrap();
    let body = serde_json::to_vec(&json!({"version":1,"revision":f.state.checkpoint().revision+1,"digest":<[u8;32]>::from(Sha256::digest(&update)),"total":update.len(),"offset":0,"data":STANDARD.encode(&update)})).unwrap();
    let packet = f
        .endpoint(1)
        .send(prepared.packet.group(), Uuid::new_v4(), &body, f.now)
        .unwrap();
    f.endpoint(2).stage_configuration(&packet, f.now).unwrap();
    let err = f
        .endpoint(2)
        .drain_configuration(packet.group(), 1, f.now)
        .unwrap_err();
    assert!(err.to_string().contains("does not activate"), "{err:#}");
    assert_eq!(
        f.endpoint(2).authority_state().unwrap().checkpoint(),
        f.state.checkpoint()
    );
    assert_eq!(
        f.endpoint(2)
            .configuration_status(packet.group(), f.now)
            .unwrap()
            .head,
        0
    );
}

#[test]
fn an_abandoned_standby_does_not_pin_unrelated_configuration_history() {
    let f = Fixture::new();
    let candidate = candidate(&f);
    let package = f.endpoint(2).key_package(Uuid::new_v4(), f.now).unwrap();
    let id = Uuid::new_v4();
    let prepared = f
        .endpoint(1)
        .prepare_standby_configuration(id, &candidate, (f.nodes[2].id(), &package), f.now)
        .unwrap();
    f.endpoint(1)
        .install_standby_configuration(id, &authorize(&f, &prepared), f.now)
        .unwrap();
    let mut state = f.state.clone();
    for i in 1..=80 {
        let update = state.renew(&f.owner, f.now + i).unwrap();
        state
            .apply_chain(std::slice::from_ref(&update), f.now + i)
            .unwrap();
        f.endpoint(1).apply_authority(&[update]).unwrap();
    }
    for _ in 0..4 {
        f.endpoint(1).clean_storage(false).unwrap();
    }
    assert_eq!(
        count(&f, 1, "authority_history"),
        gent_daemon::encrypted::history::RECENT_STATES
    );
    assert!(
        f.endpoint(1)
            .configuration_streams(f.now + 81)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        f.endpoint(1)
            .prepare_standby_configuration(id, &candidate, (f.nodes[2].id(), &package), f.now + 81)
            .unwrap()
            .packet,
        prepared.packet
    );
}

#[test]
fn standby_quota_and_schema_migration_preserve_existing_stream_retries() {
    let f = Fixture::new();
    let ordinary = f.configuration(2);
    f.db(1).execute_batch("DROP TABLE configuration_preparations; DROP TABLE owner_configuration_grants; PRAGMA user_version=20;").unwrap();
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        f.state.checkpoint()
    );
    assert_eq!(
        f.db(1)
            .pragma_query_value(None, "user_version", |r| r.get::<_, u64>(0))
            .unwrap(),
        24
    );
    let candidate = candidate(&f);
    let package = f.endpoint(2).key_package(Uuid::new_v4(), f.now).unwrap();
    let id = Uuid::new_v4();
    let prepared = f
        .endpoint(1)
        .prepare_standby_configuration(id, &candidate, (f.nodes[2].id(), &package), f.now)
        .unwrap();
    f.db(1)
        .execute_batch(
            "WITH RECURSIVE n(x) AS(SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4095)
        INSERT INTO owner_configuration_grants SELECT CAST(x AS BLOB),X'00',X'00' FROM n;",
        )
        .unwrap();
    assert_eq!(
        f.endpoint(1)
            .prepare_standby_configuration(id, &candidate, (f.nodes[2].id(), &package), f.now)
            .unwrap()
            .packet,
        prepared.packet
    );
    let err = f
        .endpoint(1)
        .prepare_standby_configuration(
            Uuid::new_v4(),
            &candidate,
            (f.nodes[2].id(), &package),
            f.now,
        )
        .err()
        .unwrap();
    assert!(err.to_string().contains("quota"), "{err:#}");
    assert_eq!(count(&f, 1, "configuration_preparations"), 1);
    assert_eq!(count(&f, 1, "outbox"), 1);
    f.db(1).execute_batch("DELETE FROM owner_configuration_grants;
        WITH RECURSIVE n(x) AS(SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<512)
        INSERT INTO owner_configuration_grants SELECT CAST(x AS BLOB),X'00',zeroblob(139264) FROM n;").unwrap();
    let err = f
        .endpoint(1)
        .prepare_standby_configuration(
            Uuid::new_v4(),
            &candidate,
            (f.nodes[2].id(), &package),
            f.now,
        )
        .err()
        .unwrap();
    assert!(err.to_string().contains("quota"), "{err:#}");
    f.endpoint(1)
        .install_standby_configuration(id, &authorize(&f, &prepared), f.now)
        .unwrap();
    f.endpoint(2).join_configuration(&ordinary, f.now).unwrap();
    f.db(1)
        .execute_batch("DROP TABLE configuration_preparations")
        .unwrap();
    assert!(OrderedEndpoint::open(f.homes[1].path(), &f.nodes[1]).is_err());
}
