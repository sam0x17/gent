use super::*;
use crate::encrypted::ordered::OrderedEndpoint;

fn package(pair: &Pair) -> Vec<u8> {
    OrderedEndpoint::open_runtime(pair.homes[0].path(), &pair.stores[0].identity.node)
        .unwrap()
        .key_package(Uuid::new_v4(), now() as u64)
        .unwrap()
}

#[tokio::test]
async fn prepared_owner_connections_preserve_current_routing_and_record_readiness() {
    let mut pair = Pair::new().await;
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let candidate = prepare(&mut pair);
    let package = package(&pair);
    let reader = pair.stores[0].identity.node.id().to_owned();
    let request = Uuid::new_v4();
    let preparation = pair.stores[1]
        .prepare_owner_configuration(
            &keys[1],
            &candidate.candidate.id,
            request,
            (&reader, &package),
        )
        .unwrap();
    let grant = pair.stores[0]
        .authorize_owner_configuration(&keys[0], &preparation)
        .unwrap();
    pair.reopen(0);
    pair.reopen(1);
    assert_eq!(
        pair.stores[1]
            .prepare_owner_configuration(
                &keys[1],
                &candidate.candidate.id,
                request,
                (&reader, &package)
            )
            .unwrap()
            .packet,
        preparation.packet
    );
    assert_eq!(
        pair.stores[0]
            .authorize_owner_configuration(&keys[0], &preparation)
            .unwrap(),
        grant
    );
    let invitation = pair.stores[1]
        .install_owner_configuration(&keys[1], request, &grant)
        .unwrap();
    let receipt = pair.stores[0]
        .receive_owner_configuration(&keys[0], &invitation)
        .unwrap();
    pair.stores[1]
        .confirm_owner_configuration(&keys[1], &receipt)
        .unwrap();
    pair.reopen(0);
    pair.reopen(1);
    pair.stores[1]
        .confirm_owner_configuration(&keys[1], &receipt)
        .unwrap();
    assert_eq!(
        status(&mut pair, 0)["configuration_preparation"]["records"],
        1
    );
    assert_eq!(
        status(&mut pair, 1)["configuration_preparation"]["records"],
        1
    );
    for (i, store) in pair.stores.iter().enumerate() {
        let session = store.network_session(&store.db, store.identity.state(&store.db).unwrap());
        if i == 0 {
            // An incoming standby is not a new active writer for the old owner.
            assert!(session.configuration_writer().is_err());
        } else {
            assert_eq!(session.configuration_writer().unwrap(), reader);
        }
    }
    assert!(
        !pair.stores[1]
            .sync_streams()
            .unwrap()
            .iter()
            .any(|s| s.outgoing && s.group == preparation.packet.group())
    );
    let id = Uuid::new_v4().to_string();
    let edit = ConfigurationEdit::RenameNode {
        name: "still-uses-original-owner".into(),
    };
    configure(&mut pair, 1, &id, edit.clone()).unwrap();
    pair.pump();
    let result = configure(&mut pair, 1, &id, edit).unwrap();
    assert_eq!(result["state"], "applied");
    assert_eq!(
        pair.stores[1]
            .identity
            .state(&pair.stores[1].db)
            .unwrap()
            .owner_epoch(),
        0
    );
    assert_eq!(status(&mut pair, 0)["signing_frozen"], false);
}

#[tokio::test]
async fn issued_handoff_allows_exact_stream_retries_but_never_new_owner_grants() {
    let mut pair = Pair::new().await;
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let candidate = prepare(&mut pair);
    let package = package(&pair);
    let reader = pair.stores[0].identity.node.id().to_owned();
    let request = Uuid::new_v4();
    let preparation = pair.stores[1]
        .prepare_owner_configuration(
            &keys[1],
            &candidate.candidate.id,
            request,
            (&reader, &package),
        )
        .unwrap();
    let pending = pair.stores[1]
        .prepare_owner_configuration(
            &keys[1],
            &candidate.candidate.id,
            Uuid::new_v4(),
            (&reader, &package),
        )
        .unwrap();
    let grant = pair.stores[0]
        .authorize_owner_configuration(&keys[0], &preparation)
        .unwrap();
    let invitation = pair.stores[1]
        .install_owner_configuration(&keys[1], request, &grant)
        .unwrap();
    let receipt = pair.stores[0]
        .receive_owner_configuration(&keys[0], &invitation)
        .unwrap();
    pair.stores[1]
        .confirm_owner_configuration(&keys[1], &receipt)
        .unwrap();
    let authorization = issue(&mut pair, &candidate);
    for i in 0..2 {
        pair.reopen(i);
    }
    assert_eq!(
        pair.stores[0]
            .authorize_owner_configuration(&keys[0], &preparation)
            .unwrap(),
        grant
    );
    assert!(
        pair.stores[0]
            .authorize_owner_configuration(&keys[0], &pending)
            .is_err()
    );
    assert_eq!(
        pair.stores[1]
            .install_owner_configuration(&keys[1], request, &grant)
            .unwrap()
            .packet,
        preparation.packet
    );
    assert_eq!(
        pair.stores[0]
            .receive_owner_configuration(&keys[0], &invitation)
            .unwrap(),
        receipt
    );
    let completed = pair.stores[1]
        .accept_owner_handoff(&keys[1], &candidate.candidate.id, &authorization)
        .unwrap();
    // A complete journal and ready transport still cannot bypass activation.
    let store = &pair.stores[1];
    assert!(store.identity.apply(&store.db, completed).is_err());
    assert_eq!(status(&mut pair, 0)["signing_frozen"], true);
    assert_eq!(status(&mut pair, 1)["activation_supported"], false);
    let id = Uuid::new_v4().to_string();
    let result = configure(
        &mut pair,
        1,
        &id,
        ConfigurationEdit::RenameNode {
            name: "pending-handoff".into(),
        },
    )
    .unwrap();
    assert_eq!(result["payload_retained"], true);
    let writer: String = pair.stores[1]
        .db
        .query_row(
            "SELECT writer FROM configuration_edits WHERE id=?1",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(writer, reader);
}

#[tokio::test]
async fn owner_stream_credentials_and_failed_commits_cannot_leave_partial_approval() {
    let mut pair = Pair::new().await;
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let candidate = prepare(&mut pair);
    let package = package(&pair);
    let reader = pair.stores[0].identity.node.id().to_owned();
    let request = Uuid::new_v4();
    assert!(
        pair.stores[1]
            .prepare_owner_configuration(
                "wrong",
                &candidate.candidate.id,
                request,
                (&reader, &package)
            )
            .is_err()
    );
    let preparation = pair.stores[1]
        .prepare_owner_configuration(
            &keys[1],
            &candidate.candidate.id,
            request,
            (&reader, &package),
        )
        .unwrap();
    assert!(
        pair.stores[0]
            .authorize_owner_configuration("wrong", &preparation)
            .is_err()
    );
    let mut changed = preparation.clone();
    changed.reader_key[0] ^= 1;
    assert!(
        pair.stores[0]
            .authorize_owner_configuration(&keys[0], &changed)
            .is_err()
    );
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_authorization BEFORE INSERT ON owner_configuration_grants BEGIN SELECT RAISE(ABORT,'authorization failure'); END;").unwrap();
    assert!(
        pair.stores[0]
            .authorize_owner_configuration(&keys[0], &preparation)
            .is_err()
    );
    assert_eq!(
        status(&mut pair, 0)["configuration_preparation"]["records"],
        0
    );
    pair.stores[0]
        .identity
        .signing_owner(&pair.stores[0].db)
        .unwrap();
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_authorization;")
        .unwrap();
    let grant = pair.stores[0]
        .authorize_owner_configuration(&keys[0], &preparation)
        .unwrap();
    assert!(
        pair.stores[1]
            .install_owner_configuration("wrong", request, &grant)
            .is_err()
    );
    let path = pair.homes[1]
        .path()
        .join("owner-candidates")
        .join(format!("{}.key", candidate.candidate.id));
    let saved = path.with_extension("saved");
    std::fs::rename(&path, &saved).unwrap();
    assert!(
        pair.stores[1]
            .install_owner_configuration(&keys[1], request, &grant)
            .is_err()
    );
    std::fs::rename(saved, path).unwrap();
    let invitation = pair.stores[1]
        .install_owner_configuration(&keys[1], request, &grant)
        .unwrap();
    assert!(
        pair.stores[0]
            .receive_owner_configuration("wrong", &invitation)
            .is_err()
    );
    let receipt = pair.stores[0]
        .receive_owner_configuration(&keys[0], &invitation)
        .unwrap();
    assert!(
        pair.stores[1]
            .confirm_owner_configuration("wrong", &receipt)
            .is_err()
    );
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_readiness BEFORE INSERT ON stream_confirmed BEGIN SELECT RAISE(ABORT,'readiness failure'); END;").unwrap();
    assert!(
        pair.stores[1]
            .confirm_owner_configuration(&keys[1], &receipt)
            .is_err()
    );
    let confirmed = || {
        pair.stores[1]
            .db
            .query_row(
                "SELECT COUNT(*) FROM stream_confirmed WHERE group_id=?1",
                [receipt.group()],
                |r| r.get::<_, u64>(0),
            )
            .unwrap()
    };
    assert_eq!(confirmed(), 0);
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_readiness;")
        .unwrap();
    pair.reopen(1);
    pair.stores[1]
        .confirm_owner_configuration(&keys[1], &receipt)
        .unwrap();
    assert_eq!(
        pair.stores[1]
            .db
            .query_row(
                "SELECT COUNT(*) FROM stream_confirmed WHERE group_id=?1",
                [receipt.group()],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        1
    );
}
