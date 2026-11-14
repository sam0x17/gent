use super::*;
use gent_crypto::succession::{SignedOwnerCandidate, SignedOwnerTransition};

fn credential(pair: &Pair, i: usize) -> String {
    config::read_private(&pair.homes[i].path().join("owner.key")).unwrap()
}

fn prepare(pair: &mut Pair) -> SignedOwnerCandidate {
    let key = credential(pair, 1);
    pair.stores[1]
        .prepare_owner_handoff(&key, &Uuid::new_v4().to_string())
        .unwrap()
}

fn issue(pair: &mut Pair, candidate: &SignedOwnerCandidate) -> SignedOwnerTransition {
    let key = credential(pair, 0);
    let authorization = pair.stores[0]
        .authorize_owner_handoff(&key, candidate)
        .unwrap();
    transfer(pair, candidate, &authorization);
    authorization
}

fn transfer(
    pair: &mut Pair,
    candidate: &SignedOwnerCandidate,
    authorization: &SignedOwnerTransition,
) {
    let keys = [credential(pair, 0), credential(pair, 1)];
    let id = &candidate.candidate.id;
    let manifest = pair.stores[0].owner_handoff_manifest(&keys[0], id).unwrap();
    pair.stores[1]
        .begin_owner_handoff_import(&keys[1], id, authorization, &manifest)
        .unwrap();
    for index in 0..manifest.pages.len() {
        let page = pair.stores[0]
            .owner_handoff_page(&keys[0], id, index)
            .unwrap();
        pair.stores[1]
            .import_owner_handoff_page(&keys[1], id, index, &page)
            .unwrap();
    }
}

#[path = "owner_journal_tests.rs"]
mod journal_tests;
#[path = "owner_activation_tests.rs"]
mod owner_activation_tests;
#[path = "owner_configuration_tests.rs"]
mod owner_configuration_tests;
#[path = "pending_configuration_tests.rs"]
mod pending_configuration_tests;

fn status(pair: &mut Pair, i: usize) -> Value {
    let credential = credential(pair, i);
    pair.stores[i]
        .execute(Request::Owner {
            credential,
            action: OwnerOp::OwnerHandoffStatus,
        })
        .unwrap()
}

fn configure(pair: &mut Pair, i: usize, id: &str, edit: ConfigurationEdit) -> Result<Value> {
    let credential = credential(pair, i);
    pair.stores[i].execute(Request::Owner {
        credential,
        action: OwnerOp::Configure {
            request_id: id.into(),
            edit,
        },
    })
}

#[tokio::test]
async fn separate_node_preparation_fences_all_owner_handles_and_survives_delayed_retries() {
    let mut pair = Pair::new().await;
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let identities = pair
        .homes
        .each_ref()
        .map(|h| std::fs::read(h.path().join("identity.key")).unwrap());
    let mut stale = Store::open(pair.homes[0].path()).unwrap();
    assert!(
        pair.stores[0]
            .prepare_owner_handoff(&keys[0], &Uuid::new_v4().to_string())
            .is_err()
    );
    let candidate = prepare(&mut pair);
    let id = &candidate.candidate.id;
    let baseline = pair.stores[0].identity.state(&pair.stores[0].db).unwrap();
    assert_eq!(baseline.checkpoint(), &candidate.candidate.base);
    assert_eq!(status(&mut pair, 0)["signing_frozen"], false);
    assert_eq!(status(&mut pair, 1)["prepared_candidates"], 1);
    assert!(!pair.homes[0].path().join("owner-candidates").exists());
    let authorization = issue(&mut pair, &candidate);
    assert_eq!(status(&mut pair, 0)["signing_frozen"], true);
    assert!(pair.stores[0].require_provisioning_owner().is_err());
    assert!(
        pair.stores[0]
            .identity
            .signing_owner(&pair.stores[0].db)
            .is_err()
    );
    assert!(stale.identity.signing_owner(&stale.db).is_err());
    assert!(
        stale
            .execute(Request::Owner {
                credential: keys[0].clone(),
                action: OwnerOp::SetPolicy {
                    policy: Policy::default()
                }
            })
            .is_err()
    );
    // Even an already computed, correctly signed old-owner revision is fenced.
    let old_key =
        gent_crypto::OwnerKey::from_secret_bytes(identities[0][40..72].try_into().unwrap());
    let package = crate::encrypted::ordered::OrderedEndpoint::open_runtime(
        pair.homes[1].path(),
        &pair.stores[1].identity.node,
    )
    .unwrap()
    .key_package(Uuid::new_v4(), now() as u64)
    .unwrap();
    assert!(
        crate::encrypted::ordered::OrderedEndpoint::open_runtime(
            pair.homes[0].path(),
            &pair.stores[0].identity.node,
        )
        .unwrap()
        .create_configuration(
            &old_key,
            Uuid::new_v4(),
            (pair.stores[1].identity.node.id(), &package),
            now() as u64,
        )
        .err()
        .unwrap()
        .to_string()
        .contains("grants are frozen")
    );
    assert!(
        stale
            .identity
            .apply(&stale.db, baseline.renew(&old_key, now() as u64).unwrap())
            .is_err()
    );
    for i in 0..2 {
        pair.reopen(i);
        pair.stores[i]
            .db
            .execute(
                "UPDATE request_clock SET floor=?1",
                [candidate.candidate.expires_at + 1],
            )
            .unwrap();
    }
    assert_eq!(
        pair.stores[1].prepare_owner_handoff(&keys[1], id).unwrap(),
        candidate
    );
    assert_eq!(
        pair.stores[0]
            .authorize_owner_handoff(&keys[0], &candidate)
            .unwrap(),
        authorization
    );
    let completed = pair.stores[1]
        .accept_owner_handoff(&keys[1], id, &authorization)
        .unwrap();
    pair.reopen(1);
    assert_eq!(
        pair.stores[1]
            .accept_owner_handoff(&keys[1], id, &authorization)
            .unwrap()
            .encode()
            .unwrap(),
        completed.encode().unwrap()
    );
    assert_eq!(status(&mut pair, 1)["completed_candidates"], 1);
    assert_eq!(status(&mut pair, 1)["activation_supported"], true);
    for (i, original) in identities.iter().enumerate() {
        pair.stores[i].maintain().unwrap();
        assert_eq!(
            std::fs::read(pair.homes[i].path().join("identity.key")).unwrap(),
            *original
        );
        assert_eq!(
            pair.stores[i]
                .identity
                .state(&pair.stores[i].db)
                .unwrap()
                .checkpoint(),
            baseline.checkpoint()
        );
    }
    // Completing preparation still cannot bypass the live activation gate.
    assert!(
        pair.stores[1]
            .identity
            .apply(&pair.stores[1].db, completed)
            .is_err()
    );
}

#[tokio::test]
async fn preparation_and_authorization_recover_atomic_database_failures() {
    let mut pair = Pair::new().await;
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let id = Uuid::new_v4().to_string();
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_candidate BEFORE INSERT ON owner_candidates BEGIN SELECT RAISE(ABORT,'candidate failure'); END;").unwrap();
    assert!(pair.stores[1].prepare_owner_handoff(&keys[1], &id).is_err());
    let path = pair.homes[1]
        .path()
        .join("owner-candidates")
        .join(format!("{id}.key"));
    let bytes = std::fs::read(&path).unwrap();
    let expected = SignedOwnerCandidate::decode(&bytes[40..]).unwrap();
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_candidate;")
        .unwrap();
    pair.reopen(1);
    assert_eq!(
        pair.stores[1].prepare_owner_handoff(&keys[1], &id).unwrap(),
        expected
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_fence BEFORE UPDATE ON owner_handoff_control BEGIN SELECT RAISE(ABORT,'fence failure'); END;").unwrap();
    assert!(
        pair.stores[0]
            .authorize_owner_handoff(&keys[0], &expected)
            .is_err()
    );
    assert_eq!(status(&mut pair, 0)["signing_frozen"], false);
    pair.stores[0]
        .identity
        .signing_owner(&pair.stores[0].db)
        .unwrap();
    assert_eq!(
        pair.stores[0]
            .db
            .query_row("SELECT COUNT(*) FROM owner_handoffs", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_fence;")
        .unwrap();
    pair.reopen(0);
    let authorization = issue(&mut pair, &expected);
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_completion BEFORE UPDATE ON owner_candidates BEGIN SELECT RAISE(ABORT,'completion failure'); END;").unwrap();
    assert!(
        pair.stores[1]
            .accept_owner_handoff(&keys[1], &id, &authorization)
            .is_err()
    );
    assert_eq!(status(&mut pair, 1)["completed_candidates"], 0);
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_completion;")
        .unwrap();
    pair.reopen(1);
    pair.stores[1]
        .accept_owner_handoff(&keys[1], &id, &authorization)
        .unwrap();
    assert_eq!(status(&mut pair, 1)["completed_candidates"], 1);
}

#[tokio::test]
async fn pending_configuration_survives_fencing_and_transport_retirement_without_rejection() {
    let mut pair = Pair::new().await;
    let candidate = prepare(&mut pair);
    let request = Uuid::new_v4().to_string();
    let edit = ConfigurationEdit::RenameNode {
        name: "after-handoff".into(),
    };
    assert_eq!(
        configure(&mut pair, 1, &request, edit.clone()).unwrap()["state"],
        "queued"
    );
    issue(&mut pair, &candidate);
    let group: Vec<u8> = pair.stores[1]
        .db
        .query_row("SELECT outgoing FROM network_links", [], |r| r.get(0))
        .unwrap();
    let next = pair.stores[0].data_next(&group).unwrap();
    pair.stores[1].data_prepare(&group).unwrap();
    let packet = pair.stores[1].data_outgoing(&group, next).unwrap().unwrap();
    for _ in 0..2 {
        assert!(
            pair.stores[0]
                .data_receive(&packet)
                .unwrap_err()
                .to_string()
                .contains("signing is frozen")
        );
        assert!(pair.stores[0].data_next(&group).is_err());
        let body: Vec<u8> = pair.stores[0]
            .db
            .query_row("SELECT body FROM inbox WHERE group_id=?1", [&group], |r| {
                r.get(0)
            })
            .unwrap();
        let frame: Frame = serde_json::from_slice(&body).unwrap();
        let Frame::Part {
            data, offset: 0, ..
        } = frame
        else {
            panic!("expected complete configuration request");
        };
        let record: Record = serde_json::from_slice(&STANDARD.decode(data).unwrap()).unwrap();
        let Event::ConfigurationRequest {
            request_id,
            edit: saved,
        } = record.event
        else {
            panic!("expected configuration request");
        };
        assert_eq!(request_id.to_string(), request);
        assert_eq!(
            serde_json::to_vec(&saved).unwrap(),
            serde_json::to_vec(&edit).unwrap()
        );
        assert_eq!(
            pair.stores[0]
                .db
                .query_row(
                    "SELECT COUNT(*) FROM configuration_edits WHERE id=?1",
                    [&request],
                    |r| r.get::<_, u64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            configure(&mut pair, 1, &request, edit.clone()).unwrap()["state"],
            "queued"
        );
        // Transport acknowledgment only means durable receipt. Once the sender
        // retires its ciphertext, the receiver must still retain this edit.
        let receipt = pair.stores[0].transport_receipt(&group, false).unwrap();
        pair.stores[1]
            .transport_confirm(&group, false, Some(&receipt))
            .unwrap();
        for i in 0..2 {
            pair.reopen(i);
        }
    }
}

#[tokio::test]
async fn committed_configuration_retries_remain_available_after_fencing() {
    let mut pair = Pair::new().await;
    let request = Uuid::new_v4();
    let edit = ConfigurationEdit::RenameNode {
        name: "before-handoff".into(),
    };
    configure(&mut pair, 1, &request.to_string(), edit.clone()).unwrap();
    pair.pump();
    let candidate = prepare(&mut pair);
    issue(&mut pair, &candidate);
    let origin = pair.stores[1].identity.node.id().to_owned();
    let saved: Vec<u8> = pair.stores[0]
        .db
        .query_row(
            "SELECT result FROM configuration_edits WHERE id=?1",
            [request.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    let store = &pair.stores[0];
    let tx = store.db.unchecked_transaction().unwrap();
    let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
    session
        .accept_configuration(&origin, request, edit)
        .unwrap();
    assert!(
        session
            .accept_configuration(&origin, request, ConfigurationEdit::Renew)
            .is_err()
    );
    tx.commit().unwrap();
    pair.reopen(0);
    assert_eq!(
        pair.stores[0]
            .db
            .query_row(
                "SELECT result FROM configuration_edits WHERE id=?1",
                [request.to_string()],
                |r| r.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
        saved
    );
    assert_eq!(
        pair.stores[0]
            .identity
            .state(&pair.stores[0].db)
            .unwrap()
            .checkpoint(),
        &candidate.candidate.base
    );
}

#[tokio::test]
async fn missing_or_corrupt_handoff_journals_never_restore_old_signing() {
    for mutation in [
        "UPDATE owner_handoff_control SET issued=NULL",
        "DELETE FROM owner_handoff_control",
        "UPDATE owner_handoffs SET authorization=x'00'",
        "DROP TABLE owner_handoff_control",
        "DELETE FROM owner_handoffs",
    ] {
        let mut pair = Pair::new().await;
        let candidate = prepare(&mut pair);
        issue(&mut pair, &candidate);
        let db = Connection::open(pair.homes[0].path().join("state.sqlite3")).unwrap();
        db.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
        db.execute_batch(mutation).unwrap();
        assert!(
            pair.stores[0]
                .identity
                .signing_owner(&pair.stores[0].db)
                .is_err(),
            "{mutation}"
        );
        assert!(Store::open(pair.homes[0].path()).is_err(), "{mutation}");
    }
}

#[tokio::test]
async fn version_seventeen_migration_preserves_keys_and_checkpoint_before_first_handoff() {
    let mut pair = Pair::new().await;
    let state = pair.stores[0].identity.state(&pair.stores[0].db).unwrap();
    let keys = std::fs::read(pair.homes[0].path().join("identity.key")).unwrap();
    pair.stores[0].db.execute_batch(
        "DROP TABLE owner_handoff_control; DROP TABLE owner_handoffs; DROP TABLE owner_candidates; PRAGMA user_version=17;",
    ).unwrap();
    pair.reopen(0);
    assert_eq!(
        pair.stores[0]
            .identity
            .state(&pair.stores[0].db)
            .unwrap()
            .checkpoint(),
        state.checkpoint()
    );
    assert_eq!(
        std::fs::read(pair.homes[0].path().join("identity.key")).unwrap(),
        keys
    );
    assert_eq!(status(&mut pair, 0)["signing_frozen"], false);
    assert_eq!(
        pair.stores[0]
            .db
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        22
    );
    let candidate = prepare(&mut pair);
    issue(&mut pair, &candidate);
    pair.reopen(0);
    assert_eq!(status(&mut pair, 0)["signing_frozen"], true);
}

#[tokio::test]
async fn preparation_requires_local_owner_and_never_replaces_a_missing_or_linked_key() {
    let mut pair = Pair::new().await;
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let request = Uuid::new_v4().to_string();
    assert!(
        pair.stores[1]
            .prepare_owner_handoff(&pair.keys[1], &request)
            .is_err()
    );
    assert!(!pair.homes[1].path().join("owner-candidates").exists());
    let candidate = prepare(&mut pair);
    let id = &candidate.candidate.id;
    assert!(
        pair.stores[0]
            .authorize_owner_handoff(&pair.keys[0], &candidate)
            .is_err()
    );
    assert_eq!(status(&mut pair, 0)["signing_frozen"], false);
    let authorization = issue(&mut pair, &candidate);
    assert!(
        pair.stores[1]
            .accept_owner_handoff(&pair.keys[1], id, &authorization)
            .is_err()
    );
    let path = pair.homes[1]
        .path()
        .join("owner-candidates")
        .join(format!("{id}.key"));
    let original = std::fs::read(&path).unwrap();
    let link = path.with_extension("link");
    std::fs::hard_link(&path, &link).unwrap();
    assert!(pair.stores[1].prepare_owner_handoff(&keys[1], id).is_err());
    assert!(
        pair.stores[1]
            .accept_owner_handoff(&keys[1], id, &authorization)
            .is_err()
    );
    std::fs::remove_file(&link).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        pair.stores[1]
            .accept_owner_handoff(&keys[1], id, &authorization)
            .is_err()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::rename(&path, &link).unwrap();
    assert!(pair.stores[1].prepare_owner_handoff(&keys[1], id).is_err());
    assert!(!path.exists());
    std::os::unix::fs::symlink(&link, &path).unwrap();
    assert!(
        pair.stores[1]
            .accept_owner_handoff(&keys[1], id, &authorization)
            .is_err()
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&link, &path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), original);
    pair.stores[1]
        .accept_owner_handoff(&keys[1], id, &authorization)
        .unwrap();
}

#[tokio::test]
async fn successor_writer_selection_uses_signed_binding_instead_of_old_streams_or_bootstrap_keys() {
    let mut pair = Pair::new().await;
    let candidate = prepare(&mut pair);
    let authorization = issue(&mut pair, &candidate);
    let credential = credential(&pair, 1);
    let completed = pair.stores[1]
        .accept_owner_handoff(&credential, &candidate.candidate.id, &authorization)
        .unwrap();
    let mut state = pair.stores[0].identity.state(&pair.stores[0].db).unwrap();
    state.advance_history(&[completed]).unwrap();
    // Inspect the planned runtime decision without activating the new epoch.
    for store in &pair.stores {
        assert_eq!(
            store
                .network_session(&store.db, state.clone())
                .configuration_writer()
                .unwrap(),
            candidate.candidate.node.id
        );
        assert_eq!(
            store.identity.is_current_owner(&state),
            store.identity.node.id() == candidate.candidate.node.id
        );
        assert!(store.identity.signing_owner(&store.db).is_err());
    }
}

#[tokio::test]
async fn stale_and_competing_candidates_cannot_freeze_a_new_checkpoint_or_replace_a_decision() {
    let mut pair = Pair::new().await;
    let owner = credential(&pair, 0);
    let stale = prepare(&mut pair);
    configure(
        &mut pair,
        0,
        &Uuid::new_v4().to_string(),
        ConfigurationEdit::Renew,
    )
    .unwrap();
    pair.pump();
    assert!(
        pair.stores[0]
            .authorize_owner_handoff(&owner, &stale)
            .is_err()
    );
    assert_eq!(status(&mut pair, 0)["signing_frozen"], false);
    let candidate = prepare(&mut pair);
    let competing = prepare(&mut pair);
    let authorization = issue(&mut pair, &candidate);
    assert!(
        pair.stores[0]
            .authorize_owner_handoff(&owner, &competing)
            .is_err()
    );
    assert_eq!(
        pair.stores[0]
            .authorize_owner_handoff(&owner, &candidate)
            .unwrap(),
        authorization
    );
    // Fencing configuration signing does not disable already permitted messages.
    let sent = pair.send(vec![]).unwrap();
    pair.pump();
    let inbox = pair.agent(1, AgentOp::Inbox).unwrap();
    assert_eq!(inbox[0]["id"], sent["message_id"]);
    assert_eq!(
        status(&mut pair, 0)["issued_request"],
        candidate.candidate.id
    );
}
