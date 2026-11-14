use super::*;
use crate::encrypted::ordered::OrderedEndpoint;

pub(super) fn complete(
    pair: &mut Pair,
    from: usize,
    to: usize,
) -> (
    SignedOwnerCandidate,
    SignedOwnerTransition,
    gent_crypto::SignedState,
) {
    let keys = [credential(pair, 0), credential(pair, 1)];
    let candidate = pair.stores[to]
        .prepare_owner_handoff(&keys[to], &Uuid::new_v4().to_string())
        .unwrap();
    let package =
        OrderedEndpoint::open_runtime(pair.homes[from].path(), &pair.stores[from].identity.node)
            .unwrap()
            .key_package(Uuid::new_v4(), now() as u64)
            .unwrap();
    let reader = pair.stores[from].identity.node.id().to_owned();
    let request = Uuid::new_v4();
    let preparation = pair.stores[to]
        .prepare_owner_configuration(
            &keys[to],
            &candidate.candidate.id,
            request,
            (&reader, &package),
        )
        .unwrap();
    let grant = pair.stores[from]
        .authorize_owner_configuration(&keys[from], &preparation)
        .unwrap();
    let invitation = pair.stores[to]
        .install_owner_configuration(&keys[to], request, &grant)
        .unwrap();
    let receipt = pair.stores[from]
        .receive_owner_configuration(&keys[from], &invitation)
        .unwrap();
    pair.stores[to]
        .confirm_owner_configuration(&keys[to], &receipt)
        .unwrap();
    let readiness = pair.stores[to]
        .owner_handoff_readiness(&keys[to], &candidate.candidate.id)
        .unwrap();
    pair.stores[from]
        .record_owner_readiness(&keys[from], &candidate, &readiness)
        .unwrap();
    let authorization = pair.stores[from]
        .authorize_owner_handoff(&keys[from], &candidate)
        .unwrap();
    let manifest = pair.stores[from]
        .owner_handoff_manifest(&keys[from], &candidate.candidate.id)
        .unwrap();
    pair.stores[to]
        .begin_owner_handoff_import(
            &keys[to],
            &candidate.candidate.id,
            &authorization,
            &manifest,
        )
        .unwrap();
    for index in 0..manifest.pages.len() {
        let page = pair.stores[from]
            .owner_handoff_page(&keys[from], &candidate.candidate.id, index)
            .unwrap();
        pair.stores[to]
            .import_owner_handoff_page(&keys[to], &candidate.candidate.id, index, &page)
            .unwrap();
    }
    let completed = pair.stores[to]
        .accept_owner_handoff(&keys[to], &candidate.candidate.id, &authorization)
        .unwrap();
    (candidate, authorization, completed)
}

pub(super) fn configuration_only(pair: &mut Pair, from: usize, to: usize) {
    for _ in 0..20 {
        let mut moved = false;
        for stream in pair.stores[from]
            .sync_streams()
            .unwrap()
            .into_iter()
            .filter(|s| s.configuration && s.outgoing)
        {
            pair.stores[from].sync_prepare(&stream.group).unwrap();
            let next = pair.stores[to].sync_next(&stream.group).unwrap();
            if let Some(packet) = pair.stores[from]
                .sync_outgoing(&stream.group, next)
                .unwrap()
            {
                pair.stores[to].sync_receive(&packet).unwrap();
                moved = true;
            }
        }
        if !moved {
            return;
        }
    }
    panic!("configuration failed to drain");
}

#[tokio::test]
async fn live_activation_adopts_a_lost_decision_and_completes_pending_edits_without_the_old_owner()
{
    let mut pair = Pair::new().await;
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let done = Uuid::new_v4().to_string();
    let edit = ConfigurationEdit::CreateGroup {
        name: "only-created-once".into(),
    };
    configure(&mut pair, 1, &done, edit.clone()).unwrap();
    let origin = pair.stores[1].identity.node.id().to_owned();
    let store = &pair.stores[0];
    let tx = store.db.unchecked_transaction().unwrap();
    store
        .network_session(&tx, store.identity.state(&tx).unwrap())
        .accept_configuration(&origin, Uuid::parse_str(&done).unwrap(), edit.clone())
        .unwrap();
    tx.commit().unwrap();
    configuration_only(&mut pair, 0, 1);
    assert_eq!(
        configure(&mut pair, 1, &done, edit.clone()).unwrap()["state"],
        "queued"
    );
    let original_revision = pair.stores[0]
        .identity
        .state(&pair.stores[0].db)
        .unwrap()
        .checkpoint()
        .revision;
    let pending = Uuid::new_v4().to_string();
    let next_edit = ConfigurationEdit::CreateGroup {
        name: "created-by-successor".into(),
    };
    configure(&mut pair, 1, &pending, next_edit.clone()).unwrap();
    let mut stale = Store::open(pair.homes[1].path()).unwrap();
    let (candidate, authorization, completed) = complete(&mut pair, 0, 1);
    assert!(
        pair.stores[0]
            .identity
            .apply(&pair.stores[0].db, completed.clone())
            .is_err()
    );
    let old_database = std::fs::read(pair.homes[0].path().join("state.sqlite3")).unwrap();
    assert!(
        pair.stores[1]
            .activate_owner_handoff("wrong", &candidate.candidate.id)
            .is_err()
    );
    let activated = pair.stores[1]
        .activate_owner_handoff(&keys[1], &candidate.candidate.id)
        .unwrap();
    assert_eq!(activated.encode().unwrap(), completed.encode().unwrap());
    assert_eq!(
        configure(&mut pair, 1, &done, edit.clone()).unwrap()["revision"],
        original_revision
    );
    assert_eq!(
        configure(&mut pair, 1, &pending, next_edit).unwrap()["state"],
        "applied"
    );
    let state = pair.stores[1].identity.state(&pair.stores[1].db).unwrap();
    assert_eq!(state.owner_epoch(), 1);
    assert!(
        state
            .state()
            .policy
            .groups
            .contains_key("only-created-once")
    );
    assert!(
        state
            .state()
            .policy
            .groups
            .contains_key("created-by-successor")
    );
    assert_eq!(state.checkpoint().revision, original_revision + 2);
    stale
        .execute(Request::Owner {
            credential: keys[1].clone(),
            action: OwnerOp::Configure {
                request_id: Uuid::new_v4().to_string(),
                edit: ConfigurationEdit::RenameNode {
                    name: "stale-handle-new-key".into(),
                },
            },
        })
        .unwrap();
    assert_eq!(
        std::fs::read(pair.homes[0].path().join("state.sqlite3")).unwrap(),
        old_database
    );
    pair.reopen(1);
    pair.stores[1].maintain().unwrap();
    assert_eq!(
        pair.stores[1]
            .activate_owner_handoff(&keys[1], &candidate.candidate.id)
            .unwrap()
            .encode()
            .unwrap(),
        completed.encode().unwrap()
    );
    assert_eq!(
        pair.stores[1]
            .accept_owner_handoff(&keys[1], &candidate.candidate.id, &authorization)
            .unwrap()
            .encode()
            .unwrap(),
        completed.encode().unwrap()
    );
    pair.pump();
    assert!(
        !pair.stores[0]
            .identity
            .is_current_owner(&pair.stores[0].identity.state(&pair.stores[0].db).unwrap())
    );
    assert!(
        pair.stores[0]
            .identity
            .signing_owner(&pair.stores[0].db)
            .is_err()
    );
    pair.stores[0].require_service_setup_role(true).unwrap();
    pair.stores[1].require_service_setup_role(false).unwrap();
    assert_eq!(
        configure(&mut pair, 1, &done, edit).unwrap()["revision"],
        original_revision
    );
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT COUNT(*) FROM configuration_pending", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn failed_activation_rolls_back_the_key_reference_decisions_and_authority() {
    let mut pair = Pair::new().await;
    let key = credential(&pair, 1);
    let id = Uuid::new_v4().to_string();
    configure(
        &mut pair,
        0,
        &id,
        ConfigurationEdit::CreateGroup {
            name: "prior-decision".into(),
        },
    )
    .unwrap();
    pair.pump();
    let (candidate, _, _) = complete(&mut pair, 0, 1);
    let base = pair.stores[1]
        .identity
        .state(&pair.stores[1].db)
        .unwrap()
        .checkpoint()
        .clone();
    let before: u64 = pair.stores[1]
        .db
        .query_row("SELECT COUNT(*) FROM configuration_edits", [], |r| r.get(0))
        .unwrap();
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_activation BEFORE UPDATE ON authority BEGIN SELECT RAISE(ABORT,'activation failure'); END;").unwrap();
    assert!(
        pair.stores[1]
            .activate_owner_handoff(&key, &candidate.candidate.id)
            .is_err()
    );
    assert_eq!(
        pair.stores[1]
            .identity
            .state(&pair.stores[1].db)
            .unwrap()
            .checkpoint(),
        &base
    );
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT COUNT(*) FROM configuration_edits", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        before
    );
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT COUNT(*) FROM owner_epochs", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert!(
        pair.stores[1]
            .identity
            .signing_owner(&pair.stores[1].db)
            .is_err()
    );
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_activation")
        .unwrap();
    pair.reopen(1);
    pair.stores[1]
        .activate_owner_handoff(&key, &candidate.candidate.id)
        .unwrap();
    let path = pair.homes[1]
        .path()
        .join("owner-candidates")
        .join(format!("{}.key", candidate.candidate.id));
    let hidden = path.with_extension("hidden");
    std::fs::rename(&path, &hidden).unwrap();
    assert!(
        pair.stores[1]
            .identity
            .signing_owner(&pair.stores[1].db)
            .is_err()
    );
    std::fs::rename(hidden, path).unwrap();
    pair.stores[1]
        .identity
        .signing_owner(&pair.stores[1].db)
        .unwrap();
    pair.stores[1]
        .db
        .execute("DELETE FROM owner_epochs", [])
        .unwrap();
    assert!(Store::open(pair.homes[1].path()).is_err());
}

#[tokio::test]
async fn activation_requires_its_private_key_and_authentic_reader_confirmation() {
    let mut pair = Pair::new().await;
    let key = credential(&pair, 1);
    let (candidate, _, _) = complete(&mut pair, 0, 1);
    let id = &candidate.candidate.id;
    let path = pair.homes[1]
        .path()
        .join("owner-candidates")
        .join(format!("{id}.key"));
    let hidden = path.with_extension("hidden");
    std::fs::rename(&path, &hidden).unwrap();
    assert!(pair.stores[1].activate_owner_handoff(&key, id).is_err());
    std::fs::rename(hidden, path).unwrap();
    let (group, wire): (Vec<u8>, Vec<u8>) = pair.stores[1].db.query_row(
        "SELECT a.group_id,a.receipt FROM stream_confirmed a JOIN streams s USING(group_id) WHERE s.purpose='configuration' AND s.writer=?1",
        [pair.stores[1].identity.node.id()], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    pair.stores[1]
        .db
        .execute(
            "UPDATE stream_confirmed SET receipt=x'00' WHERE group_id=?1",
            [&group],
        )
        .unwrap();
    assert!(pair.stores[1].activate_owner_handoff(&key, id).is_err());
    pair.stores[1]
        .db
        .execute("DELETE FROM stream_confirmed WHERE group_id=?1", [&group])
        .unwrap();
    pair.reopen(1);
    assert!(pair.stores[1].activate_owner_handoff(&key, id).is_err());
    assert_eq!(
        pair.stores[1]
            .identity
            .state(&pair.stores[1].db)
            .unwrap()
            .checkpoint(),
        &candidate.candidate.base
    );
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT COUNT(*) FROM owner_epochs", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    pair.stores[1]
        .confirm_owner_configuration(&key, &gent_crypto::stream::Receipt::decode(&wire).unwrap())
        .unwrap();
    pair.stores[1].activate_owner_handoff(&key, id).unwrap();
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
async fn activated_retry_resumes_projection_and_queued_edits_after_post_commit_failure() {
    let mut pair = Pair::new().await;
    let key = credential(&pair, 1);
    let edits: Vec<_> = ["retry-first", "retry-second"]
        .into_iter()
        .map(|name| {
            (
                Uuid::new_v4().to_string(),
                ConfigurationEdit::CreateGroup { name: name.into() },
            )
        })
        .collect();
    for (id, edit) in &edits {
        configure(&mut pair, 1, id, edit.clone()).unwrap();
    }
    let (candidate, _, completed) = complete(&mut pair, 0, 1);
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_projection BEFORE DELETE ON metadata WHEN OLD.key='config_projection' BEGIN SELECT RAISE(ABORT,'projection failure'); END;").unwrap();
    let error = pair.stores[1]
        .activate_owner_handoff(&key, &candidate.candidate.id)
        .unwrap_err();
    assert!(error.to_string().contains("projection failure"));
    assert_eq!(
        pair.stores[1]
            .identity
            .state(&pair.stores[1].db)
            .unwrap()
            .owner_epoch(),
        1
    );
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT COUNT(*) FROM configuration_pending", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        2
    );
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_projection")
        .unwrap();
    assert_eq!(
        pair.stores[1]
            .activate_owner_handoff(&key, &candidate.candidate.id)
            .unwrap()
            .encode()
            .unwrap(),
        completed.encode().unwrap()
    );
    for (id, edit) in edits {
        assert_eq!(
            configure(&mut pair, 1, &id, edit).unwrap()["state"],
            "applied"
        );
    }
    let state = pair.stores[1].identity.state(&pair.stores[1].db).unwrap();
    for name in ["retry-first", "retry-second"] {
        assert!(state.state().policy.groups.contains_key(name));
    }
    pair.reopen(1);
    assert_eq!(
        config::load_for_runtime(pair.homes[1].path())
            .unwrap()
            .applied_revision,
        Some(state.checkpoint().revision)
    );
}

#[tokio::test]
async fn authenticated_decisions_can_cross_admission_capacity_without_losing_pending_work() {
    let mut pair = Pair::new().await;
    let source_id = Uuid::new_v4().to_string();
    configure(
        &mut pair,
        0,
        &source_id,
        ConfigurationEdit::CreateGroup {
            name: "source-decision".into(),
        },
    )
    .unwrap();
    pair.pump();
    let pending_id = Uuid::new_v4().to_string();
    let edit = ConfigurationEdit::CreateGroup {
        name: "reserved-pending-work".into(),
    };
    configure(&mut pair, 1, &pending_id, edit.clone()).unwrap();
    let origin = pair.stores[1].identity.node.id().to_owned();
    let fingerprint = hash(&serde_json::to_string(&ConfigurationEdit::Renew).unwrap());
    let result = serde_json::to_vec(&crate::messages::EditResult::Rejected {
        reason: "previous decision".into(),
    })
    .unwrap();
    pair.stores[1].db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<65535) INSERT INTO configuration_edits SELECT ?1,printf('00000000-0000-4000-8000-%012x',x),?1,?2,?3,?4,1 FROM n", params![origin, fingerprint, br#"{"op":"renew"}"#.as_slice(), result]).unwrap();
    let mut retained = std::collections::BTreeSet::<(String, String)>::new();
    for store in &pair.stores {
        for row in store
            .db
            .prepare("SELECT origin,id FROM configuration_edits")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
        {
            retained.insert(row.unwrap());
        }
    }
    let expected = retained.len() as u64;
    assert!(expected > 65536);
    let (candidate, _, _) = complete(&mut pair, 0, 1);
    let key = credential(&pair, 1);
    pair.stores[1]
        .activate_owner_handoff(&key, &candidate.candidate.id)
        .unwrap();
    assert_eq!(
        configure(&mut pair, 1, &pending_id, edit).unwrap()["state"],
        "applied"
    );
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT COUNT(*) FROM configuration_edits", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        expected
    );
    let before = pair.stores[1]
        .identity
        .state(&pair.stores[1].db)
        .unwrap()
        .checkpoint()
        .clone();
    assert!(
        configure(
            &mut pair,
            1,
            &Uuid::new_v4().to_string(),
            ConfigurationEdit::CreateGroup {
                name: "no-new-capacity".into()
            }
        )
        .is_err()
    );
    assert_eq!(
        pair.stores[1]
            .identity
            .state(&pair.stores[1].db)
            .unwrap()
            .checkpoint(),
        &before
    );
    pair.reopen(1);
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT COUNT(*) FROM configuration_edits", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        expected
    );
}

#[tokio::test]
async fn successor_enrolls_a_new_node_with_the_accepted_owner_history() {
    let mut pair = Pair::new().await;
    let (candidate, _, _) = complete(&mut pair, 0, 1);
    let key = credential(&pair, 1);
    pair.stores[1]
        .activate_owner_handoff(&key, &candidate.candidate.id)
        .unwrap();
    pair.pump();
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let cluster = pair.stores[1].config.cluster.id.clone();
    pairing::join(
        home.path(),
        pairing::Options {
            replace_node: None,
            cluster: &cluster,
            name: "joined-after-handoff",
            relay_endpoint: None,
        },
        &mut OwnerPeer(&mut pair.stores[1], key),
    )
    .await
    .unwrap();
    let mut joined = Store::open(home.path()).unwrap();
    assert_eq!(joined.identity.state(&joined.db).unwrap().owner_epoch(), 1);
    assert!(joined.identity.signing_owner(&joined.db).is_err());
    joined
        .execute(Request::Agent {
            credential: config::secret(),
            action: AgentOp::Register {
                name: "new-agent".into(),
                provider: "test".into(),
            },
        })
        .unwrap();
    drop(joined);
    assert_eq!(
        Store::open(home.path())
            .unwrap()
            .identity
            .initial
            .owner_epoch(),
        1
    );
}

#[test]
fn activation_storage_cannot_be_silently_recreated_after_upgrade() {
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    config::initialize(home.path(), "activation-schema").unwrap();
    let store = Store::open(home.path()).unwrap();
    for table in [
        "owner_epochs",
        "configuration_routes",
        "retired_configuration_requests",
        "owner_readiness",
    ] {
        store
            .db
            .execute_batch(&format!("ALTER TABLE {table} RENAME TO missing_{table}"))
            .unwrap();
        assert!(Store::open(home.path()).is_err(), "recreated {table}");
        store
            .db
            .execute_batch(&format!("ALTER TABLE missing_{table} RENAME TO {table}"))
            .unwrap();
        Store::open(home.path()).unwrap();
    }
    store.db.execute_batch("DROP TABLE owner_epochs; DROP TABLE configuration_routes; DROP TABLE retired_configuration_requests; PRAGMA user_version=21").unwrap();
    let upgraded = Store::open(home.path()).unwrap();
    assert_eq!(
        upgraded
            .db
            .pragma_query_value(None, "user_version", |r| r.get::<_, u64>(0))
            .unwrap(),
        26
    );
}

#[tokio::test]
async fn consecutive_live_handoffs_back_to_the_original_node_never_restore_its_old_signer() {
    let mut pair = Pair::new().await;
    let original = pair.stores[0].identity.node.id().to_owned();
    pair.stores[0]
        .execute(Request::Owner {
            credential: credential(&pair, 0),
            action: OwnerOp::DelegateConfiguration {
                node_id: original,
                allow: true,
            },
        })
        .unwrap();
    pair.pump();
    for (epoch, from, to) in [(1, 0, 1), (2, 1, 0), (3, 0, 1)] {
        pair.pump();
        let old_streams: Vec<(Vec<u8>, u64)> = pair.stores[to]
            .db
            .prepare(
                "SELECT group_id,head FROM streams WHERE purpose='configuration' AND writer=?1",
            )
            .unwrap()
            .query_map([pair.stores[to].identity.node.id()], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let (candidate, _, _) = complete(&mut pair, from, to);
        let key = credential(&pair, to);
        pair.stores[to]
            .activate_owner_handoff(&key, &candidate.candidate.id)
            .unwrap();
        // Exercise every older stream first, independent of random group order.
        // It must not deliver this activation ahead of the new prepared stream.
        for (group, head) in old_streams {
            pair.stores[to].sync_prepare(&group).unwrap();
            assert_eq!(
                pair.stores[to]
                    .db
                    .query_row(
                        "SELECT head FROM streams WHERE group_id=?1",
                        [&group],
                        |r| r.get::<_, u64>(0)
                    )
                    .unwrap(),
                head
            );
        }
        pair.pump();
        for i in 0..2 {
            pair.reopen(i);
        }
        assert_eq!(
            pair.stores[to]
                .identity
                .state(&pair.stores[to].db)
                .unwrap()
                .owner_epoch(),
            epoch
        );
        assert!(
            pair.stores[from]
                .identity
                .signing_owner(&pair.stores[from].db)
                .is_err()
        );
        assert_ne!(
            pair.stores[to]
                .identity
                .signing_owner(&pair.stores[to].db)
                .unwrap()
                .public_key(),
            pair.stores[to].identity.initial.anchor().owner_key
        );
        let id = Uuid::new_v4().to_string();
        let edit = ConfigurationEdit::RenameNode {
            name: format!("after-handoff-{epoch}"),
        };
        configure(&mut pair, from, &id, edit.clone()).unwrap();
        pair.pump();
        assert_eq!(
            configure(&mut pair, from, &id, edit).unwrap()["state"],
            "applied"
        );
    }
    let (id, wire): (String, Vec<u8>) = pair.stores[0].db.query_row(
        "SELECT id,authorization FROM owner_handoffs WHERE id!=(SELECT issued FROM owner_handoff_control)",
        [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    let mut invalid = SignedOwnerTransition::decode(&wire).unwrap();
    invalid.transition.epoch = 0;
    pair.stores[0]
        .db
        .execute(
            "UPDATE owner_handoffs SET authorization=?1 WHERE id=?2",
            params![invalid.encode().unwrap(), id],
        )
        .unwrap();
    assert!(Store::open(pair.homes[0].path()).is_err());
    pair.stores[0]
        .db
        .execute(
            "UPDATE owner_handoffs SET authorization=?1 WHERE id=?2",
            params![wire, id],
        )
        .unwrap();
    pair.reopen(0);
}
