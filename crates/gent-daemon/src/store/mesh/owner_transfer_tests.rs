use super::*;
use gent_protocol::owner_transfer::OwnerTransferOp;

fn call(mesh: &mut Mesh, i: usize, action: OwnerTransferOp) -> Result<Value> {
    let credential = key(mesh, i);
    mesh.stores[i].execute(Request::Owner {
        credential,
        action: OwnerOp::OwnerTransfer { action },
    })
}

fn detail(mesh: &mut Mesh, i: usize, id: Uuid) -> Value {
    call(
        mesh,
        i,
        OwnerTransferOp::Status {
            request_id: Some(id.to_string()),
        },
    )
    .unwrap()
}

fn commit(mesh: &mut Mesh, i: usize, id: Uuid) -> Result<Value> {
    call(
        mesh,
        i,
        OwnerTransferOp::Commit {
            request_id: id.to_string(),
        },
    )
}

fn resume(mesh: &mut Mesh, i: usize, id: Uuid) -> Result<Value> {
    call(
        mesh,
        i,
        OwnerTransferOp::Resume {
            request_id: id.to_string(),
        },
    )
}

fn tick(mesh: &mut Mesh, i: usize) {
    mesh.stores[i]
        .db
        .execute("UPDATE owner_transfers SET retry_at=0", [])
        .unwrap();
    mesh.stores[i].owner_transfer_tick().unwrap();
}

fn epoch(mesh: &Mesh, i: usize) -> u32 {
    mesh.stores[i]
        .identity
        .state(&mesh.stores[i].db)
        .unwrap()
        .owner_epoch()
}

#[tokio::test]
async fn owner_transfer_old_commits_remain_exact_retries_after_later_epochs() {
    let mut mesh = linked().await;
    let mut completed = Vec::new();
    for (expected, from, to) in [(1, 0, 1), (2, 1, 2), (3, 2, 0)] {
        let id = Uuid::new_v4();
        let node_id = mesh.stores[to].identity.node.id().to_owned();
        call(
            &mut mesh,
            from,
            OwnerTransferOp::Prepare {
                request_id: id.to_string(),
                node_id,
            },
        )
        .unwrap();
        ready(&mut mesh, from, id);
        commit(&mut mesh, from, id).unwrap();
        for _ in 0..100 {
            for i in 0..3 {
                tick(&mut mesh, i);
            }
            mesh.round(false);
            if (0..3).all(|i| epoch(&mesh, i) == expected) {
                break;
            }
        }
        completed.push((from, id));
        for i in 0..3 {
            mesh.reopen(i);
            assert_eq!(epoch(&mesh, i), expected);
        }
        for &(source, request) in &completed {
            assert_eq!(
                commit(&mut mesh, source, request).unwrap()["state"],
                "complete"
            );
            assert_eq!(
                resume(&mut mesh, source, request).unwrap()["state"],
                "complete"
            );
            tick(&mut mesh, source);
            assert_eq!(epoch(&mesh, source), expected);
        }
    }
    for i in 0..3 {
        assert_eq!(mesh.count(i, "owner_handoffs"), 1);
    }
    mesh.stores[0].require_provisioning_owner().unwrap();
    for i in [1, 2] {
        assert!(mesh.stores[i].require_provisioning_owner().is_err());
    }
}

#[tokio::test]
async fn owner_transfer_commit_is_atomic_and_automatic_completion_survives_failures() {
    let mut mesh = linked().await;
    let id = Uuid::new_v4();
    let target = mesh.stores[1].identity.node.id().to_owned();
    let prepare = OwnerTransferOp::Prepare {
        request_id: id.to_string(),
        node_id: target.clone(),
    };
    let wrong_credential = key(&mesh, 1);
    assert!(
        mesh.stores[0]
            .execute(Request::Owner {
                credential: wrong_credential,
                action: OwnerOp::OwnerTransfer {
                    action: prepare.clone()
                },
            })
            .is_err()
    );
    assert!(call(&mut mesh, 2, prepare.clone()).is_err());
    assert_eq!(mesh.count(0, "owner_preparation_plans"), 0);

    // A rejected configuration decision gives the import a real journal page.
    let credential = key(&mesh, 0);
    let decision = mesh.stores[0]
        .execute(Request::Owner {
            credential,
            action: OwnerOp::Configure {
                request_id: Uuid::new_v4().to_string(),
                edit: ConfigurationEdit::DeleteGroup {
                    name: "absent-transfer-fixture".into(),
                },
            },
        })
        .unwrap();
    assert_eq!(decision["state"], "rejected");
    assert_eq!(
        call(&mut mesh, 0, prepare.clone()).unwrap()["state"],
        "preparing"
    );
    call(&mut mesh, 0, prepare.clone()).unwrap();
    assert!(commit(&mut mesh, 0, id).is_err());
    assert_eq!(resume(&mut mesh, 0, id).unwrap()["committed"], false);
    tick(&mut mesh, 0);
    assert_eq!(mesh.count(0, "owner_handoffs"), 0);
    ready(&mut mesh, 0, id);
    let changes = mesh.stores[0].db.total_changes();
    assert_eq!(detail(&mut mesh, 0, id)["state"], "prepared");
    assert_eq!(mesh.stores[0].db.total_changes(), changes);
    assert!(commit(&mut mesh, 1, id).is_err());
    assert_eq!(resume(&mut mesh, 0, id).unwrap()["committed"], false);
    tick(&mut mesh, 0);
    assert_eq!(mesh.count(0, "owner_handoffs"), 0);
    mesh.stores[0].require_provisioning_owner().unwrap();

    mesh.stores[0].db.execute_batch("CREATE TRIGGER fail_commit BEFORE INSERT ON owner_transfers BEGIN SELECT RAISE(ABORT,'control insertion failed'); END;").unwrap();
    assert!(
        commit(&mut mesh, 0, id)
            .unwrap_err()
            .to_string()
            .contains("control insertion failed")
    );
    for table in ["owner_handoffs", "owner_journals", "owner_transfers"] {
        assert_eq!(mesh.count(0, table), 0);
    }
    assert_eq!(detail(&mut mesh, 0, id)["signing_frozen"], false);
    mesh.stores[0].require_provisioning_owner().unwrap();
    mesh.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_commit")
        .unwrap();
    assert_eq!(commit(&mut mesh, 0, id).unwrap()["state"], "committed");
    assert_eq!(detail(&mut mesh, 0, id)["signing_frozen"], true);
    assert_eq!(mesh.count(0, "owner_transfers"), 1);

    mesh.stores[0].db.execute_batch("CREATE TRIGGER fail_queue BEFORE INSERT ON owner_deliveries BEGIN SELECT RAISE(ABORT,'delivery queue failed'); END;").unwrap();
    tick(&mut mesh, 0);
    assert!(
        detail(&mut mesh, 0, id)["error"]
            .as_str()
            .unwrap()
            .contains("delivery queue failed")
    );
    assert_eq!(mesh.count(0, "owner_deliveries"), 0);
    mesh.reopen(0);
    mesh.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_queue")
        .unwrap();
    commit(&mut mesh, 0, id).unwrap();
    assert_eq!(mesh.count(0, "owner_handoffs"), 1);
    tick(&mut mesh, 0);
    assert_eq!(mesh.count(0, "owner_deliveries"), 1);

    for _ in 0..100 {
        mesh.round(false);
        if mesh.count(1, "owner_journals") != 0 {
            break;
        }
    }
    let target_key = key(&mesh, 1);
    assert_eq!(
        mesh.stores[1]
            .owner_handoff_import_status(&target_key, &id.to_string())
            .unwrap()["pages_complete"],
        false
    );
    tick(&mut mesh, 1);
    assert_eq!(detail(&mut mesh, 1, id)["state"], "receiving");
    assert_eq!(epoch(&mesh, 1), 0);
    assert_eq!(mesh.count(1, "owner_epochs"), 0);
    for _ in 0..100 {
        mesh.round(false);
        if mesh.stores[1]
            .owner_handoff_import_status(&target_key, &id.to_string())
            .unwrap()["pages_complete"]
            == true
        {
            break;
        }
    }
    assert_eq!(
        mesh.stores[1]
            .owner_handoff_import_status(&target_key, &id.to_string())
            .unwrap()["pages_complete"],
        true
    );

    // From here until completion no source tick, packet or process is needed.
    let source_db = std::fs::read(mesh.homes[0].path().join("state.sqlite3")).unwrap();
    let key_path = mesh.homes[1]
        .path()
        .join("owner-candidates")
        .join(format!("{id}.key"));
    let original_key = std::fs::read(&key_path).unwrap();
    let saved_key = key_path.with_extension("saved");
    std::fs::rename(&key_path, &saved_key).unwrap();
    tick(&mut mesh, 1);
    assert_eq!(epoch(&mesh, 1), 0);
    assert!(detail(&mut mesh, 1, id)["error"].is_string());
    std::fs::rename(&saved_key, &key_path).unwrap();
    mesh.reopen(1);
    mesh.stores[1].db.execute_batch("CREATE TRIGGER fail_activation BEFORE INSERT ON owner_epochs BEGIN SELECT RAISE(ABORT,'activation failed'); END;").unwrap();
    tick(&mut mesh, 1);
    assert_eq!(epoch(&mesh, 1), 0);
    assert!(
        detail(&mut mesh, 1, id)["error"]
            .as_str()
            .unwrap()
            .contains("activation failed")
    );
    mesh.reopen(1);
    mesh.stores[1].db.execute_batch("DROP TRIGGER fail_activation;
        CREATE TRIGGER fail_done BEFORE UPDATE OF done ON owner_transfers WHEN NEW.done=1 BEGIN SELECT RAISE(ABORT,'completion write failed'); END;").unwrap();
    tick(&mut mesh, 1);
    assert_eq!(epoch(&mesh, 1), 1);
    assert_eq!(detail(&mut mesh, 1, id)["state"], "finishing");
    assert!(
        detail(&mut mesh, 1, id)["error"]
            .as_str()
            .unwrap()
            .contains("completion write failed")
    );
    mesh.reopen(1);
    mesh.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_done")
        .unwrap();
    resume(&mut mesh, 1, id).unwrap();
    tick(&mut mesh, 1);
    assert_eq!(detail(&mut mesh, 1, id)["state"], "complete");
    assert_eq!(mesh.count(1, "owner_epochs"), 1);
    assert_eq!(std::fs::read(&key_path).unwrap(), original_key);
    assert_eq!(
        std::fs::read(mesh.homes[0].path().join("state.sqlite3")).unwrap(),
        source_db
    );
    for _ in 0..100 {
        mesh.round(false);
        if (0..3).all(|i| epoch(&mesh, i) == 1) {
            break;
        }
    }
    for i in 0..3 {
        assert_eq!(epoch(&mesh, i), 1);
    }
    tick(&mut mesh, 0);
    assert_eq!(commit(&mut mesh, 0, id).unwrap()["state"], "complete");
    assert_eq!(resume(&mut mesh, 0, id).unwrap()["state"], "complete");
    assert_eq!(mesh.count(0, "owner_handoffs"), 1);
    assert!(mesh.stores[0].require_provisioning_owner().is_err());
}

#[tokio::test]
async fn owner_transfer_migration_preserves_manual_plans_and_refuses_missing_control_storage() {
    let mut mesh = linked().await;
    let id = Uuid::new_v4();
    start(&mut mesh, 0, 1, id);
    let original: Vec<u8> = mesh.stores[0]
        .db
        .query_row(
            "SELECT plan FROM owner_preparation_plans WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        serde_json::from_slice::<Value>(&original)
            .unwrap()
            .get("auto_activate")
            .is_none()
    );
    mesh.stores[0]
        .db
        .execute_batch("DROP TABLE owner_transfers; PRAGMA user_version=25;")
        .unwrap();
    mesh.reopen(0);
    let migrated: Vec<u8> = mesh.stores[0]
        .db
        .query_row(
            "SELECT plan FROM owner_preparation_plans WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(original, migrated);
    assert_eq!(
        mesh.stores[0]
            .db
            .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap(),
        26
    );
    let node_id = mesh.stores[1].identity.node.id().to_owned();
    assert!(
        call(
            &mut mesh,
            0,
            OwnerTransferOp::Prepare {
                request_id: id.to_string(),
                node_id
            }
        )
        .is_err()
    );
    assert!(resume(&mut mesh, 0, id).is_err());
    ready(&mut mesh, 0, id);
    assert!(commit(&mut mesh, 0, id).is_err());
    assert_eq!(mesh.count(0, "owner_handoffs"), 0);
    assert_eq!(detail(&mut mesh, 0, id)["signing_frozen"], false);
    let proposal = candidate(&mesh, 0, id);
    let source_key = key(&mesh, 0);
    mesh.stores[0]
        .authorize_owner_handoff(&source_key, &proposal)
        .unwrap();
    mesh.stores[0]
        .queue_owner_handoff_delivery(&source_key, &id.to_string())
        .unwrap();
    let target_key = key(&mesh, 1);
    for _ in 0..100 {
        mesh.round(false);
        if mesh.stores[1]
            .owner_handoff_import_status(&target_key, &id.to_string())
            .is_ok_and(|s| s["pages_complete"] == true)
        {
            break;
        }
    }
    assert_eq!(
        mesh.stores[1]
            .owner_handoff_import_status(&target_key, &id.to_string())
            .unwrap()["pages_complete"],
        true
    );
    for i in 0..3 {
        tick(&mut mesh, i);
        mesh.reopen(i);
        tick(&mut mesh, i);
        assert_eq!(epoch(&mesh, i), 0);
        assert_eq!(mesh.count(i, "owner_transfers"), 0);
        assert_eq!(detail(&mut mesh, i, id)["auto_activate"], false);
    }
    mesh.stores[0]
        .db
        .execute_batch("DROP TABLE owner_transfers")
        .unwrap();
    assert!(Store::open(mesh.homes[0].path()).is_err());
}
