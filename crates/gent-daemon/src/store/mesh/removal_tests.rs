use super::*;

fn owner(mesh: &mut Mesh, index: usize, action: OwnerOp) -> Result<Value> {
    let credential = config::read_private(&mesh.homes[index].path().join("owner.key"))?;
    mesh.stores[index].execute(Request::Owner { credential, action })
}
fn remove(mesh: &mut Mesh, index: usize, id: &str) -> Result<Value> {
    owner(mesh, index, OwnerOp::RemoveNode { node_id: id.into() })
}
fn state(mesh: &Mesh) -> VerifiedState {
    mesh.stores[0].identity.state(&mesh.stores[0].db).unwrap()
}
fn service(mesh: &mut Mesh) {
    let mut cfg = config::load(mesh.homes[0].path()).unwrap();
    cfg.cluster.local_only = false;
    cfg.service = Some(config::ServiceConfig {
        origin: "https://api.example".into(),
        account_id: Uuid::new_v4().to_string(),
    });
    config::save(mesh.homes[0].path(), &cfg).unwrap();
    mesh.reopen(0);
}

#[tokio::test]
async fn removal_is_owner_only_and_rejects_self_unknown_and_changed_service() {
    let mut mesh = Mesh::new().await;
    service(&mut mesh);
    let target = mesh.stores[1].identity.node.id().to_owned();
    let local = mesh.stores[0].identity.node.id().to_owned();
    let before = state(&mesh).checkpoint().clone();
    assert!(remove(&mut mesh, 0, &local).is_err());
    assert!(remove(&mut mesh, 0, "../node").is_err());
    assert!(remove(&mut mesh, 0, &Uuid::new_v4().to_string()).is_err());
    owner(
        &mut mesh,
        0,
        OwnerOp::DelegateConfiguration {
            node_id: target.clone(),
            allow: true,
        },
    )
    .unwrap();
    mesh.round(false);
    assert!(remove(&mut mesh, 1, &local).is_err());
    assert!(
        mesh.stores[0]
            .execute(Request::Owner {
                credential: "wrong".into(),
                action: OwnerOp::RemoveNode {
                    node_id: target.clone()
                }
            })
            .is_err()
    );
    assert!(
        serde_json::from_value::<Request>(json!({"role":"agent","credential":"unused",
        "action":{"op":"remove_node","node_id":target}}))
        .is_err()
    );
    let mut cfg = config::load(mesh.homes[0].path()).unwrap();
    cfg.service.as_mut().unwrap().origin = "https://wrong.example".into();
    config::save(mesh.homes[0].path(), &cfg).unwrap();
    assert!(remove(&mut mesh, 0, &target).is_err());
    assert_eq!(mesh.count(0, "node_removals"), 0);
    assert_eq!(state(&mesh).checkpoint().revision, before.revision + 1);
}

#[tokio::test]
async fn removal_and_service_intent_commit_together_and_retry_after_restart() {
    let mut mesh = Mesh::new().await;
    service(&mut mesh);
    let target = mesh.stores[1].identity.node.id().to_owned();
    let before = state(&mesh).checkpoint().clone();
    let history = mesh.count(0, "authority_history");
    mesh.stores[0].db.execute_batch("CREATE TRIGGER fail_removal BEFORE INSERT ON node_removals BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(remove(&mut mesh, 0, &target).is_err());
    assert_eq!(state(&mesh).checkpoint(), &before);
    assert_eq!(mesh.count(0, "authority_history"), history);
    assert_eq!(mesh.count(0, "node_removals"), 0);
    mesh.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_removal;")
        .unwrap();
    let first = remove(&mut mesh, 0, &target).unwrap();
    assert_eq!(first["service_status"], "pending");
    assert_eq!(first["revision"], before.revision + 1);
    mesh.reopen(0);
    let retry = remove(&mut mesh, 0, &target).unwrap();
    assert_eq!(retry["revision"], first["revision"]);
    assert_eq!(state(&mesh).checkpoint().revision, before.revision + 1);
    let list = owner(
        &mut mesh,
        0,
        OwnerOp::NodeRemovals {
            after: None,
            pending_only: true,
        },
    )
    .unwrap();
    assert_eq!(list["removals"], json!([retry]));
    assert!(
        owner(
            &mut mesh,
            0,
            OwnerOp::ConfirmNodeRemoval {
                node_id: target.clone(),
                revision: before.revision
            }
        )
        .is_err()
    );
    mesh.stores[0].db.execute_batch("CREATE TRIGGER fail_confirmation BEFORE UPDATE ON node_removals BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    let confirmation = OwnerOp::ConfirmNodeRemoval {
        node_id: target.clone(),
        revision: before.revision + 1,
    };
    assert!(owner(&mut mesh, 0, confirmation.clone()).is_err());
    assert_eq!(
        remove(&mut mesh, 0, &target).unwrap()["service_status"],
        "pending"
    );
    mesh.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_confirmation;")
        .unwrap();
    assert_eq!(
        owner(&mut mesh, 0, confirmation.clone()).unwrap()["service_status"],
        "confirmed"
    );
    mesh.reopen(0);
    assert_eq!(
        owner(&mut mesh, 0, confirmation).unwrap()["service_status"],
        "confirmed"
    );
    assert_eq!(
        owner(
            &mut mesh,
            0,
            OwnerOp::NodeRemovals {
                after: None,
                pending_only: true
            }
        )
        .unwrap()["removals"],
        json!([])
    );
    assert_eq!(mesh.count(0, "node_removals"), 1);
}

#[tokio::test]
async fn removal_sync_disables_existing_peer_streams_and_preserves_the_remaining_link() {
    let mut mesh = Mesh::new().await;
    for _ in 0..12 {
        mesh.round(true);
    }
    let target = mesh.stores[1].identity.node.id().to_owned();
    let target_groups: Vec<Vec<u8>> = mesh.stores[0]
        .db
        .query_row(
            "SELECT outgoing,incoming FROM network_links WHERE peer=?1",
            [&target],
            |r| Ok(vec![r.get(0)?, r.get(1)?]),
        )
        .unwrap();
    let survivor_groups: Vec<Vec<u8>> = mesh.stores[2]
        .db
        .query_row(
            "SELECT outgoing,incoming FROM network_links WHERE peer=?1",
            [&target],
            |r| Ok(vec![r.get(0)?, r.get(1)?]),
        )
        .unwrap();
    let first = remove(&mut mesh, 0, &target).unwrap();
    assert_eq!(first["service_status"], "not_configured");
    assert!(mesh.stores[0].data_prepare(&target_groups[0]).is_err());
    assert!(mesh.stores[0].data_next(&target_groups[1]).is_err());
    // The offline peer still has its old authority until receiving the update.
    assert!(mesh.stores[2].data_next(&survivor_groups[1]).is_ok());
    for _ in 0..8 {
        mesh.round(false);
    }
    assert!(mesh.stores[2].data_prepare(&survivor_groups[0]).is_err());
    assert!(mesh.stores[2].data_next(&survivor_groups[1]).is_err());
    assert_eq!(mesh.stores[2].data_streams().unwrap().len(), 2);
    assert_eq!(mesh.stores[0].data_streams().unwrap().len(), 2);
    assert_eq!(
        mesh.stores[2]
            .identity
            .state(&mesh.stores[2].db)
            .unwrap()
            .checkpoint(),
        state(&mesh).checkpoint()
    );
    mesh.reopen(0);
    mesh.reopen(2);
    for _ in 0..3 {
        mesh.round(false);
    }
    assert_eq!(mesh.stores[2].data_streams().unwrap().len(), 2);
    assert!(
        owner(
            &mut mesh,
            0,
            OwnerOp::ConfirmNodeRemoval {
                node_id: target,
                revision: first["revision"].as_u64().unwrap()
            }
        )
        .is_err()
    );
}

#[tokio::test]
async fn removal_journal_migration_missing_table_and_mismatched_record_fail_closed() {
    let mut mesh = Mesh::new().await;
    mesh.stores[0]
        .db
        .execute_batch("DROP TABLE node_removals; PRAGMA user_version=15;")
        .unwrap();
    mesh.reopen(0);
    assert_eq!(mesh.count(0, "node_removals"), 0);
    let target = mesh.stores[1].identity.node.id().to_owned();
    remove(&mut mesh, 0, &target).unwrap();
    mesh.stores[0]
        .db
        .execute("UPDATE node_removals SET signing_key=?1", [vec![0u8; 32]])
        .unwrap();
    assert!(remove(&mut mesh, 0, &target).is_err());
    mesh.stores[0]
        .db
        .execute_batch("DROP TABLE node_removals;")
        .unwrap();
    assert!(Store::open(mesh.homes[0].path()).is_err());
}

#[tokio::test]
async fn removal_capacity_preserves_existing_retry_and_rejects_new_mutation() {
    let mut mesh = Mesh::new().await;
    let target = mesh.stores[1].identity.node.id().to_owned();
    let next = mesh.stores[2].identity.node.id().to_owned();
    let first = remove(&mut mesh, 0, &target).unwrap();
    let before = state(&mesh).checkpoint().clone();
    let tx = mesh.stores[0].db.unchecked_transaction().unwrap();
    for _ in 1..8192 {
        tx.execute("INSERT INTO node_removals(node,cluster,signing_key,revision,created_at,service,confirmed) SELECT ?1,cluster,signing_key,revision,created_at,service,confirmed FROM node_removals WHERE node=?2",
            params![Uuid::new_v4().to_string(),target]).unwrap();
    }
    tx.commit().unwrap();
    assert_eq!(
        remove(&mut mesh, 0, &target).unwrap()["revision"],
        first["revision"]
    );
    assert!(remove(&mut mesh, 0, &next).is_err());
    assert_eq!(state(&mesh).checkpoint(), &before);
    assert!(state(&mesh).state().nodes.contains_key(&next));
}

#[tokio::test]
async fn replacement_schema_migrates_existing_removals_and_refuses_missing_current_structure() {
    let mut mesh = Mesh::new().await;
    let target = mesh.stores[1].identity.node.id().to_owned();
    let first = remove(&mut mesh, 0, &target).unwrap();
    assert!(first["replacement"].is_null());
    mesh.stores[0]
        .db
        .execute_batch(
            "DROP INDEX node_removals_replacement;
        ALTER TABLE node_removals DROP COLUMN replacement_key;
        ALTER TABLE node_removals DROP COLUMN replacement_node;
        PRAGMA user_version=16;",
        )
        .unwrap();
    mesh.reopen(0);
    let next = remove(&mut mesh, 0, &target).unwrap();
    assert_eq!(next["revision"], first["revision"]);
    assert!(next["replacement"].is_null());
    assert_eq!(mesh.count(0, "node_removals"), 1);
    assert_eq!(
        mesh.stores[0]
            .db
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        20
    );
    mesh.stores[0]
        .db
        .execute_batch("DROP INDEX node_removals_replacement;")
        .unwrap();
    assert!(Store::open(mesh.homes[0].path()).is_err());
    mesh.stores[0]
        .db
        .execute_batch(
            "CREATE UNIQUE INDEX node_removals_replacement ON node_removals(replacement_node);
        ALTER TABLE node_removals DROP COLUMN replacement_key;",
        )
        .unwrap();
    assert!(Store::open(mesh.homes[0].path()).is_err());
}
