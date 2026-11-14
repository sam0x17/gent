use super::*;

fn key(mesh: &Mesh, i: usize) -> String {
    config::read_private(&mesh.homes[i].path().join("owner.key")).unwrap()
}
fn configure(mesh: &mut Mesh, i: usize, id: &str, edit: ConfigurationEdit) -> Value {
    let credential = key(mesh, i);
    mesh.stores[i]
        .execute(Request::Owner {
            credential,
            action: OwnerOp::Configure {
                request_id: id.into(),
                edit,
            },
        })
        .unwrap()
}
fn config_round(mesh: &mut Mesh, online: &[usize]) -> bool {
    let mut changed = false;
    for &i in online {
        for stream in mesh.stores[i]
            .sync_streams()
            .unwrap()
            .into_iter()
            .filter(|s| s.outgoing && s.configuration)
        {
            let target = online.iter().copied().find(|&j| {
                j != i
                    && mesh.stores[j]
                        .sync_streams()
                        .unwrap()
                        .iter()
                        .any(|s| !s.outgoing && s.group == stream.group)
            });
            let Some(j) = target else { continue };
            mesh.stores[i].sync_prepare(&stream.group).unwrap();
            let next = mesh.stores[j].sync_next(&stream.group).unwrap();
            if let Some(packet) = mesh.stores[i].sync_outgoing(&stream.group, next).unwrap() {
                mesh.stores[j].sync_receive(&packet).unwrap();
                changed = true;
            }
        }
    }
    changed
}
fn configs(mesh: &mut Mesh, online: &[usize]) {
    for _ in 0..100 {
        if !config_round(mesh, online) {
            return;
        }
    }
    panic!("configuration did not drain");
}
fn pump(mesh: &mut Mesh, online: &[usize]) {
    for _ in 0..100 {
        configs(mesh, online);
        let mut changed = false;
        for &i in online {
            for stream in mesh.stores[i]
                .sync_streams()
                .unwrap()
                .into_iter()
                .filter(|s| s.outgoing && !s.configuration)
            {
                let target = online.iter().copied().find(|&j| {
                    j != i
                        && mesh.stores[j]
                            .sync_streams()
                            .unwrap()
                            .iter()
                            .any(|s| !s.outgoing && s.group == stream.group)
                });
                let Some(j) = target else { continue };
                mesh.stores[i].data_prepare(&stream.group).unwrap();
                let next = mesh.stores[j].data_next(&stream.group).unwrap();
                if let Some(packet) = mesh.stores[i].data_outgoing(&stream.group, next).unwrap() {
                    mesh.stores[j].data_receive(&packet).unwrap();
                    changed = true;
                }
            }
        }
        if !changed {
            return;
        }
    }
    panic!("online peers did not drain");
}
fn complete(
    mesh: &mut Mesh,
    from: usize,
    to: usize,
) -> gent_crypto::succession::SignedOwnerCandidate {
    let target_key = key(mesh, to);
    let candidate = mesh.stores[to]
        .prepare_owner_handoff(&target_key, &Uuid::new_v4().to_string())
        .unwrap();
    for reader in (0..mesh.stores.len()).filter(|i| *i != to) {
        let package = OrderedEndpoint::open_runtime(
            mesh.homes[reader].path(),
            &mesh.stores[reader].identity.node,
        )
        .unwrap()
        .key_package(Uuid::new_v4(), now() as u64)
        .unwrap();
        let reader_id = mesh.stores[reader].identity.node.id().to_owned();
        let request = Uuid::new_v4();
        let preparation = mesh.stores[to]
            .prepare_owner_configuration(
                &key(mesh, to),
                &candidate.candidate.id,
                request,
                (&reader_id, &package),
            )
            .unwrap();
        let credential = key(mesh, from);
        let grant = mesh.stores[from]
            .authorize_owner_configuration(&credential, &preparation)
            .unwrap();
        let invitation = mesh.stores[to]
            .install_owner_configuration(&key(mesh, to), request, &grant)
            .unwrap();
        let receipt = mesh.stores[reader]
            .receive_owner_configuration(&key(mesh, reader), &invitation)
            .unwrap();
        mesh.stores[to]
            .confirm_owner_configuration(&key(mesh, to), &receipt)
            .unwrap();
    }
    let source = key(mesh, from);
    let target = key(mesh, to);
    let authorization = mesh.stores[from]
        .authorize_owner_handoff(&source, &candidate)
        .unwrap();
    let manifest = mesh.stores[from]
        .owner_handoff_manifest(&source, &candidate.candidate.id)
        .unwrap();
    mesh.stores[to]
        .begin_owner_handoff_import(&target, &candidate.candidate.id, &authorization, &manifest)
        .unwrap();
    for index in 0..manifest.pages.len() {
        let page = mesh.stores[from]
            .owner_handoff_page(&source, &candidate.candidate.id, index)
            .unwrap();
        mesh.stores[to]
            .import_owner_handoff_page(&target, &candidate.candidate.id, index, &page)
            .unwrap();
    }
    mesh.stores[to]
        .accept_owner_handoff(&target, &candidate.candidate.id, &authorization)
        .unwrap();
    candidate
}

#[tokio::test]
async fn a_third_node_reroutes_lost_and_pending_work_while_the_old_owner_stays_offline() {
    let mut mesh = Mesh::new().await;
    for _ in 0..25 {
        mesh.round(true);
    }
    for i in 0..3 {
        assert_eq!(mesh.count(i, "network_links"), 2);
        let node = mesh.stores[i].identity.node.id().to_owned();
        let credential = key(&mesh, 0);
        mesh.stores[0]
            .execute(Request::Owner {
                credential,
                action: OwnerOp::DelegateConfiguration {
                    node_id: node,
                    allow: true,
                },
            })
            .unwrap();
    }
    pump(&mut mesh, &[0, 1, 2]);
    let origin = mesh.stores[2].identity.node.id().to_owned();
    let retired = mesh.stores[0].identity.node.id().to_owned();
    let lost = Uuid::new_v4().to_string();
    let lost_edit = ConfigurationEdit::CreateGroup {
        name: "lost-result".into(),
    };
    configure(&mut mesh, 2, &lost, lost_edit.clone());
    let store = &mesh.stores[0];
    let tx = store.db.unchecked_transaction().unwrap();
    store
        .network_session(&tx, store.identity.state(&tx).unwrap())
        .accept_configuration(&origin, Uuid::parse_str(&lost).unwrap(), lost_edit.clone())
        .unwrap();
    tx.commit().unwrap();
    configs(&mut mesh, &[0, 1, 2]);
    let decided = mesh.stores[0]
        .identity
        .state(&mesh.stores[0].db)
        .unwrap()
        .checkpoint()
        .revision;
    let pending = Uuid::new_v4().to_string();
    let pending_edit = ConfigurationEdit::CreateGroup {
        name: "pending-on-third-node".into(),
    };
    configure(&mut mesh, 2, &pending, pending_edit.clone());
    let candidate = complete(&mut mesh, 0, 1);
    let old_db = std::fs::read(mesh.homes[0].path().join("state.sqlite3")).unwrap();
    let credential = key(&mesh, 1);
    mesh.stores[1]
        .activate_owner_handoff(&credential, &candidate.candidate.id)
        .unwrap();
    mesh.reopen(1);
    mesh.reopen(2);
    // Authority receipt commits before local rerouting. A failed queue update
    // must keep the old route, input and cancellation state for a later retry.
    mesh.stores[2].db.execute_batch("CREATE TRIGGER fail_reroute BEFORE UPDATE ON configuration_edits WHEN NEW.writer!=OLD.writer BEGIN SELECT RAISE(ABORT,'reroute failure'); END;").unwrap();
    let group: Vec<u8> = mesh.stores[1].db.query_row(
        "SELECT group_id FROM configuration_streams WHERE json_extract(grant,'$.grant.reader')=?1 AND json_extract(grant,'$.grant.owner_candidate') IS NOT NULL",
        [&origin], |r| r.get(0)).unwrap();
    mesh.stores[1].sync_prepare(&group).unwrap();
    let next = mesh.stores[2].sync_next(&group).unwrap();
    let packet = mesh.stores[1].sync_outgoing(&group, next).unwrap().unwrap();
    assert!(
        mesh.stores[2]
            .sync_receive(&packet)
            .unwrap_err()
            .to_string()
            .contains("reroute failure")
    );
    assert_eq!(
        mesh.stores[2]
            .identity
            .state(&mesh.stores[2].db)
            .unwrap()
            .owner_epoch(),
        1
    );
    assert_eq!(
        mesh.stores[2]
            .db
            .query_row(
                "SELECT COUNT(*) FROM configuration_routes WHERE epoch=1",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(mesh.count(2, "configuration_pending"), 2);
    for id in [&lost, &pending] {
        assert_eq!(
            mesh.stores[2]
                .db
                .query_row(
                    "SELECT writer FROM configuration_edits WHERE id=?1",
                    [id],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            retired
        );
    }
    mesh.stores[2]
        .db
        .execute_batch("DROP TRIGGER fail_reroute")
        .unwrap();
    mesh.reopen(2);
    mesh.stores[2].maintain().unwrap();
    configs(&mut mesh, &[1, 2]);
    let current = mesh.stores[1].identity.node.id().to_owned();
    for id in [&lost, &pending] {
        let route: String = mesh.stores[2]
            .db
            .query_row(
                "SELECT writer FROM configuration_edits WHERE origin=?1 AND id=?2",
                params![origin, id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(route, current);
    }
    // A retired writer's late rejection must not decide a rerouted request.
    let store = &mesh.stores[2];
    let tx = store.db.unchecked_transaction().unwrap();
    store
        .network_session(&tx, store.identity.state(&tx).unwrap())
        .import_configuration_result(
            &retired,
            Uuid::parse_str(&pending).unwrap(),
            &hash(&serde_json::to_string(&pending_edit).unwrap()),
            crate::messages::EditResult::Rejected {
                reason: "late old-writer result".into(),
            },
        )
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        configure(&mut mesh, 2, &pending, pending_edit.clone())["state"],
        "queued"
    );
    pump(&mut mesh, &[1, 2]);
    assert_eq!(
        configure(&mut mesh, 2, &lost, lost_edit.clone())["revision"],
        decided
    );
    assert_eq!(
        configure(&mut mesh, 2, &pending, pending_edit.clone())["state"],
        "applied"
    );
    let writer: String = mesh.stores[2]
        .db
        .query_row(
            "SELECT writer FROM configuration_edits WHERE origin=?1 AND id=?2",
            params![origin, lost],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(writer, retired);
    assert_eq!(
        std::fs::read(mesh.homes[0].path().join("state.sqlite3")).unwrap(),
        old_db
    );
    assert_eq!(mesh.count(2, "configuration_pending"), 0);
    // Catch up the old owner and deliver its original buffered result as well.
    pump(&mut mesh, &[0, 1, 2]);
    let next = complete(&mut mesh, 1, 2);
    let credential = key(&mesh, 2);
    mesh.stores[2]
        .activate_owner_handoff(&credential, &next.candidate.id)
        .unwrap();
    pump(&mut mesh, &[0, 1, 2]);
    assert_eq!(
        mesh.stores[2]
            .identity
            .state(&mesh.stores[2].db)
            .unwrap()
            .owner_epoch(),
        2
    );
    assert_eq!(
        configure(&mut mesh, 2, &lost, lost_edit)["revision"],
        decided
    );
}
