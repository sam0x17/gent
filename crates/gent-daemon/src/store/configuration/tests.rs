use super::*;

#[test]
fn hosting_uses_existing_configuration_authority_and_persists_exact_retries() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("node");
    config::initialize(&home, "hosting").unwrap();
    let mut store = Store::open(&home).unwrap();
    let credential = config::read_private(&home.join("owner.key")).unwrap();
    let child = gent_crypto::NodeIdentity::generate().unwrap();
    let parent = store.identity.node.id().to_owned();
    {
        let tx = store.db.unchecked_transaction().unwrap();
        let state = store.identity.state(&tx).unwrap();
        let request = child
            .request_enrollment(state.anchor(), state.checkpoint(), "child", now() as u64)
            .unwrap();
        let update = state
            .enroll(
                &*store.identity.signing_owner(&tx).unwrap(),
                &request,
                request.fingerprint().unwrap(),
                now() as u64,
            )
            .unwrap();
        store.identity.apply(&tx, update).unwrap();
        tx.commit().unwrap();
    }
    let edit = ConfigurationEdit::HostNode {
        node_id: child.id().into(),
        parent: parent.clone(),
    };
    let checkpoint = store
        .identity
        .state(&store.db)
        .unwrap()
        .checkpoint()
        .clone();
    let rejected = store
        .execute(Request::Owner {
            credential: credential.clone(),
            action: OwnerOp::Configure {
                request_id: Uuid::new_v4().to_string(),
                edit: ConfigurationEdit::HostNode {
                    node_id: parent.clone(),
                    parent: child.id().into(),
                },
            },
        })
        .unwrap();
    assert_eq!(rejected["state"], "rejected");
    assert_eq!(
        store.identity.state(&store.db).unwrap().checkpoint(),
        &checkpoint
    );
    {
        let tx = store.db.unchecked_transaction().unwrap();
        let state = store.identity.state(&tx).unwrap();
        let session = store.network_session(&tx, state);
        let signer = store.identity.signing_owner(&tx).unwrap();
        assert!(
            session
                .revision_for_edit_with(child.id(), &edit, &*signer)
                .unwrap_err()
                .to_string()
                .contains("configuration-management grant")
        );
        // Administrative delegation is explicit, even for the child itself.
        let update = session
            .state
            .delegate_configuration(&*signer, child.id(), true, now() as u64)
            .unwrap();
        let state = store.identity.apply(&tx, update).unwrap();
        let session = store.network_session(&tx, state);
        assert!(
            session
                .revision_for_edit_with(child.id(), &edit, &*signer)
                .is_ok()
        );
        tx.commit().unwrap();
    }
    let action = OwnerOp::Configure {
        request_id: Uuid::new_v4().to_string(),
        edit,
    };
    let applied = store
        .execute(Request::Owner {
            credential: credential.clone(),
            action: action.clone(),
        })
        .unwrap();
    assert_eq!(applied["state"], "applied");
    let state = store.identity.state(&store.db).unwrap();
    assert_eq!(state.transport_host(child.id()).unwrap(), parent);
    assert!(state.state().nodes[child.id()].can_configure);
    let checkpoint = state.checkpoint().clone();
    drop(store);
    let mut store = Store::open(&home).unwrap();
    assert_eq!(
        store
            .execute(Request::Owner {
                credential: credential.clone(),
                action
            })
            .unwrap(),
        applied
    );
    assert_eq!(
        store.identity.state(&store.db).unwrap().checkpoint(),
        &checkpoint
    );
    let other = gent_crypto::NodeIdentity::generate().unwrap();
    let rejected = store
        .execute(Request::Owner {
            credential,
            action: OwnerOp::Configure {
                request_id: Uuid::new_v4().to_string(),
                edit: ConfigurationEdit::HostNode {
                    node_id: child.id().into(),
                    parent: other.id().into(),
                },
            },
        })
        .unwrap();
    assert_eq!(rejected["state"], "rejected");
    assert_eq!(
        store.identity.state(&store.db).unwrap().checkpoint(),
        &checkpoint
    );
}

#[test]
fn hosting_configuration_rejects_invalid_ids_before_queuing() {
    let child = Uuid::new_v4().to_string();
    let parent = Uuid::new_v4().to_string();
    for (node_id, parent) in [
        (child.clone(), child.clone()),
        (child.clone(), "missing".into()),
        ("missing".into(), parent.clone()),
    ] {
        assert!(validate(&ConfigurationEdit::HostNode { node_id, parent }).is_err());
    }
    assert!(
        validate(&ConfigurationEdit::HostNode {
            node_id: child,
            parent
        })
        .is_ok()
    );
}
