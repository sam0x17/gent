use super::*;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    home: tempfile::TempDir,
    store: Store,
    credential: String,
    peer: gent_crypto::NodeIdentity,
}

impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        config::initialize(home.path(), "creator").unwrap();
        let store = Store::open(home.path()).unwrap();
        crate::entitlements::grant_test(home.path(), &store.config);
        let credential = config::read_private(&home.path().join("owner.key")).unwrap();
        let peer = gent_crypto::NodeIdentity::generate().unwrap();
        let tx = store.db.unchecked_transaction().unwrap();
        let state = store.identity.state(&tx).unwrap();
        let key = store.identity.signing_owner(&tx).unwrap();
        let state = store
            .identity
            .apply(
                &tx,
                state
                    .delegate_configuration(&key, store.identity.node.id(), true, now() as u64)
                    .unwrap(),
            )
            .unwrap();
        let request = peer
            .request_enrollment(state.anchor(), state.checkpoint(), "peer", now() as u64)
            .unwrap();
        store
            .identity
            .apply(
                &tx,
                state
                    .enroll_configurator(
                        &key,
                        &request,
                        request.fingerprint().unwrap(),
                        now() as u64,
                    )
                    .unwrap(),
            )
            .unwrap();
        tx.commit().unwrap();
        Self {
            home,
            store,
            credential,
            peer,
        }
    }

    fn restart(self) -> Self {
        drop(self.store);
        Self {
            store: Store::open(self.home.path()).unwrap(),
            ..self
        }
    }

    fn activate(&mut self) {
        self.store
            .prepare_configuration_log(&self.credential)
            .unwrap();
        let commit = self.store.configuration_log_migration().unwrap().unwrap();
        self.store.accept_configuration_commit(&commit).unwrap();
    }

    fn queue(&mut self, name: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let result = self
            .store
            .execute(Request::Owner {
                credential: self.credential.clone(),
                action: OwnerOp::Configure {
                    request_id: id.clone(),
                    edit: ConfigurationEdit::RenameNode { name: name.into() },
                },
            })
            .unwrap();
        assert_eq!(result["state"], "queued");
        id
    }

    fn competing(&self, restrict: bool) -> Commit {
        let state = self.store.identity.state(&self.store.db).unwrap();
        let head = self.store.configuration_log_head().unwrap().unwrap();
        let key: Vec<u8> = self
            .store
            .db
            .query_row("SELECT capability FROM peer_configuration", [], |r| {
                r.get(0)
            })
            .unwrap();
        let key = WriteCapability::from_secret(key.as_slice().try_into().unwrap());
        let next = WriteCapability::generate().unwrap();
        let header = header(
            &state,
            head,
            self.peer.id(),
            &uuid::Uuid::new_v4().to_string(),
            [7; 32],
            &next,
        );
        let signer = NodeSigner::new(&self.peer, header.clone()).unwrap();
        let updated = if restrict {
            state.delegate_configuration(
                &signer,
                self.store.identity.node.id(),
                false,
                now() as u64,
            )
        } else {
            state.configure(
                &signer,
                "concurrent cluster name",
                (self.peer.id(), "peer"),
                state.state().policy.clone(),
                now() as u64,
            )
        }
        .unwrap();
        key.seal(header, &envelope::seal(&updated, &next).unwrap())
            .unwrap()
    }
}

#[test]
fn migration_fence_and_prepared_ciphertext_survive_restart() {
    let mut f = Fixture::new();
    let bootstrap = f.store.prepare_configuration_log(&f.credential).unwrap();
    let candidate = f.store.configuration_log_migration().unwrap().unwrap();
    assert!(f.store.identity.signing_owner(&f.store.db).is_err());
    assert_eq!(
        &std::fs::read(f.home.path().join(runtime::KEY_FILE)).unwrap()[..8],
        b"GENTKEY3"
    );
    f = f.restart();
    assert!(f.store.identity.signing_owner(&f.store.db).is_err());
    assert_eq!(
        f.store.prepare_configuration_log(&f.credential).unwrap(),
        bootstrap
    );
    assert_eq!(
        f.store.configuration_log_migration().unwrap().unwrap(),
        candidate
    );
    let receipt = f.store.accept_configuration_commit(&candidate).unwrap();
    f = f.restart();
    assert_eq!(
        f.store.accept_configuration_commit(&candidate).unwrap(),
        receipt
    );
    assert_eq!(
        f.store.configuration_log_head().unwrap().unwrap(),
        receipt.head
    );
}

#[test]
fn failed_journal_write_keeps_legacy_writer_fenced_and_can_retry() {
    let mut f = Fixture::new();
    f.store.db.execute_batch("CREATE TRIGGER fail_preparation BEFORE INSERT ON peer_configuration BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(f.store.prepare_configuration_log(&f.credential).is_err());
    assert!(f.store.configuration_log_head().unwrap().is_none());
    f = f.restart();
    assert!(f.store.identity.signing_owner(&f.store.db).is_err());
    f.store
        .db
        .execute_batch("DROP TRIGGER fail_preparation")
        .unwrap();
    f.activate();
    assert!(
        f.store
            .identity
            .state(&f.store.db)
            .unwrap()
            .state()
            .peer
            .is_some()
    );
}

#[test]
fn commit_failure_rolls_back_authority_capability_receipt_and_edit_result() {
    let mut f = Fixture::new();
    f.activate();
    let id = f.queue("renamed");
    let candidate = f.store.prepare_configuration_proposal(&id).unwrap();
    let before = f.store.configuration_log_head().unwrap();
    f.store.db.execute_batch("CREATE TRIGGER fail_receipt AFTER INSERT ON peer_configuration_history BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(f.store.accept_configuration_commit(&candidate).is_err());
    assert_eq!(f.store.configuration_log_head().unwrap(), before);
    let result: Option<Vec<u8>> = f
        .store
        .db
        .query_row(
            "SELECT result FROM configuration_edits WHERE id=?1",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(result.is_none());
    f = f.restart();
    assert_eq!(
        f.store.prepare_configuration_proposal(&id).unwrap(),
        candidate
    );
    f.store
        .db
        .execute_batch("DROP TRIGGER fail_receipt")
        .unwrap();
    let receipt = f.store.accept_configuration_commit(&candidate).unwrap();
    assert_eq!(
        f.store.accept_configuration_commit(&candidate).unwrap(),
        receipt
    );
    assert_eq!(
        config::load_for_runtime(f.home.path()).unwrap().node.name,
        "renamed"
    );
    assert!(f.store.prepare_configuration_proposal(&id).is_err());
}

#[test]
fn conflicting_write_rebases_intent_and_revocation_prevents_rebase() {
    let mut f = Fixture::new();
    f.activate();
    let id = f.queue("renamed");
    let first = f.store.prepare_configuration_proposal(&id).unwrap();
    f.store
        .accept_configuration_commit(&f.competing(false))
        .unwrap();
    f = f.restart();
    let rebased = f.store.prepare_configuration_proposal(&id).unwrap();
    assert_eq!(first.header.operation, rebased.header.operation);
    assert_eq!(first.header.intent, rebased.header.intent);
    assert_eq!(
        first.header.previous.sequence + 1,
        rebased.header.previous.sequence
    );
    f.store.accept_configuration_commit(&rebased).unwrap();
    let config = config::load_for_runtime(f.home.path()).unwrap();
    assert_eq!(config.cluster.name, "concurrent cluster name");
    assert_eq!(config.node.name, "renamed");
    let id = f.queue("forbidden");
    f.store.prepare_configuration_proposal(&id).unwrap();
    f.store
        .accept_configuration_commit(&f.competing(true))
        .unwrap();
    assert!(f.store.prepare_configuration_proposal(&id).is_err());
}

#[test]
fn missing_log_checkpoint_cannot_reinitialize_active_peer_authority() {
    let mut f = Fixture::new();
    f.activate();
    f.store
        .db
        .execute("DELETE FROM peer_configuration", [])
        .unwrap();
    drop(f.store);
    assert!(Store::open(f.home.path()).is_err());
}

#[test]
fn later_commit_replaces_the_same_setting_after_rebase() {
    let mut f = Fixture::new();
    f.activate();
    let id = uuid::Uuid::new_v4().to_string();
    let cfg = config::load_for_runtime(f.home.path()).unwrap();
    f.store
        .execute(Request::Owner {
            credential: f.credential.clone(),
            action: OwnerOp::Configure {
                request_id: id.clone(),
                edit: ConfigurationEdit::Replace {
                    cluster_name: "last committed name".into(),
                    node_name: cfg.node.name,
                    policy: cfg.policy,
                },
            },
        })
        .unwrap();
    let first = f.store.prepare_configuration_proposal(&id).unwrap();
    f.store
        .accept_configuration_commit(&f.competing(false))
        .unwrap();
    assert_eq!(
        config::load_for_runtime(f.home.path())
            .unwrap()
            .cluster
            .name,
        "concurrent cluster name"
    );
    let rebased = f.store.prepare_configuration_proposal(&id).unwrap();
    assert_eq!(first.header.operation, rebased.header.operation);
    assert_eq!(first.header.intent, rebased.header.intent);
    f.store.accept_configuration_commit(&rebased).unwrap();
    assert_eq!(
        config::load_for_runtime(f.home.path())
            .unwrap()
            .cluster
            .name,
        "last committed name"
    );
}

fn connected_home(
    node: &gent_crypto::NodeIdentity,
    state: &VerifiedState,
    commit: Option<&Commit>,
) -> (tempfile::TempDir, Store) {
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    runtime::install_joined_checkpoint(home.path(), node, state, commit, b"[]").unwrap();
    let mut cfg = config::load(home.path()).unwrap();
    cfg.relay = Some(config::RelayConfig {
        endpoint: "http://127.0.0.1:1".into(),
        credential_file: "relay.key".into(),
    });
    config::write_private(
        &home.path().join("relay.key"),
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();
    config::save(home.path(), &cfg).unwrap();
    crate::entitlements::grant_test(home.path(), &cfg);
    let store = Store::open(home.path()).unwrap();
    (home, store)
}

fn configure(store: &mut Store, edit: ConfigurationEdit) -> Commit {
    let id = uuid::Uuid::new_v4().to_string();
    let credential = config::read_private(&store.home.join("owner.key")).unwrap();
    store
        .execute(Request::Owner {
            credential,
            action: OwnerOp::Configure {
                request_id: id.clone(),
                edit,
            },
        })
        .unwrap();
    let commit = store.prepare_configuration_proposal(&id).unwrap();
    store.accept_configuration_commit(&commit).unwrap();
    commit
}

#[test]
fn member_rename_updates_only_the_signed_hosted_member() {
    let mut f = Fixture::new();
    f.activate();
    configure(
        &mut f.store,
        ConfigurationEdit::HostNode {
            node_id: f.peer.id().into(),
            parent: config::load(f.home.path()).unwrap().node.id,
        },
    );
    let before = f.store.identity.state(&f.store.db).unwrap();
    let mut expected = before.state().nodes.clone();
    expected.get_mut(f.peer.id()).unwrap().name = "Hosted tablet".into();
    configure(
        &mut f.store,
        ConfigurationEdit::RenameMember {
            node_id: f.peer.id().into(),
            name: "Hosted tablet".into(),
        },
    );
    let after = f.store.identity.state(&f.store.db).unwrap();
    assert_eq!(after.state().nodes, expected);
    assert_eq!(json!(after.state().policy), json!(before.state().policy));
    assert_eq!(after.state().name, before.state().name);
}

#[test]
fn offline_member_catches_migration_then_administers_and_enrolls_without_creator() {
    let mut f = Fixture::new();
    let state = f.store.identity.state(&f.store.db).unwrap();
    let (_peer_home, mut peer) = connected_home(&f.peer, &state, None);
    f.store
        .execute(Request::Owner {
            credential: f.credential.clone(),
            action: OwnerOp::Configure {
                request_id: uuid::Uuid::new_v4().to_string(),
                edit: ConfigurationEdit::RenameNode {
                    name: "old creator".into(),
                },
            },
        })
        .unwrap();
    f.activate();
    let migration = f
        .store
        .configuration_record(f.store.configuration_log_head().unwrap().unwrap().sequence)
        .unwrap()
        .unwrap();
    let creator = f.store.identity.node.id().to_owned();
    peer.accept_configuration_commit(&migration).unwrap();
    drop(f.store);
    configure(
        &mut peer,
        ConfigurationEdit::RenameNode {
            name: "survivor".into(),
        },
    );
    let state = peer.identity.state(&peer.db).unwrap();
    let node = gent_crypto::NodeIdentity::generate().unwrap();
    let request = node
        .request_enrollment(state.anchor(), state.checkpoint(), "third", now() as u64)
        .unwrap();
    let commit = configure(
        &mut peer,
        ConfigurationEdit::EnrollNode {
            request: STANDARD.encode(request.encode().unwrap()),
            can_configure: true,
            invitation: None,
        },
    );
    let (_third_home, mut third) = connected_home(
        &node,
        &peer.identity.state(&peer.db).unwrap(),
        Some(&commit),
    );
    let removal = configure(
        &mut peer,
        ConfigurationEdit::RemoveNode {
            node_id: creator.clone(),
        },
    );
    third.accept_configuration_commit(&removal).unwrap();
    assert!(
        peer.identity
            .state(&peer.db)
            .unwrap()
            .state()
            .retired_nodes
            .contains(&creator)
    );
    assert_eq!(
        peer.identity.state(&peer.db).unwrap().checkpoint(),
        third.identity.state(&third.db).unwrap().checkpoint()
    );
    // No preexisting data link or configuration stream connects these nodes.
    for _ in 0..8 {
        peer.mesh_tick().unwrap();
        third.mesh_tick().unwrap();
        for (from, to) in [(&peer, &third), (&third, &peer)] {
            for packet in from.direct_mesh_outgoing().unwrap() {
                let receipt = to
                    .receive_direct_mesh(from.identity.node.id(), &packet)
                    .unwrap();
                from.direct_mesh_finished(&receipt).unwrap();
                to.direct_mesh_receipt_published(packet.group()).unwrap();
            }
        }
    }
    for store in [&peer, &third] {
        assert_eq!(
            store
                .db
                .query_row("SELECT COUNT(*) FROM network_links", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
}

#[test]
fn migration_preserves_a_lost_legacy_decision_and_rejects_tampered_archive() {
    let mut f = Fixture::new();
    let base = f.store.identity.state(&f.store.db).unwrap();
    let (_home, mut restored) = connected_home(&f.store.identity.node, &base, None);
    let id = uuid::Uuid::new_v4().to_string();
    let edit = ConfigurationEdit::CreateGroup {
        name: "once".into(),
    };
    let origin = f.store.identity.node.id().to_owned();
    let tx = restored.db.unchecked_transaction().unwrap();
    configuration::storage::insert(
        &tx,
        &origin,
        &id,
        &origin,
        &configuration::fingerprint(&edit).unwrap(),
        &edit,
        None,
    )
    .unwrap();
    configuration::pending::retain(&tx, &origin, &id, &edit).unwrap();
    tx.commit().unwrap();
    let result = f
        .store
        .execute(Request::Owner {
            credential: f.credential.clone(),
            action: OwnerOp::Configure {
                request_id: id.clone(),
                edit,
            },
        })
        .unwrap();
    f.activate();
    let commit = f
        .store
        .configuration_record(f.store.configuration_log_head().unwrap().unwrap().sequence)
        .unwrap()
        .unwrap();
    restored.accept_configuration_commit(&commit).unwrap();
    let state = restored.identity.state(&restored.db).unwrap();
    let retry = restored
        .network_session(&restored.db, state)
        .configuration_status(&id)
        .unwrap();
    assert_eq!(retry["revision"], result["revision"]);
    assert_eq!(retry["state"], "applied");
    assert!(
        restored
            .pending_configuration_proposals()
            .unwrap()
            .is_empty()
    );
    let mut forged = commit;
    forged.header.intent[0] ^= 1;
    assert!(restored.accept_configuration_commit(&forged).is_err());
}

#[test]
#[ignore = "requires GENT_TEST_LEGACY_BINARY pointing to the released legacy CLI"]
fn released_binary_refuses_the_migration_identity_fence() {
    let mut f = Fixture::new();
    f.store.prepare_configuration_log(&f.credential).unwrap();
    let before = f
        .store
        .identity
        .state(&f.store.db)
        .unwrap()
        .checkpoint()
        .clone();
    let binary = std::env::var("GENT_TEST_LEGACY_BINARY").expect("legacy binary path");
    let output = tempfile::NamedTempFile::new().unwrap();
    let mut child = std::process::Command::new(binary)
        .arg("--home")
        .arg(f.home.path())
        .args(["daemon", "run"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(output.reopen().unwrap())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("legacy executable did not reject the fenced identity");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert!(!status.success());
    assert!(
        std::fs::read_to_string(output.path())
            .unwrap()
            .contains("unsupported signing key file")
    );
    assert_eq!(
        f.store.identity.state(&f.store.db).unwrap().checkpoint(),
        &before
    );
}

#[test]
fn loss_of_pro_invalidates_cached_hosting_proposal_and_allows_removal() {
    let mut f = Fixture::new();
    f.activate();
    let id = uuid::Uuid::new_v4().to_string();
    let host = ConfigurationEdit::HostNode {
        node_id: f.peer.id().into(),
        parent: f.store.config.node.id.clone(),
    };
    let submit = |id: &str| Request::Owner {
        credential: f.credential.clone(),
        action: OwnerOp::Configure {
            request_id: id.into(),
            edit: host.clone(),
        },
    };
    f.store.execute(submit(&id)).unwrap();
    f.store.prepare_configuration_proposal(&id).unwrap();
    std::fs::remove_file(f.home.path().join("test-entitlement")).unwrap();
    assert!(
        f.store
            .execute(submit(&uuid::Uuid::new_v4().to_string()))
            .unwrap_err()
            .to_string()
            .contains("Gent Pro")
    );
    assert!(f.store.prepare_configuration_proposal(&id).is_err());
    let member = f.peer.id().to_owned();
    configure(
        &mut f.store,
        ConfigurationEdit::RemoveNode {
            node_id: member.clone(),
        },
    );
    assert!(
        f.store
            .identity
            .state(&f.store.db)
            .unwrap()
            .state()
            .retired_nodes
            .contains(&member)
    );
}
