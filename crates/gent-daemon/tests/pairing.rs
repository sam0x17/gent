use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gent_daemon::{
    config,
    pairing::{self, Options, Peer, Snapshot},
    store::Store,
};
use gent_protocol::{OwnerOp, PairingOp, Policy, Request, Response};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};

struct Owner {
    home: tempfile::TempDir,
    store: Store,
    credential: String,
    cluster: String,
    fail_after: Option<usize>,
    change_before: Option<usize>,
    calls: usize,
    corrupt_grant: bool,
}
impl Owner {
    fn new() -> Self {
        Self::with_cluster(None)
    }
    fn with_cluster(cluster: Option<&str>) -> Self {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut cfg = config::initialize(home.path(), "pairing").unwrap();
        if let Some(cluster) = cluster {
            cfg.cluster.id = cluster.into();
        }
        cfg.relay = Some(config::RelayConfig {
            endpoint: "https://relay.example".into(),
            credential_file: "relay.key".into(),
        });
        config::write_private(&home.path().join("relay.key"), config::secret().as_bytes()).unwrap();
        config::save(home.path(), &cfg).unwrap();
        let store = Store::open(home.path()).unwrap();
        let credential = config::read_private(&home.path().join("owner.key")).unwrap();
        Self {
            home,
            store,
            credential,
            cluster: cfg.cluster.id,
            fail_after: None,
            change_before: None,
            calls: 0,
            corrupt_grant: false,
        }
    }
    fn owner(&mut self, action: OwnerOp) -> Result<Value> {
        match self.store.handle(Request::Owner {
            credential: self.credential.clone(),
            action,
        }) {
            Response::Ok(value) => Ok(value),
            Response::Error(error) => bail!(error),
        }
    }
    fn reopen(&mut self) {
        self.store = Store::open(self.home.path()).unwrap();
    }
}
impl Peer for Owner {
    async fn call(&mut self, action: PairingOp) -> Result<Value> {
        self.calls += 1;
        if self.change_before == Some(self.calls) {
            self.owner(OwnerOp::SetPolicy {
                policy: Policy::default(),
            })?;
        }
        let is_configuration = matches!(action, PairingOp::Configuration { .. });
        let mut value = self.owner(OwnerOp::Pair {
            cluster_id: self.cluster.clone(),
            action,
        })?;
        if self.corrupt_grant && is_configuration {
            let mut bytes = STANDARD.decode(value["grant"].as_str().unwrap())?;
            let index = bytes.len() / 2;
            bytes[index] ^= 1;
            value["grant"] = STANDARD.encode(bytes).into();
        }
        if self.fail_after == Some(self.calls) {
            bail!("lost SSH reply after commit");
        }
        Ok(value)
    }
}
async fn join(home: &Path, owner: &mut Owner) -> Result<Value> {
    let cluster = owner.cluster.clone();
    pairing::join(
        home,
        Options {
            cluster: &cluster,
            name: "new-node",
            relay_endpoint: None,
        },
        owner,
    )
    .await
}

#[tokio::test]
async fn joined_node_keeps_its_keys_and_imports_only_development_relay_access() {
    let mut owner = Owner::new();
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("joined");
    let result = join(&home, &mut owner).await.unwrap();
    assert_eq!(result["joined"], true);
    assert_eq!(result["configuration_relay"], true);
    let cfg = config::load(&home).unwrap();
    assert_eq!(cfg.node.name, "new-node");
    assert_eq!(cfg.cluster.id, owner.cluster);
    assert_eq!(
        config::read_private(&home.join("relay.key")).unwrap(),
        config::read_private(&owner.home.path().join("relay.key")).unwrap()
    );
    assert_ne!(
        config::read_private(&home.join("owner.key")).unwrap(),
        owner.credential
    );
    let identity = fs::read(home.join("identity.key")).unwrap();
    assert_eq!(&identity[..8], b"GENTKEY2");
    let owner_key = fs::read(owner.home.path().join("identity.key")).unwrap();
    assert!(
        !identity
            .windows(32)
            .any(|bytes| bytes == &owner_key[40..72])
    );
    let mut joined = Store::open(&home).unwrap();
    assert!(matches!(
        joined.handle(Request::Owner {
            credential: config::read_private(&home.join("owner.key")).unwrap(),
            action: OwnerOp::Pair {
                cluster_id: owner.cluster.clone(),
                action: PairingOp::Snapshot
            }
        }),
        Response::Error(_)
    ));
    assert!(!home.with_file_name("joined.joining").exists());
    assert_eq!(
        owner
            .owner(OwnerOp::Nodes)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let calls = owner.calls;
    assert_eq!(
        join(&home, &mut owner).await.unwrap()["already_joined"],
        true
    );
    assert_eq!(owner.calls, calls);
}

#[tokio::test]
async fn lost_pairing_replies_resume_without_duplicate_members_or_streams() {
    for interrupted in 1..=5 {
        let mut owner = Owner::new();
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("joined");
        owner.fail_after = Some(interrupted);
        assert!(join(&home, &mut owner).await.is_err());
        assert!(!config::path(&home).exists());
        let before = fs::read(home.with_file_name("joined.joining").join("join.key")).unwrap();
        owner.fail_after = None;
        owner.reopen();
        join(&home, &mut owner).await.unwrap();
        let after = fs::read(home.join("identity.key")).unwrap();
        assert_eq!(&before[8..40], &after[8..40]);
        assert_eq!(
            owner
                .owner(OwnerOp::Nodes)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let db = rusqlite::Connection::open(owner.home.path().join("state.sqlite3")).unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM configuration_streams", [], |r| r
                .get::<_, usize>(0))
                .unwrap(),
            1
        );
    }
}

#[tokio::test]
async fn concurrent_owner_edits_are_verified_before_joining_the_stream() {
    let mut owner = Owner::new();
    owner.change_before = Some(4); // Between key-package creation and the stream grant.
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("joined");
    join(&home, &mut owner).await.unwrap();
    assert_eq!(config::load(&home).unwrap().applied_revision, Some(2));
}

#[tokio::test]
async fn stale_enrollment_retries_preserve_identity_and_existing_directories() {
    let mut owner = Owner::new();
    owner.change_before = Some(2); // Enrollment request no longer has the owner's head.
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("joined");
    assert!(join(&home, &mut owner).await.is_err());
    let seed = fs::read(home.with_file_name("joined.joining").join("join.key")).unwrap();
    owner.change_before = None;
    join(&home, &mut owner).await.unwrap();
    assert_eq!(
        &seed[8..40],
        &fs::read(home.join("identity.key")).unwrap()[8..40]
    );
    let existing = temp.path().join("unrelated");
    config::private_dir(&existing).unwrap();
    fs::write(existing.join("keep"), "untouched").unwrap();
    assert!(join(&existing, &mut owner).await.is_err());
    assert_eq!(
        fs::read_to_string(existing.join("keep")).unwrap(),
        "untouched"
    );
}

#[tokio::test]
async fn tampered_grants_and_missing_or_shared_pending_keys_fail_closed() {
    let mut owner = Owner::new();
    owner.corrupt_grant = true;
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("joined");
    assert!(join(&home, &mut owner).await.is_err());
    assert!(!config::path(&home).exists());
    let pending = home.with_file_name("joined.joining");
    let key = pending.join("join.key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(join(&home, &mut owner).await.is_err());
    fs::remove_file(&key).unwrap();
    assert!(join(&home, &mut owner).await.is_err());
    symlink(temp.path().join("nonexistent"), &key).unwrap();
    assert!(join(&home, &mut owner).await.is_err());
    assert!(!temp.path().join("nonexistent").exists());
}

#[tokio::test]
async fn resumed_pairing_rejects_a_valid_snapshot_under_a_replaced_owner_key() {
    let mut owner = Owner::new();
    owner.fail_after = Some(2);
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("joined");
    assert!(join(&home, &mut owner).await.is_err());
    let mut replacement = Owner::with_cluster(Some(&owner.cluster));
    let error = join(&home, &mut replacement).await.unwrap_err();
    assert!(error.to_string().contains("authority changed"));
    assert_eq!(replacement.calls, 1);
    assert_eq!(
        replacement
            .owner(OwnerOp::Nodes)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!config::path(&home).exists());
}

#[tokio::test]
async fn a_stale_unconsumed_stream_grant_gets_a_new_package_without_replacing_node_keys() {
    let mut owner = Owner::new();
    owner.fail_after = Some(4);
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("joined");
    assert!(join(&home, &mut owner).await.is_err());
    let dir = home.with_file_name("joined.joining");
    let bytes = fs::read(dir.join("join.key")).unwrap();
    let seed: Value = serde_json::from_slice(&bytes[40..]).unwrap();
    let node = gent_crypto::NodeIdentity::from_secret_bytes(
        seed["node"].as_str().unwrap(),
        bytes[8..40].try_into().unwrap(),
    )
    .unwrap();
    owner
        .owner(OwnerOp::SetPolicy {
            policy: Policy::default(),
        })
        .unwrap();
    owner.fail_after = None;
    let value = owner
        .owner(OwnerOp::Pair {
            cluster_id: owner.cluster.clone(),
            action: PairingOp::Snapshot,
        })
        .unwrap();
    let snapshot: Snapshot = serde_json::from_value(value).unwrap();
    gent_daemon::encrypted::ordered::OrderedEndpoint::open_runtime(&dir.join("node"), &node)
        .unwrap()
        .apply_authority(&[gent_crypto::SignedState::decode(
            &STANDARD.decode(snapshot.state).unwrap(),
        )
        .unwrap()])
        .unwrap();
    join(&home, &mut owner).await.unwrap();
    assert_eq!(
        &bytes[8..40],
        &fs::read(home.join("identity.key")).unwrap()[8..40]
    );
    let db = rusqlite::Connection::open(owner.home.path().join("state.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM configuration_streams", [], |r| r
            .get::<_, usize>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        owner
            .owner(OwnerOp::Nodes)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn pairing_requires_owner_authority_exact_cluster_and_checkpoint() {
    let mut owner = Owner::new();
    let response = owner.store.handle(Request::Owner {
        credential: config::secret(),
        action: OwnerOp::Pair {
            cluster_id: owner.cluster.clone(),
            action: PairingOp::Snapshot,
        },
    });
    assert!(matches!(response, Response::Error(_)));
    assert!(
        owner
            .owner(OwnerOp::Pair {
                cluster_id: uuid::Uuid::new_v4().to_string(),
                action: PairingOp::Snapshot
            })
            .is_err()
    );
    let value = owner
        .owner(OwnerOp::Pair {
            cluster_id: owner.cluster.clone(),
            action: PairingOp::Snapshot,
        })
        .unwrap();
    let snapshot: Snapshot = serde_json::from_value(value).unwrap();
    assert!(
        owner
            .owner(OwnerOp::Pair {
                cluster_id: owner.cluster.clone(),
                action: PairingOp::History {
                    revision: snapshot.checkpoint.revision,
                    digest: [0; 32]
                }
            })
            .is_err()
    );
    let db = rusqlite::Connection::open(owner.home.path().join("state.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM authority_history", [], |r| r
            .get::<_, usize>(0))
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn joining_without_a_configuration_transport_does_not_enroll_a_disconnected_node() {
    let mut owner = Owner::new();
    let mut cfg = config::load(owner.home.path()).unwrap();
    cfg.relay = None;
    config::save(owner.home.path(), &cfg).unwrap();
    owner.reopen();
    let temp = tempfile::tempdir().unwrap();
    let error = join(&temp.path().join("node"), &mut owner)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no configuration relay"));
    assert_eq!(owner.calls, 1);
    assert_eq!(
        owner
            .owner(OwnerOp::Nodes)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
