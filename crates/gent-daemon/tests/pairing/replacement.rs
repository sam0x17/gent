use super::*;
use gent_crypto::{NodeIdentity, ReplacedNode, SignedEnrollment, VerifiedState};
use gent_daemon::store::now;
use serde_json::json;

async fn replace(home: &Path, owner: &mut Owner, target: Option<&str>) -> Result<Value> {
    let cluster = owner.cluster.clone();
    pairing::join(
        home,
        Options {
            cluster: &cluster,
            name: "replacement",
            relay_endpoint: None,
            replace_node: target,
        },
        owner,
    )
    .await
}

fn state(owner: &mut Owner) -> VerifiedState {
    let value = owner
        .owner(OwnerOp::Pair {
            cluster_id: owner.cluster.clone(),
            action: PairingOp::Snapshot,
        })
        .unwrap();
    let snapshot: Snapshot = serde_json::from_value(value).unwrap();
    VerifiedState::restore(
        snapshot.anchor,
        snapshot.checkpoint,
        gent_crypto::SignedState::decode(&STANDARD.decode(snapshot.state).unwrap()).unwrap(),
    )
    .unwrap()
}

fn enroll(owner: &mut Owner, request: &SignedEnrollment) -> Result<Value> {
    owner.owner(OwnerOp::Pair {
        cluster_id: owner.cluster.clone(),
        action: PairingOp::Enroll {
            request: STANDARD.encode(request.encode()?),
        },
    })
}

fn request(node: &NodeIdentity, target: &ReplacedNode, state: &VerifiedState) -> SignedEnrollment {
    node.request_replacement(
        state.anchor(),
        state.checkpoint(),
        "replacement",
        target.clone(),
        now() as u64,
    )
    .unwrap()
}

async fn old_node(owner: &mut Owner, home: &Path) -> ReplacedNode {
    join(home, owner).await.unwrap();
    let id = config::load(home).unwrap().node.id;
    ReplacedNode {
        signing_key: state(owner).state().nodes[&id].signing_key,
        id,
    }
}

fn count(db: &rusqlite::Connection, table: &str) -> usize {
    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[tokio::test]
async fn replacement_retries_every_pairing_reply_with_one_retirement_and_fresh_streams() {
    for interrupted in 1..=8 {
        let mut owner = Owner::new();
        let root = tempfile::tempdir().unwrap();
        let old = root.path().join("old");
        let target = old_node(&mut owner, &old).await;
        let before = state(&mut owner);
        let home = root.path().join("fresh");
        owner.calls = 0;
        owner.fail_after = Some(interrupted);
        assert!(replace(&home, &mut owner, Some(&target.id)).await.is_err());
        let pending = config::pending_join(&home).unwrap();
        let seed = fs::read(pending.join("join.key")).unwrap();
        let calls = owner.calls;
        assert!(replace(&home, &mut owner, None).await.is_err());
        assert!(
            replace(&home, &mut owner, Some(&uuid::Uuid::new_v4().to_string()))
                .await
                .is_err()
        );
        assert_eq!(
            owner.calls, calls,
            "changed intent must fail before contacting owner"
        );
        owner.fail_after = None;
        owner.reopen();
        replace(&home, &mut owner, Some(&target.id)).await.unwrap();
        assert_eq!(
            &seed[8..40],
            &fs::read(home.join("identity.key")).unwrap()[8..40]
        );
        assert_ne!(
            &seed[8..40],
            &fs::read(old.join("identity.key")).unwrap()[8..40]
        );
        let new = config::load(&home).unwrap().node.id;
        assert_ne!(target.id, new);
        let current = state(&mut owner);
        assert_eq!(
            current.checkpoint().revision,
            before.checkpoint().revision + 1
        );
        assert_eq!(current.state().nodes.len(), 2);
        assert!(current.state().retired_nodes.contains(&target.id));
        assert!(current.state().retired_keys.contains(&target.signing_key));
        assert_eq!(
            pairing::installed_replacement(&home).unwrap(),
            Some(target.clone())
        );
        let db = rusqlite::Connection::open(owner.home.path().join("state.sqlite3")).unwrap();
        assert_eq!(count(&db, "node_removals"), 1);
        assert_eq!(count(&db, "configuration_streams"), 2);
        let removal = owner
            .owner(OwnerOp::RemoveNode {
                node_id: target.id.clone(),
            })
            .unwrap();
        assert_eq!(removal["replacement"]["node_id"], new);
        assert_eq!(removal["revision"], current.checkpoint().revision);
        let links: Vec<(String, Vec<u8>, Vec<u8>)> = db
            .prepare("SELECT peer,outgoing,incoming FROM network_links")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let previous = links.iter().find(|r| r.0 == target.id).unwrap();
        let replacement = links.iter().find(|r| r.0 == new).unwrap();
        assert_ne!(previous.1, replacement.1);
        assert_ne!(previous.2, replacement.2);
        drop(Store::open(&home).unwrap());
        owner.reopen();
        replace(&home, &mut owner, Some(&target.id)).await.unwrap();
        assert_eq!(state(&mut owner).checkpoint(), current.checkpoint());
        assert!(replace(&home, &mut owner, Some(&new)).await.is_err());
    }
}

#[tokio::test]
async fn replacement_rollback_and_competing_attempts_preserve_the_committed_identity() {
    let mut owner = Owner::new();
    let root = tempfile::tempdir().unwrap();
    let target = old_node(&mut owner, &root.path().join("old")).await;
    let before = state(&mut owner);
    let new = NodeIdentity::generate().unwrap();
    let signed = request(&new, &target, &before);
    let db = rusqlite::Connection::open(owner.home.path().join("state.sqlite3")).unwrap();
    let counts = [
        count(&db, "authority_history"),
        count(&db, "authority_join_pins"),
    ];
    db.execute_batch("CREATE TRIGGER replacement_failure BEFORE INSERT ON node_removals BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(enroll(&mut owner, &signed).is_err());
    assert_eq!(state(&mut owner).checkpoint(), before.checkpoint());
    assert_eq!(
        [
            count(&db, "authority_history"),
            count(&db, "authority_join_pins")
        ],
        counts
    );
    assert_eq!(count(&db, "node_removals"), 0);
    db.execute_batch("DROP TRIGGER replacement_failure;")
        .unwrap();
    let first = enroll(&mut owner, &signed).unwrap();
    owner.reopen();
    assert_eq!(
        enroll(&mut owner, &signed).unwrap()["checkpoint"],
        first["checkpoint"]
    );
    let current = state(&mut owner);
    let competitor = NodeIdentity::generate().unwrap();
    assert!(enroll(&mut owner, &request(&competitor, &target, &current)).is_err());
    let mut wrong_key = target.clone();
    wrong_key.signing_key = competitor.public_key();
    assert!(enroll(&mut owner, &request(&new, &wrong_key, &current)).is_err());
    assert_eq!(state(&mut owner).checkpoint(), current.checkpoint());
    owner
        .owner(OwnerOp::RemoveNode {
            node_id: new.id().into(),
        })
        .unwrap();
    assert!(
        enroll(&mut owner, &signed).is_err(),
        "a later removal cannot be undone by retry"
    );
}

#[tokio::test]
async fn replacement_refuses_owner_existing_node_and_guarded_backup_targets() {
    let mut owner = Owner::new();
    let root = tempfile::tempdir().unwrap();
    let before = state(&mut owner);
    let id = config::load(owner.home.path()).unwrap().node.id;
    let target = ReplacedNode {
        id: id.clone(),
        signing_key: before.state().nodes[&id].signing_key,
    };
    let new = NodeIdentity::generate().unwrap();
    assert!(enroll(&mut owner, &request(&new, &target, &before)).is_err());
    assert!(
        replace(&root.path().join("fresh"), &mut owner, Some(&id))
            .await
            .is_err()
    );
    assert_eq!(state(&mut owner).checkpoint(), before.checkpoint());
    let existing = root.path().join("existing");
    let old = old_node(&mut owner, &existing).await;
    let current = state(&mut owner);
    assert!(replace(&existing, &mut owner, Some(&old.id)).await.is_err());
    let backup = root.path().join("backup");
    config::private_dir(&backup).unwrap();
    fs::write(backup.join(gent_daemon::recovery::MARKER), b"").unwrap();
    assert!(
        replace(&backup.join("child"), &mut owner, Some(&old.id))
            .await
            .is_err()
    );
    assert!(!backup.join("child").exists());
    assert_eq!(state(&mut owner).checkpoint(), current.checkpoint());
}

#[tokio::test]
async fn replacement_publication_retries_offline_and_pins_local_retirement() {
    let mut owner = Owner::new();
    let root = tempfile::tempdir().unwrap();
    let target = old_node(&mut owner, &root.path().join("old")).await;
    let home = root.path().join("fresh");
    owner.publication_conflict = Some(home.join("owner.key"));
    assert!(replace(&home, &mut owner, Some(&target.id)).await.is_err());
    let calls = owner.calls;
    fs::remove_file(home.join("owner.key")).unwrap();
    replace(&home, &mut owner, Some(&target.id)).await.unwrap();
    assert_eq!(owner.calls, calls);
    drop(Store::open(&home).unwrap());
    let path = home.join("node-replacement.json");
    let original = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(Store::open(&home).is_err());
    config::write_private(&path, &original).unwrap();
    let cfg = config::load(&home).unwrap();
    let mut changed = cfg.clone();
    changed.extra.remove("node_replacement");
    config::save(&home, &changed).unwrap();
    assert!(Store::open(&home).is_err());
    config::save(&home, &cfg).unwrap();
    let mut forged: Value = serde_json::from_slice(&original).unwrap();
    forged["key"] = json!(NodeIdentity::generate().unwrap().public_key());
    let forged = serde_json::to_vec(&forged).unwrap();
    config::write_private(&path, &forged).unwrap();
    assert!(Store::open(&home).is_err());
    use sha2::{Digest, Sha256};
    changed.extra.insert(
        "node_replacement".into(),
        toml::Value::String(format!("{:x}", Sha256::digest(&forged))),
    );
    config::save(&home, &changed).unwrap();
    assert!(
        Store::open(&home).is_err(),
        "a matching file hash still needs the actual signing identity"
    );
    config::write_private(&path, &original).unwrap();
    config::save(&home, &cfg).unwrap();
    drop(Store::open(&home).unwrap());
}

#[tokio::test]
async fn pending_replacement_refuses_lost_pins_and_recovers_record_before_config_write() {
    let mut owner = Owner::new();
    let root = tempfile::tempdir().unwrap();
    let target = old_node(&mut owner, &root.path().join("old")).await;
    let home = root.path().join("fresh");
    owner.calls = 0;
    owner.fail_after = Some(3);
    assert!(replace(&home, &mut owner, Some(&target.id)).await.is_err());
    owner.fail_after = None;
    let pending = config::pending_join(&home).unwrap();
    let key = pending.join("join.key");
    let seed = fs::read(&key).unwrap();
    let mut changed: Value = serde_json::from_slice(&seed[40..]).unwrap();
    changed["replacement"] = Value::Null;
    let mut changed_bytes = seed[..40].to_vec();
    changed_bytes.extend(serde_json::to_vec(&changed).unwrap());
    config::write_private(&key, &changed_bytes).unwrap();
    assert!(replace(&home, &mut owner, Some(&target.id)).await.is_err());
    config::write_private(&key, &seed).unwrap();
    let runtime = pending.join("node");
    let path = runtime.join("node-replacement.json");
    let record = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(replace(&home, &mut owner, Some(&target.id)).await.is_err());
    config::write_private(&path, &record).unwrap();
    let mut cfg = config::load(&runtime).unwrap();
    cfg.extra.remove("node_replacement");
    config::save(&runtime, &cfg).unwrap();
    replace(&home, &mut owner, Some(&target.id)).await.unwrap();
    assert_eq!(
        fs::read(home.join("node-replacement.json")).unwrap(),
        record
    );
    drop(Store::open(&home).unwrap());
}
