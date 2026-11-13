use super::*;
use gent_crypto::NodeIdentity;
use gent_daemon::store::{Store, invitations::Action};
use gent_protocol::PairingOp;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

fn fixture() -> (tempfile::TempDir, Store, String) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let home = root.path().join("owner");
    let mut cfg = config::initialize(&home, "owner").unwrap();
    cfg.cluster.local_only = false;
    cfg.service = Some(config::ServiceConfig {
        origin: "https://account.example/".into(),
        account_id: Uuid::new_v4().to_string(),
    });
    cfg.relay = Some(config::RelayConfig {
        endpoint: "https://relay.example/".into(),
        credential_file: "relay.key".into(),
    });
    config::save(&home, &cfg).unwrap();
    let owner = config::read_private(&home.join("owner.key")).unwrap();
    (root, Store::open(&home).unwrap(), owner)
}
fn issue(store: &mut Store, credential: &str) -> Invitation {
    Invitation::decode(
        &store
            .create_invitation(credential, &Uuid::now_v7().to_string(), true, None)
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn process_restart_preserves_uncertain_inputs_ids_and_completion_receipt() {
    let (root, mut store, credential) = fixture();
    let invitation = issue(&mut store, &credential);
    let home = root.path().join("joined");
    let node = NodeIdentity::generate().unwrap();
    let mut journal =
        journal::Journal::open(&home, invitation.offer(), "laptop", "session", false).unwrap();
    journal.bind(&node, "laptop").unwrap();
    let first = journal
        .reserve(Action::Pair {
            action: PairingOp::Enroll {
                request: "exact-signed-input".into(),
            },
        })
        .unwrap();
    let wire = first.encode().unwrap();
    let bearer = journal.bearer().to_string();
    drop(journal);
    let mut journal =
        journal::Journal::open(&home, invitation.offer(), "laptop", "session", false).unwrap();
    assert_eq!(journal.bearer(), bearer);
    assert_eq!(*journal.pending().unwrap().encode().unwrap(), *wire);
    assert!(
        journal
            .reserve(Action::Pair {
                action: PairingOp::Snapshot
            })
            .is_err()
    );
    assert!(
        journal
            .bind(&NodeIdentity::generate().unwrap(), "laptop")
            .is_err()
    );
    journal.complete(&first, &json!({"ok":true})).unwrap();
    let finish = journal.reserve(Action::Finish).unwrap();
    drop(journal);
    let mut journal =
        journal::Journal::open(&home, invitation.offer(), "laptop", "session", false).unwrap();
    assert_eq!(journal.pending().unwrap().id, finish.id);
    assert!(
        journal
            .complete(&finish, &json!({"finished":true,"node":"foreign"}))
            .is_err()
    );
    let receipt =
        json!({"finished":true,"invitation":invitation.offer().offer.id,"node":node.id()});
    journal.complete(&finish, &receipt).unwrap();
    drop(journal);
    let journal =
        journal::Journal::open(&home, invitation.offer(), "laptop", "session", false).unwrap();
    assert_eq!(journal.receipt(), Some(&receipt));
    assert!(journal.pending().is_none());
}

#[test]
fn replacing_an_invitation_requires_explicit_continuation_and_preserves_pins() {
    let (root, mut store, credential) = fixture();
    let first = issue(&mut store, &credential);
    let next = issue(&mut store, &credential);
    let home = root.path().join("joined");
    let node = NodeIdentity::generate().unwrap();
    let mut journal =
        journal::Journal::open(&home, first.offer(), "laptop", "first-login", false).unwrap();
    journal.bind(&node, "laptop").unwrap();
    journal
        .reserve(Action::Pair {
            action: PairingOp::Snapshot,
        })
        .unwrap();
    drop(journal);
    assert!(journal::Journal::open(&home, first.offer(), "laptop", "new-login", true).is_err());
    assert!(journal::Journal::open(&home, next.offer(), "laptop", "new-login", false).is_err());
    let mut journal =
        journal::Journal::open(&home, next.offer(), "laptop", "new-login", true).unwrap();
    journal.bind(&node, "laptop").unwrap();
    assert!(journal.pending().is_none());
    assert_eq!(journal.node().unwrap().id, node.id());
    drop(journal);
    assert!(journal::Journal::open(&home, first.offer(), "laptop", "first-login", true).is_err());
    let (_foreign_root, mut foreign_store, foreign_credential) = fixture();
    let foreign = issue(&mut foreign_store, &foreign_credential);
    assert!(journal::Journal::open(&home, foreign.offer(), "laptop", "new-login", true).is_err());
}

#[test]
fn missing_corrupt_or_shared_join_files_cannot_reset_identity() {
    let (root, mut store, credential) = fixture();
    let invitation = issue(&mut store, &credential);
    let path = root.path().join("invite");
    config::write_private(&path, &invitation.encode().unwrap()).unwrap();
    assert!(decode_file(&path).is_ok());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(decode_file(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let linked = root.path().join("linked");
    symlink(&path, &linked).unwrap();
    assert!(decode_file(&linked).is_err());
    let home = root.path().join("joined");
    config::private_dir(&config::pending_join(&home).unwrap()).unwrap();
    assert!(journal::Journal::open(&home, invitation.offer(), "laptop", "session", false).is_err());
    fs::remove_dir(config::pending_join(&home).unwrap()).unwrap();
    let mut journal =
        journal::Journal::open(&home, invitation.offer(), "laptop", "session", false).unwrap();
    journal
        .reserve(Action::Pair {
            action: PairingOp::Snapshot,
        })
        .unwrap();
    drop(journal);
    let path = home.join("auth/invitation-join.json");
    let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    saved["operations"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap()["id"] = json!("invalid-fixture-secret");
    config::write_private(&path, &serde_json::to_vec(&saved).unwrap()).unwrap();
    let error = journal::Journal::open(&home, invitation.offer(), "laptop", "session", false)
        .err()
        .unwrap();
    assert!(!format!("{error:#}").contains("invalid-fixture-secret"));
}
