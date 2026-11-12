use gent_crypto::{NodeIdentity, OwnerKey};
use gent_daemon::replica::Replica;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

const NOW: u64 = 1_800_000_000;

fn private_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn restart_preserves_anchor_checkpoint_and_complete_history() {
    let home = private_tempdir();
    let owner = OwnerKey::generate().unwrap();
    let first = NodeIdentity::generate().unwrap();
    let genesis = owner.create_cluster("test", &first, "first", NOW).unwrap();
    let mut replica = Replica::open(home.path()).unwrap();
    replica.initialize(&genesis).unwrap();
    let node = NodeIdentity::generate().unwrap();
    let request = node
        .request_enrollment(genesis.anchor(), genesis.checkpoint(), "new", NOW)
        .unwrap();
    let next = genesis
        .enroll(&owner, &request, request.fingerprint().unwrap(), NOW)
        .unwrap();
    let accepted = replica.apply(genesis.checkpoint(), &[next], NOW).unwrap();
    drop(replica);
    let mut replica = Replica::open(home.path()).unwrap();
    assert!(replica.initialize(&genesis).is_err());
    let restored = replica.load().unwrap();
    assert_eq!(restored.anchor(), genesis.anchor());
    assert_eq!(restored.checkpoint(), accepted.checkpoint());
    assert!(
        restored
            .authorize_node(node.id(), &node.public_key(), NOW)
            .is_ok()
    );
    let mut follower = genesis.clone();
    follower
        .apply_chain(&replica.history(0, 100).unwrap(), NOW)
        .unwrap();
    assert_eq!(follower.checkpoint(), restored.checkpoint());
    assert_eq!(
        fs::metadata(home.path().join("authority.sqlite3"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
}

#[test]
fn stale_writers_and_invalid_suffix_cannot_partially_commit() {
    let home = private_tempdir();
    let owner = OwnerKey::generate().unwrap();
    let node = NodeIdentity::generate().unwrap();
    let genesis = owner.create_cluster("test", &node, "first", NOW).unwrap();
    let mut first = Replica::open(home.path()).unwrap();
    first.initialize(&genesis).unwrap();
    let mut second = Replica::open(home.path()).unwrap();
    let one = genesis.renew(&owner, NOW + 1).unwrap();
    let mut writer = genesis.clone();
    writer
        .apply_chain(std::slice::from_ref(&one), NOW + 1)
        .unwrap();
    let mut invalid = writer.renew(&owner, NOW + 2).unwrap();
    invalid.signature[0] ^= 1;
    assert!(
        first
            .apply(genesis.checkpoint(), &[one.clone(), invalid], NOW + 2)
            .is_err()
    );
    assert_eq!(first.load().unwrap().checkpoint(), genesis.checkpoint());
    assert!(first.history(0, 10).unwrap().is_empty());
    let accepted = first.apply(genesis.checkpoint(), &[one], NOW + 1).unwrap();
    let competing = genesis.renew(&owner, NOW + 3).unwrap();
    assert!(
        second
            .apply(genesis.checkpoint(), &[competing], NOW + 3)
            .is_err()
    );
    assert_eq!(second.load().unwrap().checkpoint(), accepted.checkpoint());
    assert_eq!(second.history(0, 10).unwrap().len(), 1);
}

#[test]
fn database_symlinks_and_shared_files_are_rejected() {
    let home = private_tempdir();
    let other = private_tempdir();
    let target = other.path().join("existing");
    fs::write(&target, b"unchanged").unwrap();
    let path = home.path().join("authority.sqlite3");
    symlink(&target, &path).unwrap();
    assert!(Replica::open(home.path()).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"unchanged");
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Replica::open(home.path()).is_err());
}

#[test]
fn storage_failure_rolls_back_history_and_checkpoint_together() {
    let home = private_tempdir();
    let owner = OwnerKey::generate().unwrap();
    let node = NodeIdentity::generate().unwrap();
    let genesis = owner.create_cluster("test", &node, "first", NOW).unwrap();
    let mut replica = Replica::open(home.path()).unwrap();
    replica.initialize(&genesis).unwrap();
    let injection = rusqlite::Connection::open(home.path().join("authority.sqlite3")).unwrap();
    injection.execute_batch("CREATE TRIGGER reject_checkpoint BEFORE UPDATE ON cluster_state BEGIN SELECT RAISE(ABORT,'injected storage failure'); END;").unwrap();
    let next = genesis.renew(&owner, NOW + 1).unwrap();
    assert!(
        replica
            .apply(genesis.checkpoint(), std::slice::from_ref(&next), NOW + 1)
            .is_err()
    );
    drop(replica);
    let mut replica = Replica::open(home.path()).unwrap();
    assert_eq!(replica.load().unwrap().checkpoint(), genesis.checkpoint());
    assert!(replica.history(0, 10).unwrap().is_empty());
    injection
        .execute_batch("DROP TRIGGER reject_checkpoint;")
        .unwrap();
    assert!(
        replica
            .apply(genesis.checkpoint(), &[next], NOW + 1)
            .is_ok()
    );
}

#[test]
fn unknown_future_database_version_is_preserved_and_rejected() {
    let home = private_tempdir();
    drop(Replica::open(home.path()).unwrap());
    let db = rusqlite::Connection::open(home.path().join("authority.sqlite3")).unwrap();
    db.execute_batch("PRAGMA user_version=100;").unwrap();
    assert!(Replica::open(home.path()).is_err());
    let version: i64 = db
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 100);
}

#[test]
fn catch_up_persists_expired_history_without_authorizing_messages() {
    let home = private_tempdir();
    let owner = OwnerKey::generate().unwrap();
    let node = NodeIdentity::generate().unwrap();
    let genesis = owner.create_cluster("test", &node, "first", NOW).unwrap();
    let mut replica = Replica::open(home.path()).unwrap();
    replica.initialize(&genesis).unwrap();
    let next = genesis.renew(&owner, NOW + 1).unwrap();
    let accepted = replica
        .apply_history(genesis.checkpoint(), &[next])
        .unwrap();
    let later = NOW + 2 * gent_crypto::MAX_STATE_LIFETIME;
    assert!(
        accepted
            .authorize_node(node.id(), &node.public_key(), later)
            .is_err()
    );
    drop(replica);
    let mut replica = Replica::open(home.path()).unwrap();
    let restored = replica.load().unwrap();
    assert_eq!(restored.checkpoint(), accepted.checkpoint());
    assert!(
        restored
            .authorize_node(node.id(), &node.public_key(), later)
            .is_err()
    );
    let fresh = restored.renew(&owner, later).unwrap();
    let accepted = replica
        .apply(restored.checkpoint(), &[fresh], later)
        .unwrap();
    assert!(
        accepted
            .authorize_node(node.id(), &node.public_key(), later)
            .is_ok()
    );
}
