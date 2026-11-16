use super::*;

fn fixture() -> (tempfile::TempDir, Journal) {
    let temp = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let home = managed_file::normalize(&temp.path().join("node")).unwrap();
    config::initialize(&home, "old").unwrap();
    let child = home.join("clusters/legacy");
    super::super::tests::legacy_registry(&home, &child);
    config::private_dir(&home.join("auth")).unwrap();
    config::write_private(
        &home.join("auth/session.json"),
        b"{\"session\":\"private sentinel\"}",
    )
    .unwrap();
    let pending = config::pending_join(&home).unwrap();
    config::initialize(&pending, "pending").unwrap();
    let job = Journal {
        version: 1,
        original: Identity::read(&home).unwrap(),
        archive: sibling(&home, ".retired-test").unwrap(),
        homes: legacy_homes(&home).unwrap(),
        pending_join: Some(Identity::read(&pending).unwrap()),
        home,
    };
    (temp, job)
}

#[test]
fn interrupted_reset_preserves_login_and_protects_every_retired_identity() {
    let (_temp, job) = fixture();
    let owner = fs::read(job.home.join("owner.key")).unwrap();
    let session = fs::read(job.home.join("auth/session.json")).unwrap();
    let journal = sibling(&job.home, ".reset.json").unwrap();
    Snapshot::read(&journal)
        .unwrap()
        .write(&serde_json::to_string(&job).unwrap())
        .unwrap();
    assert!(ensure_idle(&job.home).is_err());
    assert!(ensure_idle(&job.home.join("clusters/legacy")).is_err());
    let locks = lock_state(&job.homes).unwrap();
    archive(&job).unwrap();
    drop(locks);
    // Simulate losing the process after rename, before session restoration.
    let loaded = load(&job.home, &Snapshot::read(&journal).unwrap()).unwrap();
    let result = finish(&loaded).unwrap();
    assert_eq!(result["login_preserved"], true);
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("private sentinel")
    );
    assert_eq!(
        fs::read(job.home.join("auth/session.json")).unwrap(),
        session
    );
    assert!(!config::path(&job.home).exists());
    assert!(!job.home.join("owner.key").exists());
    assert!(!job.home.join("clusters").exists());
    assert!(!config::pending_join(&job.home).unwrap().exists());
    assert_eq!(fs::read(job.archive.join("owner.key")).unwrap(), owner);
    for path in [
        &job.archive,
        &job.archive.join("clusters/legacy"),
        &job.archive.join("retired-pending-join"),
    ] {
        assert!(gent_daemon::recovery::ensure_active(path).is_err());
    }
    // A second interruption after restoring login is also safe.
    finish(&loaded).unwrap();
    Snapshot::read(&journal).unwrap().remove().unwrap();
    assert_eq!(resolve(&job.home, None).unwrap(), job.home);
    config::initialize(&job.home, "new").unwrap();
    assert_ne!(fs::read(job.home.join("owner.key")).unwrap(), owner);
    assert!(finish(&loaded).is_err());
}

#[test]
fn reset_refuses_running_processes_external_paths_and_linked_children() {
    let (_temp, job) = fixture();
    let daemon = managed_file::lock(&job.homes[1].join("daemon.lock")).unwrap();
    assert!(lock_state(&job.homes).is_err());
    assert!(job.home.join("owner.key").exists());
    drop(daemon);
    let outside = job.home.with_file_name("external");
    super::super::tests::legacy_registry(&job.home, &outside);
    assert!(legacy_homes(&job.home).is_err());
    super::super::tests::legacy_registry(&job.home, &job.home.join("clusters/legacy"));
    std::os::unix::fs::symlink(&outside, job.home.join("clusters/linked")).unwrap();
    assert!(legacy_homes(&job.home).is_err());
}

#[test]
fn resumed_reset_never_overwrites_a_different_home_or_account() {
    let (_temp, job) = fixture();
    archive(&job).unwrap();
    config::private_dir(&job.home.join("auth")).unwrap();
    config::write_private(&job.home.join("auth/session.json"), b"different session").unwrap();
    assert!(finish(&job).is_err());
    assert_eq!(
        fs::read(job.home.join("auth/session.json")).unwrap(),
        b"different session"
    );
    assert!(archive(&job).is_err());
}
