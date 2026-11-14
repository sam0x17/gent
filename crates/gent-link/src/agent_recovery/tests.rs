use super::*;
use std::os::unix::fs::PermissionsExt;

fn setup() -> (tempfile::TempDir, Config, PathBuf) {
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let cfg = config::initialize(&root.path().join("node"), "binding-recovery").unwrap();
    let path = root.path().join("binding.key");
    (root, cfg, path)
}

#[test]
fn binding_paths_refuse_guarded_original_and_resolved_ancestors() {
    let (root, cfg, _) = setup();
    let offline = root.path().join("offline");
    let active = root.path().join("active");
    config::private_dir(&offline).unwrap();
    config::private_dir(&active).unwrap();
    config::write_private(&offline.join(gent_daemon::recovery::MARKER), b"{}").unwrap();
    std::os::unix::fs::symlink(&active, offline.join("out")).unwrap();
    std::os::unix::fs::symlink(&offline, active.join("in")).unwrap();
    for path in [
        offline.join("nested/key"),
        offline.join("out/key"),
        active.join("in/key"),
    ] {
        let error = binding::normalize(&path).unwrap_err();
        assert!(error.to_string().contains("offline recovery"), "{error:#}");
        assert!(binding::open(&path, &cfg, true).is_err());
        assert!(!path.exists());
        assert!(!binding::sidecar(&path, ".binding.lock").exists());
    }
    assert!(binding::open(&active.join("key"), &cfg, true).is_ok());
}

#[test]
fn pending_recovery_never_becomes_a_binding_until_explicit_completion() {
    let (_root, cfg, path) = setup();
    let stable = binding::lock(&path).unwrap();
    let (mut record, key_guard) = prepare(&path, &cfg, &"11".repeat(32)).unwrap();
    let credential = config::read_private(&path).unwrap();
    assert!(ensure_ready(&path, &cfg).is_err());
    drop(key_guard);
    // Lost replies retain the same fresh credential on retry.
    let (retried, _key_guard) = prepare(&path, &cfg, &"11".repeat(32)).unwrap();
    assert_eq!(record.credential_hash, retried.credential_hash);
    assert!(prepare(&path, &cfg, &"22".repeat(32)).is_err());
    let result =
        json!({"agent":{"id":uuid::Uuid::new_v4()},"history":{"import_id":uuid::Uuid::new_v4()}});
    complete(&path, &cfg, &mut record, &result).unwrap();
    let text = fs::read_to_string(binding::sidecar(&path, ".recovery.json")).unwrap();
    assert!(!text.contains(&credential));
    ensure_ready(&path, &cfg).unwrap();
    drop(_key_guard);
    drop(stable);
    let opened = binding::open(&path, &cfg, true).unwrap();
    assert_eq!(opened.credential, credential);
}

#[test]
fn recovery_repairs_only_its_own_pending_files_and_refuses_conflicts() {
    for case in 0..5 {
        let (_root, cfg, path) = setup();
        let _stable = binding::lock(&path).unwrap();
        let (record, guard) = prepare(&path, &cfg, &"11".repeat(32)).unwrap();
        drop(guard);
        match case {
            0 => {
                fs::remove_file(&path).unwrap();
            }
            1 => {
                Snapshot::read(&path)
                    .unwrap()
                    .write(&config::secret())
                    .unwrap();
            }
            2 => {
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink("absent", &path).unwrap();
            }
            3 => {
                Snapshot::read(&binding::sidecar(&path, ".scope.json"))
                    .unwrap()
                    .write("invalid")
                    .unwrap();
            }
            4 => {
                Snapshot::read(&binding::sidecar(&path, ".recovery.json"))
                    .unwrap()
                    .write("invalid")
                    .unwrap();
            }
            _ => unreachable!(),
        }
        if case == 0 {
            let (retry, _guard) = prepare(&path, &cfg, &"11".repeat(32)).unwrap();
            assert_eq!(retry.credential_hash, record.credential_hash);
        } else {
            assert!(prepare(&path, &cfg, &"11".repeat(32)).is_err());
        }
    }
}

#[test]
fn existing_completed_busy_or_wrong_node_bindings_cannot_be_replaced() {
    let (_root, cfg, path) = setup();
    let _stable = binding::lock(&path).unwrap();
    let credential = config::binding(&path).unwrap();
    assert!(prepare(&path, &cfg, &"11".repeat(32)).is_err());
    assert_eq!(credential, config::read_private(&path).unwrap());
    fs::remove_file(&path).unwrap();
    let (mut record, guard) = prepare(&path, &cfg, &"11".repeat(32)).unwrap();
    assert!(prepare(&path, &cfg, &"11".repeat(32)).is_err());
    let mut other = cfg.clone();
    other.node.id = uuid::Uuid::new_v4().to_string();
    assert!(prepare(&path, &other, &"11".repeat(32)).is_err());
    let result =
        json!({"agent":{"id":uuid::Uuid::new_v4()},"history":{"import_id":uuid::Uuid::new_v4()}});
    complete(&path, &cfg, &mut record, &result).unwrap();
    drop(guard);
    fs::remove_file(&path).unwrap();
    assert!(prepare(&path, &cfg, &"11".repeat(32)).is_err());
    assert!(!path.exists());
}
