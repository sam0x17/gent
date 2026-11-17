use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

fn build(commit: char) -> Build {
    Build {
        commit: commit.to_string().repeat(40),
        dirty: false,
        ..build_info::current()
    }
}

struct Fixture {
    root: tempfile::TempDir,
    installation: Installation,
    candidate: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let binary = root.path().join("gent");
        let candidate = root.path().join("candidate");
        let directory = root.path().join("updates");
        config::private_dir(&directory).unwrap();
        fs::write(&binary, b"old executable").unwrap();
        fs::write(&candidate, b"new executable").unwrap();
        for path in [&binary, &candidate] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self {
            root,
            installation: Installation { binary, directory },
            candidate,
        }
    }
    fn publish(&self) {
        self.installation
            .publish(
                self.root.path(),
                build('a'),
                build('b'),
                &self.candidate,
                &install::hash(&self.installation.binary).unwrap(),
                true,
            )
            .unwrap();
    }
}

#[test]
fn stable_tag_resolution_supports_lightweight_and_annotated_tags_without_other_refs() {
    let a = "a".repeat(40);
    let b = "b".repeat(40);
    assert_eq!(
        release::parse(format!("{a}\trefs/tags/stable\n").as_bytes()).unwrap(),
        a
    );
    assert_eq!(
        release::parse(format!("{a}\trefs/tags/stable\n{b}\trefs/tags/stable^{{}}\n").as_bytes())
            .unwrap(),
        b
    );
    for bytes in [
        String::new(),
        format!("{a}\trefs/heads/main\n"),
        "oops\trefs/tags/stable\n".into(),
        format!("{a}\trefs/tags/stable^{{}}\n"),
        format!("{a}\trefs/tags/stable\n{b}\trefs/tags/stable\n"),
    ] {
        assert!(release::parse(bytes.as_bytes()).is_err());
    }
}

#[test]
fn update_preferences_are_local_and_survive_stale_signed_config_projections() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let stale = config::initialize(root.path(), "updates").unwrap();
    assert!(stale.updates().unwrap().enabled);
    config::edit_local(root.path(), |cfg| {
        cfg.set_updates(config::Updates { enabled: false })
    })
    .unwrap();
    config::save(root.path(), &stale).unwrap();
    assert!(
        !config::load(root.path())
            .unwrap()
            .updates()
            .unwrap()
            .enabled
    );
    let mut invalid = stale.clone();
    invalid
        .extra
        .insert("updates".into(), toml::Value::String("false".into()));
    assert!(invalid.validate_local().is_err());
    invalid.extra.insert(
        "updates".into(),
        toml::from_str::<toml::Value>("enable = false").unwrap(),
    );
    assert!(invalid.validate_local().is_err());
    assert_eq!(CHECK_INTERVAL, Duration::from_secs(300));
}

#[test]
fn cargo_hard_links_are_detached_before_verification_and_publication() {
    use std::os::unix::fs::{MetadataExt, symlink};
    let f = Fixture::new();
    let cached = f.root.path().join("cached-artifact");
    fs::hard_link(&f.candidate, &cached).unwrap();
    assert!(install::hash(&f.candidate).is_err());
    let snapshot = install::snapshot_artifact(&f.candidate).unwrap();
    assert_eq!(fs::metadata(&snapshot).unwrap().nlink(), 1);
    let expected = install::hash(&snapshot).unwrap();
    fs::write(&cached, b"later build rewrote the cache").unwrap();
    assert_eq!(install::hash(&snapshot).unwrap(), expected);
    f.installation
        .publish(
            f.root.path(),
            build('a'),
            build('b'),
            &snapshot,
            &install::hash(&f.installation.binary).unwrap(),
            false,
        )
        .unwrap();
    assert_eq!(fs::read(&f.installation.binary).unwrap(), b"new executable");
    fs::remove_file(&f.candidate).unwrap();
    symlink(&cached, &f.candidate).unwrap();
    assert!(install::snapshot_artifact(&f.candidate).is_err());
    fs::remove_file(&f.candidate).unwrap();
    fs::write(&f.candidate, b"unsafe artifact").unwrap();
    fs::set_permissions(&f.candidate, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(install::snapshot_artifact(&f.candidate).is_err());
    assert_eq!(install::hash(&snapshot).unwrap(), expected);
}

#[test]
fn publication_is_atomic_retains_open_executables_and_rolls_back_verified_bytes() {
    use std::io::Read;
    let f = Fixture::new();
    let old_hash = install::hash(&f.installation.binary).unwrap();
    let mut opened = fs::File::open(&f.installation.binary).unwrap();
    f.publish();
    assert_eq!(fs::read(&f.installation.binary).unwrap(), b"new executable");
    let mut old_bytes = Vec::new();
    opened.read_to_end(&mut old_bytes).unwrap();
    assert_eq!(old_bytes, b"old executable");
    let pending = f.installation.pending().unwrap().unwrap();
    assert_eq!(pending.old_hash, old_hash);
    assert_eq!(
        install::hash(&f.installation.directory.join("previous")).unwrap(),
        old_hash
    );
    f.installation
        .rollback(&pending, "test failed startup")
        .unwrap();
    assert_eq!(fs::read(&f.installation.binary).unwrap(), b"old executable");
    assert!(f.installation.pending().unwrap().is_none());
    assert_eq!(
        f.installation.status().unwrap().failed_commit,
        Some("b".repeat(40))
    );
}

#[test]
fn publication_and_rollback_refuse_external_replacements_and_corrupt_backups() {
    let f = Fixture::new();
    let expected = install::hash(&f.installation.binary).unwrap();
    fs::write(&f.installation.binary, b"user replaced this").unwrap();
    assert!(
        f.installation
            .publish(
                f.root.path(),
                build('a'),
                build('b'),
                &f.candidate,
                &expected,
                true,
            )
            .is_err()
    );
    assert!(f.installation.pending().unwrap().is_none());
    f.publish();
    let pending = f.installation.pending().unwrap().unwrap();
    fs::write(f.installation.directory.join("previous"), b"corrupt backup").unwrap();
    assert!(f.installation.rollback(&pending, "test").is_err());
    assert_eq!(fs::read(&f.installation.binary).unwrap(), b"new executable");
    fs::write(&f.installation.binary, b"outside update").unwrap();
    assert!(f.installation.rollback(&pending, "test").is_err());
    assert_eq!(fs::read(&f.installation.binary).unwrap(), b"outside update");
}

#[test]
fn startup_journal_marks_readiness_or_restores_previous_after_an_interrupted_start() {
    for healthy in [true, false] {
        let f = Fixture::new();
        f.installation
            .publish(
                f.root.path(),
                build('a'),
                build('b'),
                &f.candidate,
                &install::hash(&f.installation.binary).unwrap(),
                true,
            )
            .unwrap();
        assert!(
            !f.installation
                .begin_startup(f.root.path(), &build('b'))
                .unwrap()
        );
        assert!(f.installation.pending().unwrap().unwrap().starting);
        if healthy {
            assert_eq!(
                f.installation.healthy(&build('b')).unwrap(),
                Some(build('b'))
            );
            assert!(f.installation.healthy(&build('b')).unwrap().is_none());
            assert!(f.installation.pending().unwrap().is_none());
            assert_eq!(fs::read(&f.installation.binary).unwrap(), b"new executable");
        } else {
            assert!(
                f.installation
                    .begin_startup(f.root.path(), &build('b'))
                    .unwrap()
            );
            assert_eq!(fs::read(&f.installation.binary).unwrap(), b"old executable");
        }
    }
}

#[test]
fn update_lock_and_binary_validation_reject_competing_writers_and_unsafe_paths() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let lock = f.installation.lock().unwrap();
    assert!(f.installation.lock().is_err());
    drop(lock);
    // A concurrently spawning child can retain the inherited descriptor until
    // exec closes it, even after this thread drops its own descriptor.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(lock) = f.installation.lock() {
            drop(lock);
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "lock remained held after release"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let link = f.root.path().join("link");
    symlink(&f.installation.binary, &link).unwrap();
    assert!(install::hash(&link).is_err());
    fs::set_permissions(&f.installation.binary, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(install::hash(&f.installation.binary).is_err());
    fs::set_permissions(&f.installation.binary, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(install::hash(&f.installation.binary).is_ok());
    let mut candidate = build('a');
    assert!(eligible(&candidate));
    candidate.dirty = true;
    assert!(!eligible(&candidate));
    candidate.dirty = false;
    candidate.target = "wrong-platform".into();
    assert!(!eligible(&candidate));
}

#[tokio::test]
async fn subprocess_capture_bounds_output_and_cancels_a_stalled_process() {
    use tokio::process::Command;
    assert!(
        process::capture(
            Command::new("sh").args(["-c", "printf too-long"]),
            2,
            Duration::from_secs(2)
        )
        .await
        .is_err()
    );
    let started = std::time::Instant::now();
    assert!(
        process::capture(
            Command::new("sh").args(["-c", "sleep 30"]),
            16,
            Duration::from_millis(50)
        )
        .await
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(
        process::capture(
            Command::new("sh").args(["-c", "printf ok"]),
            16,
            Duration::from_secs(2)
        )
        .await
        .unwrap(),
        b"ok"
    );
}

#[tokio::test]
async fn failed_build_reports_failure_and_replaces_log_symlink_without_touching_target() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let log = f.installation.directory.join("build.log");
    symlink(&f.installation.binary, &log).unwrap();
    assert!(
        process::build(
            tokio::process::Command::new("sh").args(["-c", "printf failure >&2; exit 1"]),
            &log
        )
        .await
        .is_err()
    );
    assert_eq!(fs::read(&f.installation.binary).unwrap(), b"old executable");
    assert_eq!(fs::read(&log).unwrap(), b"failure");
    assert!(!fs::symlink_metadata(log).unwrap().file_type().is_symlink());
}

#[test]
fn publication_interrupted_before_swap_retries_without_suppressing_the_revision() {
    let f = Fixture::new();
    f.publish();
    let pending = f.installation.pending().unwrap().unwrap();
    fs::copy(
        f.installation.directory.join("previous"),
        &f.installation.binary,
    )
    .unwrap();
    f.installation.interrupted_publication(&pending).unwrap();
    assert!(f.installation.pending().unwrap().is_none());
    assert!(f.installation.status().unwrap().failed_commit.is_none());
    f.publish();
    assert_eq!(fs::read(&f.installation.binary).unwrap(), b"new executable");
}

#[test]
fn manual_activation_is_healthy_without_a_desktop_notification() {
    let f = Fixture::new();
    f.installation
        .publish(
            f.root.path(),
            build('a'),
            build('b'),
            &f.candidate,
            &install::hash(&f.installation.binary).unwrap(),
            false,
        )
        .unwrap();
    assert!(
        !f.installation
            .begin_startup(f.root.path(), &build('b'))
            .unwrap()
    );
    assert!(f.installation.healthy(&build('b')).unwrap().is_none());
    assert!(f.installation.pending().unwrap().is_none());
}

#[tokio::test]
async fn cache_cleanup_keeps_rollback_and_unrelated_paths_without_following_links() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    for name in [
        "a".repeat(40),
        "b".repeat(40),
        "c".repeat(40),
        "unrelated".into(),
    ] {
        fs::create_dir(root.path().join(name)).unwrap();
    }
    let other = tempfile::tempdir().unwrap();
    fs::write(other.path().join("keep"), b"untouched").unwrap();
    symlink(other.path(), root.path().join("d".repeat(40))).unwrap();
    release::prune(root.path(), &[&"a".repeat(40), &"b".repeat(40)])
        .await
        .unwrap();
    assert!(root.path().join("a".repeat(40)).is_dir());
    assert!(root.path().join("b".repeat(40)).is_dir());
    assert!(!root.path().join("c".repeat(40)).exists());
    assert!(root.path().join("unrelated").is_dir());
    assert!(root.path().join("d".repeat(40)).is_symlink());
    assert_eq!(fs::read(other.path().join("keep")).unwrap(), b"untouched");
}
