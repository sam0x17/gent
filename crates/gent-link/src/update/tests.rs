use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

fn stable(automatic: bool) -> install::Source {
    install::Source {
        channel: gent_protocol::ReleaseChannel::Stable,
        automatic,
    }
}

fn build(commit: char) -> Build {
    Build {
        commit: commit.to_string().repeat(40),
        dirty: false,
        test_build: cfg!(feature = "test-updates"),
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
                stable(true),
            )
            .unwrap();
    }
}

#[test]
fn stable_tag_resolution_supports_lightweight_and_annotated_tags_without_other_refs() {
    let a = "a".repeat(40);
    let b = "b".repeat(40);
    assert_eq!(
        release::STABLE
            .parse(format!("{a}\trefs/tags/stable\n").as_bytes())
            .unwrap(),
        a
    );
    assert_eq!(
        release::STABLE
            .parse(format!("{a}\trefs/tags/stable\n{b}\trefs/tags/stable^{{}}\n").as_bytes())
            .unwrap(),
        b
    );
    for bytes in [
        String::new(),
        format!("{a}\trefs/heads/main\n"),
        format!("{a}\trefs/heads/beta\n"),
        "oops\trefs/tags/stable\n".into(),
        format!("{a}\trefs/tags/stable^{{}}\n"),
        format!("{a}\trefs/tags/stable\n{b}\trefs/tags/stable\n"),
    ] {
        assert!(release::STABLE.parse(bytes.as_bytes()).is_err());
    }
}

#[test]
fn beta_resolution_requires_one_exact_branch() {
    let a = "a".repeat(40);
    let b = "b".repeat(40);
    assert_eq!(
        release::BETA
            .parse(format!("{a}\trefs/heads/beta\n").as_bytes())
            .unwrap(),
        a
    );
    for bytes in [
        String::new(),
        format!("{a}\trefs/tags/stable\n"),
        format!("{a}\trefs/tags/beta\n"),
        format!("{a}\trefs/heads/beta\n{b}\trefs/heads/beta^{{}}\n"),
        format!("{a}\trefs/heads/beta\n{b}\trefs/heads/beta\n"),
        "abcd\trefs/heads/beta\n".into(),
    ] {
        assert!(release::BETA.parse(bytes.as_bytes()).is_err());
    }
}

#[test]
fn status_reports_an_uninitialized_home_as_stable_and_preserves_errors_for_invalid_authority() {
    let f = Fixture::new();
    let home = f.root.path();
    let legacy = status::with_channel(home, json!({}));
    assert_eq!(legacy["channel"], "stable");
    assert_eq!(legacy["release_ref"], "refs/tags/stable");

    config::write_private(&home.join("state.sqlite3"), b"corrupt").unwrap();
    assert!(ReleaseRef::current(home).is_err());
    let status = status::with_channel(home, json!({"activation_pending": true}));
    assert_eq!(status["activation_pending"], true);
    assert!(status["channel"].is_null() && status["release_ref"].is_null());
    assert!(status["channel_error"].is_string());
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
            stable(false),
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
fn channel_receipt_survives_publish_recovery_and_rollback_without_changing_v1_records() {
    use gent_protocol::ReleaseChannel::{Beta, Stable};
    for outcome in ["healthy", "rollback", "interrupted", "legacy_ack"] {
        let f = Fixture::new();
        let home = f.root.path();
        let other = tempfile::tempdir().unwrap();
        assert_eq!(f.installation.applied_channel(home).unwrap(), Stable);
        f.installation
            .publish(
                home,
                build('a'),
                build('b'),
                &f.candidate,
                &install::hash(&f.installation.binary).unwrap(),
                install::Source {
                    channel: Beta,
                    automatic: true,
                },
            )
            .unwrap();
        let pending = f.installation.pending().unwrap().unwrap();
        assert_eq!(f.installation.applied_channel(home).unwrap(), Stable);
        match outcome {
            "healthy" => {
                f.installation.healthy(home, &build('b')).unwrap();
            }
            "rollback" => f.installation.rollback(&pending, "failed").unwrap(),
            "interrupted" => {
                fs::copy(
                    f.installation.directory.join("previous"),
                    &f.installation.binary,
                )
                .unwrap();
                f.installation.interrupted_publication(&pending).unwrap();
            }
            _ => fs::remove_file(f.installation.directory.join("pending.json")).unwrap(),
        }
        let expected = if matches!(outcome, "healthy" | "legacy_ack") {
            Beta
        } else {
            Stable
        };
        assert_eq!(
            f.installation.applied_channel(home).unwrap(),
            expected,
            "{outcome}"
        );
        assert_eq!(
            f.installation.applied_channel(other.path()).unwrap(),
            Stable
        );
    }
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
                stable(true),
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
                stable(true),
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
                f.installation.healthy(f.root.path(), &build('b')).unwrap(),
                Some(build('b'))
            );
            assert!(
                f.installation
                    .healthy(f.root.path(), &build('b'))
                    .unwrap()
                    .is_none()
            );
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
fn activation_accepts_a_daemon_older_than_the_previously_installed_binary() {
    let f = Fixture::new();
    f.publish();
    // A manual cargo install can change the executable without restarting the
    // daemon. The journal's old build then describes disk, not this process.
    assert_ne!(
        f.installation.pending().unwrap().unwrap().old,
        build_info::current()
    );
    assert!(f.installation.needs_restart(f.root.path()).unwrap());
    let other_home = tempfile::tempdir().unwrap();
    assert!(!f.installation.needs_restart(other_home.path()).unwrap());
    let lock = f.installation.lock().unwrap();
    assert!(!f.installation.needs_restart(f.root.path()).unwrap());
    drop(lock);
    let mut pending = f.installation.pending().unwrap().unwrap();
    // Returning to the running channel after an independent disk install must
    // also activate the verified binary and finish the journal.
    let running = build_info::current();
    if build_info::valid_commit(&running.commit) {
        pending.new = running;
        f.installation.write("pending.json", &pending).unwrap();
        assert!(f.installation.needs_restart(f.root.path()).unwrap());
    }
    pending.starting = true;
    f.installation.write("pending.json", &pending).unwrap();
    assert!(!f.installation.needs_restart(f.root.path()).unwrap());
    pending.starting = false;
    f.installation.write("pending.json", &pending).unwrap();
    fs::write(&f.installation.binary, b"outside replacement").unwrap();
    assert!(!f.installation.needs_restart(f.root.path()).unwrap());
}

#[test]
fn authenticated_readiness_finishes_activation_after_startup_lock_contention() {
    let f = Fixture::new();
    f.publish();
    let lock = f.installation.lock().unwrap();
    assert!(
        f.installation
            .begin_startup(f.root.path(), &build('b'))
            .is_err()
    );
    assert!(f.installation.healthy(f.root.path(), &build('b')).is_err());
    assert!(!f.installation.pending().unwrap().unwrap().starting);
    drop(lock);
    assert_eq!(
        f.installation.healthy(f.root.path(), &build('b')).unwrap(),
        Some(build('b'))
    );
    assert!(f.installation.pending().unwrap().is_none());
    assert_eq!(f.installation.status().unwrap().phase, "current");
    assert_eq!(fs::read(&f.installation.binary).unwrap(), b"new executable");
}

#[test]
fn update_lock_and_binary_validation_reject_competing_writers_and_unsafe_paths() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let lock = f.installation.lock().unwrap();
    assert!(f.installation.lock().is_err());
    drop(lock);
    assert!(f.installation.lock().is_ok());
    let link = f.root.path().join("link");
    symlink(&f.installation.binary, &link).unwrap();
    assert!(install::hash(&link).is_err());
    fs::set_permissions(&f.installation.binary, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(install::hash(&f.installation.binary).is_err());
    fs::set_permissions(&f.installation.binary, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(install::hash(&f.installation.binary).is_ok());
    let mut candidate = build('a');
    assert!(eligible(&candidate));
    candidate.test_build = !candidate.test_build;
    assert!(!eligible(&candidate));
    candidate.test_build = !candidate.test_build;
    candidate.dirty = true;
    assert!(!eligible(&candidate));
    candidate.dirty = false;
    candidate.target = "wrong-platform".into();
    assert!(!eligible(&candidate));
}

#[tokio::test]
async fn manual_update_waits_for_publication_while_scheduled_checks_skip_it() {
    let f = Fixture::new();
    let lock = f.installation.lock().unwrap();
    f.installation
        .write(
            "status.json",
            &install::Status {
                phase: "building".into(),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        workflow::apply(f.root.path(), &f.installation, Trigger::Scheduled)
            .await
            .unwrap()["state"],
        "already_running"
    );
    assert_eq!(f.installation.status().unwrap().phase, "building");
    let mut manual = Box::pin(workflow::apply(
        f.root.path(),
        &f.installation,
        Trigger::Manual,
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut manual)
            .await
            .is_err()
    );
    assert!(f.installation.pending().unwrap().is_none());
    f.publish();
    drop(lock);
    let result = tokio::time::timeout(Duration::from_secs(5), manual)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result["state"], "awaiting_activation");
    assert_eq!(result["commit"], "b".repeat(40));
    assert_eq!(fs::read(&f.installation.binary).unwrap(), b"new executable");
    assert_eq!(
        fs::read(f.installation.directory.join("previous")).unwrap(),
        b"old executable"
    );
}

#[tokio::test]
async fn cancelling_a_waiter_preserves_the_updater_and_invalid_locks_fail_immediately() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let lock = f.installation.lock().unwrap();
    let mut waiter = Box::pin(workflow::apply(
        f.root.path(),
        &f.installation,
        Trigger::Manual,
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut waiter)
            .await
            .is_err()
    );
    drop(waiter);
    assert!(f.installation.try_lock().unwrap().is_none());
    assert!(!f.installation.directory.join("status.json").exists());
    assert!(f.installation.pending().unwrap().is_none());
    drop(lock);

    let invalid = Fixture::new();
    symlink(
        &invalid.candidate,
        invalid.installation.directory.join("update.lock"),
    )
    .unwrap();
    for trigger in [Trigger::Manual, Trigger::Scheduled, Trigger::ChannelChange] {
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            workflow::apply(invalid.root.path(), &invalid.installation, trigger),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("private regular file"));
    }
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

#[tokio::test]
async fn publication_interrupted_before_swap_retries_without_suppressing_the_revision() {
    let f = Fixture::new();
    f.publish();
    let pending = f.installation.pending().unwrap().unwrap();
    fs::copy(
        f.installation.directory.join("previous"),
        &f.installation.binary,
    )
    .unwrap();
    let foreign = tempfile::tempdir().unwrap();
    let result = workflow::apply(foreign.path(), &f.installation, Trigger::ChannelChange)
        .await
        .unwrap();
    assert_eq!(result["state"], "awaiting_activation");
    assert!(f.installation.pending().unwrap().is_some());
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
            stable(false),
        )
        .unwrap();
    assert!(
        !f.installation
            .begin_startup(f.root.path(), &build('b'))
            .unwrap()
    );
    assert!(
        f.installation
            .healthy(f.root.path(), &build('b'))
            .unwrap()
            .is_none()
    );
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

#[tokio::test]
async fn shared_cache_adopts_dependencies_and_invalidates_workspace_code_on_every_attempt() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let installed = "a".repeat(40);
    let legacy = root.path().join(&installed);
    for profile in ["release", "aarch64-apple-darwin/release"] {
        let fingerprints = legacy.join(profile).join(".fingerprint");
        for package in ["gent-link-aaa", "gent-daemon-bbb", "serde-ccc"] {
            fs::create_dir_all(fingerprints.join(package)).unwrap();
            fs::write(fingerprints.join(package).join("artifact"), b"cached").unwrap();
        }
        for package in ["gent-daemon", "serde"] {
            let artifact = legacy
                .join(profile)
                .join("build")
                .join(package)
                .join("abc/out");
            fs::create_dir_all(&artifact).unwrap();
            fs::write(artifact.join("cached"), b"cached").unwrap();
        }
    }
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("keep"), b"untouched").unwrap();
    symlink(
        outside.path(),
        legacy.join("release/.fingerprint/gent-crypto-ddd"),
    )
    .unwrap();
    let shared = cache::prepare(root.path(), &installed).await.unwrap();
    assert!(!legacy.exists());
    for profile in ["release", "aarch64-apple-darwin/release"] {
        let fingerprints = shared.join(profile).join(".fingerprint");
        assert!(!fingerprints.join("gent-link-aaa").exists());
        assert!(!fingerprints.join("gent-daemon-bbb").exists());
        assert_eq!(
            fs::read(fingerprints.join("serde-ccc/artifact")).unwrap(),
            b"cached"
        );
        fs::create_dir(fingerprints.join("gent-link-aaa")).unwrap();
        assert!(!shared.join(profile).join("build/gent-daemon").exists());
        assert_eq!(
            fs::read(shared.join(profile).join("build/serde/abc/out/cached")).unwrap(),
            b"cached"
        );
    }
    assert_eq!(fs::read(outside.path().join("keep")).unwrap(), b"untouched");
    assert_eq!(
        cache::prepare(root.path(), &"b".repeat(40)).await.unwrap(),
        shared
    );
    assert!(!shared.join("release/.fingerprint/gent-link-aaa").exists());
    release::prune(root.path(), &[]).await.unwrap();
    assert!(
        shared
            .join("release/.fingerprint/serde-ccc/artifact")
            .exists()
    );
}

#[tokio::test]
async fn shared_cache_rejects_redirected_fingerprints() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("shared/release")).unwrap();
    fs::write(outside.path().join("gent-keep"), b"untouched").unwrap();
    symlink(
        outside.path(),
        root.path().join("shared/release/.fingerprint"),
    )
    .unwrap();
    assert!(cache::prepare(root.path(), &"a".repeat(40)).await.is_err());
    assert_eq!(
        fs::read(outside.path().join("gent-keep")).unwrap(),
        b"untouched"
    );
}

#[tokio::test]
async fn activated_revision_refreshes_managed_integrations_but_superseded_daemon_does_not() {
    use crate::integration::{self, Command as IntegrationCommand, Host};
    let f = Fixture::new();
    let home = f.root.path().join("node");
    config::initialize(&home, "refresh-test").unwrap();
    let directory = f.root.path().join("claude");
    // Exercise the real CLI parser so custom installations enter the registry.
    use clap::Parser;
    let cli = crate::Cli::try_parse_from([
        "gent",
        "integration",
        "install",
        "claude-code",
        "--config-dir",
        directory.to_str().unwrap(),
    ])
    .unwrap();
    let Some(crate::Command::Integration { command }) = cli.command else {
        panic!("integration command");
    };
    integration::execute(&home, command).unwrap();
    let record = directory.join(".gent-claude-code.json");
    let module = directory.join("skills/gent-wake/hooks/register.ts");
    let mut state: Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
    let current_module = state["installed"]["claude_wake"]["module"]
        .as_str()
        .unwrap()
        .to_owned();
    state["installed"]["claude_wake"]["module"] = json!("export function register(on) {}\n");
    config::write_private(&record, serde_json::to_string(&state).unwrap().as_bytes()).unwrap();
    let old_module = fs::read_to_string(&module)
        .unwrap()
        .replace(&current_module, "export function register(on) {}\n");
    config::write_private(&module, old_module.as_bytes()).unwrap();
    let executable = |build: &Build| {
        let text = serde_json::to_string(build).unwrap();
        fs::write(
            &f.installation.binary,
            format!(
                "#!/bin/sh\nprintf '%s\\n' '{}'\n",
                text.replace('\'', "'\"'\"'")
            ),
        )
        .unwrap();
    };
    executable(&build('f'));
    integrations::refresh(&home, &f.installation).await;
    assert_eq!(fs::read_to_string(&module).unwrap(), old_module);
    executable(&build_info::current());
    integrations::refresh(&home, &f.installation).await;
    assert!(
        fs::read_to_string(&module)
            .unwrap()
            .contains("claim_direct")
    );
    let status = integration::refresh::status(&home).unwrap();
    assert_eq!(status["blocked"], 0);
    let installed = integration::execute(
        &home,
        IntegrationCommand::Status {
            host: Some(Host::ClaudeCode),
            config_dir: Some(directory),
            live: false,
            host_binary: None,
        },
    )
    .unwrap();
    assert_eq!(installed["state"], "configured");
}
