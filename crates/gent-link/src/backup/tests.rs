use super::*;
use fs2::FileExt;
use gent_daemon::store::Store;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, os::unix::fs::symlink};

struct Fixture {
    _directory: tempfile::TempDir,
    home: PathBuf,
    key: PathBuf,
    archive: PathBuf,
    output: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let home = directory.path().join("node");
        config::initialize(&home, "backup").unwrap();
        drop(Store::open(&home).unwrap());
        let key = directory.path().join("recovery.key");
        execute(
            Command::Keygen {
                output: key.clone(),
            },
            None,
            None,
        )
        .unwrap();
        let archive = directory.path().join("node.age");
        let output = directory.path().join("offline");
        Self {
            _directory: directory,
            home,
            key,
            archive,
            output,
        }
    }
    fn create(&self) -> Value {
        create(&self.home, &self.archive, &self.key).unwrap()
    }
    fn verify(&self) -> Result<format::Manifest> {
        format::read(&self.archive, &read_key(&self.key)?, None)
    }
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            for (path, bytes) in tree(&entry.path()) {
                result.insert(PathBuf::from(entry.file_name()).join(path), bytes);
            }
        } else if entry.file_type().unwrap().is_file() {
            result.insert(entry.file_name().into(), fs::read(entry.path()).unwrap());
        }
    }
    result
}

#[test]
fn encrypted_round_trip_is_complete_private_guarded_and_scoped() {
    let f = Fixture::new();
    config::private_dir(&f.home.join("empty")).unwrap();
    config::write_private(
        &f.home.join("bindings/chat.key"),
        b"private conversation binding",
    )
    .unwrap();
    let image = vec![0xa5; 256 * 1024 + 17];
    config::write_private(&f.home.join("handoff/image.png"), &image).unwrap();
    config::private_dir(&f.home.join("clusters")).unwrap();
    symlink("missing-profile", f.home.join("clusters/excluded-link")).unwrap();
    let status = f.create();
    assert_eq!(status["state"], "created");
    assert!(
        status["exclusions"]
            .as_array()
            .unwrap()
            .contains(&json!("omitted: clusters"))
    );
    let ciphertext = fs::read(&f.archive).unwrap();
    for secret in [
        b"private conversation binding".as_slice(),
        b"handoff/image.png",
        fs::read(f.home.join("identity.key")).unwrap().as_slice(),
    ] {
        assert!(!ciphertext.windows(secret.len()).any(|w| w == secret));
    }
    let manifest = f.verify().unwrap();
    assert_eq!(manifest.archive_id, status["archive_id"]);
    assert_eq!(
        extract(&f.archive, &f.key, &f.output).unwrap()["state"],
        "extracted_offline"
    );
    for entry in &manifest.entries {
        let path = f.output.join(&entry.path);
        assert_eq!(
            fs::metadata(&path).unwrap().mode() & 0o777,
            if entry.is_dir() { 0o700 } else { 0o600 }
        );
        if !entry.is_dir() {
            assert_eq!(
                fs::read(&path).unwrap(),
                fs::read(f.home.join(&entry.path)).unwrap()
            );
        }
    }
    assert_eq!(fs::read(f.output.join("handoff/image.png")).unwrap(), image);
    assert!(!f.output.join("clusters").exists());
    assert!(!f.output.join("daemon.lock").exists());
    assert!(Store::open(&f.output).is_err());
    assert!(crate::contexts::resolve(&f.output, None).is_err());
    assert_eq!(fs::metadata(&f.key).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&f.archive).unwrap().mode() & 0o777, 0o600);
}

#[test]
fn corruption_wrong_keys_truncation_and_trailing_ciphertext_leave_no_output() {
    let f = Fixture::new();
    f.create();
    let original = fs::read(&f.archive).unwrap();
    let wrong = age::x25519::Identity::generate();
    assert!(format::read(&f.archive, &wrong, None).is_err());
    let mut variants: Vec<Vec<u8>> = [0, 1, 20, original.len() / 2, original.len() - 1]
        .into_iter()
        .map(|n| original[..n].to_vec())
        .collect();
    let mut corrupt = original.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    variants.push(corrupt);
    let mut trailing = original.clone();
    trailing.extend_from_slice(b"extra");
    variants.push(trailing);
    let mut concatenated = original.clone();
    concatenated.extend_from_slice(&original);
    variants.push(concatenated);
    variants.push(vec![b'x'; 16 * 1024 + 1]);
    for bytes in variants {
        fs::write(&f.archive, bytes).unwrap();
        assert!(f.verify().is_err());
        assert!(extract(&f.archive, &f.key, &f.output).is_err());
        assert!(!f.output.exists());
        assert!(!fs::read_dir(f._directory.path()).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".gent-")
        }));
    }
}

#[test]
fn busy_daemon_config_registry_credentials_and_database_refuse_capture() {
    let f = Fixture::new();
    // Warm persistent locks before checking that failed attempts publish nothing.
    drop(capture::Capture::open(&f.home).unwrap());
    for name in [
        "daemon.lock",
        "config.lock",
        "auth/session.lock",
        "gateway/state.lock",
        "host-bindings/codex/bindings.lock",
    ] {
        let path = f.home.join(name);
        config::private_dir(path.parent().unwrap()).unwrap();
        let held = config::state_lock(
            path.parent().unwrap(),
            path.file_name().unwrap().to_str().unwrap(),
        )
        .unwrap();
        assert!(create(&f.home, &f.archive, &f.key).is_err(), "{name}");
        assert!(!f.archive.exists());
        drop(held);
    }
    let path = f.home.join("bindings/chat.key");
    config::write_private(&path, b"in use").unwrap();
    let held = File::open(&path).unwrap();
    held.try_lock_exclusive().unwrap();
    assert!(create(&f.home, &f.archive, &f.key).is_err());
    drop(held);
    let db = rusqlite::Connection::open(f.home.join("state.sqlite3")).unwrap();
    db.execute_batch("BEGIN; SELECT count(*) FROM sqlite_schema;")
        .unwrap();
    assert!(create(&f.home, &f.archive, &f.key).is_err());
    db.execute_batch("ROLLBACK").unwrap();
    f.create();
}

#[test]
fn filesystem_changes_links_and_special_files_are_rejected() {
    let f = Fixture::new();
    let capture = capture::Capture::open(&f.home).unwrap();
    let manifest = capture.manifest().unwrap();
    config::write_private(&f.home.join("new-file"), b"raced").unwrap();
    assert!(capture.verify().is_err());
    let key = read_key(&f.key).unwrap();
    fs::write(f.home.join("config.toml"), b"changed").unwrap();
    assert!(format::write(Vec::new(), &key, &manifest, &f.home).is_err());
    drop(capture);
    for kind in 0..3 {
        let f = Fixture::new();
        let path = f.home.join("unsafe");
        match kind {
            0 => symlink(&f.key, &path).unwrap(),
            1 => fs::hard_link(f.home.join("identity.key"), &path).unwrap(),
            _ => {
                let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            }
        }
        assert!(create(&f.home, &f.archive, &f.key).is_err());
        assert!(!f.archive.exists());
    }
}

#[test]
fn existing_outputs_and_in_tree_secrets_are_preserved() {
    let f = Fixture::new();
    f.create();
    let before = fs::read(&f.archive).unwrap();
    assert!(create(&f.home, &f.archive, &f.key).is_err());
    assert_eq!(fs::read(&f.archive).unwrap(), before);
    let key = fs::read(&f.key).unwrap();
    assert!(
        execute(
            Command::Keygen {
                output: f.key.clone()
            },
            None,
            None
        )
        .is_err()
    );
    assert_eq!(fs::read(&f.key).unwrap(), key);
    config::private_dir(&f.output).unwrap();
    config::write_private(&f.output.join("keep"), b"keep").unwrap();
    assert!(extract(&f.archive, &f.key, &f.output).is_err());
    assert_eq!(
        tree(&f.output),
        [(PathBuf::from("keep"), b"keep".to_vec())].into()
    );
    fs::remove_file(f.output.join("keep")).unwrap();
    assert!(extract(&f.archive, &f.key, &f.output).is_err()); // even empty destinations
    let linked = f._directory.path().join("linked");
    symlink(&f.output, &linked).unwrap();
    assert!(extract(&f.archive, &f.key, &linked).is_err());
    config::write_private(&f.home.join("recovery.key"), &key).unwrap();
    let other = f._directory.path().join("other.age");
    assert!(create(&f.home, &other, &f.home.join("recovery.key")).is_err());
    assert!(create(&f.home, &f.home.join("backup.age"), &f.key).is_err());
}

#[test]
fn manifest_limits_order_parent_types_and_reserved_paths_are_enforced() {
    let f = Fixture::new();
    let manifest = capture::Capture::open(&f.home).unwrap().manifest().unwrap();
    for path in [
        "../escape",
        "/absolute",
        "a/../../escape",
        "a//b",
        "a/./b",
        "back\\slash",
        "line\nfeed",
        "recovery-required.json",
        "clusters/other",
        "daemon.sock",
        "new.lock",
        "missing/child",
    ] {
        let mut invalid = manifest.clone();
        invalid.entries.push(format::Entry {
            path: path.into(),
            kind: format::Kind::File,
            bytes: 0,
            sha256: Some(format!("{:x}", Sha256::digest([]))),
        });
        invalid.entries.sort_by(|a, b| a.path.cmp(&b.path));
        assert!(invalid.validate().is_err(), "{path}");
    }
    let mut invalid = manifest.clone();
    invalid.entries.push(invalid.entries[0].clone());
    invalid.entries.sort_by(|a, b| a.path.cmp(&b.path));
    assert!(invalid.validate().is_err());
    invalid = manifest.clone();
    invalid.entries[0].bytes = format::MAX_FILE_BYTES + 1;
    assert!(invalid.validate().is_err());
    invalid = manifest;
    invalid.version = 2;
    assert!(invalid.validate().is_err());
}

#[test]
fn publication_race_preserves_the_destination_and_scopes_are_explicit() {
    let f = Fixture::new();
    let staging = f._directory.path().join("staging");
    config::private_dir(&staging).unwrap();
    config::write_private(&staging.join("payload"), b"verified").unwrap();
    fs::create_dir(&f.output).unwrap(); // another creator won after initial checks
    assert!(publish_directory(&staging, &f.output).is_err());
    assert_eq!(fs::read_dir(&f.output).unwrap().count(), 0);
    assert_eq!(fs::read(staging.join("payload")).unwrap(), b"verified");
    fs::remove_dir(&f.output).unwrap();
    publish_directory(&staging, &f.output).unwrap();
    assert_eq!(fs::read(f.output.join("payload")).unwrap(), b"verified");
    let peer = f._directory.path().join("other-profile");
    config::initialize(&peer, "other").unwrap();
    crate::contexts::add(&f.home, &peer).unwrap();
    let mut cfg = config::load(&f.home).unwrap();
    cfg.relay = Some(config::RelayConfig {
        endpoint: "http://127.0.0.1:8787".into(),
        credential_file: f._directory.path().join("missing-external-credential"),
    });
    config::save(&f.home, &cfg).unwrap();
    let summary = f.create();
    let exclusions = serde_json::to_string(&summary["exclusions"]).unwrap();
    assert!(exclusions.contains("other profile") && exclusions.contains("other-profile"));
    assert!(
        exclusions.contains("external relay credential")
            && exclusions.contains("missing-external-credential")
    );
    assert!(
        !f._directory
            .path()
            .join("missing-external-credential")
            .exists()
    );
}

#[test]
fn configuration_is_bounded_and_unlinked_before_parsing() {
    let f = Fixture::new();
    fs::remove_file(config::path(&f.home)).unwrap();
    symlink(&f.key, config::path(&f.home)).unwrap();
    assert!(
        create(&f.home, &f.archive, &f.key)
            .unwrap_err()
            .to_string()
            .contains("regular files")
    );
    fs::remove_file(config::path(&f.home)).unwrap();
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(config::path(&f.home))
        .unwrap();
    file.set_len(16 * 1024 * 1024 + 1).unwrap();
    assert!(
        create(&f.home, &f.archive, &f.key)
            .unwrap_err()
            .to_string()
            .contains("configuration is too large")
    );
    assert!(!f.archive.exists());
}
