use super::*;
use crate::managed_file::Snapshot;
use anyhow::{Context, ensure};
use std::{fs, io::Write, os::unix::fs::PermissionsExt, path::Path};

fn replace(path: &Path, text: &str) {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap()).unwrap();
    file.write_all(text.as_bytes()).unwrap();
    file.persist(path).unwrap();
}

#[tokio::test]
async fn replacement_retries_fresh_snapshots_and_returns_only_validated_contents() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("settings.json");
    replace(&path, "original");
    let mut reads = 0;
    let value = retry_read(|| {
        reads += 1;
        let snapshot = Snapshot::read(&path)?;
        if reads < 3 {
            replace(&path, &format!("revision-{reads}"));
        }
        snapshot.verify().context("host installation validation")?;
        Ok(snapshot.text)
    })
    .await
    .unwrap();
    assert_eq!(reads, 3);
    assert_eq!(value.as_deref(), Some("revision-2"));
}

#[tokio::test]
async fn continuous_replacement_exhausts_the_budget_and_preserves_the_error() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("settings.json");
    replace(&path, "same bytes");
    let mut reads = 0;
    let error = retry_read(|| {
        reads += 1;
        let snapshot = Snapshot::read(&path)?;
        replace(&path, "same bytes");
        snapshot.verify()
    })
    .await
    .unwrap_err();
    assert_eq!(reads, 3);
    assert!(error.is::<SnapshotChanged>());
    assert_eq!(fs::read_to_string(path).unwrap(), "same bytes");
}

#[tokio::test]
async fn retries_refuse_changed_authorization_and_unsafe_files_without_repair() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("settings.json");
    replace(&path, "enabled");
    let mut reads = 0;
    let error = retry_read(|| {
        reads += 1;
        let snapshot = Snapshot::read(&path)?;
        ensure!(snapshot.text.as_deref() == Some("enabled"), "disabled");
        replace(&path, "disabled");
        snapshot.verify()
    })
    .await
    .unwrap_err();
    assert_eq!(reads, 2);
    assert_eq!(error.to_string(), "disabled");
    assert_eq!(fs::read_to_string(&path).unwrap(), "disabled");

    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    reads = 0;
    let error = retry_read(|| {
        reads += 1;
        Snapshot::read(&path)
    })
    .await
    .unwrap_err();
    assert_eq!(reads, 1);
    assert!(!error.is::<SnapshotChanged>());
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o666
    );
}
