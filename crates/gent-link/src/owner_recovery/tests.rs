use super::*;
use clap::Parser;
use gent_crypto::{NodeIdentity, OwnerKey};
use std::os::unix::fs::symlink;

fn temp() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn evidence(dir: &Path) -> (PathBuf, PathBuf, RecoveryBaseline) {
    let now = gent_daemon::store::now() as u64;
    let node = NodeIdentity::generate().unwrap();
    let owner = OwnerKey::generate().unwrap();
    let state = owner
        .create_cluster("private cluster name", &node, "private node name", now)
        .unwrap();
    let baseline = RecoveryBaseline::new(&state, now).unwrap();
    let report = node
        .observe_recovery(&state, &baseline.challenge, now)
        .unwrap();
    let challenge = destination(&dir.join("challenge.json")).unwrap();
    let witness = destination(&dir.join("witness.json")).unwrap();
    write(&challenge, &baseline.encode().unwrap()).unwrap();
    write(&witness, &report.encode().unwrap()).unwrap();
    (challenge, witness, baseline)
}

#[test]
fn private_files_refuse_links_shared_modes_and_overwrite_including_late_creation() {
    let dir = temp();
    let path = destination(&dir.path().join("nested/report")).unwrap();
    write(&path, b"private evidence").unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(destination(&path).is_err());
    assert!(write(&path, b"replacement").is_err());
    assert_eq!(read(&path).unwrap(), b"private evidence");
    let link = dir.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(read(&link).is_err() && destination(&link).is_err());
    fs::remove_file(&link).unwrap();
    fs::hard_link(&path, &link).unwrap();
    assert!(read(&path).is_err());
    fs::remove_file(&link).unwrap();
    for mode in [0o640, 0o660, 0o644] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(read(&path).is_err());
    }
    let late = destination(&dir.path().join("late")).unwrap();
    // Another writer wins after destination validation.
    fs::write(&late, "winner").unwrap();
    assert!(write(&late, b"loser").is_err());
    assert_eq!(fs::read(&late).unwrap(), b"winner");
    let linked = destination(&dir.path().join("late-link")).unwrap();
    symlink(&late, &linked).unwrap();
    assert!(write(&linked, b"loser").is_err());
    assert_eq!(fs::read(&late).unwrap(), b"winner");
}

#[test]
fn inspection_reports_missing_peers_without_exposing_policy_and_rejects_bad_evidence() {
    let dir = temp();
    let (challenge, witness, _) = evidence(dir.path());
    let complete = inspect(&challenge, std::slice::from_ref(&witness)).unwrap();
    assert_eq!(complete["all_match_baseline"], true);
    assert_eq!(complete["authorizes_owner_change"], false);
    assert_eq!(complete["proves_writer_stopped"], false);
    assert_eq!(complete["proves_global_freshness"], false);
    assert!(!complete.to_string().contains("private cluster name"));
    assert!(!complete.to_string().contains("private node name"));
    assert!(complete.get("state").is_none() && complete.get("policy").is_none());
    let missing = inspect(&challenge, &[]).unwrap();
    assert_eq!(missing["all_match_baseline"], false);
    assert_eq!(missing["missing_nodes"].as_array().unwrap().len(), 1);
    assert!(inspect(&challenge, &[witness.clone(), witness.clone()]).is_err());
    let other = temp();
    let (_, foreign, _) = evidence(other.path());
    assert!(inspect(&challenge, &[foreign]).is_err());
    let mut report = SignedRecoveryObservation::decode(&read(&witness).unwrap()).unwrap();
    report.signature[0] ^= 1;
    fs::write(&witness, report.encode().unwrap()).unwrap();
    assert!(inspect(&challenge, std::slice::from_ref(&witness)).is_err());
    let mut original = read(&challenge).unwrap();
    original.push(b'\n');
    fs::write(&challenge, original).unwrap();
    assert!(inspect(&challenge, &[]).is_err());
    assert!(inspect(&challenge, &vec![witness; 1025]).is_err());
}

#[tokio::test]
async fn inspection_needs_no_live_home_and_does_not_activate_an_offline_copy() {
    let dir = temp();
    let (challenge, witness, _) = evidence(dir.path());
    let home = dir.path().join("uninitialized");
    let command = |extra: &[&str]| {
        let mut args = vec!["gent", "--home", home.to_str().unwrap(), "--json"];
        args.extend_from_slice(extra);
        args.extend([
            "recovery",
            "inspect",
            challenge.to_str().unwrap(),
            witness.to_str().unwrap(),
        ]);
        crate::Cli::try_parse_from(args).unwrap()
    };
    crate::execute(command(&[])).await.unwrap();
    assert!(!home.exists());
    assert!(
        crate::execute(command(&["--cluster", "another"]))
            .await
            .is_err()
    );
    fs::create_dir(&home).unwrap();
    let marker = home.join("recovery-required.json");
    fs::write(&marker, b"offline").unwrap();
    crate::execute(command(&[])).await.unwrap();
    assert_eq!(fs::read(&marker).unwrap(), b"offline");
    assert_eq!(fs::read_dir(&home).unwrap().count(), 1);
}
