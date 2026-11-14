use super::*;
use std::{
    collections::BTreeMap,
    os::unix::fs::{PermissionsExt, symlink},
};

fn root() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn options(root: &Path) -> Options {
    Options {
        online: false,
        codex_config_dir: Some(root.join("codex")),
        claude_config_dir: Some(root.join("claude")),
        hooks: hooks::Options {
            shell: Some(hooks::Shell::Zsh),
            rc_file: Some(root.join("zshrc")),
        },
    }
}
// Capture paths directly, without opening sockets or following links.
fn tree(root: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        let meta = fs::symlink_metadata(&path).unwrap();
        if meta.is_dir() {
            result.extend(tree(&path));
        } else if meta.is_file() {
            let bytes = fs::read(&path).unwrap();
            result.insert(path, (meta.mode(), bytes));
        }
    }
    result
}
fn check<'a>(report: &'a Report, name: &str) -> &'a Check {
    report.checks.iter().find(|c| c.id == name).unwrap()
}

#[tokio::test]
async fn missing_and_malformed_profiles_do_not_create_files_or_echo_config_secrets() {
    let dir = root();
    let home = dir.path().join("node");
    let before = tree(dir.path());
    let report = run(&home, None, options(dir.path())).await;
    assert_eq!(report.exit_code(), 3);
    assert_eq!(check(&report, "configuration").status, Status::Fail);
    assert_eq!(tree(dir.path()), before);
    config::initialize(&home, "diagnostic").unwrap();
    fs::write(config::path(&home), "[bad PRIVATE-CONFIG-SENTINEL").unwrap();
    let before = tree(dir.path());
    let report = run(&home, None, options(dir.path())).await;
    assert!(report.home.is_none());
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("PRIVATE-CONFIG-SENTINEL")
    );
    assert_eq!(tree(dir.path()), before);
}

#[tokio::test]
async fn stopped_profiles_and_bad_credentials_are_reported_without_initialization() {
    let dir = root();
    let home = dir.path().join("node");
    config::initialize(&home, "diagnostic").unwrap();
    let before = tree(dir.path());
    let report = run(&home, None, options(dir.path())).await;
    assert_eq!(check(&report, "daemon").status, Status::Fail);
    assert_eq!(check(&report, "local_state").status, Status::Skip);
    assert_eq!(check(&report, "gateway").status, Status::Skip);
    assert_eq!(tree(dir.path()), before);
    fs::set_permissions(home.join("owner.key"), fs::Permissions::from_mode(0o644)).unwrap();
    let before = tree(dir.path());
    let report = run(&home, None, options(dir.path())).await;
    assert_eq!(check(&report, "local_state").status, Status::Fail);
    assert_eq!(tree(dir.path()), before);
    fs::remove_file(home.join("owner.key")).unwrap();
    symlink(dir.path().join("missing"), home.join("owner.key")).unwrap();
    let report = run(&home, None, options(dir.path())).await;
    assert_eq!(check(&report, "local_state").status, Status::Fail);
    assert!(
        fs::symlink_metadata(home.join("owner.key"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[tokio::test]
async fn selected_profiles_are_pinned_and_broken_selection_never_falls_back() {
    let dir = root();
    let home = dir.path().join("primary");
    let second = dir.path().join("second");
    let first = config::initialize(&home, "primary").unwrap();
    let other = config::initialize(&second, "secondary").unwrap();
    contexts::add(&home, &second).unwrap();
    contexts::switch(&home, Some(other.cluster.id.clone()), false).unwrap();
    let report = run(&home, Some(&first.cluster.id), options(dir.path())).await;
    assert_eq!(report.cluster_id, Some(first.cluster.id.clone()));
    let advice = check(&report, "daemon")
        .next
        .as_ref()
        .unwrap()
        .command
        .as_ref()
        .unwrap();
    assert!(
        advice
            .windows(2)
            .any(|s| s == ["--cluster", first.cluster.id.as_str()])
    );
    fs::remove_file(config::path(&second)).unwrap();
    let report = run(&home, None, options(dir.path())).await;
    assert!(report.home.is_none());
    assert!(!report.checks.iter().any(|c| c.id == "daemon"));
}

#[test]
fn classification_uses_scope_freshness_and_whitelisted_evidence() {
    let dir = root();
    let cfg = config::initialize(dir.path(), "diagnostic").unwrap();
    let mut report = Report {
        version: 1,
        home: Some(dir.path().into()),
        cluster_id: Some(cfg.cluster.id.clone()),
        online: false,
        checks: vec![],
    };
    let mut value = json!({"version":1,"cluster_id":cfg.cluster.id,"node_id":cfg.node.id,"process_id":1,
        "authority":{"revision":1,"fresh":false,"clock_ahead":true,"member":true,"private":"PRIVATE-SENTINEL"},
        "config_saved":false,"relay":{"configured":true,"health":{"observed_at":auth::now().unwrap(),"retrying_streams":2,"last_success_at":auth::now().unwrap()}}});
    inspect_daemon(&mut report, Some(value.clone()), &cfg);
    assert_eq!(check(&report, "authority").status, Status::Fail);
    assert_eq!(check(&report, "relay").status, Status::Warn);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("PRIVATE-SENTINEL")
    );
    report.checks.clear();
    value["cluster_id"] = json!("wrong");
    inspect_daemon(&mut report, Some(value), &cfg);
    assert_eq!(report.checks.len(), 1);
    assert_eq!(check(&report, "daemon").status, Status::Fail);
    assert_eq!(shell_arg("a'$(x)"), "'a'\\''$(x)'");
}
