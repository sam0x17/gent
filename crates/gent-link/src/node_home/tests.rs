use super::*;
use std::fs;

pub(crate) fn legacy_registry(root: &Path, child: &Path) {
    let root_cfg = inspect(root).unwrap();
    let child_cfg = if config::path(child).exists() {
        inspect(child).unwrap()
    } else {
        config::initialize(child, "legacy").unwrap()
    };
    config::edit_local(root, |cfg| {
        cfg.set_contexts(config::Contexts {
            version: 1,
            active_cluster: child_cfg.cluster.id.clone(),
            profiles: [
                (
                    root_cfg.cluster.id.clone(),
                    config::ContextProfile {
                        home: root.into(),
                        node_id: root_cfg.node.id.clone(),
                    },
                ),
                (
                    child_cfg.cluster.id,
                    config::ContextProfile {
                        home: child.into(),
                        node_id: child_cfg.node.id,
                    },
                ),
            ]
            .into(),
        })
    })
    .unwrap();
}

#[test]
fn resolution_is_read_only_and_never_redirects() {
    let dir = tempfile::tempdir().unwrap();
    let home = managed_file::normalize(&dir.path().join("node")).unwrap();
    assert_eq!(resolve(&home, None).unwrap(), home);
    assert!(resolve(&home, Some("missing")).is_err());
    assert!(!home.exists());
    let cfg = config::initialize(&home, "personal").unwrap();
    let before = fs::read(config::path(&home)).unwrap();
    for expected in [None, Some(cfg.cluster.id.as_str()), Some("personal")] {
        assert_eq!(resolve(&home, expected).unwrap(), home);
    }
    assert!(resolve(&home, Some("other")).is_err());
    assert_eq!(fs::read(config::path(&home)).unwrap(), before);
    legacy_registry(&home, &home.join("clusters/old"));
    assert!(
        resolve(&home, None)
            .unwrap_err()
            .to_string()
            .contains("gent node reset")
    );
    assert!(resolve(&home, Some(&cfg.cluster.id)).is_err());
}

#[tokio::test]
async fn creation_retries_preserve_identity_but_second_cluster_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let home = managed_file::normalize(&dir.path().join("node")).unwrap();
    provision::create(&home, "personal".into(), true)
        .await
        .unwrap();
    let config = fs::read(config::path(&home)).unwrap();
    let key = fs::read(home.join("owner.key")).unwrap();
    let daemon = managed_file::lock(&home.join("daemon.lock")).unwrap();
    assert_eq!(
        provision::create(&home, "personal".into(), true)
            .await
            .unwrap()["already_configured"],
        true
    );
    for (name, local) in [("second", true), ("personal", false)] {
        let error = provision::create(&home, name.into(), local)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("already belongs"));
    }
    assert_eq!(fs::read(config::path(&home)).unwrap(), config);
    assert_eq!(fs::read(home.join("owner.key")).unwrap(), key);
    assert!(!home.join("clusters").exists());
    drop(daemon);
}

#[test]
fn archives_symlinks_and_shared_account_markers_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let home = managed_file::normalize(&dir.path().join("node")).unwrap();
    config::initialize(&home, "personal").unwrap();
    let alias = home.with_file_name("alias");
    std::os::unix::fs::symlink(&home, &alias).unwrap();
    assert!(resolve(&alias, None).is_err());
    config::private_dir(&home.join("auth")).unwrap();
    config::write_private(&home.join("auth/account-source.json"), b"{}").unwrap();
    assert!(resolve(&home, None).is_err());
    fs::remove_file(home.join("auth/account-source.json")).unwrap();
    config::write_private(&home.join(gent_daemon::recovery::MARKER), b"{}").unwrap();
    assert!(resolve(&home, None).is_err());
    assert!(resolve(&home.join("missing"), None).is_err());
    assert!(!home.join("missing").exists());
}

#[test]
fn unapplied_policy_errors_do_not_hide_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("node");
    let mut cfg = config::initialize(&home, "node").unwrap();
    cfg.policy.rules.push(gent_protocol::Rule {
        actor: gent_protocol::Selector::Agent("invalid".into()),
        peer: gent_protocol::Selector::All,
        permission: gent_protocol::Permission::Send,
        effect: gent_protocol::Effect::Allow,
    });
    assert!(cfg.validate().is_err());
    config::write_private(
        &config::path(&home),
        toml::to_string(&cfg).unwrap().as_bytes(),
    )
    .unwrap();
    assert!(resolve(&home, None).is_ok());
}

#[tokio::test]
async fn a_new_join_code_is_rejected_before_login_or_network_access() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("node");
    config::initialize(&home, "personal").unwrap();
    let before = fs::read(config::path(&home)).unwrap();
    let code = gent_crypto::pairing::Code::generate().unwrap();
    let error = crate::enrollment::join(
        &home,
        crate::pairing::JoinArgs::code(Some(code.expose().to_string())),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("already enrolled"));
    assert!(!home.join("auth").exists());
    assert_eq!(fs::read(config::path(&home)).unwrap(), before);
}
