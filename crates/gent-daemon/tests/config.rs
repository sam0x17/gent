use gent_daemon::config;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

#[test]
fn initialization_is_non_destructive_and_secrets_are_private() {
    let root = private_tempdir();
    let home = root.path().join("state");
    let initial = config::initialize(&home, "trial").unwrap();
    let key = config::read_private(&home.join("owner.key")).unwrap();
    assert!(config::initialize(&home, "replacement").is_err());
    assert_eq!(config::load(&home).unwrap().node.id, initial.node.id);
    assert_eq!(config::read_private(&home.join("owner.key")).unwrap(), key);
    assert_eq!(
        fs::metadata(home.join("config.toml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    let mut changed = initial.clone();
    changed.node.name = "renamed".into();
    changed.extra.insert(
        "local_preference".into(),
        toml::Value::String("preserve".into()),
    );
    config::save(&home, &changed).unwrap();
    let changed = config::load(&home).unwrap();
    assert_eq!(changed.node.id, initial.node.id);
    assert_eq!(changed.extra["local_preference"].as_str(), Some("preserve"));
}

#[test]
fn invalid_edits_do_not_replace_working_configuration() {
    let root = private_tempdir();
    let mut cfg = config::initialize(root.path(), "trial").unwrap();
    let original = fs::read(config::path(root.path())).unwrap();
    cfg.node.name = "\n".into();
    assert!(config::save(root.path(), &cfg).is_err());
    assert_eq!(fs::read(config::path(root.path())).unwrap(), original);
    cfg.node.name = "valid".into();
    cfg.policy.rules.push(gent_protocol::Rule {
        actor: gent_protocol::Selector::Group("missing".into()),
        peer: gent_protocol::Selector::All,
        permission: gent_protocol::Permission::Enumerate,
        effect: gent_protocol::Effect::Allow,
    });
    assert!(cfg.validate().is_err());
    assert!(config::save(root.path(), &cfg).is_err());
    assert_eq!(fs::read(config::path(root.path())).unwrap(), original);
    cfg.policy.rules.clear();
    cfg.node.id = uuid::Uuid::nil().to_string();
    assert!(cfg.validate().is_err());
}

#[test]
fn shared_directories_and_symlink_credentials_are_rejected_without_chmod() {
    let root = private_tempdir();
    let shared = root.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(config::initialize(&shared, "trial").is_err());
    assert_eq!(
        fs::metadata(&shared).unwrap().permissions().mode() & 0o777,
        0o755
    );
    let key = root.path().join("key");
    config::binding(&key).unwrap();
    let alias = root.path().join("alias");
    symlink(&key, &alias).unwrap();
    assert!(config::read_private(&alias).is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(config::read_private(&key).is_err());
}

fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
