use super::*;
use std::os::unix::fs::MetadataExt;

fn home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    config::initialize(home.path(), "original").unwrap();
    home
}

#[test]
fn literal_editor_arguments_support_quotes_without_shell_evaluation() {
    assert_eq!(
        arguments("'/path with spaces/editor' --wait '$HOME' '`id`' ';'").unwrap(),
        ["/path with spaces/editor", "--wait", "$HOME", "`id`", ";"]
    );
    for text in ["", "''", "'unmatched", "editor\nother", "editor\0private"] {
        assert!(arguments(text).is_err());
    }
    assert!(arguments(&"x".repeat(16 * 1024 + 1)).is_err());
    assert!(arguments(&"x ".repeat(65)).is_err());
}

#[test]
fn successful_edit_retains_comments_local_settings_and_identity() {
    let root = home();
    let path = config::path(root.path());
    let original = fs::read_to_string(&path).unwrap();
    let draft = Draft::prepare(root.path()).unwrap();
    let changed = original.replace("name = \"original\"", "name = \"renamed\"")
        + "\n# local preference retained verbatim\n[my_local_settings]\ncolor = 'blue'\n";
    fs::write(&draft.path, &changed).unwrap();
    assert!(draft.save().unwrap());
    assert_eq!(fs::read_to_string(&path).unwrap(), changed);
    let after = config::load(root.path()).unwrap();
    let before = parse(&original).unwrap();
    assert_eq!(after.node.id, before.node.id);
    assert_eq!(after.cluster.id, before.cluster.id);
    assert_eq!(after.cluster.name, "renamed");
    assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
    let temporary = draft.directory.path().to_path_buf();
    drop(draft);
    assert!(!temporary.exists());
}

#[test]
fn concurrent_writer_wins_and_the_editor_draft_remains_available() {
    let root = home();
    let draft = Draft::prepare(root.path()).unwrap();
    let changed = fs::read_to_string(&draft.path)
        .unwrap()
        .replace("original", "editor-name");
    fs::write(&draft.path, &changed).unwrap();
    // This is the actual lock/write path used by local settings commands.
    config::edit_local(root.path(), |cfg| {
        cfg.node.name = "concurrent-name".into();
        Ok(())
    })
    .unwrap();
    let current = fs::read(config::path(root.path())).unwrap();
    let retained = draft.path.clone();
    let error = draft.save().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("changed while the editor was open")
    );
    assert!(format!("{:#}", draft.preserve(error)).contains("draft retained"));
    assert_eq!(fs::read(config::path(root.path())).unwrap(), current);
    assert_eq!(fs::read_to_string(retained).unwrap(), changed);
}

#[test]
fn unchanged_draft_never_overwrites_a_concurrent_projection() {
    let root = home();
    let draft = Draft::prepare(root.path()).unwrap();
    config::edit_local(root.path(), |cfg| {
        cfg.node.name = "newer".into();
        Ok(())
    })
    .unwrap();
    let path = config::path(root.path());
    let before = fs::metadata(&path).unwrap();
    assert!(!draft.save().unwrap());
    let after = fs::metadata(&path).unwrap();
    assert_eq!(
        (before.ino(), before.mtime(), before.mtime_nsec()),
        (after.ino(), after.mtime(), after.mtime_nsec())
    );
    assert_eq!(config::load(root.path()).unwrap().node.name, "newer");
}

#[test]
fn invalid_changed_or_unsafe_drafts_never_replace_live_configuration() {
    let root = home();
    let path = config::path(root.path());
    let original = fs::read(&path).unwrap();
    let draft = Draft::prepare(root.path()).unwrap();
    fs::write(&draft.path, "secret = 'DO_NOT_ECHO_THIS_VALUE\n").unwrap();
    let error = draft.save().unwrap_err();
    assert!(!format!("{error:#}").contains("DO_NOT_ECHO_THIS_VALUE"));
    let mut identity = config::load(root.path()).unwrap();
    identity.node.id = uuid::Uuid::new_v4().to_string();
    fs::write(&draft.path, toml::to_string(&identity).unwrap()).unwrap();
    assert!(draft.save().unwrap_err().to_string().contains("identity"));
    fs::write(&draft.path, &original).unwrap();
    fs::set_permissions(&draft.path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(draft.save().is_err());
    fs::remove_file(&draft.path).unwrap();
    std::os::unix::fs::symlink(&path, &draft.path).unwrap();
    assert!(draft.save().is_err());
    fs::remove_file(&draft.path).unwrap();
    fs::hard_link(&path, &draft.path).unwrap();
    assert!(draft.save().is_err());
    fs::remove_file(&draft.path).unwrap();
    assert!(draft.save().is_err());
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn managed_local_metadata_and_service_routing_cannot_be_reassigned() {
    let before = config::fresh("original").unwrap();
    for field in [
        "contexts",
        "account_source",
        "profile_setup",
        "gateway_registry",
        "host_recovery",
        "hosted_parent",
        "portable_web",
        "local_features",
    ] {
        let mut after = before.clone();
        after
            .extra
            .insert(field.into(), toml::Value::String("replacement".into()));
        assert!(protected(&before, &after).is_err());
    }
    let mut before = before;
    before.cluster.local_only = false;
    before.service = Some(config::ServiceConfig {
        origin: "https://service.example".into(),
        account_id: uuid::Uuid::new_v4().to_string(),
    });
    before.relay = Some(config::RelayConfig {
        endpoint: "https://relay.example".into(),
        credential_file: "/private/relay.key".into(),
    });
    before.validate().unwrap();
    let mut after = before.clone();
    after.relay.as_mut().unwrap().endpoint = "https://another.example".into();
    after.validate().unwrap();
    assert!(protected(&before, &after).is_err());
}

#[test]
fn recovery_guard_prevents_preparation_and_late_saves() {
    let root = home();
    let draft = Draft::prepare(root.path()).unwrap();
    let original = fs::read(config::path(root.path())).unwrap();
    let changed = fs::read_to_string(&draft.path)
        .unwrap()
        .replace("original", "edited");
    fs::write(&draft.path, changed).unwrap();
    fs::write(root.path().join(recovery::MARKER), "{}").unwrap();
    assert!(Draft::prepare(root.path()).is_err());
    assert!(
        draft
            .save()
            .unwrap_err()
            .to_string()
            .contains("offline recovery")
    );
    assert_eq!(fs::read(config::path(root.path())).unwrap(), original);
}

#[test]
fn over_limit_in_memory_edit_preserves_the_readable_configuration() {
    let root = home();
    let original = open(root.path()).unwrap();
    let oversized = "#".repeat(managed_file::LIMIT as usize + 1);
    let error = save_text(root.path(), &original, &oversized, || Ok(())).unwrap_err();
    assert!(error.to_string().contains("too large"));
    original.verify().unwrap();
}
