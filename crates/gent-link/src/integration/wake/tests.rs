use super::*;
use crate::integration::{Bindings, Host};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

fn fixture() -> (tempfile::TempDir, Bindings, Registry) {
    let home = tempfile::tempdir_in("/tmp").unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    config::initialize(home.path(), "wake-recovery").unwrap();
    let mut bindings = Bindings::new(home.path(), Host::Codex).unwrap();
    let registry = bindings
        .enable_wake(home.path(), &home.path().join("host.sock"))
        .unwrap();
    (home, bindings, registry)
}
fn bind(bindings: &mut Bindings, thread: &str) -> String {
    bindings
        .credential(
            "codex-mcp-client",
            &json!({"threadId":thread,"sessionId":"shared-tree"}),
            "gent_register",
            &json!({}),
        )
        .unwrap()
}

#[test]
fn wake_attachments_survive_restart_without_stealing_live_binding_locks() {
    let (home, mut bindings, registry) = fixture();
    let a = uuid::Uuid::now_v7().to_string();
    let b = uuid::Uuid::now_v7().to_string();
    assert!(registry.credential(&a).unwrap().is_none());
    let first = bind(&mut bindings, &a);
    let second = bind(&mut bindings, &b);
    assert_ne!(first, second);
    assert_eq!(
        registry.credential(&a).unwrap().as_deref(),
        Some(first.as_str())
    );
    assert_eq!(
        registry.credential(&b).unwrap().as_deref(),
        Some(second.as_str())
    );
    let record = fs::read_to_string(binding::sidecar(
        &key_path(&registry.folder, &a),
        ".wake.json",
    ))
    .unwrap();
    assert!(!record.contains(&first));
    let mut competing = Bindings::new(home.path(), Host::Codex).unwrap();
    assert!(
        competing
            .credential(
                "codex-mcp-client",
                &json!({"threadId":a}),
                "gent_inbox",
                &json!({})
            )
            .is_err()
    );
    drop(bindings);
    let restarted = competing
        .enable_wake(home.path(), &home.path().join("host.sock"))
        .unwrap();
    // Recovery reads existing files before this MCP connection has seen a call.
    assert_eq!(
        restarted.credential(&a).unwrap().as_deref(),
        Some(first.as_str())
    );
    assert_eq!(bind(&mut competing, &a), first);
}

#[test]
fn wake_is_endpoint_scoped_and_survives_a_polling_reconnect() {
    let (home, mut bindings, registry) = fixture();
    let thread = uuid::Uuid::now_v7().to_string();
    let credential = bind(&mut bindings, &thread);
    let alternate = Registry::new(
        home.path(),
        registry.folder.clone(),
        registry.cfg.clone(),
        &home.path().join("another.sock"),
    )
    .unwrap();
    assert!(alternate.credential(&thread).unwrap().is_none());
    drop(bindings);
    let mut polling = Bindings::new(home.path(), Host::Codex).unwrap();
    assert_eq!(bind(&mut polling, &thread), credential);
    assert_eq!(
        registry.credential(&thread).unwrap().as_deref(),
        Some(credential.as_str())
    );
    polling
        .enable_wake(home.path(), &home.path().join("another.sock"))
        .unwrap();
    assert_eq!(bind(&mut polling, &thread), credential);
    assert_eq!(
        alternate.credential(&thread).unwrap().as_deref(),
        Some(credential.as_str())
    );
    assert!(registry.credential(&thread).unwrap().is_none());
}

#[test]
fn wake_recovery_refuses_changed_credentials_scopes_records_and_offline_backups() {
    let (home, mut bindings, registry) = fixture();
    let thread = uuid::Uuid::now_v7().to_string();
    let original = bind(&mut bindings, &thread);
    drop(bindings);
    let path = key_path(&registry.folder, &thread);
    let marker = binding::sidecar(&path, ".wake.json");
    let scope = binding::sidecar(&path, ".scope.json");
    let saved = fs::read(&marker).unwrap();
    let saved_scope = fs::read(&scope).unwrap();
    for field in ["cluster_id", "node_id", "thread", "credential_hash"] {
        let mut value: serde_json::Value = serde_json::from_slice(&saved).unwrap();
        value[field] = "wrong".into();
        config::write_private(&marker, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(registry.credential(&thread).is_err());
    }
    config::write_private(&marker, &saved).unwrap();
    config::write_private(&path, config::secret().as_bytes()).unwrap();
    assert!(registry.credential(&thread).is_err());
    config::write_private(&path, original.as_bytes()).unwrap();
    fs::remove_file(&scope).unwrap();
    assert!(registry.credential(&thread).is_err());
    assert!(!scope.exists());
    config::write_private(&scope, &saved_scope).unwrap();
    config::write_private(&home.path().join(gent_daemon::recovery::MARKER), b"offline").unwrap();
    assert!(registry.credential(&thread).is_err());
    assert!(registry.coordinator().is_err());
    fs::remove_file(home.path().join(gent_daemon::recovery::MARKER)).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(registry.credential(&thread).is_err());
    assert!(!path.exists());
}

#[test]
fn wake_records_reject_links_oversize_and_unknown_versions_without_repair() {
    let (_home, mut bindings, registry) = fixture();
    let thread = uuid::Uuid::now_v7().to_string();
    bind(&mut bindings, &thread);
    drop(bindings);
    let path = binding::sidecar(&key_path(&registry.folder, &thread), ".wake.json");
    let saved = fs::read(&path).unwrap();
    for body in [b"{}".to_vec(), vec![b'x'; 4097]] {
        config::write_private(&path, &body).unwrap();
        assert!(registry.credential(&thread).is_err());
        assert_eq!(fs::read(&path).unwrap(), body);
    }
    let mut value: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    value["version"] = 2.into();
    config::write_private(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(registry.credential(&thread).is_err());
    config::write_private(&path, &saved).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(registry.credential(&thread).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let linked = path.with_extension("linked");
    fs::hard_link(&path, &linked).unwrap();
    assert!(registry.credential(&thread).is_err());
    fs::remove_file(&linked).unwrap();
    fs::rename(&path, &linked).unwrap();
    std::os::unix::fs::symlink(&linked, &path).unwrap();
    assert!(registry.credential(&thread).is_err());
}

#[test]
fn wake_coordinator_election_survives_exit_and_socket_alias_changes() {
    let (home, _bindings, registry) = fixture();
    let alias = home.path().join("alias");
    std::os::unix::fs::symlink(home.path(), &alias).unwrap();
    let other = Registry::new(
        home.path(),
        registry.folder.clone(),
        registry.cfg.clone(),
        &alias.join("host.sock"),
    )
    .unwrap();
    assert_eq!(registry.endpoint, other.endpoint);
    let lease = registry.coordinator().unwrap().unwrap();
    assert!(other.coordinator().unwrap().is_none());
    drop(lease);
    assert!(other.coordinator().unwrap().is_some());
    std::os::unix::fs::symlink(
        home.path().join("physical-old"),
        home.path().join("host.sock"),
    )
    .unwrap();
    let before = endpoint(&home.path().join("host.sock")).unwrap();
    fs::remove_file(home.path().join("host.sock")).unwrap();
    std::os::unix::fs::symlink(
        home.path().join("physical-new"),
        home.path().join("host.sock"),
    )
    .unwrap();
    assert_eq!(before, endpoint(&home.path().join("host.sock")).unwrap());
    assert!(endpoint(&alias.join("../host.sock")).is_err());
}

#[test]
fn wake_registration_uses_host_metadata_and_never_adopts_legacy_or_unknown_keys() {
    let (home, mut bindings, registry) = fixture();
    let a = uuid::Uuid::now_v7().to_string();
    let b = uuid::Uuid::now_v7().to_string();
    assert!(
        bindings
            .credential("other", &json!({"threadId":a}), "gent_register", &json!({}))
            .is_err()
    );
    assert!(
        bindings
            .credential(
                "codex-mcp-client",
                &json!({"sessionId":a}),
                "gent_register",
                &json!({"threadId":a})
            )
            .is_err()
    );
    let credential = bindings
        .credential(
            "codex-mcp-client",
            &json!({"threadId":a,"sessionId":b}),
            "gent_register",
            &json!({"threadId":b}),
        )
        .unwrap();
    assert_eq!(
        registry.credential(&a).unwrap().as_deref(),
        Some(credential.as_str())
    );
    assert!(registry.credential(&b).unwrap().is_none());
    drop(bindings);
    let mut legacy = Bindings::new(home.path(), Host::Codex).unwrap();
    bind(&mut legacy, &b);
    assert!(registry.credential(&b).unwrap().is_none());
    let mut claude = Bindings::new(home.path(), Host::ClaudeCode).unwrap();
    assert!(
        claude
            .enable_wake(home.path(), &home.path().join("host.sock"))
            .is_err()
    );
    assert!(registry.credential("../escape").is_err());
}

#[test]
fn wake_attachment_write_failure_keeps_the_same_binding_for_a_later_retry() {
    let (home, mut bindings, registry) = fixture();
    let thread = uuid::Uuid::now_v7().to_string();
    let path = key_path(&registry.folder, &thread);
    let marker = binding::sidecar(&path, ".wake.json");
    fs::create_dir(&marker).unwrap();
    let call = |b: &mut Bindings| {
        b.credential(
            "codex-mcp-client",
            &json!({"threadId":thread}),
            "gent_register",
            &json!({}),
        )
    };
    assert!(call(&mut bindings).is_err());
    let credential = config::read_private(&path).unwrap();
    assert!(registry.credential(&thread).is_err());
    fs::remove_dir(&marker).unwrap();
    assert_eq!(call(&mut bindings).unwrap(), credential);
    assert_eq!(
        registry.credential(&thread).unwrap().as_deref(),
        Some(credential.as_str())
    );
    drop(bindings);
    let mut restarted = Bindings::new(home.path(), Host::Codex).unwrap();
    restarted
        .enable_wake(home.path(), &home.path().join("host.sock"))
        .unwrap();
    assert_eq!(call(&mut restarted).unwrap(), credential);
}
