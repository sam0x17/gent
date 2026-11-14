use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    sync::{Arc, Barrier},
};

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    export: PathBuf,
    registry: Registry,
    token: String,
    id: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("node");
        config::initialize(&home, "gateway").unwrap();
        let export = home.join("host.json");
        let result = add(&home, "host", "test/conversation", &export, 24).unwrap();
        let record: Export = serde_json::from_slice(&fs::read(&export).unwrap()).unwrap();
        assert!(!result.to_string().contains(record.token.as_ref().unwrap()));
        let registry = Registry::open(&home).unwrap();
        Self {
            _temp: temp,
            home,
            export,
            registry,
            token: record.token.unwrap(),
            id: record.client,
        }
    }
    fn permit(&self) -> Permit {
        self.registry.authenticate(&self.token).unwrap()
    }
    fn bind(&self, id: &str) -> String {
        self.registry
            .credential(&self.permit(), &json!({"test/conversation":id}))
            .unwrap()
    }
}

#[test]
fn host_namespaces_and_conversations_are_durable_and_cannot_be_selected_by_arguments() {
    let f = Fixture::new();
    let a = f.bind("private-chat-a");
    let b = f.bind("private-chat-b");
    assert_ne!(a, b);
    let second = f.home.join("second.json");
    add(&f.home, "second", "test/conversation", &second, 24).unwrap();
    let export: Export = serde_json::from_slice(&fs::read(second).unwrap()).unwrap();
    let permit = f
        .registry
        .authenticate(export.token.as_deref().unwrap())
        .unwrap();
    assert_ne!(
        a,
        f.registry
            .credential(&permit, &json!({"test/conversation":"private-chat-a"}))
            .unwrap()
    );
    let reopened = Registry::open(&f.home).unwrap();
    assert_eq!(
        a,
        reopened
            .credential(&f.permit(), &json!({"test/conversation":"private-chat-a"}))
            .unwrap()
    );
    for meta in [
        json!({}),
        json!({"conversation":"private-chat-a"}),
        json!({"test/conversation":42}),
        json!({"test/conversation":""}),
        json!({"test/conversation":"a\nb"}),
        json!({"test/conversation":"x".repeat(513)}),
    ] {
        assert!(reopened.credential(&f.permit(), &meta).is_err());
    }
    assert_eq!(
        f.registry.listing().unwrap()["clients"][0]["conversations"]
            .as_u64()
            .unwrap()
            + f.registry.listing().unwrap()["clients"][1]["conversations"]
                .as_u64()
                .unwrap(),
        3
    );
    let saved = fs::read_to_string(f.home.join("gateway/state.json")).unwrap();
    for private in [&f.token, "private-chat-a", "private-chat-b"] {
        assert!(!saved.contains(private));
    }
    let listing = f.registry.listing().unwrap().to_string();
    for private in [&f.token, &a, &b] {
        assert!(!listing.contains(private));
    }
}

#[test]
fn codex_remote_threads_are_distinct_and_session_or_call_ids_cannot_replace_them() {
    let f = Fixture::new();
    let mut state = f.registry.read().unwrap();
    state.clients.get_mut(&f.id).unwrap().conversation_key = "threadId".into();
    f.registry.save(&state).unwrap();
    let original = json!({"threadId":"original", "sessionId":"shared", "callId":"one"});
    let first = f.registry.credential(&f.permit(), &original).unwrap();
    assert_eq!(
        first,
        f.registry
            .credential(
                &f.permit(),
                &json!({"threadId":"original", "sessionId":"shared", "callId":"two"})
            )
            .unwrap()
    );
    assert_ne!(
        first,
        f.registry
            .credential(
                &f.permit(),
                &json!({"threadId":"fork", "sessionId":"shared", "callId":"three"})
            )
            .unwrap()
    );
    assert!(
        f.registry
            .credential(
                &f.permit(),
                &json!({"sessionId":"shared", "arguments":{"threadId":"original"}})
            )
            .is_err()
    );
    for key in [
        "sessionId",
        "callId",
        "windowId",
        "itemId",
        "progressToken",
        "claudecode/toolUseId",
        "io.modelcontextprotocol/clientInfo",
    ] {
        assert!(conversation_key(key).is_err(), "accepted {key}");
    }
    let reopened = Registry::open(&f.home).unwrap();
    assert_eq!(first, reopened.credential(&f.permit(), &original).unwrap());

    // An older manually configured call-ID grant can still be revoked. It
    // must not make unrelated clients or the whole registry unreadable.
    let mut state = f.registry.read().unwrap();
    state.clients.get_mut(&f.id).unwrap().conversation_key = "claudecode/toolUseId".into();
    f.registry.save(&state).unwrap();
    let reopened = Registry::open(&f.home).unwrap();
    assert!(
        reopened
            .credential(&f.permit(), &json!({"claudecode/toolUseId":"call"}))
            .is_err()
    );
    reopened.listing().unwrap();
    reopened.revoke(&f.id).unwrap();
}

#[test]
fn lost_export_and_registration_responses_do_not_duplicate_or_reactivate_clients() {
    let f = Fixture::new();
    let original = fs::read(&f.export).unwrap();
    let credential = f.bind("a");
    add(&f.home, "host", "test/conversation", &f.export, 24).unwrap();
    assert_eq!(original, fs::read(&f.export).unwrap());
    assert_eq!(credential, f.bind("a"));
    assert!(add(&f.home, "host", "test/other", &f.export, 24).is_err());
    assert!(add(&f.home, "host", "test/conversation", &f.export, 48).is_err());
    assert!(
        add(
            &f.home,
            "host",
            "test/conversation",
            &f.home.join("lost.json"),
            24
        )
        .is_err()
    );
    // Simulate losing the registry commit after a successful export write.
    let mut state = f.registry.read().unwrap();
    state.clients.clear();
    f.registry.save(&state).unwrap();
    add(&f.home, "host", "test/conversation", &f.export, 24).unwrap();
    assert_eq!(original, fs::read(&f.export).unwrap());
    f.registry.authenticate(&f.token).unwrap();
    let permit = f.permit();
    f.registry.revoke(&f.id).unwrap();
    assert!(f.registry.authenticate(&f.token).is_err());
    assert!(
        f.registry
            .credential(&permit, &json!({"test/conversation":"a"}))
            .is_err()
    );
    assert!(add(&f.home, "host", "test/conversation", &f.export, 24).is_err());
}

#[test]
fn expiry_clock_rollback_and_capacity_fail_closed_without_rebinding() {
    let f = Fixture::new();
    let permit = f.permit();
    let mut state = f.registry.read().unwrap();
    let client = state.clients.get_mut(&f.id).unwrap();
    for i in 0..MAX_CLIENT_BINDINGS {
        client
            .bindings
            .insert(digest(&i.to_string()), config::secret());
    }
    let original = client.bindings[&digest("0")].clone();
    f.registry.save(&state).unwrap();
    assert_eq!(original, f.bind("0"));
    assert!(
        f.registry
            .credential(&permit, &json!({"test/conversation":"new"}))
            .is_err()
    );
    let client = state.clients.get_mut(&f.id).unwrap();
    client.created_at -= 24 * 3600;
    client.expires_at -= 24 * 3600;
    f.registry.save(&state).unwrap();
    assert!(f.registry.authenticate(&f.token).is_err());
    assert!(
        f.registry
            .credential(&permit, &json!({"test/conversation":"0"}))
            .is_err()
    );
    let client = state.clients.get_mut(&f.id).unwrap();
    client.created_at += 24 * 3600;
    client.expires_at += 24 * 3600;
    state.clock = auth::now().unwrap() + 3600;
    f.registry.save(&state).unwrap();
    assert!(f.registry.authenticate(&f.token).is_err());
    assert!(
        f.registry
            .credential(&permit, &json!({"test/conversation":"0"}))
            .is_err()
    );
}

#[test]
fn damaged_missing_or_relocated_registry_never_creates_replacement_identities() {
    let f = Fixture::new();
    let directory = f.home.join("gateway");
    let saved = fs::read(directory.join("state.json")).unwrap();
    fs::write(directory.join("state.json"), b"broken").unwrap();
    assert!(Registry::open(&f.home).is_err());
    assert!(add(&f.home, "host", "test/conversation", &f.export, 24).is_err());
    assert_eq!(fs::read(directory.join("state.json")).unwrap(), b"broken");
    fs::remove_file(directory.join("state.json")).unwrap();
    assert!(add(&f.home, "host", "test/conversation", &f.export, 24).is_err());
    assert!(!directory.join("state.json").exists());
    config::write_private(&directory.join("state.json"), &saved).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(f.registry.authenticate(&f.token).is_err());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let moved = f.home.join("moved");
    fs::rename(&directory, &moved).unwrap();
    symlink(&moved, &directory).unwrap();
    assert!(Registry::open(&f.home).is_err());
    assert!(f.registry.authenticate(&f.token).is_err());
    fs::remove_file(&directory).unwrap();
    fs::rename(&moved, &directory).unwrap();
    let mut cfg = config::load(&f.home).unwrap();
    cfg.node.id = Uuid::new_v4().to_string();
    // External tampering bypasses config::save's identity guard.
    config::write_private(
        &config::path(&f.home),
        toml::to_string(&cfg).unwrap().as_bytes(),
    )
    .unwrap();
    assert!(Registry::open(&f.home).is_err());
    assert!(f.registry.authenticate(&f.token).is_err());
}

#[test]
fn concurrent_first_setup_and_binding_allocation_preserve_one_identity() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("node");
    config::initialize(&home, "parallel").unwrap();
    let barrier = Arc::new(Barrier::new(8));
    std::thread::scope(|scope| {
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let barrier = &barrier;
            let home = &home;
            tasks.push(scope.spawn(move || {
                barrier.wait();
                add(
                    home,
                    "host",
                    "test/conversation",
                    &home.join("host.json"),
                    24,
                )
                .unwrap();
                let export: Export =
                    serde_json::from_slice(&fs::read(home.join("host.json")).unwrap()).unwrap();
                let registry = Registry::open(home).unwrap();
                let permit = registry
                    .authenticate(export.token.as_deref().unwrap())
                    .unwrap();
                registry
                    .credential(&permit, &json!({"test/conversation":"same"}))
                    .unwrap()
            }));
        }
        let credentials: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(credentials.iter().all(|c| c == &credentials[0]));
    });
    let state = Registry::open(&home).unwrap().read().unwrap();
    assert_eq!(state.clients.len(), 1);
    assert_eq!(state.clients.values().next().unwrap().bindings.len(), 1);
}

#[test]
fn orphan_empty_journal_recovers_but_nonempty_pin_loss_is_rejected() {
    let f = Fixture::new();
    let mut cfg = config::load(&f.home).unwrap();
    cfg.extra.remove("gateway_registry");
    cfg.extra.remove("local_features");
    cfg.version = 1;
    config::write_private(
        &config::path(&f.home),
        toml::to_string(&cfg).unwrap().as_bytes(),
    )
    .unwrap();
    assert!(add(&f.home, "host", "test/conversation", &f.export, 24).is_err());
    let path = f.home.join("gateway/state.json");
    let mut state: State = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    state.clients.clear();
    config::write_private(&path, &serde_json::to_vec(&state).unwrap()).unwrap();
    add(&f.home, "host", "test/conversation", &f.export, 24).unwrap();
    assert_eq!(Registry::open(&f.home).unwrap().id, f.registry.id);
    f.registry.authenticate(&f.token).unwrap();
}

#[tokio::test]
async fn disconnected_call_keeps_worker_slot_until_filesystem_work_finishes() {
    let f = Fixture::new();
    let reserved = f
        .registry
        .workers
        .clone()
        .acquire_many_owned((MAX_WORKERS - 1) as u32)
        .await
        .unwrap();
    let registry = f.registry.clone();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let task = tokio::spawn(async move {
        registry
            .blocking(move |_| {
                let _ = started.send(());
                wait.recv().unwrap();
                Ok(())
            })
            .await
    });
    ready.await.unwrap();
    task.abort();
    let _ = task.await;
    assert_eq!(f.registry.workers.available_permits(), 0);
    let failure = match f
        .registry
        .authenticate_remote(
            f.token.clone(),
            "http://127.0.0.1:8787/mcp".into(),
            Peer::default(),
        )
        .await
    {
        Err(failure) => failure,
        Ok(_) => panic!("exhausted worker pool accepted authentication"),
    };
    assert!(failure.is::<Busy>());
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while f.registry.workers.available_permits() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    f.registry
        .authenticate_remote(
            f.token.clone(),
            "http://127.0.0.1:8787/mcp".into(),
            Peer::default(),
        )
        .await
        .unwrap();
    drop(reserved);
}
