use super::*;

fn completed() -> Value {
    json!({"agent":{"id":Uuid::new_v4()},"history":{"import_id":Uuid::new_v4()}})
}

#[test]
fn gateway_recovery_reserves_one_binding_and_survives_lost_replies_without_exposing_metadata() {
    let f = Fixture::new();
    let request = "11".repeat(32);
    let permit = f.permit();
    let meta = json!({"test/conversation":"private-recovered-chat"});
    let ticket = f
        .registry
        .prepare_recovery(&f.id, "private-recovered-chat", None, &request)
        .unwrap();
    let path = f.home.join("gateway/state.json");
    let pending = fs::read(&path).unwrap();
    assert!(f.registry.credential(&permit, &meta).is_err());
    assert_eq!(fs::read(&path).unwrap(), pending);
    let retry = Registry::open(&f.home)
        .unwrap()
        .prepare_recovery(&f.id, "private-recovered-chat", None, &request)
        .unwrap();
    assert_eq!(retry.credential, ticket.credential);
    assert!(
        f.registry
            .prepare_recovery(&f.id, "private-recovered-chat", None, &"22".repeat(32))
            .is_err()
    );
    let result = completed();
    f.registry.complete_recovery(&ticket, &result).unwrap();
    f.registry.complete_recovery(&retry, &result).unwrap();
    assert!(f.registry.complete_recovery(&ticket, &completed()).is_err());
    assert_eq!(
        f.registry.credential(&permit, &meta).unwrap(),
        ticket.credential
    );
    // Credential lookup updates the registry clock without replacing recovery
    // records with legacy credentials or losing the original retry fingerprint.
    let mut state = f.registry.read().unwrap();
    state.clock -= 1;
    state.clients.get_mut(&f.id).unwrap().created_at -= 1;
    state.clients.get_mut(&f.id).unwrap().expires_at -= 1;
    f.registry.save(&state).unwrap();
    assert_eq!(
        f.registry.credential(&permit, &meta).unwrap(),
        ticket.credential
    );
    let retry = f
        .registry
        .prepare_recovery(&f.id, "private-recovered-chat", None, &request)
        .unwrap();
    assert_eq!(retry.credential, ticket.credential);
    assert_ne!(f.bind("another"), ticket.credential);
    assert_eq!(f.registry.read().unwrap().version, 7);
    let saved = fs::read_to_string(path).unwrap();
    assert!(!saved.contains("private-recovered-chat"));
    assert!(
        !f.registry
            .listing()
            .unwrap()
            .to_string()
            .contains(&ticket.credential)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(f.export).unwrap()).unwrap()["version"],
        1
    );
}

#[test]
fn gateway_recovery_rejects_existing_bindings_and_counts_pending_capacity() {
    let f = Fixture::new();
    let existing = f.bind("existing");
    assert!(
        f.registry
            .prepare_recovery(&f.id, "existing", None, &"11".repeat(32))
            .is_err()
    );
    assert_eq!(f.bind("existing"), existing);
    assert!(
        f.registry
            .prepare_recovery(&f.id, "new", Some("unexpected"), &"11".repeat(32))
            .is_err()
    );
    for bad in ["", "  ", "line\nbreak", &"x".repeat(513)] {
        assert!(
            f.registry
                .prepare_recovery(&f.id, bad, None, &"11".repeat(32))
                .is_err()
        );
    }
    let ticket = f
        .registry
        .prepare_recovery(&f.id, "pending", None, &"11".repeat(32))
        .unwrap();
    let mut state = f.registry.read().unwrap();
    let client = state.clients.get_mut(&f.id).unwrap();
    for i in client.bindings.len()..MAX_CLIENT_BINDINGS {
        client
            .bindings
            .insert(digest(&format!("occupied-{i}")), config::secret().into());
    }
    f.registry.save(&state).unwrap();
    let path = f.home.join("gateway/state.json");
    let full = fs::read(&path).unwrap();
    assert!(
        f.registry
            .prepare_recovery(&f.id, "excess", None, &"11".repeat(32))
            .is_err()
    );
    assert_eq!(full, fs::read(&path).unwrap());
    let retry = f
        .registry
        .prepare_recovery(&f.id, "pending", None, &"11".repeat(32))
        .unwrap();
    assert_eq!(ticket.credential, retry.credential);
    f.registry.complete_recovery(&ticket, &completed()).unwrap();
    assert_eq!(f.bind("pending"), ticket.credential);
}

#[test]
fn competing_recovery_and_host_calls_never_replace_a_binding() {
    for competing in [false, true] {
        let f = Fixture::new();
        let barrier = Barrier::new(2);
        let (recovery, other) = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                barrier.wait();
                f.registry
                    .prepare_recovery(&f.id, "chat", None, &"11".repeat(32))
                    .map(|t| t.credential)
            });
            let second = scope.spawn(|| {
                barrier.wait();
                if competing {
                    f.registry
                        .prepare_recovery(&f.id, "chat", None, &"22".repeat(32))
                        .map(|t| t.credential)
                } else {
                    f.registry
                        .credential(&f.permit(), &json!({"test/conversation":"chat"}))
                }
            });
            (first.join().unwrap(), second.join().unwrap())
        });
        assert_ne!(recovery.is_ok(), other.is_ok());
        assert_eq!(f.registry.read().unwrap().clients[&f.id].bindings.len(), 1);
    }
}

#[test]
fn recovery_records_reject_corruption_and_host_revocation_before_completion() {
    let f = Fixture::new();
    let ticket = f
        .registry
        .prepare_recovery(&f.id, "chat", None, &"11".repeat(32))
        .unwrap();
    let path = f.home.join("gateway/state.json");
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for field in [
        "version",
        "credential",
        "fingerprint",
        "completed",
        "unknown",
    ] {
        let mut changed = original.clone();
        let record = &mut changed["clients"][&f.id]["bindings"][digest("chat")];
        record[field] = json!("invalid");
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(Registry::open(&f.home).is_err(), "{field}");
    }
    for field in ["credential", "fingerprint"] {
        let mut changed = original.clone();
        changed["clients"][&f.id]["bindings"][digest("chat")]
            .as_object_mut()
            .unwrap()
            .remove(field);
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(Registry::open(&f.home).is_err());
    }
    let mut downgraded = original.clone();
    downgraded["version"] = json!(1);
    fs::write(&path, serde_json::to_vec(&downgraded).unwrap()).unwrap();
    assert!(Registry::open(&f.home).is_err());
    fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
    f.registry.revoke(&f.id).unwrap();
    assert!(f.registry.complete_recovery(&ticket, &completed()).is_err());
    assert!(
        f.registry
            .prepare_recovery(&f.id, "chat", None, &"11".repeat(32))
            .is_err()
    );
    assert!(f.registry.authenticate(&f.token).is_err());
}

#[test]
fn recovered_gateway_bindings_use_download_authority_only_after_completion() {
    let f = Fixture::new();
    let ticket = f
        .registry
        .prepare_recovery(&f.id, "chat", None, &"11".repeat(32))
        .unwrap();
    let pending = fs::read(f.home.join("gateway/state.json")).unwrap();
    let meta = json!({"test/conversation":"chat"});
    let target = DownloadTarget {
        file: Uuid::new_v4().to_string(),
        origin: "https://node.example".into(),
        expires_at: auth::now().unwrap() + 3600,
    };
    let permit = f.permit();
    assert!(
        f.registry
            .issue_download_local(&permit, &meta, &ticket.credential, &target)
            .is_err()
    );
    f.registry.complete_recovery(&ticket, &completed()).unwrap();
    let (token, _) = f
        .registry
        .issue_download_local(&permit, &meta, &ticket.credential, &target)
        .unwrap();
    assert_eq!(
        f.registry
            .check_download_local(&token, &target.origin)
            .unwrap()
            .credential,
        ticket.credential
    );
    fs::write(f.home.join("gateway/state.json"), pending).unwrap();
    assert!(
        f.registry
            .check_download_local(&token, &target.origin)
            .is_err()
    );
}
