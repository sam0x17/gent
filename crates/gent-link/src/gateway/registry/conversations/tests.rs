use super::*;

struct Fixture {
    _temp: tempfile::TempDir,
    registry: Registry,
    permit: Permit,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("node");
        config::initialize(&home, "handles").unwrap();
        let out = home.join("host.json");
        super::super::add(&home, "host", KEY, &out, 24).unwrap();
        let export: Export = serde_json::from_slice(&std::fs::read(out).unwrap()).unwrap();
        assert_eq!(export.version, 6);
        let registry = Registry::open(&home).unwrap();
        let permit = registry
            .authenticate(export.token.as_deref().unwrap())
            .unwrap();
        assert!(permit.conversation_handles);
        Self {
            _temp: temp,
            registry,
            permit,
        }
    }
    fn open(&self) -> (String, Conversation) {
        let handle = self.registry.open_conversation(&self.permit).unwrap()["conversation"]
            .as_str()
            .unwrap()
            .to_owned();
        (handle.clone(), Conversation::Handle(handle))
    }
}

#[test]
fn handles_isolate_chats_survive_restart_and_do_not_expose_agent_credentials() {
    let f = Fixture::new();
    let (a_handle, a) = f.open();
    let (_, b) = f.open();
    let a_key = f.registry.conversation_credential(&f.permit, &a).unwrap();
    let b_key = f.registry.conversation_credential(&f.permit, &b).unwrap();
    assert_ne!(a_key, b_key);
    let reopened = Registry::open(&f.registry.home).unwrap();
    assert_eq!(
        a_key,
        reopened.conversation_credential(&f.permit, &a).unwrap()
    );
    assert_eq!(reopened.read().unwrap().version, 8);
    let saved = std::fs::read_to_string(f.registry.directory().join("state.json")).unwrap();
    assert!(!saved.contains(&a_handle));
    let listed = reopened.listing().unwrap().to_string();
    assert!(!listed.contains(&a_handle));
    assert!(!listed.contains(&a_key));
    assert!(!listed.contains(&b_key));
    assert!(
        reopened
            .credential(&f.permit, &json!({KEY:a_handle}))
            .is_err()
    );
    assert!(reopened.credential(&f.permit, &json!({})).is_err());
}

#[test]
fn unknown_wrong_connector_and_revoked_handles_never_allocate_bindings() {
    let f = Fixture::new();
    let (_, handle) = f.open();
    let out = f.registry.home.join("second.json");
    super::super::add(&f.registry.home, "second", KEY, &out, 24).unwrap();
    let export: Export = serde_json::from_slice(&std::fs::read(out).unwrap()).unwrap();
    let second = f
        .registry
        .authenticate(export.token.as_deref().unwrap())
        .unwrap();
    assert!(
        f.registry
            .conversation_credential(&second, &handle)
            .is_err()
    );
    for value in [
        "".into(),
        "gent_h1.short".into(),
        format!("gent_h1.{}", config::secret()),
    ] {
        assert!(
            f.registry
                .conversation_credential(&f.permit, &Conversation::Handle(value))
                .is_err()
        );
    }
    assert_eq!(
        f.registry.read().unwrap().clients[&second.client]
            .bindings
            .len(),
        0
    );
    assert_eq!(
        f.registry.read().unwrap().clients[&f.permit.client]
            .bindings
            .len(),
        1
    );
    f.registry.revoke(&f.permit.client).unwrap();
    assert!(
        f.registry
            .conversation_credential(&f.permit, &handle)
            .is_err()
    );
    assert!(f.registry.open_conversation(&f.permit).is_err());
}

#[test]
fn metadata_policy_cannot_fall_back_to_handles_and_registry_cannot_downgrade() {
    let f = Fixture::new();
    let (_, handle) = f.open();
    let out = f.registry.home.join("metadata.json");
    super::super::add(&f.registry.home, "metadata", "test/conversation", &out, 24).unwrap();
    let export: Export = serde_json::from_slice(&std::fs::read(out).unwrap()).unwrap();
    let metadata = f
        .registry
        .authenticate(export.token.as_deref().unwrap())
        .unwrap();
    assert!(!metadata.conversation_handles);
    assert!(f.registry.open_conversation(&metadata).is_err());
    assert!(
        f.registry
            .conversation_credential(&metadata, &handle)
            .is_err()
    );
    assert!(
        f.registry
            .credential(&metadata, &json!({"test/conversation":"chat"}))
            .is_ok()
    );
    let mut state = f.registry.read().unwrap();
    state.version = 1;
    assert!(f.registry.save(&state).is_err());
    assert!(
        super::super::add(
            &f.registry.home,
            "metadata",
            KEY,
            &f.registry.home.join("metadata.json"),
            24
        )
        .is_err()
    );
}

#[test]
fn handle_capacity_is_bounded_without_blocking_existing_conversations() {
    let f = Fixture::new();
    let (_, handle) = f.open();
    let expected = f
        .registry
        .conversation_credential(&f.permit, &handle)
        .unwrap();
    let mut state = f.registry.read().unwrap();
    let client = state.clients.get_mut(&f.permit.client).unwrap();
    while client.bindings.len() < MAX_CLIENT_BINDINGS {
        client
            .bindings
            .insert(config::secret(), config::secret().into());
    }
    f.registry.save(&state).unwrap();
    assert!(f.registry.open_conversation(&f.permit).is_err());
    assert_eq!(
        f.registry
            .conversation_credential(&f.permit, &handle)
            .unwrap(),
        expected
    );
}
