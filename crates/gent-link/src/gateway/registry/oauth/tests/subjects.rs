use super::*;
use std::sync::Barrier;

const SUBJECT: &str = "test/subject";
fn meta(subject: &str, conversation: &str) -> Value {
    json!({SUBJECT:subject,"test/conversation":conversation})
}
fn bind(f: &Fixture, issued: &Value, subject: &str, conversation: &str) -> Result<String> {
    f.registry
        .credential(&f.permit(issued), &meta(subject, conversation))
}

#[test]
fn gateway_recovery_preserves_user_scope_and_pending_calls_do_not_pin_oauth_grants() {
    for signed in [false, true] {
        let f = Fixture::with_subject(signed, Some(SUBJECT));
        assert!(
            f.registry
                .prepare_recovery(&f.client, "private-recovery-chat", None, &"11".repeat(32))
                .is_err()
        );
        let alice = f
            .registry
            .prepare_recovery(
                &f.client,
                "private-recovery-chat",
                Some("private-alice"),
                &"11".repeat(32),
            )
            .unwrap();
        let bob = f
            .registry
            .prepare_recovery(
                &f.client,
                "private-recovery-chat",
                Some("private-bob"),
                &"11".repeat(32),
            )
            .unwrap();
        assert_ne!(alice.credential, bob.credential);
        let grant = f.grant();
        let permit = f.permit(&grant);
        let path = f.home.join("gateway/state.json");
        let before = fs::read(&path).unwrap();
        assert!(
            f.registry
                .credential(&permit, &meta("private-alice", "private-recovery-chat"))
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        let complete =
            || json!({"agent":{"id":Uuid::new_v4()},"history":{"import_id":Uuid::new_v4()}});
        f.registry.complete_recovery(&bob, &complete()).unwrap();
        // The rejected Alice call left the grant unbound; Bob can use it now.
        assert_eq!(
            bind(&f, &grant, "private-bob", "private-recovery-chat").unwrap(),
            bob.credential
        );
        f.registry.complete_recovery(&alice, &complete()).unwrap();
        assert!(bind(&f, &grant, "private-alice", "private-recovery-chat").is_err());
        let alice_grant = f.grant();
        assert_eq!(
            bind(&f, &alice_grant, "private-alice", "private-recovery-chat").unwrap(),
            alice.credential
        );
        let refreshed = f
            .registry
            .exchange(&f.refresh(&alice_grant), RESOURCE)
            .unwrap();
        assert_eq!(
            bind(&f, &refreshed, "private-alice", "private-recovery-chat").unwrap(),
            alice.credential
        );
        let reopened = Registry::open(&f.home).unwrap();
        assert_eq!(
            reopened
                .credential(
                    &f.permit(&refreshed),
                    &meta("private-alice", "private-recovery-chat")
                )
                .unwrap(),
            alice.credential
        );
        for value in ["private-alice", "private-bob", "private-recovery-chat"] {
            assert!(!fs::read_to_string(&path).unwrap().contains(value));
        }
        assert_eq!(f.registry.read().unwrap().version, 7);
    }
}

#[test]
fn user_scoped_agents_survive_refresh_reauthorization_rotation_and_restart() {
    for signed in [false, true] {
        let f = Fixture::with_subject(signed, Some(SUBJECT));
        let alice = f.grant();
        let bob = f.grant();
        let a = bind(&f, &alice, "alice-private", "same-chat").unwrap();
        let b = bind(&f, &bob, "bob-private", "same-chat").unwrap();
        assert_ne!(a, b);
        let other = bind(&f, &alice, "alice-private", "other-chat").unwrap();
        assert_ne!(a, other);
        // A valid bearer for Alice cannot select Bob using host metadata.
        let permit = f.permit(&alice);
        let before = fs::read(f.home.join("gateway/state.json")).unwrap();
        assert!(
            f.registry
                .credential(&permit, &meta("bob-private", "same-chat"))
                .is_err()
        );
        assert_eq!(fs::read(f.home.join("gateway/state.json")).unwrap(), before);
        let refreshed = f.registry.exchange(&f.refresh(&alice), RESOURCE).unwrap();
        assert_eq!(
            bind(&f, &refreshed, "alice-private", "same-chat").unwrap(),
            a
        );
        assert!(bind(&f, &refreshed, "bob-private", "same-chat").is_err());
        let reauthorized = f.grant();
        assert_eq!(
            bind(&f, &reauthorized, "alice-private", "same-chat").unwrap(),
            a
        );
        if signed {
            f.registry
                .set_signing_keys(&f.client, &super::keys::jwks(&f, "fixture-b"), 0)
                .unwrap();
            let export: Value =
                serde_json::from_slice(&fs::read(f.home.join("host.json")).unwrap()).unwrap();
            assert_eq!(export["version"], 5);
            assert_eq!(export["subject_key"], SUBJECT);
            let mut refresh = f.refresh(&reauthorized);
            super::keys::second_authentication(&mut refresh);
            let rotated = f.registry.exchange(&refresh, RESOURCE).unwrap();
            assert_eq!(bind(&f, &rotated, "alice-private", "same-chat").unwrap(), a);
        }
        let reopened = Registry::open(&f.home).unwrap();
        assert_eq!(
            reopened
                .credential(&f.permit(&bob), &meta("bob-private", "same-chat"))
                .unwrap(),
            b
        );
        let state = fs::read_to_string(f.home.join("gateway/state.json")).unwrap();
        for value in ["alice-private", "bob-private", "same-chat", "other-chat"] {
            assert!(!state.contains(value));
        }
        assert_eq!(f.registry.read().unwrap().version, 6);
        let permit = f.permit(&bob);
        f.registry.revoke(&f.client).unwrap();
        assert!(
            reopened
                .credential(&permit, &meta("bob-private", "same-chat"))
                .is_err()
        );
    }
}

#[test]
fn concurrent_first_use_pins_one_user_and_invalid_metadata_does_not_bind() {
    let f = Fixture::with_subject(false, Some(SUBJECT));
    let issued = f.grant();
    let permit = f.permit(&issued);
    let original = fs::read(f.home.join("gateway/state.json")).unwrap();
    for metadata in [
        json!({"test/conversation":"chat"}),
        json!({SUBJECT:42,"test/conversation":"chat"}),
        meta("", "chat"),
        meta("  ", "chat"),
        meta("a\nb", "chat"),
        meta(&"x".repeat(513), "chat"),
        json!({SUBJECT:"user"}),
        json!({SUBJECT:"user","arguments":{"test/conversation":"chat"}}),
        json!({"test/conversation":"chat","arguments":{SUBJECT:"user"}}),
    ] {
        assert!(f.registry.credential(&permit, &metadata).is_err());
    }
    assert_eq!(
        fs::read(f.home.join("gateway/state.json")).unwrap(),
        original
    );
    let barrier = Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = ["alice", "bob"]
            .into_iter()
            .map(|user| {
                let barrier = &barrier;
                let permit = &permit;
                let registry = &f.registry;
                scope.spawn(move || {
                    barrier.wait();
                    (user, registry.credential(permit, &meta(user, "chat")))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|(_, r)| r.is_ok()).count(), 1);
    let (user, credential) = results.iter().find(|(_, r)| r.is_ok()).unwrap();
    assert_eq!(
        &f.registry.credential(&permit, &meta(user, "chat")).unwrap(),
        credential.as_ref().unwrap()
    );
    assert_eq!(
        f.registry.read().unwrap().clients[&f.client].bindings.len(),
        1
    );
}

#[test]
fn subject_policy_cannot_disappear_or_change_during_setup_retries() {
    let f = Fixture::with_subject(true, Some(SUBJECT));
    let issued = f.grant();
    bind(&f, &issued, "private-user", "chat").unwrap();
    let registration = f.registry.signing_registration(&f.client).unwrap();
    let path = f.home.join("gateway/state.json");
    let original = fs::read(&path).unwrap();
    let export = fs::read(f.home.join("host.json")).unwrap();
    for subject in [None, Some("test/other")] {
        assert!(
            add_client(
                &f.home,
                "host",
                BindingKeys {
                    conversation: "test/conversation".into(),
                    subject: subject.map(str::to_owned)
                },
                &f.home.join("host.json"),
                720,
                Some(registration.clone()),
                None
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read(f.home.join("host.json")).unwrap(), export);
    }
    for subject in [
        "test/conversation",
        "threadId",
        "io.modelcontextprotocol/user",
        "claudecode/toolUseId",
        "bad key",
    ] {
        assert!(
            add_client(
                &f.home,
                "invalid",
                BindingKeys {
                    conversation: "test/conversation".into(),
                    subject: Some(subject.into())
                },
                &f.home.join("invalid.json"),
                24,
                Some(registration.clone()),
                None
            )
            .is_err()
        );
        assert!(!f.home.join("invalid.json").exists());
    }
    assert!(
        add_client(
            &f.home,
            "static",
            BindingKeys {
                conversation: "test/conversation".into(),
                subject: Some(SUBJECT.into())
            },
            &f.home.join("static.json"),
            24,
            None,
            None
        )
        .is_err()
    );
    let grant_id = f.permit(&issued).oauth.unwrap().0;
    for change in 0..6 {
        let mut damaged: Value = serde_json::from_slice(&original).unwrap();
        match change {
            0 => {
                damaged["clients"][&f.client]
                    .as_object_mut()
                    .unwrap()
                    .remove("subject_key");
            }
            1 => {
                damaged["clients"][&f.client]
                    .as_object_mut()
                    .unwrap()
                    .remove("subject_required");
            }
            2 => {
                damaged["oauth"]["grants"][&grant_id]
                    .as_object_mut()
                    .unwrap()
                    .remove("subject");
            }
            3 => {
                damaged["oauth"]["grants"][&grant_id]["subject"] = json!({"bound":"short"});
            }
            4 => {
                damaged["version"] = json!(5);
            }
            _ => {
                damaged["oauth"]["grants"][&grant_id]["subject"] = json!({"unknown":null});
            }
        }
        fs::write(&path, serde_json::to_vec(&damaged).unwrap()).unwrap();
        assert!(
            Registry::open(&f.home).is_err(),
            "accepted corruption {change}"
        );
    }
    fs::write(&path, original).unwrap();
    Registry::open(&f.home).unwrap();
}

#[test]
fn full_binding_capacity_does_not_pin_a_previously_unbound_grant() {
    let f = Fixture::with_subject(false, Some(SUBJECT));
    let issued = f.grant();
    let permit = f.permit(&issued);
    let path = f.home.join("gateway/state.json");
    let original = fs::read(&path).unwrap();
    // A quota refusal must happen before either a new identity or user pin
    // commits. A later valid call may still establish the grant's user.
    let mut state = f.registry.read().unwrap();
    let client = state.clients.get_mut(&f.client).unwrap();
    for index in 0..MAX_CLIENT_BINDINGS {
        client.bindings.insert(
            digest(&format!("occupied-{index}")),
            config::secret().into(),
        );
    }
    f.registry.save(&state).unwrap();
    let full = fs::read(&path).unwrap();
    assert!(
        f.registry
            .credential(&permit, &meta("alice", "chat"))
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), full);
    fs::write(&path, original).unwrap();
    f.registry
        .credential(&permit, &meta("bob", "chat"))
        .unwrap();
}
