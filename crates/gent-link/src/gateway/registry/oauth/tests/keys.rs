use super::*;
use crate::gateway::registry::keys::Update;

pub(super) fn jwks(f: &Fixture, which: &str) -> PathBuf {
    let policy = serde_json::to_value(assertion::tests::policy()).unwrap();
    let keys: Vec<_> = policy["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|k| which == "both" || k["kid"] == which)
        .cloned()
        .collect();
    let path = f.home.join(format!("{which}.json"));
    fs::write(&path, serde_json::to_vec(&json!({"keys":keys})).unwrap()).unwrap();
    path
}
pub(super) fn second_authentication(fields: &mut Parameters) {
    fields.insert(
        "client_assertion".into(),
        assertion::tests::sign(
            json!({"alg":"RS256","kid":"fixture-b"}),
            assertion::tests::claims(),
            true,
        ),
    );
}

#[test]
fn key_rotation_preserves_grants_agents_and_pending_codes_and_rejects_removed_keys() {
    let f = Fixture::with_assertions(true);
    let issued = f.grant();
    let binding = f
        .registry
        .credential(&f.permit(&issued), &json!({"test/conversation":"same"}))
        .unwrap();
    let code = f.code();
    let original = f.registry.read().unwrap();
    let path = jwks(&f, "fixture-b");
    assert_eq!(
        f.registry.signing_keys(&f.client).unwrap()["key_revision"],
        0
    );
    let result = f.registry.set_signing_keys(&f.client, &path, 0).unwrap();
    assert_eq!(result["key_revision"], 1);
    assert_eq!(result["key_ids"], json!(["fixture-b"]));
    assert_eq!(result["export_pending"], false);
    assert_eq!(
        f.registry.set_signing_keys(&f.client, &path, 0).unwrap(),
        result
    );
    let updated = f.registry.read().unwrap();
    assert_eq!(
        serde_json::to_value(&original.oauth).unwrap(),
        serde_json::to_value(&updated.oauth).unwrap()
    );
    let before = &original.clients[&f.client];
    let after = &updated.clients[&f.client];
    assert!(before.bindings == after.bindings);
    assert_eq!(before.expires_at, after.expires_at);
    assert!(before.mtls == after.mtls); // no policy changes beyond the public keys
    let saved: Export = serde_json::from_slice(&fs::read(&after.export).unwrap()).unwrap();
    assert_eq!(saved.version, 4);
    assert_eq!(saved.key_revision, 1);
    assert!(saved.token.is_none());
    assert!(
        add_client(
            &f.home,
            "host",
            "test/conversation",
            &after.export,
            720,
            before.oauth.clone(),
            None
        )
        .is_err()
    );
    add_client(
        &f.home,
        "host",
        "test/conversation",
        &after.export,
        720,
        after.oauth.clone(),
        None,
    )
    .unwrap();
    assert!(f.registry.exchange(&code, RESOURCE).is_err());
    assert!(f.registry.exchange(&f.refresh(&issued), RESOURCE).is_err());
    f.permit(&issued);
    let mut fields = f.refresh(&issued);
    second_authentication(&mut fields);
    let renewed = f.registry.exchange(&fields, RESOURCE).unwrap();
    let mut fields = code;
    second_authentication(&mut fields);
    f.registry.exchange(&fields, RESOURCE).unwrap();
    fs::remove_file(path).unwrap();
    let reopened = Registry::open(&f.home).unwrap();
    assert_eq!(
        binding,
        reopened
            .credential(&f.permit(&renewed), &json!({"test/conversation":"same"}))
            .unwrap()
    );
}

#[test]
fn key_revisions_prevent_stale_aba_updates_and_reordering_is_a_noop() {
    let f = Fixture::with_assertions(true);
    let both = jwks(&f, "both");
    let mut document: Value = serde_json::from_slice(&fs::read(&both).unwrap()).unwrap();
    document["keys"].as_array_mut().unwrap().reverse();
    fs::write(&both, serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(
        f.registry.set_signing_keys(&f.client, &both, 0).unwrap()["key_revision"],
        0
    );
    let a = jwks(&f, "fixture-a");
    let b = jwks(&f, "fixture-b");
    f.registry.set_signing_keys(&f.client, &a, 0).unwrap();
    f.registry.set_signing_keys(&f.client, &b, 1).unwrap();
    f.registry.set_signing_keys(&f.client, &a, 2).unwrap();
    assert!(f.registry.set_signing_keys(&f.client, &b, 1).is_err());
    assert!(f.registry.set_signing_keys(&f.client, &a, 0).is_err());
    assert!(f.registry.set_signing_keys(&f.client, &a, 4).is_err());
    assert_eq!(
        f.registry.set_signing_keys(&f.client, &a, 3).unwrap()["key_revision"],
        3
    );
    f.registry.revoke(&f.client).unwrap();
    assert!(f.registry.set_signing_keys(&f.client, &b, 3).is_err());
    assert!(f.registry.set_signing_keys(&f.client, &a, 3).is_err());
    // An exact retry may repair the export even after revocation, never undo it.
    assert_eq!(
        f.registry.set_signing_keys(&f.client, &a, 2).unwrap()["revoked"],
        true
    );
    let ordinary = Fixture::new();
    assert!(
        ordinary
            .registry
            .set_signing_keys(&ordinary.client, &a, 0)
            .is_err()
    );
}

#[test]
fn concurrent_key_updates_allow_only_one_revision_and_identical_retries_converge() {
    for identical in [false, true] {
        let f = Fixture::with_assertions(true);
        let a = jwks(&f, "fixture-a");
        let b = if identical {
            a.clone()
        } else {
            jwks(&f, "fixture-b")
        };
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let jobs: Vec<_> = [&a, &b]
                .into_iter()
                .map(|path| {
                    let f = &f;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        f.registry.set_signing_keys(&f.client, path, 0)
                    })
                })
                .collect();
            jobs.into_iter()
                .map(|j| j.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            if identical { 2 } else { 1 }
        );
        assert_eq!(
            f.registry.signing_keys(&f.client).unwrap()["key_revision"],
            1
        );
        assert_eq!(
            f.registry.signing_keys(&f.client).unwrap()["export_pending"],
            false
        );
    }
}

#[test]
fn interrupted_export_recovers_at_both_write_boundaries_without_overwriting_changed_files() {
    for exported in [false, true] {
        let f = Fixture::with_assertions(true);
        let path = jwks(&f, "fixture-b");
        let previous = fs::read_to_string(f.home.join("host.json")).unwrap();
        let mut state = f.registry.read().unwrap();
        let client = state.clients.get_mut(&f.client).unwrap();
        client.oauth.as_mut().unwrap().assertion =
            Some(assertion::Policy::load(&path, &f.oauth_client).unwrap());
        client.keys_updated = true;
        client.key_update = Some(Update {
            revision: 1,
            pending_export: Some(digest(&previous)),
        });
        let mut after: Value = serde_json::from_str(&previous).unwrap();
        after["version"] = json!(4);
        after["key_revision"] = json!(1);
        after["oauth"] = serde_json::to_value(&client.oauth).unwrap();
        state.version = 5;
        f.registry.save(&state).unwrap(); // durable state after the registry commit
        if exported {
            fs::write(
                f.home.join("host.json"),
                serde_json::to_vec(&after).unwrap(),
            )
            .unwrap();
        } else {
            fs::write(f.home.join("host.json"), "changed-by-user\n").unwrap();
            assert!(f.registry.set_signing_keys(&f.client, &path, 0).is_err());
            assert_eq!(
                fs::read_to_string(f.home.join("host.json")).unwrap(),
                "changed-by-user\n"
            );
            assert_eq!(
                f.registry.signing_keys(&f.client).unwrap()["export_pending"],
                true
            );
            fs::remove_file(f.home.join("host.json")).unwrap();
            assert!(f.registry.set_signing_keys(&f.client, &path, 0).is_err());
            fs::write(f.home.join("host.json"), &previous).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(f.home.join("host.json"), fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let old = jwks(&f, "fixture-a");
        assert!(f.registry.set_signing_keys(&f.client, &old, 1).is_err());
        f.registry.revoke(&f.client).unwrap();
        let reopened = Registry::open(&f.home).unwrap();
        let result = reopened.set_signing_keys(&f.client, &path, 0).unwrap();
        assert_eq!(result["key_revision"], 1);
        assert_eq!(result["export_pending"], false);
        assert_eq!(result["revoked"], true);
        let stored: Value =
            serde_json::from_slice(&fs::read(f.home.join("host.json")).unwrap()).unwrap();
        assert_eq!(stored, after);
    }
}

#[test]
fn key_updates_reject_invalid_exports_corrupt_revision_records_and_expired_clients() {
    let f = Fixture::with_assertions(true);
    let path = jwks(&f, "fixture-b");
    let export = f.home.join("host.json");
    let original = fs::read(&export).unwrap();
    let state_path = f.home.join("gateway/state.json");
    let baseline = fs::read(&state_path).unwrap();
    fs::write(&export, b"{}\n").unwrap();
    assert!(f.registry.set_signing_keys(&f.client, &path, 0).is_err());
    assert_eq!(fs::read(&state_path).unwrap(), baseline);
    fs::write(&export, original).unwrap();
    f.registry.set_signing_keys(&f.client, &path, 0).unwrap();
    // Another updated client keeps the registry at v5 if this client's
    // revision record is lost; the per-client marker must still catch it.
    let mut second = f.registry.read().unwrap().clients[&f.client]
        .oauth
        .clone()
        .unwrap();
    second.assertion.as_mut().unwrap().client_id = "https://second.example/client.json".into();
    let added = add_client(
        &f.home,
        "second",
        "test/conversation",
        &f.home.join("second.json"),
        720,
        Some(second),
        None,
    )
    .unwrap();
    f.registry
        .set_signing_keys(added["client"].as_str().unwrap(), &jwks(&f, "fixture-a"), 0)
        .unwrap();
    let baseline: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    for change in 0..4 {
        let mut corrupt = baseline.clone();
        match change {
            0 => {
                corrupt["clients"][&f.client]
                    .as_object_mut()
                    .unwrap()
                    .remove("key_update");
            }
            1 => {
                corrupt["clients"][&f.client]["key_update"]["revision"] = json!(0);
            }
            2 => {
                corrupt["clients"][&f.client]["key_update"]["pending_export"] = json!("bad");
            }
            _ => {
                corrupt["version"] = json!(4);
            }
        }
        fs::write(&state_path, serde_json::to_vec(&corrupt).unwrap()).unwrap();
        assert!(Registry::open(&f.home).is_err());
    }
    fs::write(&state_path, serde_json::to_vec(&baseline).unwrap()).unwrap();
    let mut state = f.registry.read().unwrap();
    state.clients.get_mut(&f.client).unwrap().expires_at = auth::now().unwrap();
    f.registry.save(&state).unwrap();
    assert!(
        f.registry
            .set_signing_keys(&f.client, &jwks(&f, "fixture-a"), 1)
            .is_err()
    );
    fs::write(&state_path, serde_json::to_vec(&baseline).unwrap()).unwrap();
    let mut state = f.registry.read().unwrap();
    let removed = state.clients.remove(&f.client).unwrap();
    f.registry.save(&state).unwrap();
    assert!(
        add_client(
            &f.home,
            "host",
            "test/conversation",
            &export,
            720,
            removed.oauth,
            None
        )
        .is_err()
    );
}
