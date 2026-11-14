use super::*;
use std::fs;
const RESOURCE: &str = "https://node.example/mcp";
const REDIRECT: &str = "https://host.example/callback?tenant=one";
mod keys;
struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    registry: Registry,
    client: String,
    oauth_client: String,
    secret: String,
    verifier: String,
}

#[test]
fn signed_code_and_refresh_preserve_agents_and_assertion_replays_do_not_revoke_grants() {
    let f = Fixture::with_assertions(true);
    let code = f.code();
    for key in ["client_assertion", "client_assertion_type"] {
        let mut invalid = code.clone();
        invalid.remove(key);
        assert!(f.registry.exchange(&invalid, RESOURCE).is_err());
    }
    for (key, value) in [
        ("client_secret", config::secret()),
        ("client_id", f.client.clone()),
        ("client_assertion_type", "wrong-type".into()),
    ] {
        let mut invalid = code.clone();
        invalid.insert(key.into(), value);
        assert!(f.registry.exchange(&invalid, RESOURCE).is_err());
    }
    let issued = f.registry.exchange(&code, RESOURCE).unwrap();
    let binding = f
        .registry
        .credential(&f.permit(&issued), &json!({"test/conversation":"same"}))
        .unwrap();
    let reopened = Registry::open(&f.home).unwrap();
    assert!(reopened.exchange(&code, RESOURCE).is_err());
    f.permit(&issued);
    let refresh = f.refresh(&issued);
    let rotated = reopened.exchange(&refresh, RESOURCE).unwrap();
    assert!(
        Registry::open(&f.home)
            .unwrap()
            .exchange(&refresh, RESOURCE)
            .is_err()
    );
    assert_eq!(
        binding,
        f.registry
            .credential(&f.permit(&rotated), &json!({"test/conversation":"same"}))
            .unwrap()
    );
    // A fresh assertion authenticates a replay of a spent refresh token. The
    // existing token-family replay rule still revokes that family.
    assert!(f.registry.exchange(&f.refresh(&issued), RESOURCE).is_err());
    assert!(
        f.registry
            .authenticate_at(rotated["access_token"].as_str().unwrap(), Some(RESOURCE))
            .is_err()
    );
    let reauthorized = f.grant();
    assert_eq!(
        binding,
        f.registry
            .credential(
                &f.permit(&reauthorized),
                &json!({"test/conversation":"same"})
            )
            .unwrap()
    );
    f.registry.revoke(&f.client).unwrap();
    assert!(
        f.registry
            .exchange(&f.refresh(&reauthorized), RESOURCE)
            .is_err()
    );
}

#[test]
fn concurrent_assertion_replay_consumes_once_without_revoking_the_successful_family() {
    let f = Fixture::with_assertions(true);
    let code = f.code();
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let jobs: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    f.registry.exchange(&code, RESOURCE)
                })
            })
            .collect();
        jobs.into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    f.permit(results.iter().find_map(|r| r.as_ref().ok()).unwrap());
    let state = f.registry.read().unwrap();
    assert_eq!(
        state
            .oauth
            .as_ref()
            .unwrap()
            .assertions
            .as_ref()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn signed_policies_have_no_secret_fallback_and_replay_state_cannot_disappear() {
    let f = Fixture::with_assertions(true);
    let registration = f.registry.read().unwrap().clients[&f.client]
        .oauth
        .clone()
        .unwrap();
    assert!(
        add_client(
            &f.home,
            "duplicate",
            "test/conversation",
            &f.home.join("duplicate.json"),
            24,
            Some(registration.clone()),
            None
        )
        .is_err()
    );
    assert!(!f.home.join("duplicate.json").exists());
    let mut second = registration.clone();
    second.assertion.as_mut().unwrap().client_id = "https://second.example/client.json".into();
    add_client(
        &f.home,
        "second",
        "test/conversation",
        &f.home.join("second.json"),
        24,
        Some(second),
        None,
    )
    .unwrap();
    let path = f.home.join("gateway/state.json");
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let export: Value =
        serde_json::from_slice(&fs::read(f.home.join("host.json")).unwrap()).unwrap();
    assert_eq!(original["version"], 4);
    assert_eq!(export["version"], 3);
    assert!(export.get("token").is_none());
    for change in 0..5 {
        let mut corrupt = original.clone();
        match change {
            0 => {
                corrupt["clients"][&f.client]["oauth"]
                    .as_object_mut()
                    .unwrap()
                    .remove("assertion");
            }
            1 => {
                corrupt["clients"][&f.client]
                    .as_object_mut()
                    .unwrap()
                    .remove("oauth");
            }
            2 => {
                corrupt["clients"][&f.client]["token_hash"] = json!(digest("invented-secret"));
            }
            3 => {
                corrupt["oauth"]
                    .as_object_mut()
                    .unwrap()
                    .remove("assertions");
            }
            _ => {
                corrupt["version"] = json!(3);
            }
        }
        fs::write(&path, serde_json::to_vec(&corrupt).unwrap()).unwrap();
        assert!(
            Registry::open(&f.home).is_err(),
            "accepted corruption {change}"
        );
    }
    fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
    Registry::open(&f.home).unwrap();
    let mut fallback = registration;
    fallback.assertion = None;
    assert!(
        add_client(
            &f.home,
            "host",
            "test/conversation",
            &f.home.join("host.json"),
            720,
            Some(fallback),
            None
        )
        .is_err()
    );
}

#[test]
fn assertion_replay_capacity_expires_and_invalid_requests_cannot_downgrade_authentication() {
    let f = Fixture::with_assertions(true);
    let code = f.code();
    let mut state = f.registry.read().unwrap();
    let now = auth::now().unwrap();
    state.clock = now;
    *state.oauth.as_mut().unwrap().assertions.as_mut().unwrap() = (0..MAX_ASSERTIONS)
        .map(|i| (digest(&i.to_string()), now + 60))
        .collect();
    f.registry.save(&state).unwrap();
    let failure = f.registry.exchange(&code, RESOURCE).unwrap_err();
    assert_eq!(
        failure.downcast_ref::<Failure>().unwrap().0,
        "temporarily_unavailable"
    );
    state
        .oauth
        .as_mut()
        .unwrap()
        .assertions
        .as_mut()
        .unwrap()
        .insert(digest("0"), now - 1);
    f.registry.save(&state).unwrap();
    f.registry.exchange(&code, RESOURCE).unwrap();
    let ordinary = Fixture::new();
    let mut valid = ordinary.code();
    valid.extend(f.authentication());
    assert!(ordinary.registry.exchange(&valid, RESOURCE).is_err());
    let mut authorization = f.authorization();
    authorization.extend(f.authentication());
    assert!(f.registry.begin(&authorization, RESOURCE).is_err());
}
impl Fixture {
    fn new() -> Self {
        Self::with_assertions(false)
    }
    fn with_assertions(signed: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("node");
        config::initialize(&home, "oauth").unwrap();
        let out = home.join("host.json");
        let registration = Registration {
            resource: RESOURCE.into(),
            redirect_uris: vec![REDIRECT.into()],
            assertion: signed.then(assertion::tests::policy),
        };
        let result = add_client(
            &home,
            "host",
            "test/conversation",
            &out,
            720,
            Some(registration.clone()),
            None,
        )
        .unwrap();
        assert_eq!(
            add_client(
                &home,
                "host",
                "test/conversation",
                &out,
                720,
                Some(registration),
                None,
            )
            .unwrap(),
            result
        );
        assert!(add(&home, "host", "test/conversation", &out, 720).is_err());
        let export: Export = serde_json::from_slice(&fs::read(out).unwrap()).unwrap();
        let oauth_client = export
            .oauth
            .as_ref()
            .unwrap()
            .client_id(&export.client)
            .to_string();
        Self {
            _temp: temp,
            registry: Registry::open(&home).unwrap(),
            home,
            client: export.client,
            oauth_client,
            secret: export.token.unwrap_or_default(),
            verifier: config::secret(),
        }
    }
    fn authorization(&self) -> Parameters {
        [
            ("response_type", "code".into()),
            ("client_id", self.oauth_client.clone()),
            ("redirect_uri", REDIRECT.into()),
            ("resource", RESOURCE.into()),
            ("scope", SCOPE.into()),
            ("code_challenge_method", "S256".into()),
            (
                "code_challenge",
                URL_SAFE_NO_PAD.encode(Sha256::digest(&self.verifier)),
            ),
            ("state", "private-state".into()),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect()
    }
    fn pending(&self) -> String {
        self.registry
            .begin(&self.authorization(), RESOURCE)
            .unwrap()["request"]
            .as_str()
            .unwrap()
            .into()
    }
    fn code(&self) -> Parameters {
        let request = self.pending();
        assert!(
            self.registry
                .continue_request(&request, RESOURCE)
                .unwrap()
                .is_none()
        );
        self.registry.oauth_decide(&request, true).unwrap();
        self.registry.oauth_decide(&request, true).unwrap();
        assert!(self.registry.oauth_decide(&request, false).is_err());
        let redirect = url::Url::parse(
            &self
                .registry
                .continue_request(&request, RESOURCE)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let fields: Parameters = redirect
            .query_pairs()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        assert_eq!(fields["tenant"], "one");
        assert_eq!(fields["state"], "private-state");
        assert_eq!(fields["iss"], "https://node.example");
        let mut fields: Parameters = [
            ("grant_type", "authorization_code".into()),
            ("client_id", self.oauth_client.clone()),
            ("resource", RESOURCE.into()),
            ("redirect_uri", REDIRECT.into()),
            ("code", fields["code"].clone()),
            ("code_verifier", self.verifier.clone()),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect();
        fields.extend(self.authentication());
        fields
    }
    fn grant(&self) -> Value {
        self.registry.exchange(&self.code(), RESOURCE).unwrap()
    }
    fn refresh(&self, token: &Value) -> Parameters {
        let mut fields: Parameters = [
            ("grant_type", "refresh_token".into()),
            ("client_id", self.oauth_client.clone()),
            ("resource", RESOURCE.into()),
            (
                "refresh_token",
                token["refresh_token"].as_str().unwrap().into(),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect();
        fields.extend(self.authentication());
        fields
    }
    fn authentication(&self) -> Parameters {
        if self.secret.is_empty() {
            [
                ("client_assertion_type".into(), assertion::TYPE.into()),
                (
                    "client_assertion".into(),
                    assertion::tests::token(assertion::tests::claims()),
                ),
            ]
            .into()
        } else {
            [("client_secret".into(), self.secret.clone())].into()
        }
    }
    fn permit(&self, token: &Value) -> Permit {
        self.registry
            .authenticate_at(token["access_token"].as_str().unwrap(), Some(RESOURCE))
            .unwrap()
    }
}

#[test]
fn code_requires_owner_pkce_exact_client_resource_and_redirect_and_is_single_use() {
    let f = Fixture::new();
    assert!(f.registry.authenticate(&f.secret).is_err());
    let valid = f.code();
    for (key, value) in [
        ("code_verifier", config::secret()),
        ("redirect_uri", "https://evil.example/callback".into()),
        ("resource", "https://other.example/mcp".into()),
        ("client_secret", config::secret()),
        ("client_id", Uuid::new_v4().to_string()),
    ] {
        let mut invalid = valid.clone();
        invalid.insert(key.into(), value);
        assert!(f.registry.exchange(&invalid, RESOURCE).is_err());
    }
    let token = f.registry.exchange(&valid, RESOURCE).unwrap();
    let permit = f.permit(&token);
    assert!(
        f.registry
            .authenticate_at(
                token["access_token"].as_str().unwrap(),
                Some("https://other.example/mcp")
            )
            .is_err()
    );
    assert!(
        f.registry
            .authenticate_at(token["refresh_token"].as_str().unwrap(), Some(RESOURCE))
            .is_err()
    );
    let binding = f
        .registry
        .credential(&permit, &json!({"test/conversation":"a"}))
        .unwrap();
    assert!(f.registry.exchange(&valid, RESOURCE).is_err());
    assert!(
        f.registry
            .credential(&permit, &json!({"test/conversation":"a"}))
            .is_err()
    );
    let fresh = f.grant();
    assert_eq!(
        f.registry
            .credential(&f.permit(&fresh), &json!({"test/conversation":"a"}))
            .unwrap(),
        binding
    );
    let state = fs::read_to_string(f.home.join("gateway/state.json")).unwrap();
    for private in [
        &f.secret,
        valid["code"].as_str(),
        token["access_token"].as_str().unwrap(),
        token["refresh_token"].as_str().unwrap(),
    ] {
        assert!(!state.contains(private));
    }
}

#[test]
fn refresh_rotation_preserves_bindings_but_valid_replay_and_parent_revocation_end_access() {
    let f = Fixture::new();
    let token = f.grant();
    let old_permit = f.permit(&token);
    let binding = f
        .registry
        .credential(&old_permit, &json!({"test/conversation":"a"}))
        .unwrap();
    let request = f.refresh(&token);
    let mut corrupt = request.clone();
    let forged = corrupt.get_mut("refresh_token").unwrap();
    let last = forged.pop().unwrap();
    forged.push(if last == '0' { '1' } else { '0' });
    assert!(f.registry.exchange(&corrupt, RESOURCE).is_err());
    f.permit(&token);
    let rotated = f.registry.exchange(&request, RESOURCE).unwrap();
    assert_ne!(token["access_token"], rotated["access_token"]);
    assert_ne!(token["refresh_token"], rotated["refresh_token"]);
    assert!(
        f.registry
            .credential(&old_permit, &json!({"test/conversation":"a"}))
            .is_err()
    );
    let registry = Registry::open(&f.home).unwrap();
    let permit = f.permit(&rotated);
    assert_eq!(
        registry
            .credential(&permit, &json!({"test/conversation":"a"}))
            .unwrap(),
        binding
    );
    assert!(registry.exchange(&request, RESOURCE).is_err());
    assert!(
        registry
            .credential(&permit, &json!({"test/conversation":"a"}))
            .is_err()
    );
    assert!(registry.exchange(&f.refresh(&rotated), RESOURCE).is_err());
    let fresh = f.grant();
    let fresh_permit = f.permit(&fresh);
    registry.revoke(&f.client).unwrap();
    assert!(
        registry
            .credential(&fresh_permit, &json!({"test/conversation":"a"}))
            .is_err()
    );
    assert!(registry.exchange(&f.refresh(&fresh), RESOURCE).is_err());
    assert!(registry.begin(&f.authorization(), RESOURCE).is_err());
}

#[test]
fn deny_expiry_clock_rollback_and_lost_registry_do_not_create_grants() {
    let f = Fixture::new();
    let id = f.pending();
    f.registry.oauth_decide(&id, false).unwrap();
    assert!(f.registry.oauth_decide(&id, true).is_err());
    let redirect = f.registry.continue_request(&id, RESOURCE).unwrap().unwrap();
    assert!(redirect.contains("error=access_denied") && redirect.contains("iss=https"));
    let code = f.code();
    let (id, _) = parts(&code["code"], "gent_c1").unwrap();
    let mut state = f.registry.read().unwrap();
    state
        .oauth
        .as_mut()
        .unwrap()
        .requests
        .get_mut(id)
        .unwrap()
        .code_expires_at = Some(auth::now().unwrap());
    f.registry.save(&state).unwrap();
    assert!(f.registry.exchange(&code, RESOURCE).is_err());
    let token = f.grant();
    let permit = f.permit(&token);
    let mut state = f.registry.read().unwrap();
    let id = parts(token["access_token"].as_str().unwrap(), "gent_a1")
        .unwrap()
        .0;
    state
        .oauth
        .as_mut()
        .unwrap()
        .grants
        .get_mut(id)
        .unwrap()
        .access_expires_at = auth::now().unwrap();
    f.registry.save(&state).unwrap();
    assert!(
        f.registry
            .credential(&permit, &json!({"test/conversation":"a"}))
            .is_err()
    );
    let rotated = f.registry.exchange(&f.refresh(&token), RESOURCE).unwrap();
    f.permit(&rotated);
    let mut state = f.registry.read().unwrap();
    state.clock = auth::now().unwrap() + 60;
    f.registry.save(&state).unwrap();
    assert!(f.registry.exchange(&f.refresh(&rotated), RESOURCE).is_err());
    assert!(f.registry.begin(&f.authorization(), RESOURCE).is_err());
    fs::remove_file(f.home.join("gateway/state.json")).unwrap();
    assert!(f.registry.exchange(&f.refresh(&rotated), RESOURCE).is_err());
    assert!(!f.home.join("gateway/state.json").exists());
}

#[test]
fn untrusted_inputs_and_request_capacity_are_bounded_without_redirect_or_grant_creation() {
    let f = Fixture::new();
    for (key, value) in [
        ("redirect_uri", "https://host.example/callback/extra"),
        ("code_challenge_method", "plain"),
        ("code_challenge", "short"),
        ("resource", "https://other.example/mcp"),
        ("scope", "owner"),
        ("response_type", "token"),
    ] {
        let mut fields = f.authorization();
        fields.insert(key.into(), value.into());
        assert!(f.registry.begin(&fields, RESOURCE).is_err());
    }
    assert!(f.registry.read().unwrap().oauth.is_none());
    for _ in 0..MAX_PER_CLIENT {
        f.pending();
    }
    assert!(f.registry.begin(&f.authorization(), RESOURCE).is_err());
    assert_eq!(
        f.registry.oauth_requests().unwrap()["requests"]
            .as_array()
            .unwrap()
            .len(),
        MAX_PER_CLIENT
    );
    for bad in ["client_id=a&client_id=b", "x=%", "x=%GG", "x=%FF", "x=%00"] {
        assert!(parameters(bad).is_err());
    }
    assert!(parameters(&"x".repeat(8193)).is_err());
    for bad in [
        "http://evil.example/cb",
        "https://user:pass@host.example/cb",
        "https://host.example/cb#fragment",
    ] {
        assert!(
            Registration {
                resource: RESOURCE.into(),
                redirect_uris: vec![bad.into()],
                assertion: None,
            }
            .validate()
            .is_err()
        );
    }
}

#[test]
fn native_localhost_callbacks_require_an_exact_registered_url() {
    let f = Fixture::new();
    let callback = "http://localhost:49152/callback";
    let mut state = f.registry.read().unwrap();
    state
        .clients
        .get_mut(&f.client)
        .unwrap()
        .oauth
        .as_mut()
        .unwrap()
        .redirect_uris = vec![callback.into()];
    f.registry.save(&state).unwrap();
    let mut fields = f.authorization();
    for bad in [
        "http://127.0.0.1:49152/callback",
        "http://localhost:49153/callback",
        "http://localhost:49152/other",
    ] {
        fields.insert("redirect_uri".into(), bad.into());
        assert!(f.registry.begin(&fields, RESOURCE).is_err());
    }
    fields.insert("redirect_uri".into(), callback.into());
    let pending = f.registry.begin(&fields, RESOURCE).unwrap();
    let id = pending["request"].as_str().unwrap();
    f.registry.oauth_decide(id, true).unwrap();
    let redirect = f.registry.continue_request(id, RESOURCE).unwrap().unwrap();
    assert!(redirect.starts_with(&format!("{callback}?")));
    for bad in [
        "http://localhost/callback",
        "http://localhost:0/callback",
        "http://localhost.:49152/callback",
        "http://sub.localhost:49152/callback",
        "http://localhost.example:49152/callback",
        "http://localhost:49152/callback#fragment",
        "http://user@localhost:49152/callback",
    ] {
        assert!(
            Registration {
                resource: RESOURCE.into(),
                redirect_uris: vec![bad.into()],
                assertion: None,
            }
            .validate()
            .is_err(),
            "accepted {bad}"
        );
    }
    assert!(
        Registration {
            resource: "http://localhost:49152/mcp".into(),
            redirect_uris: vec![callback.into()],
            assertion: None,
        }
        .validate()
        .is_err()
    );
}

#[test]
fn concurrent_redemption_and_refresh_commit_only_once_and_replay_revokes_the_family() {
    let f = Fixture::new();
    let code = f.code();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    f.registry.exchange(&code, RESOURCE)
                })
            })
            .collect();
        tasks
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    let token = results.into_iter().find_map(Result::ok).unwrap();
    assert!(
        f.registry
            .authenticate_at(token["access_token"].as_str().unwrap(), Some(RESOURCE))
            .is_err()
    );
    let fresh = f.grant();
    let refresh = f.refresh(&fresh);
    let results = std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    f.registry.exchange(&refresh, RESOURCE)
                })
            })
            .collect();
        tasks
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    let token = results.into_iter().find_map(Result::ok).unwrap();
    assert!(
        f.registry
            .authenticate_at(token["access_token"].as_str().unwrap(), Some(RESOURCE))
            .is_err()
    );
}
