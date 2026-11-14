use super::*;
use std::fs;
const RESOURCE: &str = "https://node.example/mcp";
const REDIRECT: &str = "https://host.example/callback?tenant=one";
struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    registry: Registry,
    client: String,
    secret: String,
    verifier: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("node");
        config::initialize(&home, "oauth").unwrap();
        let out = home.join("host.json");
        let registration = Registration {
            resource: RESOURCE.into(),
            redirect_uris: vec![REDIRECT.into()],
        };
        let result = add_client(
            &home,
            "host",
            "test/conversation",
            &out,
            720,
            Some(registration.clone()),
        )
        .unwrap();
        assert_eq!(
            add_client(
                &home,
                "host",
                "test/conversation",
                &out,
                720,
                Some(registration)
            )
            .unwrap(),
            result
        );
        assert!(add(&home, "host", "test/conversation", &out, 720).is_err());
        let export: Export = serde_json::from_slice(&fs::read(out).unwrap()).unwrap();
        Self {
            _temp: temp,
            registry: Registry::open(&home).unwrap(),
            home,
            client: export.client,
            secret: export.token,
            verifier: config::secret(),
        }
    }
    fn authorization(&self) -> Parameters {
        [
            ("response_type", "code".into()),
            ("client_id", self.client.clone()),
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
        [
            ("grant_type", "authorization_code".into()),
            ("client_id", self.client.clone()),
            ("client_secret", self.secret.clone()),
            ("resource", RESOURCE.into()),
            ("redirect_uri", REDIRECT.into()),
            ("code", fields["code"].clone()),
            ("code_verifier", self.verifier.clone()),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect()
    }
    fn grant(&self) -> Value {
        self.registry.exchange(&self.code(), RESOURCE).unwrap()
    }
    fn refresh(&self, token: &Value) -> Parameters {
        [
            ("grant_type", "refresh_token".into()),
            ("client_id", self.client.clone()),
            ("client_secret", self.secret.clone()),
            ("resource", RESOURCE.into()),
            (
                "refresh_token",
                token["refresh_token"].as_str().unwrap().into(),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect()
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
                redirect_uris: vec![bad.into()]
            }
            .validate()
            .is_err()
        );
    }
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
