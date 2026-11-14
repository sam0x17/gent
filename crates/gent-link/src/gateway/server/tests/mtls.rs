use super::*;
use crate::gateway::mtls::{Peer, Policy};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};

const NAME: &str = "client.example";

struct Ca {
    cert: Certificate,
    issuer: Issuer<'static, KeyPair>,
}
impl Ca {
    fn new(name: &str) -> Self {
        Self::new_edit(name, |_| {})
    }
    fn new_edit(name: &str, edit: impl FnOnce(&mut CertificateParams)) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        edit(&mut params);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Self {
            cert,
            issuer: Issuer::new(params, key),
        }
    }
    fn child(&self, name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Self {
            cert,
            issuer: Issuer::new(params, key),
        }
    }
    fn leaf(&self, names: Vec<String>, edit: impl FnOnce(&mut CertificateParams)) -> Leaf {
        let mut params = CertificateParams::new(names).unwrap();
        params.distinguished_name.push(DnType::CommonName, NAME);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        edit(&mut params);
        let key = KeyPair::generate().unwrap();
        Leaf {
            cert: params.signed_by(&key, &self.issuer).unwrap(),
            key,
        }
    }
    fn good(&self) -> Leaf {
        self.leaf(vec![NAME.into()], |_| {})
    }
    fn policy(&self, path: &Path) -> Policy {
        config::write_private(path, self.cert.pem().as_bytes()).unwrap();
        Policy::load(path, NAME).unwrap()
    }
}
struct Leaf {
    cert: Certificate,
    key: KeyPair,
}
impl Leaf {
    fn peer(&self) -> Peer {
        Peer::from_tls(Some(&[self.cert.der().clone()])).unwrap()
    }
    fn identity(&self) -> reqwest::Identity {
        reqwest::Identity::from_pem(
            format!("{}{}", self.cert.pem(), self.key.serialize_pem()).as_bytes(),
        )
        .unwrap()
    }
}
struct Endpoint {
    options: Run,
    server_cert: Certificate,
}
impl Endpoint {
    fn new(f: &Fixture) -> Self {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = f.home.join("tls.pem");
        let key = f.home.join("tls.key");
        config::write_private(&cert, generated.cert.pem().as_bytes()).unwrap();
        config::write_private(&key, generated.signing_key.serialize_pem().as_bytes()).unwrap();
        Self {
            options: Run {
                listen: "127.0.0.1:0".parse().unwrap(),
                origin: None,
                tls_cert: Some(cert),
                tls_key: Some(key),
            },
            server_cert: generated.cert,
        }
    }
    async fn start(&mut self, f: &Fixture) -> Running {
        let listener = TcpListener::bind(self.options.listen).await.unwrap();
        self.options.listen = listener.local_addr().unwrap();
        self.options.origin = Some(format!("https://localhost:{}", self.options.listen.port()));
        let (host, origin) = origin(&self.options, self.options.listen).unwrap();
        let policies = Registry::open(&f.home).unwrap().tls_policies().unwrap();
        Running::start(
            &f.home,
            listener,
            origin,
            host,
            tls(&self.options, &policies).unwrap(),
        )
        .await
    }
    fn client(&self, leaf: Option<&Leaf>) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .resolve("localhost", self.options.listen)
            .add_root_certificate(
                reqwest::Certificate::from_pem(self.server_cert.pem().as_bytes()).unwrap(),
            );
        if let Some(leaf) = leaf {
            builder = builder.identity(leaf.identity());
        }
        builder.build().unwrap()
    }
}
fn grant(
    f: &Fixture,
    name: &str,
    policy: Policy,
    oauth: Option<registry::oauth::Registration>,
) -> (String, String) {
    let out = f.home.join(format!("{name}.json"));
    let added = registry::add_client(
        &f.home,
        name,
        "test/conversation",
        &out,
        24,
        oauth,
        Some(policy),
    )
    .unwrap();
    let export: Value = serde_json::from_slice(&fs::read(out).unwrap()).unwrap();
    (
        added["client"].as_str().unwrap().into(),
        export["token"].as_str().unwrap_or_default().into(),
    )
}

#[test]
fn client_certificate_policy_requires_exact_san_usage_validity_and_a_bounded_ca() {
    let f = Fixture::new();
    let ca = Ca::new("allowed");
    let ca_path = f.home.join("ca.pem");
    let policy = ca.policy(&ca_path);
    let now = crate::auth::now().unwrap();
    policy.verify(&ca.good().peer(), now).unwrap();
    policy.verify(&ca.good().peer(), now).unwrap(); // rotated leaf, same authority
    assert!(policy.verify(&Peer::default(), now).is_err());
    for (index, ca) in [
        Ca::new_edit("expired", |p| {
            p.not_after = rcgen::date_time_ymd(2020, 1, 1)
        }),
        Ca::new_edit("future", |p| {
            p.not_before = rcgen::date_time_ymd(4090, 1, 1)
        }),
    ]
    .iter()
    .enumerate()
    {
        // Expired anchors remain inspectable/revocable; they cannot authenticate.
        let policy = ca.policy(&f.home.join(format!("time-{index}.pem")));
        policy.validate().unwrap();
        assert!(policy.verify(&ca.good().peer(), now).is_err());
    }
    for leaf in [
        Ca::new("untrusted").good(),
        ca.leaf(vec!["other.example".into()], |_| {}),
        ca.leaf(vec!["*.example".into()], |_| {}),
        ca.leaf(vec!["CLIENT.example".into()], |_| {}),
        ca.leaf(vec![], |_| {}), // matching CN cannot replace DNS SAN
        ca.leaf(vec![NAME.into()], |p| {
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth]
        }),
        ca.leaf(vec![NAME.into()], |p| p.extended_key_usages.clear()),
        ca.leaf(vec![NAME.into()], |p| {
            p.not_after = rcgen::date_time_ymd(2020, 1, 1)
        }),
        ca.leaf(vec![NAME.into()], |p| {
            p.not_before = rcgen::date_time_ymd(4090, 1, 1)
        }),
    ] {
        assert!(policy.verify(&leaf.peer(), now).is_err());
    }
    for name in [
        "*.example",
        "CLIENT.example",
        "client.example.",
        "127.0.0.1",
        "client/example",
        "",
        "a\nb",
    ] {
        assert!(Policy::load(&ca_path, name).is_err(), "accepted {name}");
    }
    let oversized = tokio_rustls::rustls::pki_types::CertificateDer::from(vec![0; 8193]);
    assert!(Peer::from_tls(Some(&[oversized])).is_err());
    assert!(Peer::from_tls(Some(&vec![ca.cert.der().clone(); 9])).is_err());
    for contents in [
        String::new(),
        "x".repeat(16385),
        format!("{}{}", ca.cert.pem(), ca.cert.pem()),
        ca.good().cert.pem(),
        ca.good().key.serialize_pem(),
    ] {
        fs::write(&ca_path, contents).unwrap();
        assert!(Policy::load(&ca_path, NAME).is_err());
    }
    fs::remove_file(&ca_path).unwrap();
    assert!(Policy::load(&ca_path, NAME).is_err());
}

#[tokio::test]
async fn mtls_is_per_grant_survives_restart_and_cannot_be_forged_by_http_or_plaintext() {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let root = Ca::new("shared root");
    let ca = root.child("allowed intermediate");
    let other = root.child("other allowed intermediate");
    let (id, token) = grant(&f, "pinned", ca.policy(&f.home.join("ca.pem")), None);
    let (_, other_token) = grant(&f, "other", other.policy(&f.home.join("other.pem")), None);
    let mut endpoint = Endpoint::new(&f);
    let server = endpoint.start(&f).await;
    let anonymous = endpoint.client(None);
    let trusted = endpoint.client(Some(&ca.good()));
    let wrong_authority = endpoint.client(Some(&other.good()));
    let wrong_name = endpoint.client(Some(&ca.leaf(vec!["other.example".into()], |_| {})));
    let rpc = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
    for client in [&anonymous, &wrong_authority, &wrong_name] {
        assert_eq!(
            server
                .post(client, &token)
                .json(&rpc)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        server
            .post(&anonymous, &token)
            .header("x-client-cert", ca.good().cert.pem().replace('\n', " "))
            .header("x-tls-client-name", NAME)
            .json(&rpc)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        server
            .post(&endpoint.client(Some(&Ca::new("untrusted").good())), &token)
            .json(&rpc)
            .send()
            .await
            .is_err()
    );
    assert_eq!(
        server
            .post(&trusted, "bad")
            .json(&rpc)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        server
            .rpc(&wrong_authority, &other_token, "tools/list", json!({}))
            .await["result"]["tools"]
            .is_array()
    );
    // Grants without a certificate policy retain their original bearer semantics.
    assert!(
        server
            .rpc(&anonymous, &f.token, "tools/list", json!({}))
            .await["result"]["tools"]
            .is_array()
    );
    let first = server
        .call(
            &trusted,
            &token,
            "chat",
            "gent_register",
            json!({"name":"pinned", "provider":"fixture"}),
        )
        .await;
    server.close().await;
    let server = endpoint.start(&f).await;
    let rotated = endpoint.client(Some(&ca.good()));
    let restored = server
        .call(&rotated, &token, "chat", "gent_identity", json!({}))
        .await;
    assert_eq!(first["agent"]["id"], restored["agent"]["id"]);
    let registry = Registry::open(&f.home).unwrap();
    let permit = registry
        .authenticate_remote(token.clone(), server.url.clone(), ca.good().peer())
        .await
        .unwrap();
    registry.revoke(&id).unwrap();
    assert!(
        registry
            .credential_remote(permit, json!({"test/conversation":"chat"}))
            .await
            .is_err()
    );
    assert_eq!(
        server
            .post(&rotated, &token)
            .json(&rpc)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    server.close().await;
    // A fresh active grant remains protected when an owner starts plain HTTP.
    let plaintext = f.start().await;
    assert_eq!(
        plaintext
            .post(&client(), &other_token)
            .json(&rpc)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    plaintext.close().await;
    daemon.close(&f.home).await;
}

#[test]
fn mtls_registration_is_durable_and_retries_cannot_remove_or_replace_the_policy() {
    let f = Fixture::new();
    let ca = Ca::new("allowed");
    let path = f.home.join("ca.pem");
    let policy = ca.policy(&path);
    let out = f.home.join("pinned.json");
    let first = registry::add_client(
        &f.home,
        "pinned",
        "test/conversation",
        &out,
        24,
        None,
        Some(policy.clone()),
    )
    .unwrap();
    assert_eq!(
        registry::add_client(
            &f.home,
            "pinned",
            "test/conversation",
            &out,
            24,
            None,
            Some(policy.clone())
        )
        .unwrap(),
        first
    );
    assert!(
        registry::add_client(&f.home, "pinned", "test/conversation", &out, 24, None, None).is_err()
    );
    let different = Ca::new("changed").policy(&f.home.join("changed.pem"));
    assert!(
        registry::add_client(
            &f.home,
            "pinned",
            "test/conversation",
            &out,
            24,
            None,
            Some(different)
        )
        .is_err()
    );
    fs::remove_file(path).unwrap(); // persisted bytes, no mutable runtime file reference
    assert_eq!(
        Registry::open(&f.home)
            .unwrap()
            .tls_policies()
            .unwrap()
            .len(),
        1
    );
    registry::add_client(
        &f.home,
        "oauth",
        "test/conversation",
        &f.home.join("oauth.json"),
        24,
        Some(registry::oauth::Registration {
            resource: "https://gateway.example/mcp".into(),
            redirect_uris: vec!["https://host.example/cb".into()],
            assertion: None,
        }),
        None,
    )
    .unwrap();
    let (second_id, _) = grant(&f, "second-pinned", policy.clone(), None);
    let state_path = f.home.join("gateway/state.json");
    let mut state: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(state["version"], 3);
    state["version"] = json!(2);
    fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(Registry::open(&f.home).is_err());
    state["version"] = json!(3);
    fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let id = first["client"].as_str().unwrap();
    for field in ["mtls", "mtls_required"] {
        let mut damaged = state.clone();
        damaged["clients"][id]
            .as_object_mut()
            .unwrap()
            .remove(field);
        fs::write(&state_path, serde_json::to_vec(&damaged).unwrap()).unwrap();
        assert!(Registry::open(&f.home).is_err());
    }
    fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let registry = Registry::open(&f.home).unwrap();
    let listing = registry.listing().unwrap();
    let client = listing["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "pinned")
        .unwrap();
    assert_eq!(client["mtls"], policy.summary());
    registry.revoke(first["client"].as_str().unwrap()).unwrap();
    assert_eq!(registry.tls_policies().unwrap().len(), 1);
    registry.revoke(&second_id).unwrap();
    assert!(registry.tls_policies().unwrap().is_empty());
}

#[tokio::test]
async fn mtls_oauth_keeps_browser_consent_open_but_binds_exchange_refresh_and_mcp_to_the_peer() {
    oauth_peer(false).await;
}

#[tokio::test]
async fn mtls_and_signed_assertions_are_both_required_when_configured() {
    oauth_peer(true).await;
}

async fn oauth_peer(signed: bool) {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let ca = Ca::new("allowed");
    let mut endpoint = Endpoint::new(&f);
    // Reserve an address so the resource can be pinned before TLS startup.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    endpoint.options.listen = listener.local_addr().unwrap();
    drop(listener);
    let origin = format!("https://localhost:{}", endpoint.options.listen.port());
    let resource = format!("{origin}/mcp");
    let callback = "https://host.example/callback";
    let (id, secret) = grant(
        &f,
        "oauth",
        ca.policy(&f.home.join("ca.pem")),
        Some(registry::oauth::Registration {
            resource: resource.clone(),
            redirect_uris: vec![callback.into()],
            assertion: signed.then(crate::gateway::assertion::tests::policy),
        }),
    );
    let server = endpoint.start(&f).await;
    let client_id = if signed {
        crate::gateway::assertion::tests::CLIENT
    } else {
        &id
    };
    let authenticate = |fields: &mut std::collections::BTreeMap<String, String>, second: bool| {
        if signed {
            let mut claims = crate::gateway::assertion::tests::claims();
            claims["aud"] = json!(format!("{origin}/oauth/token"));
            fields.insert(
                "client_assertion_type".into(),
                crate::gateway::assertion::TYPE.into(),
            );
            fields.insert(
                "client_assertion".into(),
                crate::gateway::assertion::tests::sign(
                    json!({"alg":"RS256","kid":if second { "fixture-b" } else { "fixture-a" }}),
                    claims,
                    second,
                ),
            );
        } else {
            fields.insert("client_secret".into(), secret.clone());
        }
    };
    let browser = endpoint.client(None);
    let host = endpoint.client(Some(&ca.good()));
    let verifier = config::secret();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(&verifier));
    for path in [
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-authorization-server",
    ] {
        assert_eq!(
            browser
                .get(format!("{origin}{path}"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    let fields = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", callback),
        ("resource", &resource),
        ("code_challenge_method", "S256"),
        ("code_challenge", &challenge),
        ("state", "roundtrip"),
    ];
    assert_eq!(
        browser
            .get(format!("{origin}/oauth/authorize"))
            .query(&fields)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let registry = Registry::open(&f.home).unwrap();
    let pending = registry.oauth_requests().unwrap();
    let request = pending["requests"][0]["request"].as_str().unwrap();
    registry.oauth_decide(request, true).unwrap();
    let response = browser
        .get(format!("{origin}/oauth/continue?request={request}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let callback_url = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    let values: std::collections::BTreeMap<_, _> = callback_url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(values["state"], "roundtrip");
    assert_eq!(values["iss"], origin);
    let mut form: std::collections::BTreeMap<String, String> = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("resource", &resource),
        ("redirect_uri", callback),
        ("code", &values["code"]),
        ("code_verifier", &verifier),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    authenticate(&mut form, false);
    let token_url = format!("{origin}/oauth/token");
    let denied: Value = browser
        .post(&token_url)
        .form(&form)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(denied["error"], "invalid_client");
    if signed {
        let mut missing = form.clone();
        missing.remove("client_assertion");
        let rejected: Value = host
            .post(&token_url)
            .form(&missing)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(rejected["error"], "invalid_client");
    }
    let token: Value = host
        .post(&token_url)
        .form(&form)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access = token["access_token"].as_str().unwrap();
    let first = server
        .call(
            &host,
            access,
            "chat",
            "gent_register",
            json!({"name":"oauth", "provider":"fixture"}),
        )
        .await;
    let rpc = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
    assert_eq!(
        server
            .post(&browser, access)
            .json(&rpc)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut refresh: std::collections::BTreeMap<String, String> = [
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("resource", &resource),
        ("refresh_token", token["refresh_token"].as_str().unwrap()),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    authenticate(&mut refresh, false);
    let denied: Value = browser
        .post(&token_url)
        .form(&refresh)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(denied["error"], "invalid_client");
    let mut rotated: Value = host
        .post(&token_url)
        .form(&refresh)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let restored = server
        .call(
            &host,
            rotated["access_token"].as_str().unwrap(),
            "chat",
            "gent_identity",
            json!({}),
        )
        .await;
    assert_eq!(first["agent"]["id"], restored["agent"]["id"]);
    assert_eq!(
        server
            .post(&host, access)
            .json(&rpc)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    if signed {
        let mut policy = serde_json::to_value(crate::gateway::assertion::tests::policy()).unwrap();
        policy["keys"]
            .as_array_mut()
            .unwrap()
            .retain(|key| key["kid"] == "fixture-b");
        let path = f.home.join("replacement.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({"keys":policy["keys"]})).unwrap(),
        )
        .unwrap();
        registry.set_signing_keys(&id, &path, 0).unwrap();
        refresh.insert(
            "refresh_token".into(),
            rotated["refresh_token"].as_str().unwrap().into(),
        );
        authenticate(&mut refresh, false);
        let rejected: Value = host
            .post(&token_url)
            .form(&refresh)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(rejected["error"], "invalid_client");
        authenticate(&mut refresh, true);
        let rejected: Value = browser
            .post(&token_url)
            .form(&refresh)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(rejected["error"], "invalid_client");
        rotated = host
            .post(&token_url)
            .form(&refresh)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let restored = server
            .call(
                &host,
                rotated["access_token"].as_str().unwrap(),
                "chat",
                "gent_identity",
                json!({}),
            )
            .await;
        assert_eq!(first["agent"]["id"], restored["agent"]["id"]);
        assert_eq!(
            server
                .post(&browser, rotated["access_token"].as_str().unwrap())
                .json(&rpc)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    registry.revoke(&id).unwrap();
    assert_eq!(
        server
            .post(&host, rotated["access_token"].as_str().unwrap())
            .json(&rpc)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    server.close().await;
    daemon.close(&f.home).await;
}
