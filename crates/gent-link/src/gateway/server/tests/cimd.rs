use super::*;
use crate::gateway::{
    assertion,
    metadata::{
        runtime::Runtime,
        tests::{Server, published},
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

const ID: &str = "https://metadata.example/client.json";
const CALLBACK: &str = "https://host.example/callback";

async fn runtime(
    registry: &Registry,
    resource: &str,
    local: &str,
    source: Arc<Server>,
) -> Arc<Runtime> {
    let mut runtime = Runtime::new(registry.clone(), resource.into(), &[local.into()])
        .await
        .unwrap();
    Arc::get_mut(&mut runtime).unwrap().fetcher = Some(Arc::new(move |r| {
        let source = source.clone();
        Box::pin(async move { source.import_registration(r).await })
    }));
    runtime
}

fn authentication(resource: &str, second: bool) -> Vec<(&'static str, String)> {
    let mut claims = assertion::tests::claims();
    claims["iss"] = json!(ID);
    claims["sub"] = json!(ID);
    claims["aud"] = json!(resource.strip_suffix("/mcp").unwrap().to_string() + "/oauth/token");
    let signed = assertion::tests::sign(
        json!({"alg":"RS256","kid":if second {"fixture-b"} else {"fixture-a"}}),
        claims,
        second,
    );
    vec![
        ("client_id", ID.into()),
        ("resource", resource.into()),
        ("client_assertion_type", assertion::TYPE.into()),
        ("client_assertion", signed),
    ]
}

async fn refresh(
    client: &reqwest::Client,
    resource: &str,
    token: &str,
    second: bool,
) -> reqwest::Response {
    let mut fields = authentication(resource, second);
    fields.push(("grant_type", "refresh_token".into()));
    fields.push(("refresh_token", token.into()));
    client
        .post(resource.replace("/mcp", "/oauth/token"))
        .form(&fields)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn cimd_discovery_fetch_rotation_restart_and_failed_refresh_preserve_agents() {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://{address}");
    let resource = format!("{origin}/mcp");
    let source = Arc::new(Server::start().await);
    source.reply("/client.json", &serde_json::to_vec(&published()).unwrap());
    let mut policy = assertion::tests::policy();
    policy.client_id = ID.into();
    let keys = serde_json::to_value(&policy).unwrap()["keys"].clone();
    source.reply(
        "/jwks.json",
        &serde_json::to_vec(&json!({"keys":keys})).unwrap(),
    );
    let added = registry::add_client(
        &f.home,
        "CIMD host",
        "test/conversation",
        &f.home.join("cimd.json"),
        24,
        Some(registry::oauth::Registration {
            resource: resource.clone(),
            redirect_uris: vec![CALLBACK.into()],
            assertion: Some(policy),
        }),
        None,
    )
    .unwrap();
    let local = added["client"].as_str().unwrap();
    let registry = Registry::open(&f.home).unwrap();
    let metadata = runtime(&registry, &resource, local, source.clone()).await;
    let server = Running::start_with_metadata(
        &f.home,
        listener,
        origin.clone(),
        address.to_string(),
        None,
        metadata.clone(),
    )
    .await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let discovery: Value = client
        .get(format!("{origin}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(discovery["client_id_metadata_document_supported"], true);
    assert!(discovery.get("registration_endpoint").is_none());
    assert_eq!(source.requests.lock().unwrap().len(), 0);
    let verifier = config::secret();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(&verifier));
    let mut fields = vec![
        ("response_type", "code"),
        ("client_id", ID),
        ("redirect_uri", CALLBACK),
        ("resource", resource.as_str()),
        ("code_challenge_method", "S256"),
        ("code_challenge", challenge.as_str()),
    ];
    fields[1].1 = "https://unapproved.example/client.json";
    assert_eq!(
        client
            .get(format!("{origin}/oauth/authorize"))
            .query(&fields)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    fields[1].1 = ID;
    fields[2].1 = "https://host.example/second"; // published, but not owner-selected
    assert_eq!(
        client
            .get(format!("{origin}/oauth/authorize"))
            .query(&fields)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(source.requests.lock().unwrap().len(), 0);
    fields[2].1 = CALLBACK;
    let response = client
        .get(format!("{origin}/oauth/authorize"))
        .query(&fields)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.text().await.unwrap().contains(ID));
    assert_eq!(source.requests.lock().unwrap().len(), 2);
    let pending = registry.oauth_requests().unwrap();
    let request = pending["requests"][0]["request"].as_str().unwrap();
    registry.oauth_decide(request, true).unwrap();
    let response = client
        .get(format!("{origin}/oauth/continue?request={request}"))
        .send()
        .await
        .unwrap();
    let location = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    let code = location
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let mut fields = authentication(&resource, false);
    fields.extend([
        ("grant_type", "authorization_code".into()),
        ("redirect_uri", CALLBACK.into()),
        ("code", code),
        ("code_verifier", verifier),
    ]);
    let response = client
        .post(format!("{origin}/oauth/token"))
        .form(&fields)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let issued: Value = response.json().await.unwrap();
    assert_eq!(source.requests.lock().unwrap().len(), 2);
    let agent = server
        .call(
            &client,
            issued["access_token"].as_str().unwrap(),
            "same-chat",
            "gent_register",
            json!({"name":"CIMD agent","provider":"synthetic"}),
        )
        .await;
    source.reply(
        "/jwks.json",
        &serde_json::to_vec(&json!({"keys":[keys[1]]})).unwrap(),
    );
    metadata.expire_for_test(ID).await;
    let token = issued["refresh_token"].as_str().unwrap();
    assert_eq!(
        refresh(&client, &resource, token, false).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        registry.signing_keys(local).unwrap()["key_ids"],
        json!(["fixture-b"])
    );
    let response = refresh(&client, &resource, token, true).await;
    assert_eq!(response.status(), StatusCode::OK);
    let issued: Value = response.json().await.unwrap();
    assert_eq!(
        server
            .call(
                &client,
                issued["access_token"].as_str().unwrap(),
                "same-chat",
                "gent_identity",
                json!({})
            )
            .await["agent"]["id"],
        agent["agent"]["id"]
    );
    server.close().await;
    let metadata = runtime(&registry, &resource, local, source.clone()).await;
    let listener = TcpListener::bind(address).await.unwrap();
    let server = Running::start_with_metadata(
        &f.home,
        listener,
        origin,
        address.to_string(),
        None,
        metadata.clone(),
    )
    .await;
    let before = source.requests.lock().unwrap().len();
    let token = issued["refresh_token"].as_str().unwrap();
    let response = refresh(&client, &resource, token, true).await;
    assert_eq!(response.status(), StatusCode::OK);
    let issued: Value = response.json().await.unwrap();
    assert_eq!(source.requests.lock().unwrap().len(), before + 2);
    metadata.expire_for_test(ID).await;
    let mut changed = published();
    changed["redirect_uris"] = json!(["https://host.example/second"]);
    source.reply("/client.json", &serde_json::to_vec(&changed).unwrap());
    let before = fs::read(f.home.join("gateway/state.json")).unwrap();
    let response = refresh(
        &client,
        &resource,
        issued["refresh_token"].as_str().unwrap(),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(fs::read(f.home.join("gateway/state.json")).unwrap(), before);
    // Existing short-lived access tokens retain their original authorization.
    assert_eq!(
        server
            .call(
                &client,
                issued["access_token"].as_str().unwrap(),
                "same-chat",
                "gent_identity",
                json!({})
            )
            .await["agent"]["id"],
        agent["agent"]["id"]
    );
    let before = source.requests.lock().unwrap().len();
    registry.revoke(local).unwrap();
    assert_eq!(
        refresh(
            &client,
            &resource,
            issued["refresh_token"].as_str().unwrap(),
            true
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(source.requests.lock().unwrap().len(), before);
    server.close().await;
    daemon.close(&f.home).await;
}
