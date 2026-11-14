use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

#[tokio::test]
async fn oauth_discovery_consent_pkce_refresh_and_revocation_work_through_real_http() {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://{address}");
    let resource = format!("{origin}/mcp");
    let export = f.home.join("oauth.json");
    let redirect = "https://host.example/callback?tenant=1";
    let added = registry::add_client(
        &f.home,
        "OAuth <host>",
        "test/conversation",
        &export,
        720,
        Some(registry::oauth::Registration {
            resource: resource.clone(),
            redirect_uris: vec![redirect.into()],
            assertion: None,
        }),
        None,
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&fs::read(export).unwrap()).unwrap();
    let id = added["client"].as_str().unwrap();
    let secret = value["token"].as_str().unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let server = Running::start(&f.home, listener, origin.clone(), address.to_string(), None).await;
    let denied = client.get(&resource).send().await.unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert!(
        denied.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("/.well-known/oauth-protected-resource/mcp")
    );
    let meta: Value = client
        .get(format!("{origin}/.well-known/oauth-protected-resource/mcp"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(meta["resource"], resource);
    assert_eq!(meta["authorization_servers"][0], origin);
    let meta: Value = client
        .get(format!("{origin}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(meta["authorization_response_iss_parameter_supported"], true);
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));
    assert!(meta.get("registration_endpoint").is_none());
    assert!(meta.get("client_id_metadata_document_supported").is_none());
    let verifier = config::secret();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(&verifier));
    let fields = [
        ("response_type", "code"),
        ("client_id", id),
        ("redirect_uri", redirect),
        ("resource", &resource),
        ("code_challenge_method", "S256"),
        ("code_challenge", &challenge),
        ("state", "roundtrip-state"),
    ];
    let response = client
        .get(format!("{origin}/oauth/authorize"))
        .query(&fields)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    let html = response.text().await.unwrap();
    assert!(html.contains("OAuth &lt;host&gt;"));
    assert!(!html.contains(secret));
    let registry = Registry::open(&f.home).unwrap();
    let pending = registry.oauth_requests().unwrap();
    let request = pending["requests"][0]["request"].as_str().unwrap();
    let continued = format!("{origin}/oauth/continue?request={request}");
    assert_eq!(
        client.get(&continued).send().await.unwrap().status(),
        StatusCode::OK
    );
    registry.oauth_decide(request, true).unwrap();
    let authorized = client.get(&continued).send().await.unwrap();
    assert_eq!(authorized.status(), StatusCode::SEE_OTHER);
    let location = url::Url::parse(authorized.headers()["location"].to_str().unwrap()).unwrap();
    let callback: std::collections::BTreeMap<_, _> = location
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(callback["iss"], origin);
    assert_eq!(callback["state"], "roundtrip-state");
    assert_eq!(callback["tenant"], "1");
    let endpoint = format!("{origin}/oauth/token");
    let token_fields = [
        ("grant_type", "authorization_code"),
        ("client_id", id),
        ("client_secret", secret),
        ("resource", &resource),
        ("redirect_uri", redirect),
        ("code", &callback["code"]),
        ("code_verifier", &verifier),
    ];
    let response = client
        .post(&endpoint)
        .form(&token_fields)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let issued: Value = response.json().await.unwrap();
    let token = issued["access_token"].as_str().unwrap();
    assert_eq!(issued["token_type"], "Bearer");
    assert!(issued["expires_in"].as_u64().unwrap() <= 900);
    assert_eq!(
        server
            .post(&client, secret)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let a = server
        .call(
            &client,
            token,
            "a",
            "gent_register",
            json!({"name":"A","provider":"synthetic-oauth"}),
        )
        .await;
    let b = server
        .call(
            &client,
            token,
            "b",
            "gent_register",
            json!({"name":"B","provider":"synthetic-oauth"}),
        )
        .await;
    assert_ne!(a["agent"]["id"], b["agent"]["id"]);
    server.close().await;
    let listener = TcpListener::bind(address).await.unwrap();
    let server = Running::start(&f.home, listener, origin.clone(), address.to_string(), None).await;
    let refresh_fields = [
        ("grant_type", "refresh_token"),
        ("client_id", id),
        ("client_secret", secret),
        ("resource", &resource),
        ("refresh_token", issued["refresh_token"].as_str().unwrap()),
    ];
    let response = client
        .post(&endpoint)
        .form(&refresh_fields)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rotated: Value = response.json().await.unwrap();
    let current = rotated["access_token"].as_str().unwrap();
    assert_eq!(
        server
            .post(&client, token)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server
            .call(&client, current, "a", "gent_identity", json!({}))
            .await["agent"]["id"],
        a["agent"]["id"]
    );
    assert_eq!(
        server
            .call(&client, current, "b", "gent_identity", json!({}))
            .await["agent"]["id"],
        b["agent"]["id"]
    );
    registry.revoke(id).unwrap();
    assert_eq!(
        server
            .post(&client, current)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .post(&endpoint)
            .form(&refresh_fields)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let too_large = client
        .post(&endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("a".repeat(8193))
        .send()
        .await
        .unwrap();
    assert_eq!(too_large.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        client
            .post(&endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body("client_id=a&client_id=b")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .get(format!("{origin}/.well-known/oauth-authorization-server"))
            .header("host", "evil.example")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    server.close().await;
    daemon.close(&f.home).await;
}
