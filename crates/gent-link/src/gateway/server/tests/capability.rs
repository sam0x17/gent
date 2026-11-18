use super::*;

async fn rpc(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
) -> reqwest::Response {
    let mut request = client
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method);
    if let Some(name) = params["name"].as_str() {
        request = request.header("mcp-name", name);
    }
    request
        .json(&json!({"jsonrpc":"2.0", "id":1, "method":method,
            "params":params}))
        .send()
        .await
        .unwrap()
}

async fn call(client: &reqwest::Client, url: &str, name: &str, arguments: Value) -> Value {
    let response = rpc(
        client,
        url,
        "tools/call",
        json!({"name":name,"arguments":arguments,
        "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}}}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = response.json().await.unwrap();
    assert!(value.get("error").is_none(), "{value}");
    assert_ne!(value["result"]["isError"], true, "{value}");
    serde_json::from_str(value["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn url_authentication_rotation_and_revocation_keep_chat_identities() {
    let f = Fixture::new();
    registry::capability::create(&f.home).unwrap();
    registry::capability::create(&f.home).unwrap();
    let daemon = Daemon::start(&f.home).await;
    let server = f.start().await;
    let base = server.url.trim_end_matches("/mcp").to_owned();
    let url = registry::capability::url(&f.home, &base, false).unwrap();
    let client = client();
    let init = rpc(
        &client,
        &url,
        "initialize",
        json!({"protocolVersion":"2026-07-28",
        "capabilities":{},"clientInfo":{"name":"phone","version":"1"}}),
    )
    .await;
    assert_eq!(init.status(), StatusCode::OK);
    let init = init.text().await.unwrap();
    assert!(!init.contains("gent_g1."));
    let chat =
        call(&client, &url, "gent_conversation_open", json!({})).await["conversation"].clone();
    let other =
        call(&client, &url, "gent_conversation_open", json!({})).await["conversation"].clone();
    let agent = call(
        &client,
        &url,
        "gent_register",
        json!({"conversation":chat,"name":"phone","provider":"synthetic"}),
    )
    .await;
    let second = call(
        &client,
        &url,
        "gent_register",
        json!({"conversation":other,"name":"other","provider":"synthetic"}),
    )
    .await;
    assert_ne!(agent["agent"]["id"], second["agent"]["id"]);
    assert!(
        !Registry::open(&f.home)
            .unwrap()
            .listing()
            .unwrap()
            .to_string()
            .contains("gent_g1.")
    );
    let rotated = registry::capability::url(&f.home, &base, true).unwrap();
    assert_ne!(url, rotated);
    let invalid = rpc(&client, &url, "tools/list", json!({})).await;
    assert_eq!(invalid.status(), StatusCode::NOT_FOUND);
    assert!(!invalid.headers().contains_key("www-authenticate"));
    let identity = call(
        &client,
        &rotated,
        "gent_identity",
        json!({"conversation":chat}),
    )
    .await;
    assert_eq!(identity["agent"]["id"], agent["agent"]["id"]);
    for invalid in [
        format!("{base}/mcp/{}", f.token),
        format!("{rotated}?secret=x"),
        format!("{rotated}/more"),
    ] {
        assert!(
            !rpc(&client, &invalid, "tools/list", json!({}))
                .await
                .status()
                .is_success()
        );
    }
    // Copying a valid URL's secret to another node cannot authenticate it there.
    let different = Fixture::new();
    let second_server = different.start().await;
    let wrong = format!(
        "{}/{}",
        second_server.url,
        rotated.rsplit('/').next().unwrap()
    );
    assert_eq!(
        rpc(&client, &wrong, "tools/list", json!({})).await.status(),
        StatusCode::NOT_FOUND
    );
    second_server.close().await;
    server.close().await;
    let server = f.start().await;
    let url =
        registry::capability::url(&f.home, server.url.trim_end_matches("/mcp"), false).unwrap();
    assert_eq!(
        call(&client, &url, "gent_identity", json!({"conversation":chat})).await["agent"]["id"],
        agent["agent"]["id"]
    );
    registry::capability::revoke(&f.home).unwrap();
    assert_eq!(
        rpc(&client, &url, "tools/list", json!({})).await.status(),
        StatusCode::NOT_FOUND
    );
    assert!(registry::capability::url(&f.home, &base, true).is_err());
    server.close().await;
    daemon.close(&f.home).await;
}
