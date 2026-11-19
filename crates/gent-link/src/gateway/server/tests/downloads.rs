use super::*;
use crate::gateway::downloads::Runtime;
use axum::http::Method;
use gent_protocol::file_objects::IncomingFile;

async fn start(f: &Fixture, address: Option<SocketAddr>, enabled: bool) -> (Running, Arc<Runtime>) {
    let listener = TcpListener::bind(address.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://{address}");
    let registry = Registry::open(&f.home)
        .unwrap()
        .with_file_downloads(
            if enabled {
                std::slice::from_ref(&f.id)
            } else {
                &[]
            },
            &origin,
        )
        .unwrap();
    let downloads = registry.downloads.clone();
    let metadata = crate::gateway::metadata::runtime::Runtime::new(
        registry.clone(),
        format!("{origin}/mcp"),
        &[],
    )
    .await
    .unwrap();
    let stop = CancellationToken::new();
    let app = router(
        f.home.clone(),
        registry,
        address.to_string(),
        origin.clone(),
        stop.clone(),
        metadata,
    );
    let task = tokio::spawn(serve(listener, app, None, stop.clone()));
    (
        Running {
            address,
            url: format!("{origin}/mcp"),
            stop,
            task: Some(task),
        },
        downloads,
    )
}
async fn import(f: &Fixture, bytes: &[u8], name: &str, mime: &str) -> Value {
    let registry = Registry::open(&f.home).unwrap();
    let permit = registry.authenticate(&f.token).unwrap();
    let credential = registry
        .credential(&permit, &json!({"test/conversation":"a"}))
        .unwrap();
    gent_daemon::receive_file(
        &f.home,
        credential,
        IncomingFile {
            request_id: request_id(),
            source_id: "a".repeat(64),
            name: name.into(),
            media_type: mime.into(),
        },
        bytes,
    )
    .await
    .unwrap()["file"]
        .clone()
}
async fn register(server: &Running, client: &reqwest::Client, f: &Fixture, chat: &str) -> Value {
    server
        .call(
            client,
            &f.token,
            chat,
            "gent_register",
            json!({"name":chat,"provider":"fixture"}),
        )
        .await
}
async fn link(
    server: &Running,
    client: &reqwest::Client,
    f: &Fixture,
    chat: &str,
    id: &str,
) -> Value {
    let raw=server.rpc(client,&f.token,"tools/call",json!({"name":"gent_file_link","arguments":{"file_id":id},"_meta":{"test/conversation":chat}})).await;
    assert_ne!(raw["result"]["isError"], true, "{raw}");
    let value: Value =
        serde_json::from_str(raw["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let resource = &raw["result"]["content"][1];
    assert_eq!(resource["type"], "resource_link");
    assert_eq!(resource["uri"], value["download_url"]);
    assert_eq!(resource["name"], value["file"]["name"]);
    assert_eq!(resource["size"], value["file"]["byte_length"]);
    value
}

#[tokio::test]
async fn downloads_deliver_exact_bytes_safe_headers_and_survive_both_restarts() {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let (server, _) = start(&f, None, true).await;
    let client = client();
    register(&server, &client, &f, "a").await;
    let bytes = vec![37; 2 * 1024 * 1024 + 19];
    let file = import(&f, &bytes, "quote\" café.html", "text/html").await;
    let linked = link(&server, &client, &f, "a", file["id"].as_str().unwrap()).await;
    let url = linked["download_url"].as_str().unwrap();
    let response = client
        .get(url)
        .header("origin", "https://chat.example")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("sandbox")
    );
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"download\"; filename*=UTF-8''quote%22%20caf%C3%A9.html"
    );
    assert_eq!(&response.bytes().await.unwrap()[..], bytes);
    let head = client.head(url).send().await.unwrap();
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(
        head.headers()[header::CONTENT_LENGTH],
        bytes.len().to_string()
    );
    assert!(head.bytes().await.unwrap().is_empty());
    assert_eq!(
        client
            .get(url)
            .header(header::RANGE, "bytes=0-10")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::RANGE_NOT_SATISFIABLE
    );
    for bad in [
        format!("{url}?extra=1"),
        format!("{url}/more"),
        format!("{url}x"),
    ] {
        assert!(!client.get(bad).send().await.unwrap().status().is_success());
    }
    assert_eq!(
        client.post(url).send().await.unwrap().status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        client
            .get(url)
            .header("x-forwarded-host", "forged")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let empty = import(&f, b"", "empty.bin", "application/octet-stream").await;
    let empty_link = link(&server, &client, &f, "a", empty["id"].as_str().unwrap()).await;
    let response = client
        .get(empty_link["download_url"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.bytes().await.unwrap().is_empty());
    let address = server.address;
    server.close().await;
    daemon.close(&f.home).await;
    let daemon = Daemon::start(&f.home).await;
    let (server, _) = start(&f, Some(address), true).await;
    assert_eq!(
        &client.get(url).send().await.unwrap().bytes().await.unwrap()[..],
        bytes
    );
    server.close().await;
    let (server, _) = start(&f, Some(address), false).await;
    assert_eq!(
        client.get(url).send().await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    server.close().await;
    daemon.close(&f.home).await;
}

#[tokio::test]
async fn download_links_follow_message_permissions_agent_and_host_revocation() {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let (server, _) = start(&f, None, true).await;
    let client = client();
    let a = register(&server, &client, &f, "a").await;
    let b = register(&server, &client, &f, "b").await;
    let file = import(
        &f,
        b"private-file",
        "private.bin",
        "application/octet-stream",
    )
    .await;
    let denied=server.rpc(&client,&f.token,"tools/call",json!({"name":"gent_file_link","arguments":{"file_id":file["id"]},"_meta":{"test/conversation":"b"}})).await;
    assert_eq!(denied["result"]["isError"], true);
    let policy = Policy {
        rules: [Permission::Enumerate, Permission::Send, Permission::Receive]
            .into_iter()
            .map(|permission| Rule {
                actor: Selector::All,
                peer: Selector::All,
                permission,
                effect: Effect::Allow,
            })
            .collect(),
        ..Policy::default()
    };
    owner(
        &f.home,
        OwnerOp::SetPolicy {
            policy: policy.clone(),
        },
    )
    .await;
    server.call(&client,&f.token,"a","gent_send_non_blocking",json!({"recipient":b["agent"]["id"],"request_id":request_id(),"text":"file","file_ids":[file["id"]]})).await;
    let messages = server
        .call(&client, &f.token, "b", "gent_inbox", json!({}))
        .await;
    let incoming = messages[0]["attachments"][0]["id"].as_str().unwrap();
    let received = link(&server, &client, &f, "b", incoming).await;
    let original = link(&server, &client, &f, "a", file["id"].as_str().unwrap()).await;
    let received_url = received["download_url"].as_str().unwrap();
    let own_url = original["download_url"].as_str().unwrap();
    assert_eq!(
        client.get(received_url).send().await.unwrap().status(),
        StatusCode::OK
    );
    let mut denied_policy = policy;
    denied_policy.rules.push(Rule {
        actor: Selector::Agent(b["agent"]["id"].as_str().unwrap().into()),
        peer: Selector::Agent(a["agent"]["id"].as_str().unwrap().into()),
        permission: Permission::Receive,
        effect: Effect::Deny,
    });
    owner(
        &f.home,
        OwnerOp::SetPolicy {
            policy: denied_policy,
        },
    )
    .await;
    assert_eq!(
        client.get(received_url).send().await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client.get(own_url).send().await.unwrap().status(),
        StatusCode::OK
    );
    owner(
        &f.home,
        OwnerOp::Revoke {
            agent_id: a["agent"]["id"].as_str().unwrap().into(),
        },
    )
    .await;
    assert_eq!(
        client.get(own_url).send().await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    Registry::open(&f.home).unwrap().revoke(&f.id).unwrap();
    assert_eq!(
        client.head(received_url).send().await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    server.close().await;
    daemon.close(&f.home).await;
}

#[tokio::test]
async fn downloads_hold_capacity_through_body_clones_and_release_on_drop() {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let (server, runtime) = start(&f, None, true).await;
    let client = client();
    register(&server, &client, &f, "a").await;
    let file = import(&f, b"bounded body", "file.bin", "application/octet-stream").await;
    let linked = link(&server, &client, &f, "a", file["id"].as_str().unwrap()).await;
    let token = linked["download_url"]
        .as_str()
        .unwrap()
        .split_once("/files/")
        .unwrap()
        .1;
    let registry = Registry::open(&f.home).unwrap();
    let headers = HeaderMap::new();
    let fetch = || runtime.handle(&registry, &f.home, token, &Method::GET, &headers);
    let first = fetch().await;
    assert_eq!(first.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(first.into_body(), 1024).await.unwrap();
    let clone = bytes.clone();
    drop(bytes);
    let second = fetch().await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(fetch().await.status(), StatusCode::SERVICE_UNAVAILABLE);
    // HEAD does not allocate a download payload.
    assert_eq!(
        runtime
            .handle(&registry, &f.home, token, &Method::HEAD, &headers)
            .await
            .status(),
        StatusCode::OK
    );
    drop(clone);
    let third = fetch().await;
    assert_eq!(third.status(), StatusCode::OK);
    assert_eq!(fetch().await.status(), StatusCode::SERVICE_UNAVAILABLE);
    // An abandoned body releases capacity without requiring consumption.
    drop(second);
    assert_eq!(fetch().await.status(), StatusCode::OK);
    drop(third);
    server.close().await;
    daemon.close(&f.home).await;
}

#[tokio::test]
async fn downloads_require_selection_for_each_host_even_when_tool_is_visible() {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let out = f.home.join("unselected.json");
    registry::add(&f.home, "unselected", "test/conversation", &out, 24).unwrap();
    let value: Value = serde_json::from_slice(&fs::read(out).unwrap()).unwrap();
    let token = value["token"].as_str().unwrap();
    let (server, _) = start(&f, None, true).await;
    let client = client();
    server
        .call(
            &client,
            token,
            "a",
            "gent_register",
            json!({"name":"a","provider":"fixture"}),
        )
        .await;
    let tools = server.rpc(&client, token, "tools/list", json!({})).await;
    assert!(
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "gent_file_link")
    );
    let result = server
        .rpc(
            &client,
            token,
            "tools/call",
            json!({
                "name":"gent_file_link", "arguments":{"file_id":request_id()},
                "_meta":{"test/conversation":"a"}
            }),
        )
        .await;
    assert_eq!(result["result"]["isError"], true);
    assert_eq!(
        result["result"]["content"][0]["text"],
        "download links are disabled for this host"
    );
    server.close().await;
    daemon.close(&f.home).await;
}
