use super::*;
use crate::gateway::registry;
use gent_daemon::{config, request};
use gent_protocol::{Effect, OwnerOp, Permission, Policy, Rule, Selector};
use serde_json::{Value, json};
use std::{fs, path::Path};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinHandle,
};
mod capability;
mod cimd;
mod conversations;
mod dashboard_html;
mod downloads;
mod files;
mod mtls;
mod oauth;
mod permissions;
mod request_reply;

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    token: String,
    id: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let home = managed_file::normalize(&temp.path().join("node")).unwrap();
        config::initialize(&home, "gateway").unwrap();
        let export = home.join("host.json");
        let added =
            registry::add(&home, "synthetic-host", "test/conversation", &export, 24).unwrap();
        let value: Value = serde_json::from_slice(&fs::read(export).unwrap()).unwrap();
        Self {
            _temp: temp,
            home,
            token: value["token"].as_str().unwrap().into(),
            id: added["client"].as_str().unwrap().into(),
        }
    }
    async fn start(&self) -> Running {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        Running::start(&self.home, listener, origin, address.to_string(), None).await
    }
}
struct Running {
    address: SocketAddr,
    url: String,
    stop: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
}
impl Running {
    async fn start(
        home: &Path,
        listener: TcpListener,
        origin: String,
        host: String,
        tls: Option<TlsAcceptor>,
    ) -> Self {
        let registry = Registry::open(home).unwrap();
        let metadata = crate::gateway::metadata::runtime::Runtime::new(
            registry.clone(),
            format!("{origin}/mcp"),
            &[],
        )
        .await
        .unwrap();
        Self::start_with_metadata(home, listener, origin, host, tls, metadata).await
    }
    async fn start_with_metadata(
        home: &Path,
        listener: TcpListener,
        origin: String,
        host: String,
        tls: Option<TlsAcceptor>,
        metadata: Arc<crate::gateway::metadata::runtime::Runtime>,
    ) -> Self {
        let registry = Registry::open(home).unwrap();
        Self::start_with_registry(home, listener, origin, host, tls, metadata, registry).await
    }
    async fn start_with_registry(
        home: &Path,
        listener: TcpListener,
        origin: String,
        host: String,
        tls: Option<TlsAcceptor>,
        metadata: Arc<crate::gateway::metadata::runtime::Runtime>,
        registry: Registry,
    ) -> Self {
        let stop = CancellationToken::new();
        let app = router(
            home.into(),
            registry,
            host,
            origin.clone(),
            stop.clone(),
            metadata,
        );
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(serve(listener, app, tls, stop.clone()));
        Self {
            address,
            url: format!("{origin}/mcp"),
            stop,
            task: Some(task),
        }
    }
    async fn close(mut self) {
        self.stop.cancel();
        self.task.take().unwrap().await.unwrap().unwrap();
    }
    fn post(&self, client: &reqwest::Client, token: &str) -> reqwest::RequestBuilder {
        client
            .post(&self.url)
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-11-25")
    }
    async fn rpc(
        &self,
        client: &reqwest::Client,
        token: &str,
        method: &str,
        params: Value,
    ) -> Value {
        let response = self
            .post(client, token)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        serde_json::from_str(&body).unwrap()
    }
    async fn call(
        &self,
        client: &reqwest::Client,
        token: &str,
        chat: &str,
        name: &str,
        arguments: Value,
    ) -> Value {
        let result = self
            .rpc(
                client,
                token,
                "tools/call",
                json!({"name":name,"arguments":arguments,
            "_meta":{"test/conversation":chat}}),
            )
            .await;
        assert!(result.get("error").is_none(), "{result}");
        assert_ne!(result["result"]["isError"], true, "{result}");
        serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
struct Daemon(Option<JoinHandle<Result<()>>>);
impl Daemon {
    async fn start(home: &Path) -> Self {
        let path = home.to_path_buf();
        let task = tokio::spawn(async move { gent_daemon::run(&path).await });
        for _ in 0..200 {
            if home.join("daemon.sock").exists() {
                return Self(Some(task));
            }
            assert!(!task.is_finished(), "daemon failed to start");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
        panic!("daemon did not start");
    }
    async fn close(mut self, home: &Path) {
        let task = self.0.take().unwrap();
        task.abort();
        let _ = task.await;
        fs::remove_file(home.join("daemon.sock")).unwrap();
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}
async fn owner(home: &Path, action: OwnerOp) -> Value {
    request(
        home,
        gent_protocol::Request::Owner {
            credential: config::read_private(&home.join("owner.key")).unwrap(),
            action,
        },
    )
    .await
    .unwrap()
}
async fn import_file_for_chat_a(f: &Fixture, bytes: &[u8], name: &str, mime: &str) -> Value {
    let registry = Registry::open(&f.home).unwrap();
    let permit = registry.authenticate(&f.token).unwrap();
    let credential = registry
        .credential(&permit, &json!({"test/conversation":"a"}))
        .unwrap();
    gent_daemon::receive_file(
        &f.home,
        credential,
        gent_protocol::file_objects::IncomingFile {
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

fn request_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

#[tokio::test]
async fn http_boundary_rejects_wrong_authority_origin_auth_proxy_and_oversized_payloads() {
    let f = Fixture::new();
    let server = f.start().await;
    let client = client();
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
    assert_eq!(
        client
            .post(&server.url)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server
            .post(&client, "bad")
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for (key, value) in [
        ("host", "attacker.invalid"),
        ("origin", "https://attacker.invalid"),
        ("forwarded", "host=anything"),
        ("x-forwarded-for", "127.0.0.1"),
        ("x-forwarded-host", "localhost"),
    ] {
        assert_eq!(
            server
                .post(&client, &f.token)
                .header(key, value)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    let query = format!("{}?token={}", server.url, "not-a-credential");
    assert_eq!(
        client
            .post(query)
            .bearer_auth(&f.token)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    // Repeated Authorization/Origin fields must not become first-value-wins.
    for extra in [
        format!("Authorization: Bearer {}\r\n", f.token),
        format!(
            "Origin: http://{}\r\nOrigin: http://{}\r\n",
            server.address, server.address
        ),
    ] {
        let mut socket = TcpStream::connect(server.address).await.unwrap();
        let wire = format!(
            "POST /mcp HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n{}Content-Length: 0\r\nConnection: close\r\n\r\n",
            server.address, f.token, extra
        );
        socket.write_all(wire.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        let status = String::from_utf8(response).unwrap();
        assert!(status.starts_with("HTTP/1.1 401") || status.starts_with("HTTP/1.1 403"));
    }
    let tools = server.rpc(&client, &f.token, "tools/list", json!({})).await;
    let names: Vec<_> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"gent_send_non_blocking"));
    for hidden in ["gent_file_paths", "gent_file_import", "gent_file_export"] {
        assert!(!names.contains(&hidden));
        let result = server
            .rpc(
                &client,
                &f.token,
                "tools/call",
                json!({"name":hidden,"arguments":{},"_meta":{"test/conversation":"a"}}),
            )
            .await;
        assert!(result.get("error").is_some());
    }
    let oversized = server
        .post(&client, &f.token)
        .header("content-type", "application/json")
        .body(" ".repeat(gent_protocol::MAX_FRAME_BYTES + 1))
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let initialized = server
        .rpc(
            &client,
            &f.token,
            "initialize",
            json!({"protocolVersion":"2025-11-25",
        "capabilities":{},"clientInfo":{"name":"synthetic-host","version":"1"},"_meta":{"test/conversation":"a"}}),
        )
        .await;
    assert!(
        initialized["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("user-controlled gateway")
    );
    let missing = server
        .rpc(
            &client,
            &f.token,
            "tools/call",
            json!({"name":"gent_register","arguments":{"name":"a","provider":"generic"}}),
        )
        .await;
    assert_eq!(missing["result"]["isError"], true);
    let forged = server
        .rpc(
            &client,
            &f.token,
            "tools/call",
            json!({"name":"gent_register",
        "arguments":{"name":"a","provider":"generic","credential":"forged","test/conversation":"b"},
        "_meta":{"test/conversation":"a"}}),
        )
        .await;
    assert_eq!(forged["result"]["isError"], true);
    Registry::open(&f.home).unwrap().revoke(&f.id).unwrap();
    // Same HTTP pool, revoked on the next request including tools/list.
    assert_eq!(
        server
            .post(&client, &f.token)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    server.close().await;
}

#[tokio::test]
async fn web_dashboard_tools_use_the_bound_chat() {
    let f = Fixture::new();
    gent_daemon::entitlements::grant_test(&f.home, &config::load(&f.home).unwrap());
    let daemon = Daemon::start(&f.home).await;
    let server = f.start().await;
    let client = client();
    for name in ["trainer", "observer"] {
        server
            .call(
                &client,
                &f.token,
                name,
                "gent_register",
                json!({"name":name,"provider":"web"}),
            )
            .await;
    }
    let board = json!({"title":"Training","widgets":[
        {"id":"step","kind":"progress","label":"Step","value":10},
        {"id":"run","kind":"link","label":"Run details","value":"https://example.org/runs/1"},
        {"id":"temp","kind":"metric","label":"GPU temperature","unit":"°C","value":48},
        {"id":"cost","kind":"scatter","label":"Cost per run","unit":"USD","x_unit":"s","value":[[6,2],[9,1]]},
        {"id":"jobs","kind":"bar","label":"Jobs","value":[{"label":"CPU","value":7}]},
        {"id":"share","kind":"pie","label":"Worker share","value":[{"label":"GPU","value":4},{"label":"CPU","value":2}]},
        {"id":"load","kind":"radar","label":"Utilization","unit":"%",
            "value":[{"label":"CPU","value":20},{"label":"GPU","value":45},{"label":"Memory","value":51}]},
        {"id":"preview","kind":"image","label":"Preview","value":concat!("data:image/png;base64,",
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGNQSwkHAAGVAOICf7lpAAAAAElFTkSuQmCC")}
    ]});
    let define = json!({"expected_revision":0,"board":board});
    assert_eq!(
        server
            .call(
                &client,
                &f.token,
                "trainer",
                "gent_dashboard_define",
                define
            )
            .await["revision"],
        1
    );
    assert_eq!(
        server
            .call(
                &client,
                &f.token,
                "observer",
                "gent_dashboard_get",
                json!({})
            )
            .await["board"],
        Value::Null
    );
    let invalid = server
        .rpc(
            &client,
            &f.token,
            "tools/call",
            json!({"name":"gent_dashboard_update","_meta":{"test/conversation":"trainer"},
                "arguments":{"expected_revision":1,"values":{"run":"file:///tmp/results"}}}),
        )
        .await;
    assert_eq!(invalid["result"]["isError"], true);
    assert_eq!(
        server
            .call(
                &client,
                &f.token,
                "trainer",
                "gent_dashboard_update",
                json!({"expected_revision":1,"values":{"step":50,"run":"https://example.org/runs/2",
                    "temp":49,"cost":[[10,3]],"jobs":[{"label":"GPU","value":9}]}})
            )
            .await["revision"],
        2
    );
    let list = owner(&f.home, OwnerOp::Dashboards { after: None }).await;
    let mut expected = board;
    for (index, value) in [
        (0, json!(50)),
        (1, json!("https://example.org/runs/2")),
        (2, json!(49)),
        (3, json!([[10, 3]])),
        (4, json!([{"label":"GPU","value":9}])),
    ] {
        expected["widgets"][index]["value"] = value;
    }
    assert_eq!(list["rows"][0]["board"], expected);
    server
        .call(
            &client,
            &f.token,
            "trainer",
            "gent_dashboard_delete",
            json!({"expected_revision":2}),
        )
        .await;
    assert_eq!(
        owner(&f.home, OwnerOp::Dashboards { after: None }).await["rows"],
        json!([])
    );
    assert_eq!(
        server
            .call(
                &client,
                &f.token,
                "trainer",
                "gent_babysit",
                json!({"enabled":false})
            )
            .await["enabled"],
        false
    );
    assert_eq!(
        server
            .call(&client, &f.token, "observer", "gent_babysit", json!({}))
            .await["enabled"],
        true
    );
    server.close().await;
    daemon.close(&f.home).await;
}

#[tokio::test]
async fn agents_exchange_images_receipts_and_relay_turns_across_gateway_and_daemon_restarts() {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let server = f.start().await;
    let client = client();
    let a = server
        .call(
            &client,
            &f.token,
            "a",
            "gent_register",
            json!({"name":"A","provider":"unknown-host"}),
        )
        .await;
    let b = server
        .call(
            &client,
            &f.token,
            "b",
            "gent_register",
            json!({"name":"B","provider":"another-host"}),
        )
        .await;
    assert_ne!(a["agent"]["id"], b["agent"]["id"]);
    let other_export = f.home.join("other-host.json");
    registry::add(
        &f.home,
        "other-host",
        "test/conversation",
        &other_export,
        24,
    )
    .unwrap();
    let other: Value = serde_json::from_slice(&fs::read(other_export).unwrap()).unwrap();
    let other_token = other["token"].as_str().unwrap();
    let other_agent = server
        .call(
            &client,
            other_token,
            "a",
            "gent_register",
            json!({"name":"other A","provider":"unknown-host"}),
        )
        .await;
    assert_ne!(other_agent["agent"]["id"], a["agent"]["id"]);
    assert_eq!(
        server
            .call(&client, &f.token, "a", "gent_identity", json!({}))
            .await["agent"]["id"],
        a["agent"]["id"]
    );
    assert_eq!(a["access_route"]["mode"], "user_controlled_gateway");
    let (a_id, b_id) = (
        a["agent"]["id"].as_str().unwrap(),
        b["agent"]["id"].as_str().unwrap(),
    );
    owner(
        &f.home,
        OwnerOp::SetPolicy {
            policy: Policy::default(),
        },
    )
    .await;
    let denied=server.rpc(&client,&f.token,"tools/call",json!({"name":"gent_send_non_blocking","arguments":{
        "recipient":b_id,"request_id":request_id(),"text":"denied"},"_meta":{"test/conversation":"a"}})).await;
    assert_eq!(denied["result"]["isError"], true);
    let mut policy = Policy::default();
    for permission in [Permission::Enumerate, Permission::Send, Permission::Receive] {
        policy.rules.push(Rule {
            actor: Selector::All,
            peer: Selector::All,
            permission,
            effect: Effect::Allow,
        });
    }
    owner(&f.home, OwnerOp::SetPolicy { policy }).await;
    let png = json!({"name":"preview.png","media_type":"image/png",
        "data_base64":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aL1cAAAAASUVORK5CYII="});
    let args = json!({"recipient":b_id,"request_id":request_id(),"text":"review image","files":[png.clone()]});
    let sent = server
        .call(
            &client,
            &f.token,
            "a",
            "gent_send_non_blocking",
            args.clone(),
        )
        .await;
    let duplicate = server
        .call(&client, &f.token, "a", "gent_send_non_blocking", args)
        .await;
    assert_eq!(sent["message_id"], duplicate["message_id"]);
    assert_eq!(duplicate["duplicate"], true);
    let inbox = server
        .rpc(
            &client,
            &f.token,
            "tools/call",
            json!({"name":"gent_inbox","arguments":{},"_meta":{"test/conversation":"b"}}),
        )
        .await;
    assert_eq!(inbox["result"]["content"][1]["type"], "image");
    assert_eq!(inbox["result"]["content"][1]["data"], png["data_base64"]);
    let messages: Value =
        serde_json::from_str(inbox["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(messages.as_array().unwrap().len(), 1);
    let message_id = messages[0]["id"].as_str().unwrap();
    server
        .call(
            &client,
            &f.token,
            "b",
            "gent_ack",
            json!({"message_id":message_id}),
        )
        .await;
    let status = server
        .call(
            &client,
            &f.token,
            "a",
            "gent_message_status",
            json!({"message_id":message_id}),
        )
        .await;
    assert_eq!(status["state"], "delivered");
    server.call(&client,&f.token,"b","gent_reply",json!({"message_id":message_id,"request_id":request_id(),"text":"looks good","files":[png.clone()]})).await;
    let attachment = server
        .call(
            &client,
            &f.token,
            "a",
            "gent_relay_attach",
            json!({"target":b_id,"request_id":request_id()}),
        )
        .await;
    let attachment_id = attachment["attachment"]["id"].as_str().unwrap();
    let turn = server
        .call(
            &client,
            &f.token,
            "a",
            "gent_relay_send_non_blocking",
            json!({"attachment_id":attachment_id,
        "request_id":request_id(),"text":"make it blue","files":[png.clone()]}),
        )
        .await;
    let turn_id = turn["turn_id"].as_str().unwrap();
    server.close().await;
    daemon.close(&f.home).await;
    let daemon = Daemon::start(&f.home).await;
    let server = f.start().await;
    let recovered = server
        .call(&client, &f.token, "a", "gent_identity", json!({}))
        .await;
    assert_eq!(recovered["agent"]["id"], a_id);
    let replies = server
        .call(&client, &f.token, "a", "gent_inbox", json!({}))
        .await;
    assert_eq!(replies[0]["text"], "looks good");
    assert_eq!(replies[0]["files"][0]["data_base64"], png["data_base64"]);
    let pending = server
        .call(&client, &f.token, "b", "gent_relay_next", json!({}))
        .await;
    assert_eq!(pending["request"]["id"], turn_id);
    let response = json!({"turn_id":turn_id,"request_id":request_id(),"text":"done","files":[png.clone()],"outcome":"complete"});
    server
        .call(
            &client,
            &f.token,
            "b",
            "gent_relay_respond",
            response.clone(),
        )
        .await;
    server
        .call(&client, &f.token, "b", "gent_relay_respond", response)
        .await;
    let complete = server
        .call(
            &client,
            &f.token,
            "a",
            "gent_relay_turn_status",
            json!({"turn_id":turn_id}),
        )
        .await;
    assert_eq!(complete["state"], "completed", "{complete}");
    assert_eq!(complete["responses"].as_array().unwrap().len(), 1);
    assert_eq!(
        complete["responses"][0]["files"][0]["data_base64"],
        png["data_base64"]
    );
    owner(
        &f.home,
        OwnerOp::Revoke {
            agent_id: a_id.into(),
        },
    )
    .await;
    server.close().await;
    let server = f.start().await;
    let revoked = server
        .rpc(
            &client,
            &f.token,
            "tools/call",
            json!({"name":"gent_register",
        "arguments":{"name":"A","provider":"unknown-host"},"_meta":{"test/conversation":"a"}}),
        )
        .await;
    assert_eq!(revoked["result"]["isError"], true);
    server.close().await;
    daemon.close(&f.home).await;
}

#[tokio::test]
async fn direct_tls_requires_valid_server_trust_and_plaintext_cannot_bind_publicly() {
    let f = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin_text = format!("https://localhost:{}", address.port());
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = f.home.join("tls.pem");
    let key = f.home.join("tls.key");
    config::write_private(&cert, generated.cert.pem().as_bytes()).unwrap();
    config::write_private(&key, generated.signing_key.serialize_pem().as_bytes()).unwrap();
    let mut options = Run {
        hosted: None,
        file_downloads: vec![],
        file_origin: vec![],
        client_metadata: vec![],
        listen: address,
        origin: Some(origin_text.clone()),
        tls_cert: Some(cert.clone()),
        tls_key: Some(key.clone()),
    };
    let (host, origin_text) = origin(&options, address).unwrap();
    let server = Running::start(
        &f.home,
        listener,
        origin_text,
        host,
        tls(&options, &[]).unwrap(),
    )
    .await;
    let trusted = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .resolve("localhost", address)
        .add_root_certificate(
            reqwest::Certificate::from_pem(generated.cert.pem().as_bytes()).unwrap(),
        )
        .build()
        .unwrap();
    let response = server
        .rpc(&trusted, &f.token, "tools/list", json!({}))
        .await;
    assert!(response["result"]["tools"].is_array());
    let untrusted = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .resolve("localhost", address)
        .build()
        .unwrap();
    assert!(
        server
            .post(&untrusted, &f.token)
            .json(&json!({}))
            .send()
            .await
            .is_err()
    );
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(tls(&options, &[]).is_err());
    options.tls_cert = None;
    options.tls_key = None;
    options.origin = None;
    assert!(origin(&options, "0.0.0.0:8787".parse().unwrap()).is_err());
    assert!(origin(&options, "[::]:8787".parse().unwrap()).is_err());
    assert!(origin(&options, "[::1]:8787".parse().unwrap()).is_ok());
    server.close().await;
}
