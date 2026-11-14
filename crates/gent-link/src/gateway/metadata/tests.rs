use super::*;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::{TlsAcceptor, rustls};

const ID: &str = "https://metadata.example/client.json";
const RESOURCE: &str = "https://node.example/mcp";
const CALLBACK: &str = "https://host.example/callback";
fn published() -> Value {
    json!({"client_id":ID,"client_name":"Fixture","redirect_uris":[CALLBACK,"https://host.example/second"],
        "jwks_uri":"https://metadata.example/jwks.json","token_endpoint_auth_method":"private_key_jwt",
        "token_endpoint_auth_methods_supported":["none","private_key_jwt"],
        "token_endpoint_auth_signing_alg":"RS256","grant_types":["authorization_code","refresh_token"],
        "response_types":["code"],"logo_uri":"http://127.0.0.1/do-not-fetch"})
}
fn validate(doc: &Value) -> Result<Url> {
    document(
        &serde_json::to_vec(doc)?,
        &endpoint(ID)?,
        RESOURCE,
        &[CALLBACK.into()],
    )
}

#[test]
fn metadata_urls_and_dns_answers_exclude_local_reserved_and_rebinding_destinations() {
    endpoint(ID).unwrap();
    for url in [
        "http://metadata.example/client.json",
        "https://metadata.example/",
        "https://metadata.example:444/client.json",
        "https://metadata.example:443/client.json",
        "https://metadata.example/client.json?q=1",
        "https://metadata.example/client.json#f",
        "https://user@metadata.example/client.json",
        "https://127.0.0.1/client.json",
        "https://[::1]/client.json",
        "https://metadata.example./client.json",
        "https://LOCALHOST/client.json",
        "https://-bad.example/client.json",
        "https://meta_data.example/client.json",
        "https://metadata.example/a/../client.json",
    ] {
        assert!(endpoint(url).is_err(), "accepted {url}");
    }
    for ip in [
        "0.1.2.3",
        "10.2.3.4",
        "100.64.0.1",
        "100.127.255.255",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "192.0.0.1",
        "192.0.2.5",
        "192.88.99.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.4",
        "203.0.113.7",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "2001::1",
        "2001:2::1",
        "2001:20::1",
        "2001:db8::1",
        "2002:808:808::1",
        "3fff::1",
    ] {
        let ip: IpAddr = ip.parse().unwrap();
        assert!(!public_ip(ip), "accepted {ip}");
        assert!(
            destinations(vec![
                SocketAddr::new("8.8.8.8".parse().unwrap(), 443),
                SocketAddr::new(ip, 443)
            ])
            .is_err()
        );
    }
    for ip in [
        "8.8.8.8",
        "1.1.1.1",
        "100.128.0.1",
        "172.32.0.1",
        "192.0.3.1",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
    ] {
        let ip: IpAddr = ip.parse().unwrap();
        assert!(public_ip(ip), "rejected {ip}");
        destinations(vec![SocketAddr::new(ip, 443)]).unwrap();
    }
    assert!(destinations(vec![]).is_err());
    assert!(destinations(vec!["8.8.8.8:80".parse().unwrap()]).is_err());
    assert!(destinations(vec!["8.8.8.8:443".parse().unwrap(); 33]).is_err());
}

#[test]
fn metadata_checks_identity_selected_callbacks_methods_and_same_origin_keys() {
    let original = published();
    validate(&original).unwrap();
    for (field, value) in [
        ("client_id", json!("https://other.example/client.json")),
        ("client_name", json!("\nname")),
        ("client_name", json!("")),
        ("redirect_uris", json!(["https://host.example/other"])),
        ("redirect_uris", json!([CALLBACK, CALLBACK])),
        ("jwks_uri", json!("https://other.example/jwks.json")),
        ("jwks_uri", json!("http://metadata.example/jwks.json")),
        ("jwks", json!({"keys":[]})),
        ("token_endpoint_auth_methods_supported", json!(["none"])),
        (
            "token_endpoint_auth_methods_supported",
            json!(["private_key_jwt", "private_key_jwt"]),
        ),
        ("token_endpoint_auth_signing_alg", json!("HS256")),
        ("grant_types", json!(["client_credentials"])),
        ("grant_types", json!(["authorization_code"])),
        ("response_types", json!(["token"])),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(validate(&changed).is_err(), "accepted {field}");
    }
    for field in ["client_id", "client_name", "redirect_uris", "jwks_uri"] {
        let mut changed = original.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(validate(&changed).is_err());
    }
    let mut legacy = original.clone();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("token_endpoint_auth_methods_supported");
    validate(&legacy).unwrap();
    legacy["token_endpoint_auth_method"] = json!("none");
    assert!(validate(&legacy).is_err());
    let mut plural = original;
    plural["token_endpoint_auth_method"] = json!("none"); // local policy selects a supported signed method
    validate(&plural).unwrap();
    assert!(
        document(
            &vec![b' '; MAX_BYTES + 1],
            &endpoint(ID).unwrap(),
            RESOURCE,
            &[CALLBACK.into()]
        )
        .is_err()
    );
    let raw = serde_json::to_string(&plural).unwrap();
    let duplicate = format!("{{\"client_id\":\"{ID}\",{}", &raw[1..]);
    assert!(
        document(
            duplicate.as_bytes(),
            &endpoint(ID).unwrap(),
            RESOURCE,
            &[CALLBACK.into()]
        )
        .is_err()
    );
}

struct Server {
    address: SocketAddr,
    ca: reqwest::Certificate,
    replies: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    requests: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}
impl Server {
    async fn start() -> Self {
        let generated =
            rcgen::generate_simple_self_signed(vec!["metadata.example".into()]).unwrap();
        let ca = reqwest::Certificate::from_der(generated.cert.der()).unwrap();
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![generated.cert.der().clone()], key.into())
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let replies = Arc::new(Mutex::new(BTreeMap::<String, Vec<u8>>::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stored = replies.clone();
        let observed = requests.clone();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    socket=listener.accept()=> {
                        let Ok((socket,_))=socket else { break; };
                        let acceptor=acceptor.clone(); let replies=stored.clone(); let requests=observed.clone();
                        tasks.spawn(async move {
                            let Ok(mut stream)=acceptor.accept(socket).await else { return; };
                            let mut bytes=Vec::new(); let mut chunk=[0u8;1024];
                            while !bytes.windows(4).any(|v|v==b"\r\n\r\n") && bytes.len()<8192 {
                                let Ok(n)=stream.read(&mut chunk).await else { return; };
                                if n==0 { return; } bytes.extend_from_slice(&chunk[..n]);
                            }
                            let request=String::from_utf8(bytes).unwrap();
                            let path=request.split_whitespace().nth(1).unwrap().to_string();
                            requests.lock().unwrap().push(request);
                            if path=="/slow" { tokio::time::sleep(Duration::from_secs(2)).await; }
                            let reply=replies.lock().unwrap().get(&path).cloned().unwrap_or_else(||b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec());
                            let _=stream.write_all(&reply).await;
                            let _=stream.shutdown().await;
                        });
                    }
                    Some(_) = tasks.join_next(), if !tasks.is_empty()=> {}
                }
            }
        });
        Self {
            address,
            ca,
            replies,
            requests,
            task,
        }
    }
    fn client(&self, url: &Url) -> reqwest::Client {
        // Only tests inject a loopback destination and fixture root. Production
        // fetch validates every DNS answer and uses the normal TLS trust store.
        client(url, &[self.address])
            .tls_built_in_root_certs(false)
            .add_root_certificate(self.ca.clone())
            .build()
            .unwrap()
    }
    fn reply(&self, path: &str, body: &[u8]) {
        let mut response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
        response.extend_from_slice(body);
        self.replies.lock().unwrap().insert(path.into(), response);
    }
    async fn import(&self) -> Result<Policy> {
        import_using(ID, RESOURCE, &[CALLBACK.into()], |url| {
            let client = self.client(&url);
            async move { response(&client, &url).await }
        })
        .await
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn actual_tls_import_and_refresh_preserve_scope_and_reject_changed_metadata() {
    let server = Server::start().await;
    server.reply("/client.json", &serde_json::to_vec(&published()).unwrap());
    let keys =
        serde_json::to_value(super::super::assertion::tests::policy()).unwrap()["keys"].clone();
    server.reply(
        "/jwks.json",
        &serde_json::to_vec(&json!({"keys":keys})).unwrap(),
    );
    let policy = server.import().await.unwrap();
    assert_eq!(policy.client_id, ID);
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("node");
    gent_daemon::config::initialize(&home, "metadata").unwrap();
    let result = super::super::registry::add_client(
        &home,
        "host",
        "test/conversation",
        &home.join("host.json"),
        24,
        Some(Registration {
            resource: RESOURCE.into(),
            redirect_uris: vec![CALLBACK.into()],
            assertion: Some(policy),
        }),
        None,
    )
    .unwrap();
    let id = result["client"].as_str().unwrap();
    let registry = super::super::Registry::open(&home).unwrap();
    let original = std::fs::read(home.join("gateway/state.json")).unwrap();
    let mut changed = published();
    changed["redirect_uris"] = json!(["https://host.example/other"]);
    server.reply("/client.json", &serde_json::to_vec(&changed).unwrap());
    assert!(server.import().await.is_err());
    assert_eq!(
        std::fs::read(home.join("gateway/state.json")).unwrap(),
        original
    );
    server.reply("/client.json", &serde_json::to_vec(&published()).unwrap());
    server.reply(
        "/jwks.json",
        &serde_json::to_vec(&json!({"keys":[keys[1]]})).unwrap(),
    );
    let policy = server.import().await.unwrap();
    let result = registry
        .set_verified_signing_keys(id, policy.clone(), 0)
        .unwrap();
    assert_eq!(result["key_revision"], 1);
    assert_eq!(
        result,
        registry.set_verified_signing_keys(id, policy, 0).unwrap()
    );
    assert_eq!(
        registry.signing_registration(id).unwrap().redirect_uris,
        vec![CALLBACK]
    );
    let mut foreign = server.import().await.unwrap();
    foreign.client_id = "https://other.example/client.json".into();
    assert!(registry.set_verified_signing_keys(id, foreign, 1).is_err());
    assert!(
        registry
            .set_verified_signing_keys(id, server.import().await.unwrap(), 9)
            .is_err()
    );
    assert!(server.requests.lock().unwrap().iter().all(|r| {
        !r.to_lowercase().contains("authorization:")
            && !r.to_lowercase().contains("cookie:")
            && (r.starts_with("GET /client.json ") || r.starts_with("GET /jwks.json "))
    }));
}

#[tokio::test]
async fn fetch_enforces_tls_redirect_body_type_size_and_timeout_boundaries() {
    let server = Server::start().await;
    let url = endpoint(ID).unwrap();
    server.reply("/client.json", b"{}");
    let untrusted = client(&url, &[server.address])
        .tls_built_in_root_certs(false)
        .build()
        .unwrap();
    assert!(response(&untrusted, &url).await.is_err());
    let wrong = endpoint("https://other.example/client.json").unwrap();
    assert!(response(&server.client(&wrong), &wrong).await.is_err());
    let trusted = server.client(&url);
    for reply in [
        b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/private\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",MAX_BYTES+1).into_bytes(),
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",MAX_BYTES+1,"x".repeat(MAX_BYTES+1)).into_bytes(),
    ] {
        server.replies.lock().unwrap().insert("/client.json".into(),reply);
        let before=server.requests.lock().unwrap().len();
        assert!(response(&trusted,&url).await.is_err());
        assert_eq!(server.requests.lock().unwrap().len(),before+1);
    }
    let slow = endpoint("https://metadata.example/slow").unwrap();
    let bounded = client(&slow, &[server.address])
        .tls_built_in_root_certs(false)
        .add_root_certificate(server.ca.clone())
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    assert!(response(&bounded, &slow).await.is_err());
}
