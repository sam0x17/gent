use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

async fn start(f: &Fixture, calls: Arc<AtomicUsize>, revoke: bool) -> Running {
    let mut registry = Registry::open(&f.home)
        .unwrap()
        .with_file_origins(&[format!("{}=https://files.example", f.id)])
        .unwrap();
    let home = f.home.clone();
    let id = f.id.clone();
    Arc::get_mut(&mut registry.files).unwrap().fetcher = Some(Arc::new(move |url| {
        calls.fetch_add(1, Ordering::SeqCst);
        let home = home.clone();
        let id = id.clone();
        Box::pin(async move {
            if url.path() == "/failure" {
                anyhow::bail!("secret URL error: {url}");
            }
            if revoke {
                Registry::open(&home).unwrap().revoke(&id).unwrap();
            }
            Ok(Zeroizing::new(vec![23; 2 * 1024 * 1024 + 7]))
        })
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://{address}");
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
    Running {
        address,
        url: format!("{origin}/mcp"),
        stop,
        task: Some(task),
    }
}
fn args() -> Value {
    json!({"request_id":request_id(),"file":{"download_url":"https://files.example/file?token=private-original","file_id":"host-file","file_name":"from-host.bin","mime_type":"application/octet-stream"}})
}
async fn denied(
    server: &Running,
    client: &reqwest::Client,
    f: &Fixture,
    arguments: Value,
    chat: &str,
) -> Value {
    let value=server.rpc(client,&f.token,"tools/call",json!({"name":"gent_file_import_remote","arguments":arguments,"_meta":{"test/conversation":chat}})).await;
    assert_eq!(value["result"]["isError"], true, "{value}");
    value
}

#[tokio::test]
async fn host_file_import_retries_after_restart_without_refetch_or_shared_access() {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let server = start(&f, calls.clone(), false).await;
    let client = client();
    for chat in ["a", "b"] {
        server
            .call(
                &client,
                &f.token,
                chat,
                "gent_register",
                json!({"name":chat,"provider":"fixture"}),
            )
            .await;
    }
    let arguments = args();
    let export = f.home.join("no-file-host.json");
    registry::add(&f.home, "no-files", "test/conversation", &export, 24).unwrap();
    let other: Value = serde_json::from_slice(&fs::read(export).unwrap()).unwrap();
    let other_token = other["token"].as_str().unwrap();
    server
        .call(
            &client,
            other_token,
            "a",
            "gent_register",
            json!({"name":"other","provider":"fixture"}),
        )
        .await;
    let disabled=server.rpc(&client,other_token,"tools/call",json!({"name":"gent_file_import_remote","arguments":arguments,"_meta":{"test/conversation":"a"}})).await;
    assert_eq!(disabled["result"]["isError"], true);
    let before = server
        .rpc(
            &client,
            &f.token,
            "tools/call",
            json!({"name":"gent_file_import_remote","arguments":arguments}),
        )
        .await;
    assert_eq!(before["result"]["isError"], true);
    let mut wrong = arguments.clone();
    wrong["file"]["download_url"] = json!("https://other.example/private");
    denied(&server, &client, &f, wrong, "a").await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let imported = server
        .call(
            &client,
            &f.token,
            "a",
            "gent_file_import_remote",
            arguments.clone(),
        )
        .await;
    assert_eq!(imported["duplicate"], false);
    let id = imported["file"]["id"].as_str().unwrap();
    assert_eq!(imported["file"]["byte_length"], 2 * 1024 * 1024 + 7);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let outsider=server.rpc(&client,&f.token,"tools/call",json!({"name":"gent_file_read","arguments":{"file_id":id,"chunk_index":0},"_meta":{"test/conversation":"b"}})).await;
    assert_eq!(outsider["result"]["isError"], true);
    let mut changed = arguments.clone();
    changed["file"]["file_id"] = json!("other-host-file");
    denied(&server, &client, &f, changed, "a").await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.close().await;
    daemon.close(&f.home).await;
    let daemon = Daemon::start(&f.home).await;
    let server = start(&f, calls.clone(), false).await;
    let mut retry = arguments;
    retry["file"]["download_url"] = json!("https://files.example/failure?token=refreshed-private");
    let duplicate = server
        .call(
            &client,
            &f.token,
            "a",
            "gent_file_import_remote",
            retry.clone(),
        )
        .await;
    assert_eq!(duplicate["file"], imported["file"]);
    assert_eq!(duplicate["duplicate"], true);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    retry["request_id"] = json!(request_id());
    let error = denied(&server, &client, &f, retry, "a").await;
    assert!(!error.to_string().contains("refreshed-private"));
    assert!(
        !fs::read_to_string(f.home.join("gateway/state.json"))
            .unwrap()
            .contains("private-original")
    );
    server.close().await;
    daemon.close(&f.home).await;
}

#[tokio::test]
async fn revoking_host_during_download_prevents_import() {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let server = start(&f, calls.clone(), true).await;
    let client = client();
    server
        .call(
            &client,
            &f.token,
            "a",
            "gent_register",
            json!({"name":"a","provider":"fixture"}),
        )
        .await;
    denied(&server, &client, &f, args(), "a").await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // The host was revoked before any import transaction; a fresh local owner
    // inspection must show no file object created by the rejected call.
    let report = owner(&f.home, OwnerOp::FilesStatus).await;
    assert_eq!(report["objects"]["count"], 0);
    server.close().await;
    daemon.close(&f.home).await;
}
