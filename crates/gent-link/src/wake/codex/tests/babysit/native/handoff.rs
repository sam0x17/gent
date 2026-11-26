use super::*;
use std::sync::atomic::AtomicBool;

async fn handoff(host: &mut Host, thread: &str, name: &str, path: &Path) -> Result<Value> {
    let id = host
        .rpc(
            "turn/start",
            json!({"threadId":thread,"input":[],"toolOutput":{
                "namespace":"codex_tui","name":name,"output":"synthetic","retain":true
            }}),
        )
        .await?["turn"]["id"]
        .clone();
    stopped(host, thread, &id, path).await?;
    Ok(id)
}

pub(super) async fn retry(
    host: &mut Host,
    thread: &str,
    failed: &Value,
    path: &Path,
) -> Result<Value> {
    let current = last(host, thread).await?;
    assert_ne!(current["id"], *failed);
    assert_eq!(current["rootTurnId"], *failed);
    stopped(host, thread, &current["id"], path).await?;
    let items = host
        .rpc(
            "thread/items/list",
            json!({"threadId":thread,"turnId":current["id"]}),
        )
        .await?;
    let [entry] = items["data"].as_array().unwrap().as_slice() else {
        panic!("expected one item")
    };
    assert_eq!(entry["item"]["type"], "userMessage");
    assert!(Uuid::parse_str(entry["item"]["clientId"].as_str().unwrap()).is_ok());
    assert_eq!(
        entry["item"]["content"],
        json!([{"type":"text","text":"please continue","text_elements":[]}])
    );
    Ok(current["id"].clone())
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server"]
async fn named_host_handoff_gets_one_continuation() -> Result<()> {
    let node = Node::start().await?;
    config::set_ordinary_babysitter_enabled(&node.home, true)?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let (mut child, socket) = start_host(node.root.path(), listener.local_addr()?).await?;
    let error = json!({"error":{"type":"invalid_request_error","code":"invalid_value",
        "message":"Invalid value: 'message'. Supported values are: 'code_interpreter', 'programmatic_tool_calling', 'function', 'namespace', 'tool_search', 'file_search', 'web_search_preview', 'web_search_preview_2025_03_11', 'image_generation', 'mcp', 'custom', 'computer', 'computer_use_preview', 'shell', and 'apply_patch'.","param":"input[0].tools[1].type"}});
    let expected_error = error.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let hold = Arc::new(AtomicBool::new(false));
    let held = hold.clone();
    let provider = Router::new().route(
        "/v1/responses",
        post(move || {
            count.fetch_add(1, Ordering::SeqCst);
            let blocked = held.load(Ordering::SeqCst);
            let response = error.clone();
            async move {
                if blocked {
                    std::future::pending().await
                }
                (StatusCode::BAD_REQUEST, Json(response))
            }
        }),
    );
    let trial = async {
        let mut host = Host::connect(&socket).await?;
        let t = host.rpc("thread/start", json!({"cwd":node.root.path().join("work"),"threadSource":"user","historyMode":"paginated"})).await?;
        let thread = t["thread"]["id"].as_str().unwrap();
        let path = Path::new(t["thread"]["path"].as_str().unwrap());
        let (_bindings, registry, _) = node.register(&socket, thread).await?;
        let primer = host.rpc("turn/start",json!({"threadId":thread,"turnTrigger":"user","input":[{"type":"text","text":"fixture"}]})).await?;
        stopped(&mut host, thread, &primer["turn"]["id"], path).await?;
        let other = handoff(&mut host, thread, "different_tool", path).await?;
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        assert_eq!(last(&mut host, thread).await?["id"], other);

        // Intervening manual turn followed by a native stop before the sweep.
        let name = "send_message_to_thread";
        handoff(&mut host, thread, name, path).await?;
        hold.store(true, Ordering::SeqCst);
        let manual = host.rpc("turn/start",json!({"threadId":thread,"turnTrigger":"user","input":[{"type":"text","text":"carry on"}]})).await?["turn"]["id"].clone();
        while calls.load(Ordering::SeqCst) < 4 {
            sleep(Duration::from_millis(20)).await;
        }
        host.rpc("turn/interrupt", json!({"threadId":thread,"turnId":manual}))
            .await?;
        while last(&mut host, thread).await?["status"] != "interrupted" {
            sleep(Duration::from_millis(20)).await;
        }
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        assert_eq!(last(&mut host, thread).await?["id"], manual);
        hold.store(false, Ordering::SeqCst);

        let first = handoff(&mut host, thread, name, path).await?;
        let head = last(&mut host, thread).await?;
        assert_eq!(head["error"]["codexErrorInfo"], "other");
        assert_eq!(
            serde_json::from_str::<Value>(head["error"]["message"].as_str().unwrap())?,
            expected_error
        );
        let (mut a, mut b) = (None, None);
        tokio::try_join!(
            sweep(&node.home, &registry, &mut a, Sweep::GoalsOnly),
            sweep(&node.home, &registry, &mut b, Sweep::GoalsOnly)
        )?;
        retry(&mut host, thread, &first, path).await?;

        let second = handoff(&mut host, thread, name, path).await?;
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        assert_eq!(last(&mut host, thread).await?["id"], second);
        sleep(Duration::from_secs(15)).await;
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        let automatic = retry(&mut host, thread, &second, path).await?;
        sleep(Duration::from_secs(15)).await;
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        assert_eq!(last(&mut host, thread).await?["id"], automatic);
        let list = host
            .rpc(
                "thread/turns/list",
                json!({"threadId":thread,"itemsView":"notLoaded","limit":20}),
            )
            .await?;
        assert_eq!(list["data"].as_array().unwrap().len(), 8);
        assert_eq!(calls.load(Ordering::SeqCst), 8);
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::select! {
        result=tokio::time::timeout(Duration::from_secs(50),trial)=>result?,
        result=axum::serve(listener,provider)=>{result?;anyhow::bail!("fixture provider stopped")}
    };
    child.kill().await?;
    result
}
