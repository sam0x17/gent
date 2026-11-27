use super::*;

// Deliver a native goal tool call, then wait to send the provider error until
// the independent observer has received the resulting Blocked notification.
const BLOCK_WITH_TOOL: &str = concat!(
    "event: response.created\n",
    r#"data: {"type":"response.created","response":{"id":"fixture"}}"#,
    "\n\n",
    "event: response.output_item.done\n",
    r#"data: {"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_fixture","call_id":"call_fixture","name":"update_goal","arguments":"{\"status\":\"blocked\"}"}}"#,
    "\n\n",
    "event: response.completed\n",
    r#"data: {"type":"response.completed","response":{"id":"fixture"}}"#,
    "\n\n"
);

#[derive(Clone, Copy, PartialEq)]
enum Outcome {
    Resume,
    LongResume,
    UserBlock,
    ToolBlock,
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server with native goals"]
async fn installed_codex_retries_provider_blocks_once_and_preserves_deliberate_blocks() -> Result<()>
{
    let overload = (
        StatusCode::SERVICE_UNAVAILABLE,
        "application/json",
        r#"{"error":{"type":"server_error","message":"Synthetic model is at capacity"}}"#,
    );
    let http_error = json!({"httpConnectionFailed":{"httpStatusCode":503}});
    for ((status, content_type, body), expected_error, outcome) in [
        (
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "text/plain",
                "Server is draining",
            ),
            http_error.clone(),
            Outcome::Resume,
        ),
        (overload, http_error.clone(), Outcome::Resume),
        (overload, http_error.clone(), Outcome::UserBlock),
        (overload, http_error, Outcome::ToolBlock),
        (
            (
                StatusCode::BAD_REQUEST,
                "application/json",
                r#"{"error":{"message":"Unknown parameter: 'input[0].tools[0].tools[0].role'.","type":"invalid_request_error","code":"unknown_parameter","param":"input[0].tools[0].tools[0].role"}}"#,
            ),
            json!("other"),
            Outcome::Resume,
        ),
        (
            (
                StatusCode::OK,
                "text/event-stream",
                "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"fixture\"}}\n\n",
            ),
            json!("other"),
            Outcome::Resume,
        ),
        (
            (
                StatusCode::BAD_REQUEST,
                "application/json",
                r#"{"error":{"type":"invalid_request_error","message":"Invalid value: 'message'. Supported values are: 'function'. input[0].tools[1].type"}}"#,
            ),
            json!("other"),
            Outcome::Resume,
        ),
        (
            (
                StatusCode::BAD_REQUEST,
                "application/json",
                r#"{"error":{"type":"invalid_request_error","code":"invalid_request_error","message":"Invalid request payload","param":"12345"}}"#,
            ),
            json!("other"),
            Outcome::LongResume,
        ),
    ] {
        let node = Node::start().await?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let (mut child, socket) = start_host(node.root.path(), listener.local_addr()?).await?;
        let calls = Arc::new(AtomicUsize::new(0));
        let received = calls.clone();
        let block_seen = Arc::new(tokio::sync::Notify::new());
        let release_error = block_seen.clone();
        let model = Router::new().route(
            "/v1/responses",
            post(move || {
                let index = received.fetch_add(1, Ordering::SeqCst);
                let release_error = release_error.clone();
                async move {
                    if outcome == Outcome::LongResume && index == 0 {
                        release_error.notified().await;
                    }
                    if outcome == Outcome::ToolBlock {
                        if index == 0 {
                            return (
                                StatusCode::OK,
                                [("content-type", "text/event-stream")],
                                BLOCK_WITH_TOOL,
                            );
                        }
                        if index == 1 {
                            release_error.notified().await;
                        }
                    }
                    if index > usize::from(outcome == Outcome::ToolBlock) {
                        std::future::pending::<()>().await;
                    }
                    (status, [("content-type", content_type)], body)
                }
            }),
        );
        let trial = async {
            let mut observer = Host::connect(&socket).await?;
            let mut host = Host::connect(&socket).await?;
            let result = host
                .rpc("thread/start", json!({"cwd":node.root.path().join("work")}))
                .await?;
            let thread = result["thread"]["id"].as_str().context("missing thread")?;
            let (_bindings, registry, registered) = node.register(&socket, thread).await?;
            if outcome == Outcome::LongResume {
                host.rpc("turn/start", json!({"threadId":thread,"input":[{"type":"text","text":"Start one synthetic fixture."}]})).await?;
                while calls.load(Ordering::SeqCst) == 0 {
                    sleep(Duration::from_millis(20)).await;
                }
                sleep(Duration::from_secs(1)).await;
            }
            host.rpc("thread/goal/set", json!({"threadId":thread,"objective":"Count one fixture.","status":"active","origin":"user"})).await?;
            let mut injected_at = None;
            if outcome == Outcome::LongResume {
                let path = Path::new(
                    result["thread"]["path"]
                        .as_str()
                        .context("missing rollout path")?,
                );
                injected_at = Some((path, path.metadata()?.len()));
                inject_wrapper_history(&mut host, thread).await?;
                block_seen.notify_one();
            }
            let first_block = next_block(&mut observer, thread).await?;
            block_seen.notify_one();
            let turn = loop {
                let turn = last(&mut host, thread).await?;
                if turn["status"] == "failed" {
                    break turn;
                }
                sleep(Duration::from_millis(20)).await;
            };
            assert_eq!(first_block["turnId"], turn["id"]);
            assert_eq!(turn["error"]["codexErrorInfo"], expected_error);
            if let Some((path, offset)) = injected_at {
                assert!(path.metadata()?.len() - offset > 8 * 1024 * 1024);
                assert!(first_block["goal"]["createdAt"].as_i64() > turn["startedAt"].as_i64());
            }
            if outcome == Outcome::UserBlock {
                host.rpc(
                    "thread/goal/set",
                    json!({"threadId":thread,"status":"blocked","origin":"user"}),
                )
                .await?;
                assert!(next_block(&mut observer, thread).await?["turnId"].is_null());
            }
            sweep(&node.home, &registry, &mut None, Sweep::WakeAndGoals).await?;
            if matches!(outcome, Outcome::Resume | Outcome::LongResume) {
                while calls.load(Ordering::SeqCst) < 2 {
                    sleep(Duration::from_millis(20)).await;
                }
                let resumed = last(&mut host, thread).await?;
                assert_eq!(resumed["status"], "inProgress");
                assert_ne!(resumed["id"], turn["id"]);
                sweep(&node.home, &registry, &mut None, Sweep::WakeAndGoals).await?;
                assert_eq!(last(&mut host, thread).await?["id"], resumed["id"]);
                assert_eq!(calls.load(Ordering::SeqCst), 2);
                assert_eq!(node.notices(&registered).await?, 1);
            } else {
                assert_eq!(
                    host.rpc("thread/goal/get", json!({"threadId":thread}))
                        .await?["goal"]["status"],
                    "blocked"
                );
                assert_eq!(last(&mut host, thread).await?, turn);
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    1 + usize::from(outcome == Outcome::ToolBlock)
                );
                assert_eq!(node.notices(&registered).await?, 0);
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(30), trial) => result??,
            result = axum::serve(listener,model) => {result?; anyhow::bail!("fixture provider stopped")}
        }
        child.kill().await?;
    }
    Ok(())
}

// These are synthetic history items in the disposable host. The host owns the
// actual user turn, goal setter, terminal provider error and subsequent retry.
async fn inject_wrapper_history(host: &mut Host, thread: &str) -> Result<()> {
    let output = "fixture ".repeat(7000);
    for batch in (0..174).step_by(8) {
        let mut items = Vec::new();
        for i in batch..(batch + 8).min(174) {
            let exec = format!("exec_{i}");
            let wait = format!("wait_{i}");
            items.extend([
                json!({"type":"custom_tool_call","name":"exec","call_id":exec,"input":"text(1)"}),
                json!({"type":"custom_tool_call_output","call_id":exec,"output":output}),
                json!({"type":"function_call","name":"wait","call_id":wait,"arguments":"{}"}),
                json!({"type":"function_call_output","call_id":wait,"output":"done"}),
            ]);
        }
        host.rpc(
            "thread/inject_items",
            json!({"threadId":thread,"items":items}),
        )
        .await?;
    }
    Ok(())
}
