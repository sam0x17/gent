//! A goal's terminal failure and the following queue admission share a clock second.
use super::*;
use tokio::sync::Notify;

fn schema_error() -> Value {
    json!({"error":{
        "message":"Invalid value: 'message'. Supported values are: 'code_interpreter', 'programmatic_tool_calling', 'function', 'namespace', 'tool_search', 'file_search', 'web_search_preview', 'web_search_preview_2025_03_11', 'image_generation', 'mcp', 'custom', 'computer', 'computer_use_preview', 'shell', and 'apply_patch'.",
        "type":"invalid_request_error","code":"invalid_value","param":"input[0].tools[1].type"
    }})
}

async fn run(explicit_block: bool) -> Result<()> {
    let node = Node::start().await?;
    config::set_ordinary_babysitter_enabled(&node.home, true)?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let (mut child, socket) = start_host(node.root.path(), listener.local_addr()?).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let model = Router::new().route("/v1/responses", post({
        let calls = calls.clone();
        let release = release.clone();
        move || {
            let i = calls.fetch_add(1, Ordering::SeqCst);
            let release = release.clone();
            async move {
                let body = match i {
                    0 => {
                        release.notified().await;
                        json!({"error":{"message":"Invalid request payload","type":"invalid_request_error","code":"invalid_request_error","param":"13741"}})
                    }
                    1 => schema_error(),
                    _ => std::future::pending().await,
                };
                (StatusCode::BAD_REQUEST, Json(body))
            }
        }
    }));
    let exercise = async {
        let mut observer = Host::connect(&socket).await?;
        let mut host = Host::connect(&socket).await?;
        let result = host
            .rpc("thread/start", json!({"cwd":node.root.path().join("work")}))
            .await?;
        let thread = result["thread"]["id"].as_str().context("missing thread")?;
        let path = Path::new(result["thread"]["path"].as_str().context("missing path")?);
        let (_binding, registry, registered) = node.register(&socket, thread).await?;
        let id = json!({"threadId":thread});
        host.rpc(
            "thread/goal/set",
            json!({"threadId":thread,"objective":"Finish this fixture.","status":"active","origin":"user"}),
        ).await?;
        while calls.load(Ordering::SeqCst) == 0 {
            sleep(Duration::from_millis(5)).await;
        }
        let client = Uuid::new_v4().to_string();
        let added = host
            .rpc(
                "thread/queue/add",
                json!({
                    "threadId":thread, "clientUserMessageId":client,
                    "input":[{"type":"text", "text":"Synthetic queued receipt."}]
                }),
            )
            .await?;
        assert_eq!(added["queuedSubmission"]["clientUserMessageId"], client);
        // Hold the initial request across a second, then release close to the boundary.
        let prior = gent_daemon::store::now();
        while gent_daemon::store::now() == prior {
            sleep(Duration::from_millis(3)).await;
        }
        release.notify_one();
        let blocked = next_block(&mut observer, thread).await?;
        let (goal_turn, queue_turn) = loop {
            let page = host.rpc(
                "thread/turns/list",
                json!({"threadId":thread,"limit":3,"sortDirection":"asc","itemsView":"notLoaded"}),
            ).await?;
            let turns = page["data"].as_array().context("missing page")?;
            if turns.len() == 2 && turns.iter().all(|t| t["status"] == "failed") {
                break (turns[0].clone(), turns[1].clone());
            }
            sleep(Duration::from_millis(5)).await;
        };
        let updated = &blocked["goal"]["updatedAt"];
        assert_eq!(blocked["turnId"], goal_turn["id"]);
        assert_eq!(goal_turn["completedAt"], *updated);
        assert_eq!(queue_turn["startedAt"], *updated);
        assert!(goal_turn["startedAt"].as_i64().unwrap() < updated.as_i64().unwrap());
        assert_eq!(
            serde_json::from_str::<Value>(queue_turn["error"]["message"].as_str().unwrap())?,
            schema_error()
        );
        let rows = rollout(path)?;
        assert_eq!(trigger(&rows, &goal_turn), "goal");
        assert_eq!(trigger(&rows, &queue_turn), "queue");
        assert!(
            rows.iter()
                .any(|r| r["payload"]["turn_id"] == queue_turn["id"]
                    && r["payload"]["item"]["client_id"] == client)
        );
        assert_eq!(
            host.rpc("thread/queue/list", id.clone()).await?["data"],
            json!([])
        );
        while !matches!(
            host.rpc(
                "thread/read",
                json!({"threadId":thread,"includeTurns":false}),
            )
            .await?["thread"]["status"]["type"]
                .as_str(),
            Some("idle" | "systemError")
        ) {
            sleep(Duration::from_millis(5)).await;
        }
        if explicit_block {
            host.rpc(
                "thread/goal/set",
                json!({"threadId":thread,"status":"blocked","origin":"user"}),
            )
            .await?;
            let explicit = next_block(&mut observer, thread).await?;
            assert!(explicit["turnId"].is_null());
            assert_eq!(explicit["goal"]["updatedAt"], *updated);
        }
        sweep(&node.home, &registry, &mut None, Sweep::WakeAndGoals).await?;
        let state = host.rpc("thread/goal/get", id.clone()).await?["goal"]["status"].clone();
        if explicit_block {
            assert_eq!(state, "blocked");
            assert_eq!(last(&mut host, thread).await?["id"], queue_turn["id"]);
        } else {
            assert_eq!(
                state, "active",
                "provider-blocked goal missed after same-second queue admission"
            );
            while calls.load(Ordering::SeqCst) < 3 {
                sleep(Duration::from_millis(5)).await;
            }
            let resumed = last(&mut host, thread).await?;
            assert_eq!(resumed["status"], "inProgress");
            assert_eq!(trigger(&rollout(path)?, &resumed), "goal");
        }
        sweep(&node.home, &registry, &mut None, Sweep::WakeAndGoals).await?;
        let notices = node.notices(&registered).await?;
        let db = rusqlite::Connection::open_with_flags(
            node.home.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let (claimed, submitted, turn, reason): (usize, usize, Option<String>, Option<String>) = db
            .query_row(
                "SELECT count(*), coalesce(sum(submitted), 0), max(turn), max(reason)
                 FROM babysitter_attempts WHERE agent=?1",
                [&registered],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
        let ordinary: usize = db.query_row(
            "SELECT count(*) FROM babysitter_chat_attempts WHERE agent=?1",
            [&registered],
            |r| r.get(0),
        )?;
        let n = usize::from(!explicit_block);
        assert_eq!((claimed, submitted, ordinary), (n, n, 0));
        assert_eq!(notices, n);
        assert_eq!(calls.load(Ordering::SeqCst), 2 + n);
        if n == 1 {
            assert_eq!(turn.as_deref(), queue_turn["id"].as_str());
            assert_eq!(
                serde_json::from_str::<String>(reason.as_deref().unwrap())?,
                "tool_schema"
            );
        }
        eprintln!(
            "owner-block={explicit_block} provider-calls={} claims={claimed} submissions={submitted} notices={notices} ordinary={ordinary}",
            2 + n
        );
        Ok::<(), anyhow::Error>(())
    };
    let result = tokio::select! {
        done = tokio::time::timeout(Duration::from_secs(25), exercise) => done?,
        done = axum::serve(listener, model) => { done?; anyhow::bail!("provider stopped") }
    };
    child.kill().await?;
    result
}

#[tokio::test]
#[ignore = "requires installed native Codex"]
async fn installed_codex_retries_provider_anchor_with_same_second_queue_failure() -> Result<()> {
    run(false).await
}

#[tokio::test]
#[ignore = "requires installed native Codex"]
async fn installed_codex_preserves_owner_block_after_same_second_queue_failure() -> Result<()> {
    run(true).await
}
