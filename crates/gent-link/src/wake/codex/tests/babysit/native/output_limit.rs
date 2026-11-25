use super::*;

const INCOMPLETE: &str = concat!(
    "event: response.created\n",
    r#"data: {"type":"response.created","response":{"id":"fixture","status":"in_progress"}}"#,
    "\n\nevent: response.incomplete\n",
    r#"data: {"type":"response.incomplete","response":{"id":"fixture","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}}"#,
    "\n\n",
);

#[tokio::test]
#[ignore = "requires an installed Codex app-server"]
async fn ordinary_output_limit() -> Result<()> {
    trial(false).await
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server with native goals"]
async fn goal_output_limit() -> Result<()> {
    trial(true).await
}

async fn trial(goal: bool) -> Result<()> {
    let node = Node::start().await?;
    config::set_ordinary_babysitter_enabled(&node.home, true)?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let (mut child, socket) = start_host(node.root.path(), listener.local_addr()?).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let received = calls.clone();
    let provider = Router::new().route(
        "/v1/responses",
        post(move || {
            let index = received.fetch_add(1, Ordering::SeqCst);
            async move {
                if index > 0 {
                    std::future::pending::<()>().await;
                }
                ([("content-type", "text/event-stream")], INCOMPLETE)
            }
        }),
    );
    let trial = async {
        let mut host = Host::connect(&socket).await?;
        let result = host
            .rpc("thread/start", json!({"cwd":node.root.path().join("work")}))
            .await?;
        let thread = result["thread"]["id"]
            .as_str()
            .context("missing fixture thread")?;
        let path = Path::new(
            result["thread"]["path"]
                .as_str()
                .context("missing fixture rollout")?,
        );
        let (_bindings, registry, registered) = node.register(&socket, thread).await?;
        let params = json!({"threadId":thread});
        if goal {
            host.rpc(
                "thread/goal/set",
                json!({"threadId":thread, "objective":"Count one fixture.", "status":"active", "origin":"user"}),
            ).await?;
        } else {
            host.rpc(
                "turn/start",
                json!({"threadId":thread, "turnTrigger":"user", "clientUserMessageId":Uuid::new_v4(),
                    "input":[{"type":"text","text":"Count one fixture."}]}),
            ).await?;
        }
        let turn = loop {
            if calls.load(Ordering::SeqCst) > 0 {
                let meta = host
                    .rpc(
                        "thread/read",
                        json!({"threadId":thread,"includeTurns":false}),
                    )
                    .await?;
                if matches!(
                    meta["thread"]["status"]["type"].as_str(),
                    Some("idle" | "systemError")
                ) {
                    break last(&mut host, thread).await?;
                }
            }
            sleep(Duration::from_millis(20)).await;
        };
        let goal_state = host.rpc("thread/goal/get", params.clone()).await?["goal"].clone();
        assert_eq!(turn["status"], "failed");
        assert_eq!(
            turn["error"]["message"],
            "Incomplete response returned, reason: max_output_tokens"
        );
        assert_eq!(turn["error"]["codexErrorInfo"], "other");
        assert!(turn["error"]["additionalDetails"].is_null());
        assert!(turn["error"]["misalignment"].is_null());
        if goal {
            assert_eq!(goal_state["status"], "blocked");
        } else {
            assert!(goal_state.is_null());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        while calls.load(Ordering::SeqCst) < 2 {
            sleep(Duration::from_millis(20)).await;
        }
        let resumed = last(&mut host, thread).await?;
        assert_ne!(resumed["id"], turn["id"]);
        assert_eq!(resumed["status"], "inProgress");
        let current = host.rpc("thread/goal/get", params).await?["goal"].clone();
        if goal {
            assert_eq!(current["status"], "active");
            assert_eq!(current["createdAt"], goal_state["createdAt"]);
            assert_eq!(current["objective"], goal_state["objective"]);
            assert_eq!(trigger(&rollout(path)?, &resumed), "goal");
        } else {
            assert!(current.is_null());
            assert_eq!(resumed["rootTurnId"], turn["id"]);
            assert_eq!(trigger(&rollout(path)?, &resumed), "gent_babysitter");
            let items = host
                .rpc(
                    "thread/items/list",
                    json!({"threadId":thread,"turnId":resumed["id"]}),
                )
                .await?;
            let input = &items["data"][0]["item"];
            assert_eq!(input["type"], "userMessage");
            assert_eq!(
                input["content"],
                json!([{"type":"text","text":"please continue","text_elements":[]}])
            );
        }
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        assert_eq!(last(&mut host, thread).await?["id"], resumed["id"]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let notices = crate::owner(
            &node.home,
            gent_protocol::OwnerOp::NotificationPending {
                scope: node.scope.clone(),
            },
        )
        .await?;
        if goal {
            let notices = notices.as_array().context("invalid notification outbox")?;
            assert_eq!(notices.len(), 1);
            assert_eq!(
                notices[0]["event"],
                json!({"kind":"goal_resumed", "chat":registered, "node":config::load(&node.home)?.node.id, "reason":"capacity"})
            );
        } else {
            assert_eq!(notices, json!([]));
        }
        let db = rusqlite::Connection::open_with_flags(
            node.home.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let mut query = db.prepare(
            "SELECT 'ordinary',reason FROM babysitter_chat_attempts WHERE agent=?1 AND turn=?2 AND admitted=1 AND submitted=1
             UNION ALL SELECT 'goal',reason FROM babysitter_attempts WHERE agent=?1 AND turn=?2 AND submitted=1"
        )?;
        let receipts = query
            .query_map([registered.as_str(), turn["id"].as_str().unwrap()], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(
            receipts,
            [(
                if goal { "goal" } else { "ordinary" }.to_owned(),
                serde_json::to_string("capacity")?
            )]
        );
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(30),trial) => result?,
        result = axum::serve(listener,provider) => { result?; anyhow::bail!("fixture provider stopped") }
    };
    child.kill().await?;
    result
}
