use super::*;

const CONTENT_ROLE: &str = "input[1].content[0].role";
const TOOL_ROLE: &str = "input[0].tools[0].tools[0].role";

fn provider_error(path: &str) -> Value {
    json!({"error":{"message":format!("Unknown parameter: '{path}'."),"type":"invalid_request_error","code":"unknown_parameter","param":path}})
}

async fn failed(host: &mut Host, thread: &str, id: &Value) -> Result<Value> {
    loop {
        let turn = last(host, thread).await?;
        if turn["id"] == *id && turn["status"] == "failed" {
            return Ok(turn);
        }
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server with native goals"]
async fn installed_codex_retries_latest_consecutive_provider_failure() -> Result<()> {
    for user_block in [false, true] {
        trial(user_block).await?;
    }
    Ok(())
}

async fn trial(user_block: bool) -> Result<()> {
    let node = Node::start().await?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let (mut child, socket) = start_host(node.root.path(), listener.local_addr()?).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let received = calls.clone();
    let model = Router::new().route(
        "/v1/responses",
        post(move || {
            let index = received.fetch_add(1, Ordering::SeqCst);
            async move {
                let path = match index {
                    0 => CONTENT_ROLE,
                    1 => TOOL_ROLE,
                    _ => std::future::pending().await,
                };
                (StatusCode::BAD_REQUEST, Json(provider_error(path)))
            }
        }),
    );
    let trial = async {
        let mut observer = Host::connect(&socket).await?;
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
                .context("missing rollout")?,
        );
        let (_bindings, registry, registered) = node.register(&socket, thread).await?;
        host.rpc("thread/goal/set", json!({"threadId":thread,"objective":"Count one fixture.","status":"active","origin":"user"})).await?;
        let blocked = next_block(&mut observer, thread).await?;
        let first = failed(&mut host, thread, &blocked["turnId"]).await?;
        assert_eq!(first["id"], blocked["turnId"]);
        assert_eq!(first["status"], "failed");
        assert_eq!(
            serde_json::from_str::<Value>(first["error"]["message"].as_str().unwrap())?,
            provider_error(CONTENT_ROLE)
        );
        let updated = blocked["goal"]["updatedAt"].as_i64().unwrap();
        assert!(
            (first["startedAt"].as_i64().unwrap()..=first["completedAt"].as_i64().unwrap())
                .contains(&updated)
        );
        let current = if user_block {
            host.rpc(
                "thread/goal/set",
                json!({"threadId":thread,"status":"blocked","origin":"user"}),
            )
            .await?;
            let deliberate = next_block(&mut observer, thread).await?;
            assert!(deliberate["turnId"].is_null());
            deliberate["goal"].clone()
        } else {
            blocked["goal"].clone()
        };
        while gent_daemon::store::now() <= current["updatedAt"].as_i64().unwrap() {
            sleep(Duration::from_millis(10)).await;
        }
        let user = host.rpc("turn/start", json!({"threadId":thread,"input":[{"type":"text","text":"Count a second fixture."}]})).await?;
        let latest = failed(&mut host, thread, &user["turn"]["id"]).await?;
        assert_eq!(latest["id"], user["turn"]["id"]);
        assert_eq!(latest["status"], "failed");
        assert_eq!(
            serde_json::from_str::<Value>(latest["error"]["message"].as_str().unwrap())?,
            provider_error(TOOL_ROLE)
        );
        assert!(latest["startedAt"].as_i64().unwrap() > updated);
        let goal = || json!({"threadId":thread});
        assert_eq!(host.rpc("thread/goal/get", goal()).await?["goal"], current);
        assert_eq!(
            host.rpc("thread/queue/list", goal()).await?["data"],
            json!([])
        );
        let rows = rollout(path)?;
        assert_eq!(trigger(&rows, &first), "goal");
        assert!(matches!(
            trigger(&rows, &latest).as_str(),
            None | Some("user")
        ));
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        if user_block {
            assert_eq!(host.rpc("thread/goal/get", goal()).await?["goal"], current);
            assert_eq!(last(&mut host, thread).await?, latest);
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(node.notices(&registered).await?, 0);
            return Ok(());
        }
        assert_eq!(
            host.rpc("thread/goal/get", goal()).await?["goal"]["status"],
            "active"
        );
        while calls.load(Ordering::SeqCst) < 3 {
            sleep(Duration::from_millis(10)).await;
        }
        let resumed = last(&mut host, thread).await?;
        assert_ne!(resumed["id"], latest["id"]);
        assert_eq!(resumed["status"], "inProgress");
        assert_eq!(trigger(&rollout(path)?, &resumed), "goal");
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(node.notices(&registered).await?, 1);
        let db = rusqlite::Connection::open_with_flags(
            node.home.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let (turn, failed_at, reason): (String, i64, String) = db.query_row(
            "SELECT turn, failed_at, reason FROM babysitter_attempts WHERE agent=?1 AND submitted=1", [&registered],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(latest["id"], turn);
        assert_eq!(latest["completedAt"], failed_at);
        assert_eq!(serde_json::from_str::<Value>(&reason)?, "tool_schema");
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(30),trial) => result??,
        result = axum::serve(listener,model) => {result?; anyhow::bail!("fixture provider stopped")}
    }
    child.kill().await?;
    Ok(())
}
