//! Installed native app-server, temporary Gent node, loopback-only Responses provider.
use super::*;

#[tokio::test]
#[ignore = "requires an installed Codex app-server"]
async fn ordinary_claim_reaches_native_input_once_without_a_goal() -> Result<()> {
    ordinary_native_trial(false, None).await
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server"]
async fn ordinary_user_turn_after_a_completed_native_goal_is_retried() -> Result<()> {
    ordinary_native_trial(true, None).await
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server"]
async fn composer_recovers_a_failed_request_after_a_user_steer() -> Result<()> {
    ordinary_native_trial(false, Some("composer")).await
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server"]
async fn user_trigger_recovers_a_failed_request_after_a_user_steer() -> Result<()> {
    ordinary_native_trial(true, Some("user")).await
}

async fn ordinary_native_trial(completed_goal: bool, steered_trigger: Option<&str>) -> Result<()> {
    const FIXTURE_ROOT: &str = "GENT_TEST_ORDINARY_CODEX_ROOT";
    if let Some(root) = std::env::var_os(FIXTURE_ROOT) {
        let root = PathBuf::from(root);
        let home = root.join("node");
        let registry = Registry::codex(&home, &root.join("codex/host.sock"))?;
        return sweep(&home, &registry, &mut None, Sweep::GoalsOnly).await;
    }
    let node = Node::start().await?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let (mut child, socket) = start_host(node.root.path(), listener.local_addr()?).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let received = calls.clone();
    let steered = steered_trigger.is_some();
    let composer = steered_trigger == Some("composer");
    let initial_calls = 1 + usize::from(steered);
    let release = Arc::new(tokio::sync::Notify::new());
    let hold = release.clone();
    let provider = Router::new().route("/v1/responses",post(move || {
        let index = received.fetch_add(1,Ordering::SeqCst);
        let hold = hold.clone();
        async move {
            if index > initial_calls { std::future::pending().await }
            if steered && index == 0 { hold.notified().await; }
            let error = if composer && index == initial_calls {
                json!({"type":"invalid_request_error","code":"invalid_value","message":"Invalid value: ''. Supported values are: 'assistant', 'system', 'developer', and 'user'.","param":"input[12]"})
            } else if steered {
                json!({"type":"invalid_request_error","code":"invalid_request_error","message":"Invalid request payload","param":"56959"})
            } else {
                json!({"type":"invalid_request_error","code":"unknown_parameter","message":"Unknown parameter: 'input[0].tools[0].role'.","param":"input[0].tools[0].role"})
            };
            (StatusCode::BAD_REQUEST, Json(json!({"error":error})))
        }
    }));
    let trial = async {
        let mut host = Host::connect(&socket).await?;
        let t = host
            .rpc("thread/start", json!({"cwd":node.root.path().join("work")}))
            .await?;
        let thread = t["thread"]["id"].as_str().unwrap();
        let (_bindings, registry, registered) = node.register(&socket, thread).await?;
        let prior = if completed_goal {
            let result = host
                .rpc(
                    "thread/goal/set",
                    json!({"threadId":thread,"objective":"Finished fixture",
                "status":"complete","origin":"user"}),
                )
                .await?;
            let completed_at = result["goal"]["updatedAt"]
                .as_i64()
                .context("missing goal completion")?;
            while gent_daemon::store::now() <= completed_at {
                sleep(Duration::from_millis(20)).await;
            }
            result["goal"].clone()
        } else {
            Value::Null
        };
        let id = host
            .rpc(
                "turn/start",
                json!({"threadId":thread,"turnTrigger":steered_trigger.unwrap_or("user"),
            "clientUserMessageId":Uuid::new_v4(),
            "input":[{"type":"text","text":"please continue"}]}),
            )
            .await?["turn"]["id"]
            .clone();
        if steered {
            while calls.load(Ordering::SeqCst) == 0 {
                sleep(Duration::from_millis(20)).await;
            }
            host.rpc(
                "turn/steer",
                json!({"threadId":thread, "expectedTurnId":id,
                "clientUserMessageId":Uuid::new_v4(),
                "input":[{"type":"text","text":"also check the second item"}]}),
            )
            .await?;
            release.notify_one();
        }
        while !last(&mut host, thread)
            .await
            .is_ok_and(|t| t["id"] == id && t["status"] == "failed")
        {
            sleep(Duration::from_millis(20)).await;
        }
        sweep(&node.home, &registry, &mut None, Sweep::WakeAndGoals).await?;
        assert_eq!(calls.load(Ordering::SeqCst), initial_calls);
        if steered {
            let items = host
                .rpc("thread/items/list", json!({"threadId":thread,"turnId":id}))
                .await?;
            let inputs: Vec<_> = items["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| &entry["item"])
                .filter(|item| item["type"] == "userMessage")
                .collect();
            assert_eq!(inputs.len(), 2);
            assert_ne!(inputs[0]["clientId"], inputs[1]["clientId"]);
        }
        // The ordinary checkbox works with goal recovery disabled.
        config::write_private(&node.home.join("babysitter-disabled"), b"")?;
        config::set_ordinary_babysitter_enabled(&node.home, true)?;
        let mut other = Command::new(std::env::current_exe()?)
            .args(["--ignored", "--exact",
                "wake::codex::tests::babysit::native::ordinary::ordinary_claim_reaches_native_input_once_without_a_goal"])
            .env_clear()
            .env("HOME", node.root.path())
            .env(FIXTURE_ROOT, node.root.path())
            .kill_on_drop(true)
            .spawn()?;
        let (mut a, mut b) = (None, None);
        tokio::try_join!(
            sweep(&node.home, &registry, &mut a, Sweep::GoalsOnly),
            sweep(&node.home, &registry, &mut b, Sweep::GoalsOnly),
            async {
                ensure!(
                    other.wait().await?.success(),
                    "second fixture scanner failed"
                );
                Ok(())
            }
        )?;
        let first_auto = loop {
            let t = last(&mut host, thread).await?;
            if t["id"] != id && t["status"] == "failed" {
                break t;
            }
            sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(first_auto["rootTurnId"], id);
        assert_eq!(
            host.rpc("thread/goal/get", json!({"threadId":thread}))
                .await?["goal"],
            prior
        );
        let items = host
            .rpc(
                "thread/items/list",
                json!({"threadId":thread,"turnId":first_auto["id"]}),
            )
            .await?;
        let items = items["data"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        let user = &items[0]["item"];
        assert_eq!(user["type"], "userMessage");
        assert!(Uuid::parse_str(user["clientId"].as_str().unwrap()).is_ok());
        assert_eq!(
            user["content"],
            json!([{"type":"text","text":"please continue","text_elements":[]}])
        );
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        assert_eq!(calls.load(Ordering::SeqCst), initial_calls + 1);
        sleep(Duration::from_secs(15)).await;
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        while calls.load(Ordering::SeqCst) < initial_calls + 2 {
            sleep(Duration::from_millis(20)).await;
        }
        let second = last(&mut host, thread).await?;
        assert_eq!(second["rootTurnId"], id);
        host.rpc(
            "turn/interrupt",
            json!({"threadId":thread,"turnId":second["id"]}),
        )
        .await?;
        while last(&mut host, thread).await?["status"] != "interrupted" {
            sleep(Duration::from_millis(20)).await;
        }
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        assert_eq!(calls.load(Ordering::SeqCst), initial_calls + 2);
        assert_eq!(node.notices(&registered).await?, 0);
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::select! {
        result=tokio::time::timeout(Duration::from_secs(40),trial)=>result?,
        result=axum::serve(listener,provider)=>{ result?; anyhow::bail!("fixture provider stopped") }
    };
    child.kill().await?;
    result
}
