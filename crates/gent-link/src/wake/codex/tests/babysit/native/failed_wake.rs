//! A genuine pending relay is the next native input after a provider refusal.
use super::*;
use gent_protocol::{Effect, OwnerOp, Permission, Policy, Rule, Selector};

#[tokio::test]
#[ignore = "requires installed Codex app-server with systemError status"]
async fn managed_catch_up_delivers_the_existing_relay_with_the_old_wake_lease_held() -> Result<()> {
    let node = Node::start().await?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let (mut child, socket) = start_host(node.root.path(), listener.local_addr()?).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let requests = calls.clone();
    let provider = Router::new().route("/v1/responses",post(move || {
        let i = requests.fetch_add(1,Ordering::SeqCst);
        async move {
            if i == 0 {
                (StatusCode::BAD_REQUEST,[("content-type","application/json")],
                 r#"{"error":{"type":"invalid_request_error","code":"invalid_request_error","message":"Invalid request payload","param":"21846"}}"#)
            } else {
                (StatusCode::OK,[("content-type","text/event-stream")], concat!(
                 "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"fixture\"}}\n\n",
                 "event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"role\":\"assistant\",\"id\":\"msg\",\"content\":[{\"type\":\"output_text\",\"text\":\"Fixture relay answer.\"}]}}\n\n",
                 "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"fixture\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n"))
            }
        }
    }));
    let trial = async {
        // Keep the recorded integration separate from the provider fixture profile.
        super::super::scheduler::install(
            &node,
            &node.root.path().join("installed-codex"),
            &socket,
        )?;
        let mut host = Host::connect(&socket).await?;
        let t=host.rpc("thread/start",json!({"cwd":node.root.path().join("work"),"historyMode":"paginated","threadSource":"user"})).await?;
        let thread = t["thread"]["id"].as_str().unwrap();
        let path = Path::new(t["thread"]["path"].as_str().unwrap());
        let (_binding, registry, recipient) = node.register(&socket, thread).await?;
        config::write_private(&node.home.join("babysitter-disabled"), b"")?;
        config::set_ordinary_babysitter_enabled(&node.home, false)?;
        let key = registry.credential(thread)?.unwrap();
        agent(
            &node.home,
            &key,
            AgentOp::Babysit {
                enabled: Some(false),
            },
        )
        .await?;
        let prior = host
            .rpc(
                "turn/start",
                json!({"threadId":thread,"input":[{"type":"text","text":"Start the fixture."}]}),
            )
            .await?;
        stopped(&mut host, thread, &prior["turn"]["id"], path).await?;
        let meta = host
            .rpc(
                "thread/read",
                json!({"threadId":thread,"includeTurns":false}),
            )
            .await?;
        assert_eq!(meta["thread"]["status"]["type"], "systemError");
        assert_eq!(meta["thread"]["canAcceptDirectInput"], true);

        let mut legacy = if let Some(binary) = std::env::var_os("GENT_TEST_LEGACY_WAKE_BINARY") {
            let mut child = Command::new(binary)
                .env_clear()
                .env("HOME", node.root.path())
                .env("TMPDIR", node.root.path())
                .current_dir(node.root.path())
                .arg("--home")
                .arg(&node.home)
                .args(["mcp", "serve", "--host", "codex", "--wake-socket"])
                .arg(&socket)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            while registry.coordinator()?.is_some() {
                ensure!(child.try_wait()?.is_none(), "legacy fixture MCP exited");
                sleep(Duration::from_millis(30)).await;
            }
            Some(child)
        } else {
            None
        };
        let _lease = if legacy.is_none() {
            Some(registry.coordinator()?.unwrap())
        } else {
            None
        };
        let sender = config::secret();
        agent(
            &node.home,
            &sender,
            AgentOp::Register {
                name: "fixture-intermediary".into(),
                provider: "test".into(),
            },
        )
        .await?;
        crate::owner(
            &node.home,
            OwnerOp::SetPolicy {
                policy: Policy {
                    rules: [Permission::Enumerate, Permission::Send, Permission::Receive]
                        .map(|permission| Rule {
                            actor: Selector::All,
                            peer: Selector::All,
                            permission,
                            effect: Effect::Allow,
                        })
                        .into(),
                    ..Default::default()
                },
            },
        )
        .await?;
        let sent = agent(
            &node.home,
            &sender,
            AgentOp::RequestReply {
                recipient,
                request_id: Uuid::now_v7().to_string(),
                text: "Please answer this fixture.".into(),
                files: vec![],
                file_ids: vec![],
            },
        )
        .await?;
        let message = sent["message_id"].as_str().unwrap();
        let expected = format!(
            "User relay via Gent (\"fixture-intermediary\"). Answer normally; your final response is returned automatically. If this arrives during other work, use gent_relay_next and gent_relay_respond to answer this request separately.\nGent message: {message}\n\nPlease answer this fixture."
        );
        ensure!(
            agent(&node.home, &key, AgentOp::WakePending).await?["pending"][0]["message_id"]
                == message,
            "missing pending relay"
        );
        if legacy.is_some() {
            // A full old-coordinator polling interval leaves this failure stranded.
            sleep(Duration::from_secs(6)).await;
            assert_eq!(
                agent(&node.home, &key, AgentOp::WakePending).await?["pending"][0]["message_id"],
                message
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
        let home = node.home.clone();
        let watcher = Runner(tokio::spawn(async move {
            crate::integration::pending::maintain(&home).await
        }));
        let turn = loop {
            let head = last(&mut host, thread).await?;
            if head["id"] != prior["turn"]["id"] && head["status"] == "completed" {
                break head;
            }
            sleep(Duration::from_millis(40)).await;
        };
        assert!(registry.coordinator()?.is_none());
        drop(watcher);
        let entries = host
            .rpc(
                "thread/items/list",
                json!({"threadId":thread,"turnId":turn["id"]}),
            )
            .await?;
        let users: Vec<_> = entries["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| &entry["item"])
            .filter(|i| i["type"] == "userMessage")
            .collect();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0]["content"][0]["text"], expected);
        let record = crate::owner(
            &node.home,
            OwnerOp::WakeShow {
                message_id: message.into(),
            },
        )
        .await?;
        assert_eq!(record["attempt_id"], users[0]["clientId"]);
        assert_eq!(record["submission_id"], turn["id"]);
        // The still-attached coordinator uses the original dispatch to observe
        // native intake and send the final relay reply. Neither sweep resubmits.
        if let Some(old) = &mut legacy {
            loop {
                ensure!(old.try_wait()?.is_none(), "legacy fixture MCP exited");
                let status = crate::owner(
                    &node.home,
                    OwnerOp::WakeShow {
                        message_id: message.into(),
                    },
                )
                .await?;
                if status["direct"]["response_message_id"].is_string() {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        } else {
            sweep(&node.home, &registry, &mut None, Sweep::WakeOnly).await?;
            crate::integration::pending::Pending::default()
                .tick(&node.home)
                .await?;
            sweep(&node.home, &registry, &mut None, Sweep::WakeOnly).await?;
        }
        let record = crate::owner(
            &node.home,
            OwnerOp::WakeShow {
                message_id: message.into(),
            },
        )
        .await?;
        ensure!(
            record["inbox_seen_at"].is_number() && record["direct"]["finished"] == true,
            "missing relay receipt"
        );
        ensure!(
            record["direct"]["response_message_id"].is_string(),
            "missing final response"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(last(&mut host, thread).await?["id"], turn["id"]);
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::select! {
        result=tokio::time::timeout(Duration::from_secs(35),trial)=>result?,
        result=axum::serve(listener,provider)=>{result?;anyhow::bail!("fixture provider stopped")}
    };
    child.kill().await?;
    result
}
