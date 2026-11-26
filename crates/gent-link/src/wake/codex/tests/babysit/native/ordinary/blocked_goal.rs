//! Both recovery paths share a real daemon, native app-server and loopback provider.
use super::*;
use tokio::sync::Notify;

const ERROR: &str = r#"{"error":{"type":"invalid_request_error","code":"invalid_request_error","message":"Invalid request payload","param":"21846"}}"#;
const OK: &str = concat!(
    "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"fixture\"}}\n\n",
    "event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"role\":\"assistant\",\"id\":\"msg\",\"content\":[{\"type\":\"output_text\",\"text\":\"Finished the fixture.\"}]}}\n\n",
    "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"fixture\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n",
);

#[tokio::test]
#[ignore = "requires an installed Codex app-server with native goals"]
async fn independent_user_root_leaves_provider_blocked_goal_untouched() -> Result<()> {
    trial(Outcome::Success).await
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server with native goals"]
async fn independent_user_root_preserves_a_same_second_user_block() -> Result<()> {
    trial(Outcome::UserBlock).await
}

#[tokio::test]
#[ignore = "requires installed Codex and the real 15s and 60s backoff intervals"]
async fn independent_user_root_retries_to_the_ordinary_limit() -> Result<()> {
    trial(Outcome::Repeat).await
}

#[derive(Clone, Copy, PartialEq)]
enum Outcome {
    Success,
    UserBlock,
    Repeat,
}

async fn trial(outcome: Outcome) -> Result<()> {
    let user_block = outcome == Outcome::UserBlock;
    let node = Node::start().await?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let (mut child, socket) = start_host(node.root.path(), listener.local_addr()?).await?;
    let queued = if user_block { 0 } else { 2 };
    let calls = Arc::new(AtomicUsize::new(0));
    let gates: Arc<[_; 3]> = Arc::new(std::array::from_fn(|_| Notify::new()));
    let received = calls.clone();
    let hold = gates.clone();
    let provider = Router::new().route(
        "/v1/responses",
        post(move || {
            let index = received.fetch_add(1, Ordering::SeqCst);
            let hold = hold.clone();
            async move {
                if index == 0 {
                    hold[0].notified().await;
                }
                if index == 0 || index == queued + 1 {
                    return (
                        StatusCode::BAD_REQUEST,
                        [("content-type", "application/json")],
                        ERROR,
                    );
                }
                if index == 1 {
                    hold[1].notified().await;
                }
                if index == queued + 2 {
                    hold[2].notified().await;
                }
                if outcome == Outcome::Repeat && index >= queued + 2 {
                    return (
                        StatusCode::BAD_REQUEST,
                        [("content-type", "application/json")],
                        ERROR,
                    );
                }
                (StatusCode::OK, [("content-type", "text/event-stream")], OK)
            }
        }),
    );
    let trial = async {
        let mut observer = Host::connect(&socket).await?;
        let mut host = Host::connect(&socket).await?;
        let t = host.rpc("thread/start",json!({"cwd":node.root.path().join("work"),"threadSource":"user","historyMode":"paginated"})).await?;
        let thread = t["thread"]["id"].as_str().unwrap();
        let path = Path::new(t["thread"]["path"].as_str().unwrap());
        let (_bindings, registry, agent) = node.register(&socket, thread).await?;
        let params = json!({"threadId":thread});
        host.rpc("thread/goal/set",json!({"threadId":thread,"objective":"Finish the goal fixture.","status":"active","origin":"user"})).await?;
        while calls.load(Ordering::SeqCst) == 0 {
            sleep(Duration::from_millis(10)).await;
        }
        for _ in 0..queued {
            host.rpc("thread/queue/add",json!({"threadId":thread,"clientUserMessageId":Uuid::new_v4(),"input":[{"type":"text","text":"Process a queued fixture."}]})).await?;
        }
        while chrono::Utc::now().timestamp_subsec_millis() > 100 {
            sleep(Duration::from_millis(5)).await;
        }
        gates[0].notify_one();
        let block = next_block(&mut observer, thread).await?;
        let old = block["goal"].clone();
        if user_block {
            host.rpc(
                "thread/goal/set",
                json!({"threadId":thread,"status":"blocked","origin":"user"}),
            )
            .await?;
            let explicit = next_block(&mut observer, thread).await?;
            assert!(explicit["turnId"].is_null());
            assert_eq!(explicit["goal"], old);
        }
        while gent_daemon::store::now() <= old["updatedAt"].as_i64().unwrap() {
            sleep(Duration::from_millis(10)).await;
        }
        if queued > 0 {
            gates[1].notify_one();
            loop {
                let page = host.rpc("thread/turns/list",json!({"threadId":thread,"limit":8,"sortDirection":"desc","itemsView":"notLoaded"})).await?;
                let turns = page["data"].as_array().unwrap();
                if turns.len() == queued + 1
                    && turns[..queued].iter().all(|t| t["status"] == "completed")
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        }
        assert_eq!(
            host.rpc("thread/goal/get", params.clone()).await?["goal"],
            old
        );
        host.rpc(
            "thread/settings/update",
            json!({"threadId":thread,"effort":"low"}),
        )
        .await?;
        let result = host
            .rpc(
                "turn/start",
                json!({"threadId":thread,"clientUserMessageId":Uuid::new_v4(),"turnTrigger":"user",
            "input":[{"type":"text","text":"Inspect the independent fixture."}]}),
            )
            .await?;
        let root = &result["turn"]["id"];
        assert_ne!(*root, block["turnId"]);
        assert_eq!(result["turn"]["rootTurnId"], *root);
        stopped(&mut host, thread, root, path).await?;
        assert_eq!(
            host.rpc("thread/goal/get", params.clone()).await?["goal"],
            old
        );

        let db = rusqlite::Connection::open_with_flags(
            node.home.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let counts = || -> rusqlite::Result<(i64, i64, i64)> {
            db.query_row(
            "SELECT (SELECT count(*) FROM babysitter_chat_attempts WHERE agent=?1 AND admitted=1 AND submitted=1),
                    (SELECT count(*) FROM babysitter_attempts WHERE agent=?1 AND attempt IS NOT NULL),
                    (SELECT count(*) FROM babysitter_attempts WHERE agent=?1 AND submitted=1)",
            [&agent],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))
        };
        // The goal route also sees this exact head before ordinary is enabled.
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        assert_eq!(counts()?, (0, 0, 0));
        assert_eq!(
            host.rpc("thread/goal/get", params.clone()).await?["goal"],
            old
        );
        config::set_ordinary_babysitter_enabled(&node.home, true)?;
        let (mut a, mut b) = (None, None);
        tokio::try_join!(
            sweep(&node.home, &registry, &mut a, Sweep::GoalsOnly),
            sweep(&node.home, &registry, &mut b, Sweep::WakeAndGoals)
        )?;
        assert_eq!(counts()?, (i64::from(!user_block), 0, 0));
        if user_block {
            assert_eq!(last(&mut host, thread).await?["id"], *root);
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        } else {
            while calls.load(Ordering::SeqCst) != queued + 3 {
                sleep(Duration::from_millis(10)).await;
            }
            let continued = last(&mut host, thread).await?;
            let rows = rollout(path)?;
            assert_eq!(continued["rootTurnId"], *root);
            assert_eq!(trigger(&rows, &continued), "gent_babysitter");
            assert!(
                rows.iter()
                    .any(|r| r["payload"]["turn_id"] == continued["id"]
                        && r["payload"]["item"]["type"] == "UserMessage"
                        && r["payload"]["item"]["content"][0]["text"] == "please continue")
            );
            assert_eq!(
                host.rpc("thread/goal/get", params.clone()).await?["goal"],
                old
            );
            sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
            gates[2].notify_one();
            if outcome == Outcome::Repeat {
                let mut turn = continued["id"].clone();
                let mut parent = root.clone();
                for (ordinal, delay) in [(1, 15), (2, 60), (3, 0)] {
                    stopped(&mut host, thread, &turn, path).await?;
                    let failure = last(&mut host, thread).await?;
                    assert_eq!(failure["rootTurnId"], *root);
                    let attempt: String = db.query_row(
                        "SELECT attempt FROM babysitter_chat_attempts WHERE agent=?1
                         AND operator=?2 AND turn=?3 AND ordinal=?4 AND admitted=1 AND submitted=1",
                        rusqlite::params![agent, root.as_str(), parent.as_str(), ordinal],
                        |row| row.get(0),
                    )?;
                    let items = host
                        .rpc(
                            "thread/items/list",
                            json!({"threadId":thread,"turnId":turn}),
                        )
                        .await?;
                    let [only] = items["data"].as_array().unwrap().as_slice() else {
                        panic!("expected exactly one native input");
                    };
                    assert_eq!(only["item"]["clientId"], attempt);
                    assert_eq!(
                        only["item"]["content"],
                        json!([{"type":"text","text":"please continue","text_elements":[]}])
                    );
                    sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
                    assert_eq!(counts()?, (ordinal, 0, 0));
                    assert_eq!(
                        host.rpc("thread/goal/get", params.clone()).await?["goal"],
                        old
                    );
                    if ordinal == 3 {
                        break;
                    }
                    let due = failure["completedAt"].as_i64().unwrap() + delay;
                    while gent_daemon::store::now() < due {
                        sleep(Duration::from_millis(100)).await;
                    }
                    let (mut a, mut b) = (None, None);
                    tokio::try_join!(
                        sweep(&node.home, &registry, &mut a, Sweep::GoalsOnly),
                        sweep(&node.home, &registry, &mut b, Sweep::WakeAndGoals)
                    )?;
                    assert_eq!(counts()?, (ordinal + 1, 0, 0));
                    let retry = last(&mut host, thread).await?;
                    assert_eq!(trigger(&rollout(path)?, &retry), "gent_babysitter");
                    assert_ne!(retry["id"], turn);
                    parent = turn;
                    turn = retry["id"].clone();
                }
                assert_eq!(calls.load(Ordering::SeqCst), queued + 5);
            } else {
                while last(&mut host, thread).await?["status"] != "completed" {
                    sleep(Duration::from_millis(10)).await;
                }
                sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
                assert_eq!(counts()?, (1, 0, 0));
                assert_eq!(calls.load(Ordering::SeqCst), queued + 3);
            }
        }
        assert_eq!(host.rpc("thread/goal/get", params).await?["goal"], old);
        assert_eq!(node.notices(&agent).await?, 0);
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::select! {
        result=tokio::time::timeout(Duration::from_secs(110),trial)=>result?,
        result=axum::serve(listener,provider)=>{result?;anyhow::bail!("fixture provider stopped")}
    };
    child.kill().await?;
    result
}
