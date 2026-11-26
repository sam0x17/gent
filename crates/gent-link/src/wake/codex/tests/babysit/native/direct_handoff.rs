//! A real named host handoff, followed exclusively by Gent notifications.
use super::*;

#[tokio::test]
#[ignore = "requires an installed Codex app-server"]
async fn one_notification_on_a_named_handoff_gets_one_retry() -> Result<()> {
    trial(1, false).await
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server"]
async fn three_notifications_on_a_named_handoff_get_one_retry() -> Result<()> {
    trial(3, false).await
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server"]
async fn direct_evidence_retired_during_the_last_queue_read_blocks_submission() -> Result<()> {
    trial(1, true).await
}

async fn trial(deliveries: usize, retire_during_check: bool) -> Result<()> {
    let node = Node::start().await?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let (mut child, socket) = start_host(node.root.path(), listener.local_addr()?).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let provider = Router::new().route("/v1/responses", post({
        let calls = calls.clone();
        let release = release.clone();
        move || {
            let i = calls.fetch_add(1, Ordering::SeqCst);
            let release = release.clone();
            async move {
                if (1..=deliveries+1).contains(&i) { release.notified().await; }
                (StatusCode::BAD_REQUEST, Json(json!({"error":{"type":"invalid_request_error",
                    "code":"unknown_parameter","message":"Unknown parameter: 'input[0].tools[0].role'.",
                    "param":"input[0].tools[0].role"}})))
            }
        }
    }));
    let exercise = async {
        let mut host = Host::connect(&socket).await?;
        let t = host
            .rpc(
                "thread/start",
                json!({"cwd":node.root.path().join("work"),
            "threadSource":"user","historyMode":"paginated"}),
            )
            .await?;
        let thread = t["thread"]["id"].as_str().unwrap();
        let path = Path::new(t["thread"]["path"].as_str().unwrap());
        let (bindings, registry, recipient) = node.register(&socket, thread).await?;
        let sender = config::secret();
        agent(
            &node.home,
            &sender,
            AgentOp::Register {
                name: "fixture-sender".into(),
                provider: "fixture".into(),
            },
        )
        .await?;
        let primer = host
            .rpc(
                "turn/start",
                json!({"threadId":thread,"turnTrigger":"user",
            "input":[{"type":"text","text":"Prime this fixture."}]}),
            )
            .await?;
        stopped(&mut host, thread, &primer["turn"]["id"], path).await?;
        let root = host.rpc("turn/start",json!({"threadId":thread,"input":[],
            "toolOutput":{"namespace":"codex_tui","name":"send_message_to_thread","output":"synthetic","retain":true}
        })).await?["turn"]["id"].clone();
        for i in 0..deliveries {
            while calls.load(Ordering::SeqCst) < i + 2 {
                sleep(Duration::from_millis(10)).await;
            }
            if i > 0 {
                sleep(Duration::from_secs(6)).await;
            }
            agent(
                &node.home,
                &sender,
                AgentOp::Send {
                    recipient: recipient.clone(),
                    request_id: Uuid::now_v7().to_string(),
                    text: format!("Fixture notification {i}."),
                    files: vec![],
                    file_ids: vec![],
                },
            )
            .await?;
            sweep(&node.home, &registry, &mut None, Sweep::WakeOnly).await?;
            release.notify_one();
            while calls.load(Ordering::SeqCst) < i + 3 {
                sleep(Duration::from_millis(10)).await;
            }
            sweep(&node.home, &registry, &mut None, Sweep::WakeOnly).await?;
        }
        let delivered = gent_daemon::store::now();
        while gent_daemon::store::now() <= delivered {
            sleep(Duration::from_millis(10)).await;
        }
        release.notify_one();
        stopped(&mut host, thread, &root, path).await?;
        let items = host
            .rpc(
                "thread/items/list",
                json!({"threadId":thread,"turnId":root}),
            )
            .await?;
        let users = items["data"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["item"]["type"] == "userMessage")
            .count();
        assert_eq!(users, deliveries);
        assert!(trigger(&rollout(path)?, &last(&mut host, thread).await?).is_null());
        config::set_ordinary_babysitter_enabled(&node.home, true)?;
        if retire_during_check {
            // Reuse the real rollout and journal, interposing only the final host read.
            let mut before = Read::new(thread);
            before.meta = host
                .rpc(
                    "thread/read",
                    json!({"threadId":thread,"includeTurns":false}),
                )
                .await?["thread"]
                .clone();
            before.turn = last(&mut host, thread).await?;
            before.goal = Value::Null;
            let client = items["data"]
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["item"]["type"] == "userMessage")
                .unwrap();
            let mut after = before.clone();
            after.retire_dispatch_on_queue_read = Some((
                node.home.join("state.sqlite3"),
                serde_json::from_value(client["item"]["clientId"].clone())?,
            ));
            drop(bindings);
            let mock = super::super::host(thread, before, after, false);
            let (_binding, proxy, bound) = node.register(&mock.path, thread).await?;
            assert_eq!(bound, recipient);
            crate::wake::codex::ordinary::inspect(
                &node.home,
                &proxy,
                thread,
                &proxy.credential(thread)?.unwrap(),
            )
            .await?;
            let db = rusqlite::Connection::open_with_flags(
                node.home.join("state.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            let state:(usize,usize,usize)=db.query_row("SELECT count(*),sum(admitted),sum(submitted) FROM babysitter_chat_attempts WHERE agent=?1",
                [&recipient],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            assert_eq!(state, (1, 0, 0));
            assert_eq!(calls.load(Ordering::SeqCst), deliveries + 2);
            return Ok(());
        }
        let (mut a, mut b) = (None, None);
        tokio::try_join!(
            sweep(&node.home, &registry, &mut a, Sweep::GoalsOnly),
            sweep(&node.home, &registry, &mut b, Sweep::GoalsOnly)
        )?;
        let child = super::handoff::retry(&mut host, thread, &root, path).await?;
        let db = rusqlite::Connection::open_with_flags(
            node.home.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let submitted: usize = db.query_row("SELECT count(*) FROM babysitter_chat_attempts
            JOIN babysitter_chat_direct_handoffs USING(attempt) WHERE agent=?1 AND turn=?2 AND ordinal=0 AND admitted=1 AND submitted=1",
            rusqlite::params![recipient,root.as_str().unwrap()],|row|row.get(0))?;
        assert_eq!(submitted, 1);
        sleep(Duration::from_secs(16)).await;
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        assert_eq!(last(&mut host, thread).await?["id"], child);
        assert_eq!(calls.load(Ordering::SeqCst), deliveries + 3);
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::select! {
        result=tokio::time::timeout(Duration::from_secs(60),exercise)=>result?,
        result=axum::serve(listener,provider)=>{result?;anyhow::bail!("fixture provider stopped")}
    };
    child.kill().await?;
    result
}
