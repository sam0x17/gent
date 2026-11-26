//! A private Codex app-server, two disposable Gent registrations and a loopback provider.
use super::*;

#[tokio::test]
#[ignore = "requires an installed Codex app-server"]
async fn user_root_with_two_observed_gent_deliveries_gets_one_continuation() -> Result<()> {
    mixed_foreground_trial(0, 2).await
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server"]
async fn four_foreground_steers_then_a_gent_delivery_get_one_continuation() -> Result<()> {
    mixed_foreground_trial(4, 1).await
}

async fn mixed_foreground_trial(steers: usize, deliveries: usize) -> Result<()> {
    let node = Node::start().await?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let (mut child, socket) = start_host(node.root.path(), listener.local_addr()?).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let gates: Arc<[_]> = (0..=steers + deliveries)
        .map(|_| tokio::sync::Notify::new())
        .collect();
    let requests = calls.clone();
    let provider_gates = gates.clone();
    let model = Router::new().route(
        "/v1/responses",
        post(move || {
            let index = requests.fetch_add(1, Ordering::SeqCst);
            let gates = provider_gates.clone();
            async move {
                if let Some(gate) = index.checked_sub(1).and_then(|i| gates.get(i)) {
                    gate.notified().await;
                }
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error":{"type":"invalid_request_error",
                "code":"unknown_parameter","message":"Unknown parameter: 'input[0].tools[0].role'.",
                "param":"input[0].tools[0].role"}})),
                )
            }
        }),
    );
    let trial = async {
        let mut host = Host::connect(&socket).await?;
        let result = host
            .rpc(
                "thread/start",
                json!({"cwd":node.root.path().join("work"),
            "threadSource":"user","historyMode":"paginated"}),
            )
            .await?;
        let thread = result["thread"]["id"].as_str().unwrap();
        let (_bindings, registry, recipient) = node.register(&socket, thread).await?;
        let sender = config::secret();
        agent(
            &node.home,
            &sender,
            AgentOp::Register {
                name: "fixture-sender".into(),
                provider: "test".into(),
            },
        )
        .await?;
        // Reproduce a manual continuation in an existing conversation. Its first-ever
        // turn has a different startup envelope and is outside this narrow proof.
        let path = Path::new(result["thread"]["path"].as_str().unwrap());
        let primer = host
            .rpc(
                "turn/start",
                json!({"threadId":thread, "turnTrigger":"user",
            "input":[{"type":"text","text":"Prime the fixture conversation."}]}),
            )
            .await?;
        stopped(&mut host, thread, &primer["turn"]["id"], path).await?;
        let root = host.rpc("turn/start",json!({"threadId":thread,"turnTrigger":"user",
            "clientUserMessageId":Uuid::new_v4(),"input":[{"type":"text","text":"Resume the fixture task."}]})).await.context("start resumed operator turn")?["turn"]["id"].clone();
        for (i, gate) in gates.iter().take(steers).enumerate() {
            while calls.load(Ordering::SeqCst) <= i + 1 {
                sleep(Duration::from_millis(20)).await;
            }
            host.rpc("turn/steer", json!({"threadId":thread,"expectedTurnId":root,
                "clientUserMessageId":Uuid::new_v4(),"input":[{"type":"text","text":format!("Foreground steer {i}.")}]})).await?;
            gate.notify_one();
        }
        for (n, gate) in gates.iter().skip(steers).take(deliveries).enumerate() {
            while calls.load(Ordering::SeqCst) <= steers + n + 1 {
                sleep(Duration::from_millis(20)).await;
            }
            // Respect the native dispatch interval and separate the opener's second from each claim.
            sleep(Duration::from_secs(if n == 0 { 2 } else { 6 })).await;
            agent(
                &node.home,
                &sender,
                AgentOp::Send {
                    recipient: recipient.clone(),
                    request_id: Uuid::now_v7().to_string(),
                    text: format!("Fixture notification {n}."),
                    files: vec![],
                    file_ids: vec![],
                },
            )
            .await?;
            sweep(&node.home, &registry, &mut None, Sweep::WakeOnly).await?;
            gate.notify_one();
            while calls.load(Ordering::SeqCst) <= steers + n + 2 {
                sleep(Duration::from_millis(20)).await;
            }
            sweep(&node.home, &registry, &mut None, Sweep::WakeOnly).await?;
            assert_eq!(last(&mut host, thread).await?["id"], root);
        }
        // The claim guard vetoes any wake in the failure's own clock second.
        // As in the incident, all dispatches have already completed before that second.
        let delivered_at = gent_daemon::store::now();
        while gent_daemon::store::now() <= delivered_at {
            sleep(Duration::from_millis(20)).await;
        }
        gates[steers + deliveries].notify_one();
        stopped(&mut host, thread, &root, path).await?;
        let db = rusqlite::Connection::open_with_flags(
            node.home.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let finished: usize = db.query_row(
            "SELECT count(*) FROM wake_dispatches WHERE agent=?1 AND json_extract(payload,'$.direct.finished')=1
             AND json_extract(payload,'$.submission_id')=?2", rusqlite::params![recipient,root.as_str().unwrap()],
            |row| row.get(0),
        )?;
        assert_eq!(finished, deliveries);
        config::set_ordinary_babysitter_enabled(&node.home, true)?;
        let (mut a, mut b) = (None, None);
        tokio::try_join!(
            sweep(&node.home, &registry, &mut a, Sweep::GoalsOnly),
            sweep(&node.home, &registry, &mut b, Sweep::GoalsOnly)
        )?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let continuation = loop {
            let t = last(&mut host, thread).await?;
            if t["id"] != root && t["status"] == "failed" {
                break t;
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "mixed root was not recovered"
            );
            sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(continuation["rootTurnId"], root);
        let accepted: String = db.query_row(
            "SELECT attempt FROM babysitter_chat_attempts WHERE agent=?1 AND turn=?2
             AND ordinal=0 AND admitted=1 AND submitted=1",
            rusqlite::params![recipient, root.as_str().unwrap()],
            |row| row.get(0),
        )?;
        let page = host
            .rpc(
                "thread/items/list",
                json!({"threadId":thread,"turnId":continuation["id"]}),
            )
            .await?;
        let [only] = page["data"].as_array().unwrap().as_slice() else {
            anyhow::bail!("unexpected continuation items")
        };
        assert_eq!(only["item"]["clientId"], accepted);
        assert_eq!(only["item"]["content"][0]["text"], "please continue");
        sleep(Duration::from_secs(16)).await;
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        assert_eq!(last(&mut host, thread).await?["id"], continuation["id"]);
        assert_eq!(calls.load(Ordering::SeqCst), steers + deliveries + 3);
        Ok::<_, anyhow::Error>(())
    };
    let outcome = tokio::select! {
        result=tokio::time::timeout(Duration::from_secs(55),trial)=>result?,
        result=axum::serve(listener,model)=>{result?;anyhow::bail!("fixture provider stopped")}
    };
    child.kill().await?;
    outcome
}
