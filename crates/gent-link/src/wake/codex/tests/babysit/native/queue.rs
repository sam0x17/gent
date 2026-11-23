//! A real Codex queue drains past a provider failure while its goal stays blocked.
use super::*;
use tokio::sync::Notify;

const RECEIPTS: usize = 27;
const AFTER_QUEUE: usize = 1 + 1 + RECEIPTS;
const GOAL: &str = "Count these synthetic receipts.";
const BAD_REQUEST: &str = r#"{"error":{"message":"Invalid request payload","type":"invalid_request_error","code":"invalid_request_error","param":"5431"}}"#;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Decision {
    Resume,
    ResumeAfterDelayedError,
    NewUserTurn,
    UserBlock,
    UserBlockDuringQueue,
}

#[derive(Default)]
struct Provider {
    calls: AtomicUsize,
    finish_initial_goal_turn: Notify,
    drain_remaining_queue: Notify,
}

impl Provider {
    async fn reply(
        &self,
        decision: Decision,
    ) -> (StatusCode, [(&'static str, &'static str); 1], String) {
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        match index {
            0 => self.finish_initial_goal_turn.notified().await,
            1 => {
                if decision == Decision::ResumeAfterDelayedError {
                    let started = gent_daemon::store::now();
                    while gent_daemon::store::now() == started {
                        sleep(Duration::from_millis(10)).await;
                    }
                }
                return (
                    StatusCode::BAD_REQUEST,
                    [("content-type", "application/json")],
                    BAD_REQUEST.into(),
                );
            }
            2 => self.drain_remaining_queue.notified().await,
            i if i < AFTER_QUEUE || (i == AFTER_QUEUE && decision == Decision::NewUserTurn) => {}
            _ => std::future::pending().await, // Observe the resumed turn in progress.
        }
        let response = format!("fixture-{index}");
        let mut body = String::new();
        for event in [
            json!({"type":"response.created","response":{"id":response}}),
            json!({"type":"response.output_item.done","output_index":0,"item":{"type":"message","role":"assistant","id":format!("message-{index}"),"content":[{"type":"output_text","text":"Synthetic receipt."}]}}),
            json!({"type":"response.completed","response":{"id":response,"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}),
        ] {
            use std::fmt::Write;
            write!(
                body,
                "event: {}\ndata: {event}\n\n",
                event["type"].as_str().unwrap()
            )
            .unwrap();
        }
        (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            body,
        )
    }

    async fn wait_for_calls(&self, count: usize) {
        while self.calls.load(Ordering::SeqCst) < count {
            sleep(Duration::from_millis(10)).await;
        }
    }
}

async fn idle(host: &mut Host, thread: &str) -> Result<()> {
    while host
        .rpc(
            "thread/read",
            json!({"threadId":thread,"includeTurns":false}),
        )
        .await?["thread"]["status"]["type"]
        != "idle"
    {
        sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

async fn blocked_update(observer: &mut Host, thread: &str) -> Result<Value> {
    while let Some(frame) = observer.socket.next().await {
        if let Message::Text(text) = frame? {
            let event: Value = serde_json::from_str(&text)?;
            let params = &event["params"];
            if event["method"] == "thread/goal/updated"
                && params["threadId"] == thread
                && params["goal"]["status"] == "blocked"
            {
                return Ok(params.clone());
            }
        }
    }
    anyhow::bail!("fixture closed before the native blocked-goal update")
}

fn rollout(path: &Path) -> Result<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn trigger<'a>(rows: &'a [Value], turn: &Value) -> &'a Value {
    let start = rows
        .iter()
        .map(|row| &row["payload"])
        .find(|p| p["type"] == "task_started" && p["turn_id"] == turn["id"])
        .expect("native turn start");
    assert_eq!(start["started_at"], turn["startedAt"]);
    assert_eq!(start["turn_attribution"]["turn_id"], turn["id"]);
    &start["turn_attribution"]["turn_trigger"]
}

async fn user_block(host: &mut Host, observer: &mut Host, thread: &str) -> Result<Value> {
    let result = host
        .rpc(
            "thread/goal/set",
            json!({"threadId":thread,"status":"blocked","origin":"user"}),
        )
        .await?;
    let change = blocked_update(observer, thread).await?;
    assert!(change["turnId"].is_null());
    assert_eq!(result["goal"], change["goal"]);
    Ok(change["goal"].clone())
}

async fn verify_history(
    host: &mut Host,
    path: &Path,
    queued: &[String],
    blocked_event: &Value,
    decision: Decision,
) -> Result<()> {
    let thread = blocked_event["threadId"].as_str().unwrap();
    let updated = blocked_event["goal"]["updatedAt"].as_i64().unwrap();
    let history = host
        .rpc(
            "thread/turns/list",
            json!({"threadId":thread,"limit":40,"sortDirection":"asc","itemsView":"notLoaded"}),
        )
        .await?;
    let turns = history["data"].as_array().context("missing turn history")?;
    assert_eq!(turns.len(), AFTER_QUEUE);
    let rows = rollout(path)?;
    assert_eq!(trigger(&rows, &turns[0]), "goal");
    assert_eq!(turns[0]["status"], "completed");
    for (turn, id) in turns[1..].iter().zip(queued) {
        assert_eq!(trigger(&rows, turn), "queue");
        assert!(
            rows.iter().any(|r| {
                let p = &r["payload"];
                r["type"] == "event_msg"
                    && p["type"] == "item_completed"
                    && p["thread_id"] == thread
                    && p["turn_id"] == turn["id"]
                    && p["item"]["type"] == "UserMessage"
                    && p["item"]["client_id"].as_str() == Some(id)
            }),
            "queued message did not reach its native turn"
        );
    }
    let failed = &turns[1];
    assert_eq!(failed["id"], blocked_event["turnId"]);
    assert_eq!(failed["status"], "failed");
    if decision == Decision::ResumeAfterDelayedError {
        assert!(updated > failed["startedAt"].as_i64().unwrap());
    } else if decision == Decision::Resume {
        assert_eq!(updated, failed["startedAt"].as_i64().unwrap());
    }
    assert_eq!(failed["error"]["codexErrorInfo"], "other");
    assert_eq!(
        serde_json::from_str::<Value>(failed["error"]["message"].as_str().unwrap())?,
        serde_json::from_str::<Value>(BAD_REQUEST)?
    );
    assert!(
        (failed["startedAt"].as_i64().unwrap()..=failed["completedAt"].as_i64().unwrap())
            .contains(&updated)
    );
    assert!(
        turns[2..]
            .iter()
            .all(|t| t["status"] == "completed" && t["error"].is_null())
    );
    assert!(turns.last().unwrap()["completedAt"].as_i64().unwrap() > updated);
    Ok(())
}

async fn trial(node: &Node, socket: &Path, provider: &Provider, decision: Decision) -> Result<()> {
    let mut observer = Host::connect(socket).await?;
    let mut host = Host::connect(socket).await?;
    let started = host
        .rpc("thread/start", json!({"cwd":node.root.path().join("work")}))
        .await?;
    let thread = started["thread"]["id"]
        .as_str()
        .context("missing fixture thread")?;
    let path = Path::new(
        started["thread"]["path"]
            .as_str()
            .context("missing fixture rollout")?,
    );
    assert!(path.starts_with(node.root.path().canonicalize()?.join("codex")));
    let (_binding, registry, registered) = node.register(socket, thread).await?;
    let params = json!({"threadId":thread});
    host.rpc(
        "thread/goal/set",
        json!({"threadId":thread,"objective":GOAL,"status":"active","origin":"user"}),
    )
    .await?;
    provider.wait_for_calls(1).await;

    let mut queued = Vec::new();
    for i in 0..=RECEIPTS {
        let id = Uuid::new_v4().to_string();
        let added = host
            .rpc(
                "thread/queue/add",
                json!({"threadId":thread,"clientUserMessageId":id,
            "input":[{"type":"text","text":format!("Synthetic queue submission {i}.")}]}),
            )
            .await?;
        assert_eq!(added["queuedSubmission"]["clientUserMessageId"], id);
        queued.push(id);
    }
    if matches!(decision, Decision::Resume | Decision::UserBlockDuringQueue) {
        // Release near the start of a native clock second to exercise the
        // equal-timestamp paths for both provider and user blocks.
        let second = gent_daemon::store::now();
        while gent_daemon::store::now() == second {
            sleep(Duration::from_millis(10)).await;
        }
    }
    provider.finish_initial_goal_turn.notify_one();
    provider.wait_for_calls(3).await;
    let blocked = host.rpc("thread/goal/get", params.clone()).await?["goal"].clone();
    let blocked_event = blocked_update(&mut observer, thread).await?;
    assert_eq!(blocked_event["goal"], blocked);
    if decision == Decision::UserBlockDuringQueue {
        assert_eq!(
            user_block(&mut host, &mut observer, thread).await?,
            blocked,
            "the fixture needs a deliberate block in the same timestamp second"
        );
    }
    // Cross a native timestamp boundary while the first receipt is held.
    let updated = blocked["updatedAt"]
        .as_i64()
        .context("missing goal timestamp")?;
    while gent_daemon::store::now() <= updated {
        sleep(Duration::from_millis(20)).await;
    }
    provider.drain_remaining_queue.notify_one();
    provider.wait_for_calls(AFTER_QUEUE).await;
    idle(&mut host, thread).await?;
    assert_eq!(
        host.rpc("thread/goal/get", params.clone()).await?["goal"],
        blocked
    );
    let queue = host.rpc("thread/queue/list", params.clone()).await?;
    assert_eq!(queue["data"], json!([]));
    assert!(queue["nextCursor"].is_null());

    verify_history(&mut host, path, &queued, &blocked_event, decision).await?;
    match decision {
        Decision::NewUserTurn => {
            let submitted = host.rpc("turn/start", json!({"threadId":thread,"input":[{"type":"text","text":"Handle a new ordinary user request."}]})).await?;
            provider.wait_for_calls(AFTER_QUEUE + 1).await;
            idle(&mut host, thread).await?;
            let new_turn = last(&mut host, thread).await?;
            assert_eq!(new_turn["status"], "completed");
            assert_eq!(new_turn["id"], submitted["turn"]["id"]);
            let rows = rollout(path)?;
            let source = trigger(&rows, &new_turn);
            assert!(source.is_null() || *source == "user");
        }
        Decision::UserBlock => {
            user_block(&mut host, &mut observer, thread).await?;
        }
        Decision::Resume | Decision::ResumeAfterDelayedError | Decision::UserBlockDuringQueue => {}
    }
    let goal_before = host.rpc("thread/goal/get", params.clone()).await?["goal"].clone();
    let turn_before = last(&mut host, thread).await?;
    let calls_before = provider.calls.load(Ordering::SeqCst);
    sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
    let goal_after = host.rpc("thread/goal/get", params.clone()).await?["goal"].clone();
    if matches!(
        decision,
        Decision::Resume | Decision::ResumeAfterDelayedError
    ) {
        assert_eq!(
            goal_after["status"], "active",
            "queue-masked provider block was missed"
        );
        for field in ["threadId", "createdAt", "objective", "tokenBudget"] {
            assert_eq!(goal_after[field], blocked[field]);
        }
        provider.wait_for_calls(AFTER_QUEUE + 1).await;
        let resumed = last(&mut host, thread).await?;
        assert_ne!(resumed["id"], turn_before["id"]);
        assert_eq!(resumed["status"], "inProgress");
        assert_eq!(trigger(&rollout(path)?, &resumed), "goal");
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        assert_eq!(last(&mut host, thread).await?["id"], resumed["id"]);
        assert_eq!(provider.calls.load(Ordering::SeqCst), AFTER_QUEUE + 1);
        let notices = crate::owner(
            &node.home,
            gent_protocol::OwnerOp::NotificationPending {
                scope: node.scope.clone(),
            },
        )
        .await?;
        assert_eq!(notices.as_array().unwrap().len(), 1);
        assert_eq!(notices[0]["event"]["kind"], "goal_resumed");
        assert_eq!(notices[0]["event"]["chat"], registered);
        assert_eq!(notices[0]["event"]["reason"], "request_payload");
    } else {
        assert_eq!(goal_after, goal_before);
        assert_eq!(goal_after["status"], "blocked");
        assert_eq!(last(&mut host, thread).await?, turn_before);
        assert_eq!(provider.calls.load(Ordering::SeqCst), calls_before);
        assert_eq!(node.notices(&registered).await?, 0);
    }
    Ok(())
}

async fn exercise_queue(decision: Decision) -> Result<()> {
    let node = Node::start().await?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let (mut child, socket) = start_host(node.root.path(), listener.local_addr()?).await?;
    let provider = Arc::new(Provider::default());
    let model = Router::new().route(
        "/v1/responses",
        post({
            let provider = provider.clone();
            move || {
                let provider = provider.clone();
                async move { provider.reply(decision).await }
            }
        }),
    );
    let result = tokio::select! {
        r = tokio::time::timeout(Duration::from_secs(45), trial(&node, &socket, &provider, decision)) => r.context("native queue trial timed out")?,
        r = axum::serve(listener, model) => {r?; anyhow::bail!("fixture provider stopped")}
    };
    child.kill().await?;
    result
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server with native goals and queueing"]
async fn installed_codex_resumes_a_queue_masked_provider_block_once() -> Result<()> {
    exercise_queue(Decision::Resume).await
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server with native goals and queueing"]
async fn installed_codex_preserves_a_new_user_turn_after_the_queue_drains() -> Result<()> {
    exercise_queue(Decision::NewUserTurn).await
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server with native goals and queueing"]
async fn installed_codex_preserves_an_explicit_user_block_after_the_queue_drains() -> Result<()> {
    exercise_queue(Decision::UserBlock).await
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server with native goals and queueing"]
async fn installed_codex_preserves_a_same_second_user_block_inside_the_queue() -> Result<()> {
    exercise_queue(Decision::UserBlockDuringQueue).await
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server with native goals and queueing"]
async fn installed_codex_resumes_a_queue_failure_that_crosses_a_timestamp_second() -> Result<()> {
    exercise_queue(Decision::ResumeAfterDelayedError).await
}
