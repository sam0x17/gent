use super::*;
use crate::integration::Host as NativeHost;
use gent_daemon::config;
use uuid::Uuid;

struct Node {
    root: tempfile::TempDir,
    home: PathBuf,
    daemon: tokio::task::JoinHandle<Result<()>>,
    scope: gent_protocol::notifications::Scope,
    stop: tokio_util::sync::CancellationToken,
}
impl Drop for Node {
    fn drop(&mut self) {
        self.daemon.abort();
    }
}
impl Node {
    async fn start() -> Result<Self> {
        Self::start_with_service(false).await
    }

    async fn start_with_service(enrolled: bool) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("node");
        let mut cfg = config::initialize(&home, "babysitter-test")?;
        cfg.extra
            .insert("transport".into(), toml::toml! { direct = "off" }.into());
        let scope = gent_protocol::notifications::Scope {
            account: Uuid::new_v4().to_string(),
            origin: "https://127.0.0.1:9".into(),
        };
        if enrolled {
            cfg.cluster.local_only = false;
            cfg.relay = Some(config::RelayConfig {
                endpoint: scope.origin.clone(),
                credential_file: "relay.key".into(),
            });
            config::write_private(&home.join("relay.key"), config::secret().as_bytes())?;
            cfg.service = Some(config::ServiceConfig {
                origin: scope.origin.clone(),
                account_id: scope.account.clone(),
            });
        }
        config::save(&home, &cfg)?;
        assert!(!gent_daemon::entitlements::paid(&home, &cfg));
        let now = gent_daemon::store::now();
        config::private_dir(&home.join("auth"))?;
        config::write_private(
            &home.join("auth/session.json"),
            &serde_json::to_vec(&json!({
                "version":1,"phase":"active","token":format!("gent_s1.{now}.{}",config::secret()),
                "service":scope.origin,"session":{"account_id":scope.account,"github_subject":"fixture",
                    "github_login":"fixture","created_at":now,"expires_at":now+3600}
            }))?,
        )?;
        let lock = gent_daemon::DaemonLock::acquire(&home)?;
        let stop = tokio_util::sync::CancellationToken::new();
        let daemon = tokio::spawn(gent_daemon::run_locked_until(
            lock,
            stop.clone().cancelled_owned(),
        ));
        let node = Self {
            root,
            home,
            daemon,
            scope,
            stop,
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while !node.home.join("daemon.sock").exists() {
                assert!(!node.daemon.is_finished());
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        Ok(node)
    }
    async fn register(&self, socket: &Path, thread: &str) -> Result<(Bindings, Registry, String)> {
        let mut bindings = Bindings::new(&self.home, NativeHost::Codex)?;
        let registry = bindings.enable_wake(&self.home, socket)?;
        let credential = bindings.credential(
            "codex-mcp-client",
            &json!({"threadId":thread}),
            "gent_register",
            &json!({}),
        )?;
        let registered = agent(
            &self.home,
            &credential,
            AgentOp::Register {
                name: "synthetic".into(),
                provider: "codex".into(),
            },
        )
        .await?;
        Ok((
            bindings,
            registry,
            registered["agent"]["id"]
                .as_str()
                .context("missing agent id")?
                .to_owned(),
        ))
    }

    async fn notices(&self, registered: &str) -> Result<usize> {
        let notices = crate::owner(
            &self.home,
            gent_protocol::OwnerOp::NotificationPending {
                scope: self.scope.clone(),
            },
        )
        .await?;
        let notices = notices
            .as_array()
            .context("invalid outbox")?
            .iter()
            .filter(|n| n["event"]["kind"] == "goal_resumed" && n["event"]["chat"] == registered)
            .count();
        Ok(notices)
    }
}

#[derive(Clone)]
struct Read {
    meta: Value,
    goal: Value,
    turn: Value,
    older_turns: Vec<Value>,
    queue: Vec<Value>,
    append_on_queue_read: Option<Value>,
    retire_dispatch_on_queue_read: Option<(PathBuf, Uuid)>,
}
impl Read {
    fn new(thread: &str) -> Self {
        let now = gent_daemon::store::now();
        Self {
            older_turns: Vec::new(),
            queue: Vec::new(),
            append_on_queue_read: None,
            retire_dispatch_on_queue_read: None,
            meta: json!({"id":thread,"canAcceptDirectInput":true,"status":{"type":"systemError"}}),
            goal: json!({"threadId":thread,"objective":"Finish synthetic task","status":"active","createdAt":now-40,"updatedAt":now-1,"tokenBudget":120,"tokensUsed":1,"timeUsedSeconds":1}),
            turn: json!({"id":Uuid::now_v7(),"status":"failed","items":[],"itemsView":"notLoaded","startedAt":now-3,"completedAt":now,
                "error":{"codexErrorInfo":{"httpConnectionFailed":{"httpStatusCode":503}},"message":"Synthetic model is at capacity","misalignment":null}}),
        }
    }
}

fn host(thread: &str, before: Read, after: Read, lose_reply: bool) -> Fixture {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let reads = AtomicUsize::new(0);
    let thread = thread.to_owned();
    let unbound = Uuid::now_v7().to_string();
    Fixture::respond(move |request| {
        let params = &request["params"];
        if request["method"] == "thread/loaded/list" {
            return Some(json!({"data":[unbound,thread],"nextCursor":null}));
        }
        assert_eq!(params["threadId"], thread);
        if request["method"] == "thread/read" {
            reads.fetch_add(1, Ordering::Relaxed);
        }
        let r = if reads.load(Ordering::Relaxed) <= 1 {
            &before
        } else {
            &after
        };
        Some(match request["method"].as_str().unwrap() {
            "thread/read" => {
                assert_eq!(params["includeTurns"], false);
                json!({"thread":r.meta})
            }
            "thread/turns/list" => {
                let blocked = r.goal["status"] == "blocked";
                let limit = if blocked { 32 } else { 1 };
                assert_eq!(params["limit"], limit);
                assert_eq!(params["itemsView"], "notLoaded");
                assert_eq!(params["sortDirection"], "desc");
                let offset = params["cursor"].as_str().map_or(0, |s| s.parse().unwrap());
                let data: Vec<_> = std::iter::once(&r.turn)
                    .chain(&r.older_turns)
                    .skip(offset)
                    .take(limit)
                    .collect();
                let next = offset + data.len();
                json!({"data":data,"nextCursor":(next <= r.older_turns.len()).then(||next.to_string())})
            }
            "thread/goal/get" => json!({"goal":r.goal}),
            "thread/queue/list" => {
                if let Some((path, attempt)) = &r.retire_dispatch_on_queue_read {
                    rusqlite::Connection::open(path)
                        .unwrap()
                        .execute(
                            "DELETE FROM wake_dispatches WHERE attempt_id=?1",
                            [attempt.to_string()],
                        )
                        .unwrap();
                }
                if let Some(row) = &r.append_on_queue_read {
                    use std::io::Write;
                    let mut file = std::fs::OpenOptions::new()
                        .append(true)
                        .open(r.meta["path"].as_str().unwrap())
                        .unwrap();
                    writeln!(file, "{row}").unwrap();
                }
                json!({"data":r.queue})
            }
            "thread/goal/set" => {
                assert_eq!(
                    *params,
                    json!({"threadId":thread,"status":"active","origin":"automatic"})
                );
                if lose_reply {
                    return None;
                }
                let mut goal = r.goal.clone();
                goal["status"] = json!("active");
                json!({"goal":goal})
            }
            method => panic!("unexpected host operation: {method}"),
        })
    })
}

#[derive(Debug, PartialEq)]
struct Observed {
    reads: usize,
    resumes: usize,
    notices: usize,
}

async fn exercise(
    node: &Node,
    before: Read,
    after: Read,
    lose_reply: bool,
    sweeps: usize,
) -> Result<Observed> {
    let thread = before.meta["id"].as_str().unwrap();
    let host = host(thread, before.clone(), after, lose_reply);
    let (_bindings, registry, registered) = node.register(&host.path, thread).await?;
    for _ in 0..sweeps {
        sweep(&node.home, &registry, &mut None, Sweep::WakeAndGoals).await?;
    }
    let (reads, resumes) = {
        let requests = host.requests.lock().unwrap();
        assert!(requests.iter().all(|r| matches!(
            r["method"].as_str(),
            Some(
                "initialize"
                    | "initialized"
                    | "thread/loaded/list"
                    | "thread/read"
                    | "thread/turns/list"
                    | "thread/goal/get"
                    | "thread/queue/list"
                    | "thread/goal/set"
            )
        )));
        let count = |method: &str| requests.iter().filter(|r| r["method"] == method).count();
        (count("thread/read"), count("thread/goal/set"))
    };
    Ok(Observed {
        reads,
        resumes,
        notices: node.notices(&registered).await?,
    })
}

#[tokio::test]
async fn native_resume_is_claimed_once_even_when_the_acknowledgement_is_lost() -> Result<()> {
    let node = Node::start().await?;
    for (status, lose_reply) in [("active", false), ("usageLimited", false), ("active", true)] {
        let mut initial = Read::new(&Uuid::now_v7().to_string());
        initial.goal["status"] = json!(status);
        if status == "usageLimited" {
            initial.turn["error"]["codexErrorInfo"] = json!("usageLimitExceeded");
        }
        assert_eq!(
            exercise(&node, initial.clone(), initial, lose_reply, 2).await?,
            Observed {
                reads: 3,
                resumes: 1,
                notices: usize::from(!lose_reply)
            }
        );
    }
    Ok(())
}

#[tokio::test]
async fn user_stops_and_intervening_changes_leave_the_goal_alone() -> Result<()> {
    let node = Node::start().await?;
    for change in [
        "paused",
        "blocked",
        "budgetLimited",
        "complete",
        "cancelled",
        "approval",
        "userInput",
        "misalignment",
        "unrelated quota",
        "new turn",
        "goal replaced",
        "goal edited",
        "goal cleared",
        "status changed",
        "budget changed",
    ] {
        let before = Read::new(&Uuid::now_v7().to_string());
        let mut after = before.clone();
        match change {
            "cancelled" => after.turn["status"] = json!("interrupted"),
            "approval" | "userInput" => {
                after.meta["status"] = json!({"type":"active","activeFlags":[if change=="approval" {"waitingOnApproval"} else {"waitingOnUserInput"}]})
            }
            "misalignment" => {
                after.turn["error"]["misalignment"] = json!({"message":"requires human"})
            }
            "unrelated quota" => after.goal["status"] = json!("usageLimited"),
            "new turn" => after.turn["id"] = json!(Uuid::now_v7()),
            "goal replaced" => after.goal["objective"] = json!("New goal"),
            "goal edited" => after.goal["updatedAt"] = json!(gent_daemon::store::now()),
            "goal cleared" => after.goal = Value::Null,
            "status changed" => {
                after.goal["status"] = json!("usageLimited");
                after.turn["error"]["codexErrorInfo"] = json!("usageLimitExceeded");
            }
            "budget changed" => after.goal["tokenBudget"] = json!(25),
            status => after.goal["status"] = json!(status),
        }
        assert_eq!(
            exercise(&node, before, after, false, 1).await?,
            Observed {
                reads: 2,
                resumes: 0,
                notices: 0
            },
            "{change}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_existing_human_stop_or_newer_goal_never_reaches_the_claim_recheck() -> Result<()> {
    let node = Node::start().await?;
    for stop in [
        "paused",
        "blocked",
        "budgetLimited",
        "complete",
        "cancelled",
        "waitingOnUserInput",
        "waitingOnApproval",
        "later edit",
        "misalignment",
    ] {
        let mut state = Read::new(&Uuid::now_v7().to_string());
        match stop {
            "cancelled" => state.turn["status"] = json!("interrupted"),
            "waitingOnUserInput" | "waitingOnApproval" => {
                state.meta["status"] = json!({"type":"active","activeFlags":[stop]})
            }
            "later edit" => {
                state.goal["updatedAt"] = json!(state.turn["completedAt"].as_i64().unwrap() + 1)
            }
            "misalignment" => state.turn["error"]["misalignment"] = json!({"message":"needs user"}),
            status => state.goal["status"] = json!(status),
        }
        assert_eq!(
            exercise(&node, state.clone(), state, false, 1).await?,
            Observed {
                reads: 1,
                resumes: 0,
                notices: 0
            },
            "{stop}"
        );
    }
    Ok(())
}

#[test]
fn temporary_unavailability_on_failed_provider_turns_is_retryable() {
    use super::super::babysit::terminal_failure;
    use gent_protocol::notifications::Failure;

    let demand = "We’re currently experiencing high demand, which may cause temporary errors.";
    let mut turn = json!({"status":"failed","error":{
        "codexErrorInfo":{"httpConnectionFailed":{"httpStatusCode":503}},
        "message":"unexpected status 503 Service Unavailable: Server is draining, url: https://provider.example/responses"
    }});
    assert_eq!(terminal_failure(&turn), Some(Failure::Capacity));
    // A status number quoted in the body must not override the host's status.
    turn["error"]["codexErrorInfo"]["httpConnectionFailed"]["httpStatusCode"] = json!(403);
    assert_eq!(terminal_failure(&turn), None);
    turn["error"]["codexErrorInfo"] = json!("other");
    turn["error"]["additionalDetails"] = json!("provider request ID");
    for message in [
        demand.to_owned(),
        demand.replace('’', "'"),
        json!({"error":{"type":"server_error","message":demand}}).to_string(),
    ] {
        turn["error"]["message"] = json!(message);
        assert_eq!(terminal_failure(&turn), Some(Failure::Capacity));
    }
    turn["error"]["message"] = json!(format!("A tool printed: {demand}"));
    assert_eq!(terminal_failure(&turn), None);
    turn["error"]["message"] = json!(demand);
    turn["status"] = json!("interrupted");
    assert_eq!(terminal_failure(&turn), None);
}

#[test]
fn output_limit_must_be_the_error_on_a_failed_codex_turn() {
    use crate::wake::codex::babysit::terminal_failure;

    let message = "Incomplete response returned, reason: max_output_tokens";
    let mut turn = json!({"status":"failed","error":{"codexErrorInfo":"other","message":message}});
    assert_eq!(
        terminal_failure(&turn),
        Some(gent_protocol::notifications::Failure::Capacity)
    );
    for status in ["completed", "interrupted", "inProgress"] {
        turn["status"] = json!(status);
        assert_eq!(terminal_failure(&turn), None);
    }
    turn = json!({"status":"failed","error":{"codexErrorInfo":"other","message":"unrelated"},
        "items":[{"type":"agentMessage","text":message}]});
    assert_eq!(terminal_failure(&turn), None);
}

mod native;
mod ordinary;
mod rollout;
mod scheduler;

mod consecutive;
mod failed_wake;
mod queued;
