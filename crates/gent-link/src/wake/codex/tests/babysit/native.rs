//! Opt-in contract test for the installed Codex executable, with an isolated
//! host, Gent node and loopback Responses provider.
use super::*;
use axum::{Json, Router, http::StatusCode, routing::post};
use std::{
    net::SocketAddr,
    process::Stdio,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{
    net::TcpListener,
    process::{Child, Command},
    time::sleep,
};

async fn last(host: &mut Host, thread: &str) -> Result<Value> {
    let page = host
        .rpc(
            "thread/turns/list",
            json!({"threadId":thread,"limit":1,"sortDirection":"desc","itemsView":"notLoaded"}),
        )
        .await?;
    Ok(page["data"][0].clone())
}

async fn start_host(root: &Path, endpoint: SocketAddr) -> Result<(Child, PathBuf)> {
    let profile = root.join("codex");
    let work = root.join("work");
    let os_home = root.join("os-home");
    for dir in [&profile, &work, &os_home] {
        config::private_dir(dir)?;
    }
    config::write_private(
        &profile.join("config.toml"),
        format!(
            r#"
model = "synthetic"
model_provider = "fixture"
check_for_update_on_startup = false
approval_policy = "never"
sandbox_mode = "read-only"
web_search = "disabled"
[analytics]
enabled = false
[features]
goals = true
apps = false
shell_tool = false
multi_agent = false
[model_providers.fixture]
name = "Gent fixture"
base_url = "http://{endpoint}/v1"
wire_api = "responses"
requires_openai_auth = false
request_max_retries = 0
stream_max_retries = 0
"#
        )
        .as_bytes(),
    )?;
    let socket = profile.join("host.sock");
    let mut child = Command::new("codex")
        .current_dir(&work)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").context("missing PATH")?)
        .env("HOME", os_home)
        .env("CODEX_HOME", &profile)
        .env("TMPDIR", root)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .args(["app-server", "--listen"])
        .arg(format!("unix://{}", socket.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !socket.exists() {
            ensure!(
                child.try_wait()?.is_none(),
                "Codex app-server exited during startup"
            );
            sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok((child, socket))
}

#[tokio::test]
#[ignore = "requires an installed Codex app-server with native goals"]
async fn installed_codex_resumes_a_usage_limited_and_an_already_active_goal() -> Result<()> {
    let node = Node::start().await?;
    let root = node.root.path();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let endpoint = listener.local_addr()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let received = calls.clone();
    let model = Router::new().route("/v1/responses",post(move || {
        let index = received.fetch_add(1,Ordering::SeqCst);
        async move {
            if index != 0 { std::future::pending::<()>().await; }
            (StatusCode::TOO_MANY_REQUESTS,Json(json!({"error":{"type":"usage_limit_reached","message":"Synthetic quota","plan_type":"plus","resets_at":gent_daemon::store::now()+60}})))
        }
    }));
    let (mut child, socket) = start_host(root, endpoint).await?;
    let work = root.join("work");
    let trial = async {
        let mut host = Host::connect(&socket).await?;
        let thread = host.rpc("thread/start", json!({"cwd":work})).await?["thread"]["id"]
            .as_str()
            .context("missing thread")?
            .to_owned();
        let (_bindings, registry, registered) = node.register(&socket, &thread).await?;
        let params = json!({"threadId":thread});
        host.rpc("thread/goal/set",json!({"threadId":thread,"objective":"Count one synthetic fixture.","status":"active","origin":"user"})).await?;
        loop {
            if host.rpc("thread/goal/get", params.clone()).await?["goal"]["status"]
                == "usageLimited"
                && last(&mut host, &thread).await?["status"] == "failed"
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        sweep(&node.home, &registry, &mut None, Sweep::WakeAndGoals).await?;
        while calls.load(Ordering::SeqCst) < 2 {
            sleep(Duration::from_millis(20)).await;
        }
        let first = last(&mut host, &thread).await?;
        assert_eq!(first["status"], "inProgress");
        assert_eq!(node.notices(&registered).await?, 1);
        // An interrupt creates an idle, still-active goal without editing the
        // host database. The adapter must honor that human stop.
        host.rpc(
            "turn/interrupt",
            json!({"threadId":thread,"turnId":first["id"]}),
        )
        .await?;
        while host
            .rpc(
                "thread/read",
                json!({"threadId":thread,"includeTurns":false}),
            )
            .await?["thread"]["status"]["type"]
            != "idle"
        {
            sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(last(&mut host, &thread).await?["status"], "interrupted");
        sweep(&node.home, &registry, &mut None, Sweep::WakeAndGoals).await?;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            host.rpc("thread/goal/get", params).await?["goal"]["status"],
            "active"
        );

        let resume = json!({"threadId":thread,"status":"active","origin":"automatic"});
        host.rpc("thread/goal/set", resume.clone()).await?;
        while calls.load(Ordering::SeqCst) < 3 {
            sleep(Duration::from_millis(20)).await;
        }
        let second = last(&mut host, &thread).await?;
        assert_ne!(first["id"], second["id"]);
        host.rpc("thread/goal/set", resume).await?;
        sleep(Duration::from_millis(500)).await;
        assert_eq!(last(&mut host, &thread).await?["id"], second["id"]);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        Ok(())
    };
    let result = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(30),trial) => result?,
        result = axum::serve(listener,model) => {result?; anyhow::bail!("fixture provider stopped")}
    };
    child.kill().await?;
    result
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

async fn next_block(observer: &mut Host, thread: &str) -> Result<Value> {
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
    anyhow::bail!("fixture host closed before blocked goal update")
}

mod blocked;
mod consecutive;
mod queue;

mod ordinary;
mod output_limit;
