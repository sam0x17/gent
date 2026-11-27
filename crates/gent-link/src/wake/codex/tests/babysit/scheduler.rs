use super::*;
use clap::Parser;
use std::process::Stdio;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
};

const DAEMON_HOME: &str = "GENT_TEST_BABYSITTER_DAEMON_HOME";
const ACTIVATION_TEST: &str =
    "wake::codex::tests::babysit::scheduler::daemon_activation_with_a_live_legacy_coordinator";

pub(super) fn install(node: &Node, directory: &Path, socket: &Path) -> Result<()> {
    let cli = crate::Cli::try_parse_from([
        "gent",
        "integration",
        "install",
        "codex",
        "--no-vscode",
        "--config-dir",
        directory.to_str().unwrap(),
        "--wake-socket",
        socket.to_str().unwrap(),
    ])?;
    let Some(crate::Command::Integration { command }) = cli.command else {
        unreachable!()
    };
    crate::integration::execute(&node.home, command)?;
    Ok(())
}

fn launch(node: &Node) -> Result<Child> {
    // The service, discovery, and host supervisors see only this fixture's user profile.
    Ok(Command::new(std::env::current_exe()?)
        .args(["--exact", ACTIVATION_TEST, "--nocapture"])
        .env_clear()
        .env("HOME", node.root.path())
        .env("PATH", node.root.path())
        .env(DAEMON_HOME, &node.home)
        .stdin(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?)
}

async fn stop(mut daemon: Child) -> Result<()> {
    daemon.stdin.take().unwrap().write_all(b"q").await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(10), daemon.wait())
            .await??
            .success()
    );
    Ok(())
}

fn count(host: &Fixture, method: &str) -> usize {
    host.requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["method"] == method)
        .count()
}

async fn until(mut ready: impl FnMut() -> bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn daemon_activation_with_a_live_legacy_coordinator() -> Result<()> {
    if let Some(home) = std::env::var_os(DAEMON_HOME) {
        let lock = gent_daemon::DaemonLock::acquire(Path::new(&home))?;
        return crate::auth::renewal::run_daemon(lock, async {
            let _ = tokio::io::stdin().read_u8().await;
        })
        .await;
    }
    let mut node = Node::start().await?;
    let thread = Uuid::now_v7().to_string();
    let state = Read::new(&thread);
    let host = host(&thread, state.clone(), state, false);
    install(&node, &node.root.path().join("custom-codex"), &host.path)?;
    let other = node.root.path().join("moved-profile");
    install(&node, &other, &node.root.path().join("other.sock"))?;
    std::fs::rename(&other, node.root.path().join("moved"))?;
    std::os::unix::fs::symlink(node.root.path().join("moved"), other)?;
    let (_bindings, registry, registered) = node.register(&host.path, &thread).await?;

    // Hold the original, wake-only flock in this process through both daemon
    // lifetimes. The synthetic host and its original MCP binding stay live.
    let _old_mcp = registry.coordinator()?.unwrap();
    node.stop.cancel();
    (&mut node.daemon).await??;
    assert!(!config::load(&node.home)?.discovery()?.enabled);
    let first = launch(&node)?;
    until(|| count(&host, "thread/goal/set") == 1).await?;
    // A pre-handoff, goal-capable watcher can still race us. Both versions
    // submit through the same durable claim and notification outbox.
    sweep(&node.home, &registry, &mut None, Sweep::WakeAndGoals).await?;
    assert_eq!(node.notices(&registered).await?, 1);
    assert!(registry.coordinator()?.is_none());
    assert!(registry.daemon_babysitter()?.is_none());
    stop(first).await?;
    assert!(registry.daemon_babysitter()?.is_some());

    let reads = count(&host, "thread/goal/get");
    crate::integration::discovery::configure(&node.home, true)?;
    let restarted = launch(&node)?;
    until(|| count(&host, "thread/goal/get") > reads).await?;
    assert_eq!(node.notices(&registered).await?, 1);
    assert!(registry.coordinator()?.is_none());
    assert!(registry.daemon_babysitter()?.is_none());

    config::write_private(&node.home.join("babysitter-disabled"), b"")?;
    until(|| registry.daemon_babysitter().unwrap().is_some()).await?;
    stop(restarted).await?;
    assert_eq!(count(&host, "thread/goal/set"), 1);
    assert_eq!(count(&host, "turn/start"), 0);
    Ok(())
}

#[tokio::test]
async fn attached_scanners_yield_to_managed_ownership_and_keep_standalone_coverage() -> Result<()> {
    let node = Node::start().await?;
    let thread = Uuid::now_v7().to_string();
    let state = Read::new(&thread);
    let host = host(&thread, state.clone(), state, false);
    let (_bindings, registry, registered) = node.register(&host.path, &thread).await?;
    let old = registry.coordinator()?.unwrap();
    let mut attached = Attached::default();
    let mut second = Attached::default();
    assert_eq!(
        attached.work(&registry, &node.home)?,
        Some(Sweep::GoalsOnly)
    );
    assert_eq!(second.work(&registry, &node.home)?, None);

    let managed = registry.daemon_babysitter()?.unwrap();
    assert_eq!(attached.work(&registry, &node.home)?, None);
    drop(old);
    let wake = attached.work(&registry, &node.home)?.unwrap();
    assert_eq!(wake, Sweep::WakeOnly);
    sweep(&node.home, &registry, &mut None, wake).await?;
    assert_eq!(count(&host, "thread/loaded/list"), 1);
    assert_eq!(count(&host, "thread/read"), 0);
    drop(managed);
    let work = attached.work(&registry, &node.home)?.unwrap();
    assert_eq!(work, Sweep::WakeAndGoals);
    let key = registry.credential(&thread)?.unwrap();
    agent(
        &node.home,
        &key,
        AgentOp::Babysit {
            enabled: Some(false),
        },
    )
    .await?;
    sweep(&node.home, &registry, &mut None, work).await?;
    assert_eq!(count(&host, "thread/goal/set"), 0);
    agent(
        &node.home,
        &key,
        AgentOp::Babysit {
            enabled: Some(true),
        },
    )
    .await?;
    sweep(&node.home, &registry, &mut None, work).await?;
    assert_eq!(node.notices(&registered).await?, 1);
    config::write_private(&node.home.join("babysitter-disabled"), b"")?;
    assert_eq!(attached.work(&registry, &node.home)?, Some(Sweep::WakeOnly));
    assert_eq!(second.work(&registry, &node.home)?, None);
    Ok(())
}

#[tokio::test]
async fn managed_goal_sweep_leaves_pending_inbox_for_the_wake_coordinator() -> Result<()> {
    let node = Node::start().await?;
    let thread = Uuid::now_v7().to_string();
    let target = thread.clone();
    let host = Fixture::respond(move |request| {
        let params = &request["params"];
        if request["method"] == "thread/loaded/list" {
            // A restarted host rejects the previous incarnation's page cursor.
            return params["cursor"]
                .is_null()
                .then(|| json!({"data":[target],"nextCursor":null}));
        }
        assert_eq!(params["threadId"], target);
        Some(match request["method"].as_str().unwrap() {
            "thread/read" => {
                json!({"thread":{"id":target,"status":{"type":"active"},"canAcceptDirectInput":true}})
            }
            "turn/start" => json!({"turn":{"id":Uuid::now_v7()}}),
            method => panic!("unexpected host operation: {method}"),
        })
    });
    let (_bindings, registry, recipient) = node.register(&host.path, &thread).await?;
    let key = registry.credential(&thread)?.unwrap();
    let sender = config::secret();
    agent(
        &node.home,
        &sender,
        AgentOp::Register {
            name: "sender".into(),
            provider: "test".into(),
        },
    )
    .await?;
    agent(
        &node.home,
        &sender,
        AgentOp::Send {
            recipient,
            request_id: Uuid::now_v7().to_string(),
            text: "synthetic inbox".into(),
            files: vec![],
            file_ids: vec![],
        },
    )
    .await?;
    let pending = agent(&node.home, &key, AgentOp::WakePending).await?;
    assert_eq!(pending["pending"].as_array().unwrap().len(), 1);
    let mut cursor = Some("old-host-cursor".into());
    assert!(
        sweep(&node.home, &registry, &mut cursor, Sweep::GoalsOnly)
            .await
            .is_err()
    );
    sweep(&node.home, &registry, &mut cursor, Sweep::GoalsOnly).await?;
    assert_eq!(count(&host, "turn/start"), 0);
    assert_eq!(
        agent(&node.home, &key, AgentOp::WakePending).await?,
        pending
    );
    sweep(&node.home, &registry, &mut cursor, Sweep::WakeOnly).await?;
    assert_eq!(count(&host, "turn/start"), 1);
    assert_eq!(count(&host, "thread/read"), 2);
    Ok(())
}
