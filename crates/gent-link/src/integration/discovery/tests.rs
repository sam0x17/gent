use super::*;
use gent_protocol::OwnerOp;

struct Daemon(tokio::task::JoinHandle<anyhow::Result<()>>);
impl Drop for Daemon {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn fixture() -> (tempfile::TempDir, PathBuf, config::Config, Daemon) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("node");
    let cfg = config::initialize(&home, "discovery").unwrap();
    let path = home.clone();
    let daemon = Daemon(tokio::spawn(async move { gent_daemon::run(&path).await }));
    for _ in 0..200 {
        if home.join("daemon.sock").exists() {
            return (temp, home, cfg, daemon);
        }
        assert!(!daemon.0.is_finished());
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("test daemon did not start")
}

#[tokio::test]
async fn repeated_enable_and_refresh_during_scan_preserve_saved_results() {
    let (_temp, home, cfg, _daemon) = fixture().await;
    configure(&home, true).unwrap();
    assert_eq!(status(&home).unwrap()["scan"], "pending");
    let (saved, mut catalog) = storage::read(&home, &cfg).unwrap();
    catalog.checked = Some(super::super::now().unwrap());
    catalog.hosts.insert("codex".into(), json!({"status":"scanning","count":32,"next_page":{"archived":false,"cursor":"second-page"}}));
    storage::save(&saved, &catalog).unwrap();
    let lock = scan_lock(&home).unwrap().unwrap();
    let recovery = super::super::recovery::discovery_lock(&home).unwrap();
    let enabled = execute(&home, Command::Enable).await.unwrap();
    assert!(enabled["enabled"].as_bool().unwrap());
    assert_eq!(enabled["scan"], "running");
    assert_eq!(
        enabled["hosts"]["codex"]["next_page"]["cursor"],
        "second-page"
    );
    let refreshed = execute(&home, Command::Refresh).await.unwrap();
    assert_eq!(enabled, refreshed);
    drop(recovery);
    drop(lock);
    assert_eq!(status(&home).unwrap()["scan"], "idle");
}

#[tokio::test]
async fn opt_in_registration_preserves_native_bindings_duplicates_and_pending_delivery() {
    let (_temp, home, cfg, _daemon) = fixture().await;
    let socket = home.join("codex.sock");
    let inventory = hosts::Inventory {
        chats: vec![],
        directory: home.clone(),
        socket: Some(socket.clone()),
        binary: "/bin/false".into(),
        truncated: false,
        page: None,
    };
    let one = hosts::Chat {
        last_activity_at: None,
        id: uuid::Uuid::new_v4().to_string(),
        name: Some("cit".into()),
        working_dir: None,
        recoverable: true,
    };
    let two = hosts::Chat {
        last_activity_at: None,
        id: uuid::Uuid::new_v4().to_string(),
        name: Some("cit".into()),
        working_dir: None,
        recoverable: true,
    };
    assert!(
        register(&home, &cfg, Host::Codex, &inventory, &one)
            .await
            .is_err()
    );
    assert!(!home.join("host-bindings").exists());
    configure(&home, true).unwrap();
    let first = register(&home, &cfg, Host::Codex, &inventory, &one)
        .await
        .unwrap();
    let second = register(&home, &cfg, Host::Codex, &inventory, &two)
        .await
        .unwrap();
    assert_ne!(first.agent, second.agent);
    assert_eq!(first.name, second.name);
    let first_key = bindings::credential(&home, &cfg, Host::Codex, &one.id).unwrap();
    let second_key = bindings::credential(&home, &cfg, Host::Codex, &two.id).unwrap();
    let mut native = super::super::Bindings::new(&home, Host::Codex).unwrap();
    native.enable_wake(&home, &socket).unwrap();
    assert_eq!(
        native
            .credential(
                "codex-mcp-client",
                &json!({"threadId":one.id}),
                "gent_identity",
                &json!({})
            )
            .unwrap(),
        first_key
    );
    // A live MCP binding never needs to relinquish its lock for discovery.
    let repeated = register(&home, &cfg, Host::Codex, &inventory, &one)
        .await
        .unwrap();
    assert_eq!(repeated.agent, first.agent);
    let found = agent(&home, &first_key, AgentOp::Agents).await.unwrap();
    assert_eq!(
        found
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["name"] == "cit")
            .count(),
        2
    );
    let sent = agent(
        &home,
        &first_key,
        AgentOp::Send {
            recipient: second.agent.clone(),
            request_id: uuid::Uuid::now_v7().to_string(),
            text: "synthetic request".into(),
            files: vec![],
            file_ids: vec![],
        },
    )
    .await
    .unwrap();
    let pending = crate::owner(&home, OwnerOp::WakePendingAgents { after: None })
        .await
        .unwrap();
    assert_eq!(pending["agents"], json!([second.agent]));
    assert!(!pending.to_string().contains("synthetic request"));
    let inbox = agent(&home, &second_key, AgentOp::Inbox).await.unwrap();
    assert!(inbox.to_string().contains("synthetic request"));
    let pending_agent = agent(&home, &second_key, AgentOp::WakePending)
        .await
        .unwrap();
    assert_eq!(pending_agent["pending"].as_array().unwrap().len(), 1);
    let message_id = pending_agent["pending"][0]["message_id"]
        .as_str()
        .unwrap()
        .to_owned();
    agent(
        &home,
        &second_key,
        AgentOp::WakeDirectClaim {
            message_id,
            attempt_id: uuid::Uuid::new_v4().to_string(),
            target: gent_protocol::wake::WakeTarget::Codex {
                thread_id: two.id.clone(),
            },
        },
    )
    .await
    .unwrap();
    assert_eq!(
        crate::owner(&home, OwnerOp::WakePendingAgents { after: None })
            .await
            .unwrap()["agents"],
        json!([])
    );
    assert!(sent.is_object());
    configure(&home, false).unwrap();
    assert!(
        register(&home, &cfg, Host::Codex, &inventory, &one)
            .await
            .is_err()
    );
    assert!(
        super::super::recovery::recover_discovered(
            &home,
            &first.agent,
            first.recovery.as_ref().unwrap()
        )
        .await
        .is_err()
    );
    assert_eq!(
        bindings::credential(&home, &cfg, Host::Codex, &one.id).unwrap(),
        first_key
    );
}

#[test]
fn discovery_does_not_redirect_a_live_endpoint_or_repin_another_node() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    let cfg = config::initialize(&home, "test").unwrap();
    let thread = uuid::Uuid::new_v4().to_string();
    let key = bindings::credential(&home, &cfg, Host::Codex, &thread).unwrap();
    let first = home.join("one.sock");
    bindings::remember(&home, &cfg, &thread, &key, &first).unwrap();
    assert!(bindings::remember(&home, &cfg, &thread, &key, &home.join("two.sock")).is_err());
    assert_eq!(
        super::super::wake::Registry::codex(&home, &first)
            .unwrap()
            .credential(&thread)
            .unwrap()
            .as_deref(),
        Some(key.as_str())
    );
    let mut wrong = cfg.clone();
    wrong.node.id = uuid::Uuid::new_v4().to_string();
    assert!(bindings::credential(&home, &wrong, Host::Codex, &thread).is_err());
}
