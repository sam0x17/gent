use super::test_support::Running;
use super::*;
use crate::integration::recovery::{self as scheduler, Command};
use gent_daemon::config::RecoveryAgent;
use gent_protocol::{Effect, OwnerOp, Permission, Policy, Rule, Selector};
use std::{fs, os::unix::fs::PermissionsExt};

async fn enable(f: &Running) -> RecoveryAgent {
    let value = scheduler::execute(
        &f.fixture.home,
        Command::Enable {
            host: Host::ClaudeCode,
            thread_id: f.session.clone(),
            config_dir: Some(f.fixture.directory.clone()),
            host_binary: Some(f.fixture.binary.clone()),
        },
    )
    .await
    .unwrap();
    assert_eq!(value["agent"], f.agent);
    serde_json::from_value(value["selection"].clone()).unwrap()
}

async fn send(f: &Running) {
    let sender = config::secret();
    gent_daemon::request(
        &f.fixture.home,
        Request::Agent {
            credential: sender.clone(),
            action: AgentOp::Register {
                name: "sender".into(),
                provider: "fixture".into(),
            },
        },
    )
    .await
    .unwrap();
    crate::owner(
        &f.fixture.home,
        OwnerOp::SetPolicy {
            policy: Policy {
                rules: [Permission::Enumerate, Permission::Send, Permission::Receive]
                    .into_iter()
                    .map(|permission| Rule {
                        actor: Selector::All,
                        peer: Selector::All,
                        permission,
                        effect: Effect::Allow,
                    })
                    .collect(),
                ..Default::default()
            },
        },
    )
    .await
    .unwrap();
    gent_daemon::request(
        &f.fixture.home,
        Request::Agent {
            credential: sender,
            action: AgentOp::Send {
                recipient: f.agent.clone(),
                request_id: uuid::Uuid::now_v7().to_string(),
                text: "PRIVATE_PENDING".into(),
                files: vec![],
                file_ids: vec![],
            },
        },
    )
    .await
    .unwrap();
}

fn history(f: &Running) -> PathBuf {
    let assistant = uuid::Uuid::new_v4().to_string();
    let path = f
        .fixture
        .directory
        .join("projects/work")
        .join(format!("{}.jsonl", f.session));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    config::write_private(&path, format!("{}\n{}\n",
        json!({"type":"assistant","sessionId":f.session,"cwd":f.fixture.directory,"uuid":assistant,
            "message":{"role":"assistant","stop_reason":"end_turn"}}),
        json!({"type":"system","subtype":"turn_duration","parentUuid":assistant})).as_bytes()).unwrap();
    let job = f
        .fixture
        .directory
        .join("jobs")
        .join(&f.session[..8])
        .join("state.json");
    fs::create_dir_all(job.parent().unwrap()).unwrap();
    fs::set_permissions(job.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    config::write_private(&job, json!({"sessionId":f.session,"cwd":f.fixture.directory,
        "linkScanPath":path,"inFlight":{"tasks":0,"queued":0,"drainableMonitors":0,"kinds":[]},"children":null
    }).to_string().as_bytes()).unwrap();
    path
}

#[tokio::test]
async fn selection_pending_work_and_durable_budget_gate_automatic_attachment() {
    let f = Running::new().await;
    let home = &f.fixture.home;
    f.inventory(f.row(Some(23)), "reply");
    let selected = enable(&f).await;
    assert_eq!(enable(&f).await, selected);
    f.inventory(f.row(None), "reply");
    f.fixture
        .script("printf 'unexpected host query\\n' >> \"$0.calls\"\nexit 1\n");
    assert_eq!(
        scheduler::recover(home, &f.agent, &selected).await.unwrap(),
        "waiting"
    );
    assert!(f.calls().is_empty());
    f.fixture.script("if [ \"$1\" = agents ]; then cat \"$0.reply\"; else\nprintf 'attach\\n' >> \"$0.calls\"\ncp \"$0.after\" \"$0.reply\"\nfi\n");
    send(&f).await;
    assert_eq!(
        scheduler::recover(home, &f.agent, &selected).await.unwrap(),
        "needs_owner"
    );
    assert!(f.calls().is_empty());
    let path = history(&f);
    assert_eq!(
        scheduler::recover(home, &f.agent, &selected).await.unwrap(),
        "resumed"
    );
    assert_eq!(f.calls(), "attach\n");
    f.inventory(f.row(None), "reply");
    assert_eq!(
        scheduler::recover(home, &f.agent, &selected).await.unwrap(),
        "limited"
    );
    assert_eq!(f.calls(), "attach\n");
    fs::write(path, "PRIVATE_INVALID_HISTORY").unwrap();
    let review = scheduler::execute(
        home,
        Command::Inspect {
            agent: f.agent.clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(review["inspection"]["readiness"], "needs_owner");
    assert!(!review.to_string().contains("PRIVATE_"));
    scheduler::execute(
        home,
        Command::Disable {
            agent: f.agent.clone(),
        },
    )
    .await
    .unwrap();
    assert!(scheduler::recover(home, &f.agent, &selected).await.is_err());
    assert_eq!(f.calls(), "attach\n");
}

#[tokio::test]
async fn changed_binding_cwd_or_installation_refuses_automatic_attachment() {
    let f = Running::new().await;
    f.inventory(f.row(Some(23)), "reply");
    let selected = enable(&f).await;
    send(&f).await;
    history(&f);
    f.inventory(f.row(None), "reply");
    for case in ["cwd", "credential"] {
        let mut entry = selected.clone();
        if case == "cwd" {
            entry.working_dir = Some("/foreign".into());
        } else {
            entry.credential_hash = "0".repeat(64);
        }
        assert!(
            recovery::check(&f.fixture.home, &f.agent, &entry)
                .await
                .is_err()
        );
        assert!(
            recovery::restore(&f.fixture.home, &f.agent, &entry)
                .await
                .is_err()
        );
        assert!(f.calls().is_empty());
    }
    f.fixture.uninstall();
    assert!(
        scheduler::recover(&f.fixture.home, &f.agent, &selected)
            .await
            .is_err()
    );
    assert!(f.calls().is_empty());
}
