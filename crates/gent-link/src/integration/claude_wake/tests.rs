use super::*;
use crate::integration::{Bindings, now, record_hook};
use gent_protocol::{Effect, OwnerOp, Permission, Policy, Rule, Selector};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

fn home() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    config::initialize(dir.path(), "claude-wake-test").unwrap();
    dir
}
fn bind(home: &Path, bindings: &mut Bindings, session: &str, child: Option<&str>) -> String {
    let tool = uuid::Uuid::new_v4().to_string();
    let mut event = json!({"hook_event_name":"PreToolUse", "session_id":session,
        "tool_use_id":tool, "tool_name":"mcp__gent__gent_register", "tool_input":{}});
    if let Some(child) = child {
        event["agent_id"] = child.into();
    }
    record_hook(home, &event, now().unwrap()).unwrap();
    bindings
        .credential(
            "claude-code",
            &json!({"claudecode/toolUseId":tool}),
            "gent_register",
            &json!({}),
        )
        .unwrap()
}
fn path(home: &Path, cfg: &config::Config, session: &str) -> PathBuf {
    scope_path(home, cfg, Host::ClaudeCode).join(format!("{}.key", session_key(session, None)))
}

#[tokio::test]
async fn retained_guard_passes_human_input_without_state_but_rejects_broken_notifications() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("missing-home");
    let directory = root.path().join("missing-host");
    let mut event = json!({"hook_event_name":"UserPromptSubmit", "prompt":"Please continue."});
    assert_eq!(
        guard_event(&home, &directory, &event).await.unwrap(),
        json!({"continue":true})
    );
    event["prompt"] = format!("{PROMPT}\nGent dispatch: legacy-attempt").into();
    assert!(guard_event(&home, &directory, &event).await.is_err());
    event["prompt"] = notification(
        &uuid::Uuid::new_v4().to_string(),
        &uuid::Uuid::now_v7().to_string(),
        &uuid::Uuid::new_v4().to_string(),
    )
    .into();
    event["session_id"] = uuid::Uuid::new_v4().to_string().into();
    assert!(guard_event(&home, &directory, &event).await.is_err());
    assert!(!home.exists() && !directory.exists());
}

#[test]
fn read_only_bridge_keeps_live_credentials_and_parent_child_sessions_separate() {
    let home = home();
    let cfg = config::load(home.path()).unwrap();
    let session = uuid::Uuid::new_v4().to_string();
    let other = uuid::Uuid::new_v4().to_string();
    let folder = scope_path(home.path(), &cfg, Host::ClaudeCode);
    assert!(credential(home.path(), &cfg, &session).unwrap().is_none());
    assert!(
        !folder.exists(),
        "unknown sessions must not create host state"
    );
    let mut bindings = Bindings::new(home.path(), Host::ClaudeCode).unwrap();
    let child = bind(home.path(), &mut bindings, &session, Some("child"));
    assert!(credential(home.path(), &cfg, &session).unwrap().is_none());
    let parent = bind(home.path(), &mut bindings, &session, None);
    let second = bind(home.path(), &mut bindings, &other, None);
    assert_ne!(child, parent);
    assert_ne!(parent, second);
    assert_eq!(
        credential(home.path(), &cfg, &session).unwrap(),
        Some(parent.clone())
    );
    assert_eq!(credential(home.path(), &cfg, &other).unwrap(), Some(second));
    // A second MCP still cannot own the binding. The bridge took no live lock.
    assert!(binding::open(&path(home.path(), &cfg, &session), &cfg, true).is_err());
    drop(bindings);
    assert_eq!(
        credential(home.path(), &cfg, &session).unwrap(),
        Some(parent)
    );
    assert!(credential(home.path(), &cfg, "../wrong").is_err());
}

#[test]
fn bridge_refuses_missing_scope_linked_or_replaced_keys_and_offline_state() {
    let home = home();
    let cfg = config::load(home.path()).unwrap();
    let session = uuid::Uuid::new_v4().to_string();
    let mut bindings = Bindings::new(home.path(), Host::ClaudeCode).unwrap();
    let original = bind(home.path(), &mut bindings, &session, None);
    drop(bindings);
    let key = path(home.path(), &cfg, &session);
    let scope = binding::sidecar(&key, ".scope.json");
    let saved = fs::read(&scope).unwrap();
    fs::remove_file(&scope).unwrap();
    assert!(credential(home.path(), &cfg, &session).is_err());
    assert!(!scope.exists());
    config::write_private(&scope, &saved).unwrap();
    config::write_private(&key, config::secret().as_bytes()).unwrap();
    assert!(credential(home.path(), &cfg, &session).is_err());
    config::write_private(&key, original.as_bytes()).unwrap();
    let alias = key.with_extension("alias");
    fs::hard_link(&key, &alias).unwrap();
    assert!(credential(home.path(), &cfg, &session).is_err());
    fs::remove_file(&alias).unwrap();
    fs::rename(&key, &alias).unwrap();
    std::os::unix::fs::symlink(&alias, &key).unwrap();
    assert!(credential(home.path(), &cfg, &session).is_err());
    fs::remove_file(&key).unwrap();
    fs::rename(&alias, &key).unwrap();
    let marker = home.path().join(gent_daemon::recovery::MARKER);
    config::write_private(&marker, b"offline").unwrap();
    assert!(credential(home.path(), &cfg, &session).is_err());
    fs::remove_file(marker).unwrap();
    config::write_private(&binding::sidecar(&key, ".recovery.json"), b"{}").unwrap();
    assert!(credential(home.path(), &cfg, &session).is_err());
}

struct Daemon(tokio::task::JoinHandle<Result<()>>);
impl Drop for Daemon {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn bridge_claims_once_checks_scope_and_records_only_the_supplied_native_turn() {
    let home = home();
    let directory = home.path().join("claude");
    let result = install::change(
        home.path(),
        install::Args {
            host: Host::ClaudeCode,
            config_dir: Some(directory.clone()),
            wake: true,
            wake_socket: None,
            vscode: false,
            vscode_settings: None,
        },
        true,
    )
    .unwrap();
    let generation = result["claude_wake"].as_str().unwrap().to_owned();
    let session = uuid::Uuid::new_v4().to_string();
    let mut bindings = Bindings::new(home.path(), Host::ClaudeCode).unwrap();
    let key = bind(home.path(), &mut bindings, &session, None);
    let node = home.path().to_path_buf();
    let daemon = Daemon(tokio::spawn(async move { gent_daemon::run(&node).await }));
    for _ in 0..200 {
        if home.path().join("daemon.sock").exists() {
            break;
        }
        assert!(!daemon.0.is_finished());
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let input = |operation| Input {
        installation_id: generation.clone(),
        session_id: session.clone(),
        operation,
    };
    let sender = config::secret();
    rpc(
        home.path(),
        &sender,
        AgentOp::Register {
            name: "sender".into(),
            provider: "fixture".into(),
        },
    )
    .await
    .unwrap();
    let agent = rpc(
        home.path(),
        &key,
        AgentOp::Register {
            name: "recipient".into(),
            provider: "claude-code".into(),
        },
    )
    .await
    .unwrap();
    let policy = Policy {
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
    };
    crate::owner(
        home.path(),
        OwnerOp::SetPolicy {
            policy: policy.clone(),
        },
    )
    .await
    .unwrap();
    let message = rpc(
        home.path(),
        &sender,
        AgentOp::Send {
            recipient: agent["agent"]["id"].as_str().unwrap().into(),
            request_id: uuid::Uuid::now_v7().to_string(),
            text: "PRIVATE-BRIDGE-CONTENT".into(),
            files: vec![],
            file_ids: vec![],
        },
    )
    .await
    .unwrap();
    let answer = run(home.path(), &directory, input(Operation::Claim))
        .await
        .unwrap();
    assert!(!answer.to_string().contains("PRIVATE-BRIDGE-CONTENT"));
    assert!(!answer.to_string().contains(&key));
    assert_eq!(answer["dispatch"]["message_id"], message["message_id"]);
    let dispatch = &answer["dispatch"];
    let guard = json!({"hook_event_name":"UserPromptSubmit", "session_id":session,
        "prompt":dispatch["text"]});
    assert_eq!(
        guard_event(home.path(), &directory, &guard).await.unwrap(),
        json!({"continue":true})
    );
    for field in ["session_id", "installation_id", "message_id", "attempt_id"] {
        let mut changed = guard.clone();
        let replacement = uuid::Uuid::new_v4().to_string();
        if field == "session_id" {
            changed[field] = replacement.into();
        } else {
            let original = if field == "installation_id" {
                &generation
            } else {
                dispatch[field].as_str().unwrap()
            };
            changed["prompt"] = guard["prompt"]
                .as_str()
                .unwrap()
                .replace(original, &replacement)
                .into();
        }
        assert!(
            guard_event(home.path(), &directory, &changed)
                .await
                .is_err(),
            "accepted changed {field}"
        );
    }
    crate::owner(
        home.path(),
        OwnerOp::SetPolicy {
            policy: Policy::default(),
        },
    )
    .await
    .unwrap();
    assert!(guard_event(home.path(), &directory, &guard).await.is_err());
    crate::owner(home.path(), OwnerOp::SetPolicy { policy })
        .await
        .unwrap();
    assert!(guard_event(home.path(), &directory, &guard).await.is_ok());
    let check = || Operation::Check {
        message_id: dispatch["message_id"].as_str().unwrap().into(),
        attempt_id: dispatch["attempt_id"].as_str().unwrap().into(),
    };
    assert_eq!(
        run(home.path(), &directory, input(Operation::Claim))
            .await
            .unwrap()["dispatch"],
        Value::Null
    );
    assert_eq!(
        run(home.path(), &directory, input(check())).await.unwrap()["eligible"],
        true
    );
    let stale = Input {
        installation_id: uuid::Uuid::new_v4().to_string(),
        ..input(check())
    };
    assert!(run(home.path(), &directory, stale).await.is_err());
    let wrong = Input {
        session_id: uuid::Uuid::new_v4().to_string(),
        ..input(check())
    };
    assert!(run(home.path(), &directory, wrong).await.is_err());
    let turn_id = uuid::Uuid::new_v4().to_string();
    let report = || Operation::Submitted {
        message_id: dispatch["message_id"].as_str().unwrap().into(),
        attempt_id: dispatch["attempt_id"].as_str().unwrap().into(),
        turn_id: turn_id.clone(),
    };
    assert_eq!(
        run(home.path(), &directory, input(report())).await.unwrap()["recorded"],
        true
    );
    assert_eq!(
        run(home.path(), &directory, input(report())).await.unwrap()["recorded"],
        true
    );
    assert_eq!(
        run(home.path(), &directory, input(check())).await.unwrap()["eligible"],
        false
    );
    assert!(guard_event(home.path(), &directory, &guard).await.is_err());
    let saved = crate::owner(
        home.path(),
        OwnerOp::WakeShow {
            message_id: message["message_id"].as_str().unwrap().into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(saved["submission_id"], turn_id);
    assert_eq!(
        saved["target"],
        json!({"host":"claude_code","session_id":session})
    );
    install::change(
        home.path(),
        install::Args {
            host: Host::ClaudeCode,
            config_dir: Some(directory.clone()),
            wake: false,
            wake_socket: None,
            vscode: false,
            vscode_settings: None,
        },
        false,
    )
    .unwrap();
    assert!(run(home.path(), &directory, input(report())).await.is_err());
    assert!(guard_event(home.path(), &directory, &guard).await.is_err());
    assert!(
        !directory
            .join("skills/gent-wake/hooks/register.ts")
            .exists()
    );
}
