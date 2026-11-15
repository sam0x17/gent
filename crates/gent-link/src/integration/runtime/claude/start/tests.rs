use super::super::test_support::Fixture;
use super::test_support::Running;
use super::*;

#[tokio::test]
async fn startup_checks_local_binding_and_uses_only_exact_native_attach_with_literal_profile() {
    let fixture = Running::new().await;
    fixture.inventory(fixture.row(Some(23)), "reply");
    let live = fixture.start().await.unwrap();
    assert_eq!(live["action"], "already_running");
    assert_eq!(live["agent"], fixture.agent);
    assert!(fixture.calls().is_empty());
    fixture.inventory(fixture.row(None), "reply");
    let result = fixture.start().await.unwrap();
    assert_eq!(result["action"], "attached");
    assert_eq!(result["gent_binding_checked"], true);
    assert_eq!(result["native_attach_attempts"], 1);
    assert_eq!(result["session"]["session_id"], fixture.session);
    assert!(!result.to_string().contains("PRIVATE_"));
    assert_eq!(
        fixture.calls().lines().collect::<Vec<_>>(),
        [
            "attach",
            &fixture.session[..8],
            fixture.fixture.directory.to_str().unwrap(),
            fixture.fixture.directory.to_str().unwrap()
        ]
    );
}

#[tokio::test]
async fn missing_session_wake_or_binding_never_queries_or_starts_a_native_host() {
    for mode in [
        "missing_session",
        "invalid_session",
        "polling",
        "missing_binding",
    ] {
        let fixture = Fixture::new();
        fixture.install(mode != "polling");
        let session = if mode == "missing_session" {
            None
        } else if mode == "invalid_session" {
            Some("../foreign".into())
        } else {
            Some(uuid::Uuid::new_v4().to_string())
        };
        assert!(
            run(
                &fixture.home,
                Args {
                    host: Host::ClaudeCode,
                    session_id: session,
                    config_dir: Some(fixture.directory.clone()),
                    host_binary: Some(fixture.binary.clone())
                }
            )
            .await
            .is_err()
        );
        assert!(!PathBuf::from(format!("{}.args", fixture.binary.display())).exists());
    }
}

#[tokio::test]
async fn ambiguous_absent_interactive_and_mismatched_native_targets_never_attach() {
    let fixture = Running::new().await;
    for (field, value) in [
        ("sessionId", json!(uuid::Uuid::new_v4().to_string())),
        ("kind", json!("interactive")),
        ("id", json!("someone-else")),
        ("id", Value::Null),
    ] {
        let mut row = fixture.row(None);
        row[field] = value;
        fixture.inventory(row, "reply");
        assert!(fixture.start().await.is_err());
        assert!(fixture.calls().is_empty());
    }
}

#[tokio::test]
async fn native_success_without_a_reported_worker_cannot_claim_startup_succeeded() {
    let fixture = Running::new().await;
    fixture.inventory(fixture.row(None), "after");
    let error = fixture.start().await.unwrap_err();
    assert!(error.to_string().contains("did not report"));
    assert_eq!(
        fixture
            .calls()
            .lines()
            .filter(|line| *line == "attach")
            .count(),
        3
    );
}

#[tokio::test]
async fn changed_session_or_installation_after_attachment_refuses_success_without_retry() {
    for mode in ["cwd", "session", "disabled"] {
        let fixture = Running::new().await;
        if mode == "disabled" {
            fixture.fixture.script("if [ \"$1\" = agents ]; then cat \"$0.reply\"; else\nprintf 'attach\\n' >> \"$0.calls\"\nprintf '{\"disableAllHooks\":true}' > \"$CLAUDE_CONFIG_DIR/settings.json\"\nfi\n");
        } else {
            let mut row = fixture.row(Some(23));
            row[if mode == "cwd" { "cwd" } else { "sessionId" }] = if mode == "cwd" {
                json!("/foreign")
            } else {
                json!(uuid::Uuid::new_v4().to_string())
            };
            fixture.inventory(row, "after");
        }
        assert!(fixture.start().await.is_err());
        assert_eq!(
            fixture
                .calls()
                .lines()
                .filter(|line| *line == "attach")
                .count(),
            1
        );
    }
}
