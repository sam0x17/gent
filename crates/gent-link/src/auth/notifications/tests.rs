use super::*;
use axum::{Json, Router, http::HeaderMap, routing::get};
use std::{fs, os::unix::fs::PermissionsExt, process::Command, sync::Arc};
use tokio::net::TcpListener;

#[tokio::test]
async fn device_cursor_survives_reconnect_and_skips_future_event_kinds() {
    const TEST: &str =
        "auth::notifications::tests::device_cursor_survives_reconnect_and_skips_future_event_kinds";
    const FIXTURE: &str = "GENT_TEST_PRIVATE_NOTIFICATION_FIXTURE";
    let Some(root) = std::env::var_os(FIXTURE) else {
        let scratch = tempfile::tempdir().unwrap();
        let sender = scratch.path().join("notify-send");
        fs::write(&sender, "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$GENT_TEST_PRIVATE_NOTIFICATION_FIXTURE/banners\"\n").unwrap();
        fs::set_permissions(sender, fs::Permissions::from_mode(0o700)).unwrap();
        // The child has a private PATH. No banner can reach the user's desktop.
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST])
            .env(FIXTURE, scratch.path())
            .env("PATH", scratch.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        return;
    };
    let root = Path::new(&root);
    let home = root.join("node");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let login = Saved {
        version: 1,
        phase: Phase::Active,
        service: url,
        token: credential("gent_s1").unwrap(),
        session: Some(ServiceSession {
            account_id: "fixture".into(),
            github_subject: "1".into(),
            github_login: "fixture".into(),
            created_at: now().unwrap(),
            expires_at: now().unwrap() + 7200,
        }),
    };
    let session = source::directory(&home).unwrap().join("session.json");
    save(&session, Some(&login)).unwrap();
    let token = Arc::new(format!("Bearer {}", login.token));
    let app = Router::new().route("/v1/notifications",get(move |headers:HeaderMap| {
        let token = token.clone();
        async move {
            assert_eq!(headers["authorization"].to_str().unwrap(), token.as_str());
            let rows = match headers["x-gent-after"].to_str().unwrap() {
                "0" => json!([{"sequence":1,"notice":{"event":{"kind":"future_event"}}},
                    {"sequence":2,"notice":{"event":{"kind":"goal_resumed","reason":"future_reason"}}},
                    {"sequence":3,"notice":{"id":uuid::Uuid::new_v4(),"created_at":now().unwrap(),
                    "event":{"kind":"update_installed","node":uuid::Uuid::new_v4(),"commit":"a".repeat(40)}}}]),
                "3" => json!([]),
                cursor => panic!("unexpected cursor {cursor}"),
            };
            Json(rows)
        }
    }));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    collect(&home, &login).await.unwrap();
    collect(&home, &login).await.unwrap();
    let cursor = cursor_path(&home, &login).unwrap();
    assert_eq!(fs::read_to_string(&cursor).unwrap(), "3");
    let banners = root.join("banners");
    let first = fs::read_to_string(&banners).unwrap();
    assert_eq!(first.lines().filter(|l| *l == "Gent updated").count(), 1);
    assert!(first.contains(" updated to aaaaaaaaaaaa."));
    save(&session, None).unwrap();
    fs::remove_file(&cursor).unwrap();
    collect(&home, &login).await.unwrap();
    assert!(!cursor.exists());
    assert_eq!(fs::read_to_string(banners).unwrap(), first);
    server.abort();
}
