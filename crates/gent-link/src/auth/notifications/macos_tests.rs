use super::*;
use crate::desktop::notification_app::FIXTURE_OPEN;
use axum::{Json, Router, http::HeaderMap, routing::get};
use std::{fs, os::unix::fs::PermissionsExt};

#[tokio::test]
async fn macos_notification_cursor_requires_native_acceptance() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("node");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let login = Saved {
        version: 1,
        phase: Phase::Active,
        service: format!("http://{}/", listener.local_addr().unwrap()),
        token: credential("gent_s1").unwrap(),
        session: Some(ServiceSession {
            account_id: "fixture".into(),
            github_subject: "1".into(),
            github_login: "fixture".into(),
            created_at: now().unwrap(),
            expires_at: now().unwrap() + 3600,
        }),
    };
    save(
        &source::directory(&home).unwrap().join("session.json"),
        Some(&login),
    )
    .unwrap();
    let notice = Notice {
        id: uuid::Uuid::new_v4(),
        created_at: now().unwrap() as i64,
        event: Event::UpdateInstalled {
            node: uuid::Uuid::new_v4(),
            commit: "a".repeat(40),
        },
    };
    let api = Router::new().route(
        "/v1/notifications",
        get(move |headers: HeaderMap| {
            let rows = match headers["x-gent-after"].to_str().unwrap() {
                "41" => json!([{"sequence":42, "notice":notice}]),
                "42" => json!([]),
                cursor => panic!("unexpected cursor {cursor}"),
            };
            async { Json(rows) }
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, api).await.unwrap() });
    let cursor = cursor_path(&home, &login).unwrap();
    Snapshot::read(&cursor).unwrap().write("41").unwrap();
    let open = temp.path().join("open");
    let icon = home.join("desktop-icon.png");
    FIXTURE_OPEN
        .scope(open.clone(), async {
            fs::write(&open, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&open, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(collect(&home, &login, &icon).await.is_err());
            assert_eq!(fs::read_to_string(&cursor).unwrap(), "41");

            fs::write(
                &open,
                "#!/bin/sh\n/usr/bin/plutil -extract id raw -n \"$5\" > \"$7\"\n",
            )
            .unwrap();
            collect(&home, &login, &icon).await.unwrap();
            assert_eq!(fs::read_to_string(&cursor).unwrap(), "42");
            fs::remove_file(&open).unwrap();
            collect(&home, &login, &icon).await.unwrap();
        })
        .await;
    server.abort();
}
