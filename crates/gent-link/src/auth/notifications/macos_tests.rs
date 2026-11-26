use super::*;
use crate::desktop::notification_delivery::channel;
use axum::{Json, Router, http::HeaderMap, routing::get};
use std::fs;

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
    let session = source::directory(&home).unwrap().join("session.json");
    save(&session, Some(&login)).unwrap();
    let notice = Notice {
        id: uuid::Uuid::new_v4(),
        created_at: now().unwrap() as i64,
        event: Event::UpdateInstalled {
            node: uuid::Uuid::new_v4(),
            commit: "a".repeat(40),
        },
    };
    let notice_id = notice.id;
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
    let (cursor, _) = cursor_paths(&home, &login).unwrap();
    Snapshot::read(&cursor).unwrap().write("41").unwrap();
    let (gui, mut deliveries) = channel();
    let (_, disconnected) = tokio::join!(
        async {
            let message = deliveries.next().await;
            assert_eq!(message["notification"]["id"], notice_id.to_string());
            drop(deliveries); // App quit between submission and acknowledgment.
        },
        collect(&home, &login, &gui)
    );
    assert!(disconnected.is_err());
    assert_eq!(fs::read_to_string(&cursor).unwrap(), "41");

    let (gui, mut deliveries) = channel();
    let mut previous = uuid::Uuid::nil().to_string();
    for accepted in [false, true] {
        let (_, collected) = tokio::join!(
            async {
                let message = deliveries.next().await;
                let banner = &message["notification"];
                assert_eq!(banner["id"], notice_id.to_string());
                assert_eq!(banner["title"], "Gent updated");
                let attempt = banner["attempt"].as_str().unwrap();
                assert_ne!(attempt, previous);
                assert!(!deliveries.receive("refresh"));
                let reply = |attempt: &str, accepted| {
                    json!({"op":"notification_result","attempt":attempt,"accepted":accepted})
                        .to_string()
                };
                assert!(deliveries.receive(&reply(&previous, !accepted)));
                assert!(deliveries.receive(&reply(attempt, accepted)));
                previous = attempt.to_owned();
            },
            collect(&home, &login, &gui)
        );
        assert_eq!(collected.is_ok(), accepted);
        assert_eq!(
            fs::read_to_string(&cursor).unwrap(),
            if accepted { "42" } else { "41" }
        );
        if !accepted {
            save(&session, None).unwrap();
            collect(&home, &login, &gui).await.unwrap();
            assert_eq!(fs::read_to_string(&cursor).unwrap(), "41");
            save(&session, Some(&login)).unwrap();
        }
    }
    drop(deliveries);
    collect(&home, &login, &gui).await.unwrap(); // Reconnect at 42 requires no GUI delivery.
    server.abort();
}
