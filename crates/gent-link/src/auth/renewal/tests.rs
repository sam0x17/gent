use super::*;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::test]
async fn node_removal_service_retries_an_uncertain_delete_with_the_same_identity() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    let original = session();
    let (origin, task) = server(vec![
        (200, json!(original)),
        (503, json!({"error":"lost_response"})),
        (200, json!(original)),
        (204, Value::Null),
    ])
    .await;
    let token = saved(&home, &origin, &original);
    let pin = ServiceConfig {
        origin,
        account_id: original.account_id.clone(),
    };
    let cluster = uuid::Uuid::new_v4().to_string();
    let node = uuid::Uuid::new_v4().to_string();
    let first = Service::open_pinned(&home, Some(&pin)).await.unwrap();
    assert!(first.revoke_node(&cluster, &node).await.is_err());
    drop(first);
    let second = Service::open_pinned(&home, Some(&pin)).await.unwrap();
    assert!(second.revoke_node(&cluster, "../different").await.is_err());
    second.revoke_node(&cluster, &node).await.unwrap();
    let calls = task.await.unwrap();
    assert_eq!(calls[1], calls[3]);
    assert_eq!(
        calls[1].0,
        format!("DELETE /v1/clusters/{cluster}/nodes/{node} HTTP/1.1")
    );
    assert_eq!(
        read(&home.join("auth/session.json"))
            .unwrap()
            .unwrap()
            .token,
        token
    );
}

#[tokio::test]
async fn node_removal_checks_account_and_origin_before_contacting_service() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    let original = session();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    saved(&home, &origin, &original);
    let wrong_account = ServiceConfig {
        origin: origin.clone(),
        account_id: uuid::Uuid::new_v4().to_string(),
    };
    assert!(
        Service::open_pinned(&home, Some(&wrong_account))
            .await
            .is_err()
    );
    let wrong_origin = ServiceConfig {
        origin: "https://wrong.example".into(),
        account_id: original.account_id,
    };
    assert!(
        Service::open_pinned(&home, Some(&wrong_origin))
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

fn session() -> ServiceSession {
    ServiceSession {
        account_id: uuid::Uuid::new_v4().to_string(),
        github_subject: "101".into(),
        github_login: "fixture".into(),
        created_at: now().unwrap() - SESSION_LIFETIME_SECONDS + 30,
        expires_at: now().unwrap() + 30,
    }
}

fn saved(home: &Path, origin: &str, session: &ServiceSession) -> String {
    config::private_dir(home).unwrap();
    config::private_dir(&home.join("auth")).unwrap();
    let token = candidate().unwrap();
    save(
        &home.join("auth/session.json"),
        Some(&Saved {
            version: 1,
            service: origin.into(),
            token: token.clone(),
            phase: Phase::Active,
            session: Some(session.clone()),
        }),
    )
    .unwrap();
    token
}

// Every response closes its connection. The test inspects complete native HTTP
// requests, including the observed expiry sent to the renewal endpoint.
async fn server(
    replies: Vec<(u16, Value)>,
) -> (String, tokio::task::JoinHandle<Vec<(String, Value)>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut calls = Vec::new();
        for (status, value) in replies {
            let (stream, _) = timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut stream = BufReader::new(stream);
            let mut first = String::new();
            stream.read_line(&mut first).await.unwrap();
            let mut length = 0;
            loop {
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await.unwrap();
            calls.push((
                first.trim().into(),
                if bytes.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes).unwrap()
                },
            ));
            let body = value.to_string();
            stream.write_all(format!("HTTP/1.1 {status} fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        }
        calls
    });
    (origin, task)
}

#[tokio::test]
async fn lost_renewal_response_recovers_the_same_bearer_without_repeating_extension() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    let original = session();
    let mut extended = original.clone();
    extended.expires_at = now().unwrap() + SESSION_LIFETIME_SECONDS;
    let (origin, server) = server(vec![
        (200, json!(original)),
        (503, json!({"error":"lost_response"})),
        (200, json!(extended)),
    ])
    .await;
    let token = saved(&home, &origin, &original);
    let path = home.join("auth/session.json");
    let bytes = std::fs::read(&path).unwrap();
    assert!(renew(&home, None).await.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let result = renew(&home, None).await.unwrap();
    assert_eq!(result["account"]["expires_at"], extended.expires_at);
    assert_eq!(read(&path).unwrap().unwrap().token, token);
    let calls = server.await.unwrap();
    assert_eq!(
        calls.iter().map(|c| c.0.as_str()).collect::<Vec<_>>(),
        vec![
            "GET /v1/auth/session HTTP/1.1",
            "POST /v1/auth/session/renew HTTP/1.1",
            "GET /v1/auth/session HTTP/1.1"
        ]
    );
    assert_eq!(
        calls[1].1,
        json!({"expected_expires_at": original.expires_at})
    );
}

#[tokio::test]
async fn renewal_saves_only_valid_account_and_lease_responses() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    let original = session();
    let mut foreign = original.clone();
    foreign.account_id = uuid::Uuid::new_v4().to_string();
    let (origin, server) = server(vec![(200, json!(original)), (200, json!(foreign))]).await;
    saved(&home, &origin, &original);
    let path = home.join("auth/session.json");
    let bytes = std::fs::read(&path).unwrap();
    assert!(renew(&home, None).await.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(server.await.unwrap().len(), 2);
}

#[tokio::test]
async fn revoked_remote_session_does_not_start_login_or_change_local_credentials() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    let (origin, server) = server(vec![(401, json!({"error":"session_unavailable"}))]).await;
    saved(&home, &origin, &session());
    let path = home.join("auth/session.json");
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        renew(&home, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("expired or revoked")
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(server.await.unwrap().len(), 1);
}

#[tokio::test]
async fn missing_disabled_wrong_pin_and_locked_login_fail_before_network_access() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    assert!(renew(&home, None).await.is_err());
    assert!(!home.exists());
    let session = session();
    saved(&home, "http://127.0.0.1:9", &session);
    let pin = ServiceConfig {
        origin: "https://other.example".into(),
        account_id: session.account_id.clone(),
    };
    assert!(
        renew(&home, Some(&pin))
            .await
            .unwrap_err()
            .to_string()
            .contains("pinned")
    );
    let _lock = managed_file::lock(&home.join("auth/session.lock")).unwrap();
    assert!(renew(&home, None).await.is_err());
    let path = home.join("auth/session.json");
    let mut state = read(&path).unwrap().unwrap();
    for phase in [Phase::Pending, Phase::Revoking] {
        state.phase = phase;
        save(&path, Some(&state)).unwrap();
        assert!(
            renew(&home, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("finish gent auth")
        );
    }
}

#[test]
fn lease_validation_rejects_rebinding_rollback_and_excessive_extension() {
    let original = session();
    let timestamp = now().unwrap();
    assert!(due(&original, timestamp));
    assert!(validate(&original, &original, timestamp).is_ok());
    for field in 0..5 {
        let mut changed = original.clone();
        match field {
            0 => changed.github_subject = "other".into(),
            1 => changed.created_at += 1,
            2 => changed.expires_at -= 1,
            3 => changed.expires_at = timestamp,
            _ => changed.expires_at = timestamp + SESSION_LIFETIME_SECONDS + 61,
        }
        assert!(validate(&original, &changed, timestamp).is_err());
    }
    let mut changed = original.clone();
    changed.expires_at = timestamp + SESSION_LIFETIME_SECONDS;
    assert!(!due(&changed, timestamp));
    changed.github_login = "renamed".into();
    assert!(validate(&original, &changed, timestamp).is_ok());
}

#[test]
fn signed_channel_switch_keeps_saved_login_account_binding_and_notification_scope() -> Result<()> {
    use gent_protocol::{ConfigurationEdit, OwnerOp, ReleaseChannel, Request, Response};
    let scratch = tempfile::tempdir()?;
    let home = scratch.path().join("node");
    config::initialize(&home, "account")?;
    let mut store = gent_daemon::store::Store::open(&home)?;
    let owner = config::read_private(&home.join("owner.key"))?;
    let account = session();
    saved(&home, DEFAULT_SERVICE, &account);
    let path = home.join("auth/session.json");
    let snapshot = Snapshot::read(&path)?;
    let login = read(&path)?.unwrap();
    let mut pin = ServiceConfig {
        origin: ACCOUNT.beta.into(),
        account_id: account.account_id.clone(),
    };
    for (channel, service, billing) in [
        (
            ReleaseChannel::Beta,
            ACCOUNT.beta,
            "https://beta.gent.link/account",
        ),
        (
            ReleaseChannel::Stable,
            DEFAULT_SERVICE,
            "https://gent.link/account",
        ),
    ] {
        let request = Request::Owner {
            credential: owner.clone(),
            action: OwnerOp::Configure {
                request_id: uuid::Uuid::new_v4().to_string(),
                edit: ConfigurationEdit::SetReleaseChannel { channel },
            },
        };
        assert!(matches!(store.handle(request), Response::Ok(_)));
        check_pin(&login, Some(&pin))?;
        let endpoint = account_endpoint(&home, &login.service)?;
        assert_eq!(endpoint.origin().ascii_serialization(), service);
        assert_eq!(billing_page(&endpoint)?.as_str(), billing);
        let scope = notifications::scope(&home).unwrap();
        assert_eq!(scope.origin, login.service);
        assert_eq!(scope.account, account.account_id);
        snapshot.verify()?;
    }
    pin.account_id = uuid::Uuid::new_v4().to_string();
    assert!(check_pin(&login, Some(&pin)).is_err());
    pin.account_id = account.account_id;
    pin.origin = STAGING_SERVICE.into();
    assert!(check_pin(&login, Some(&pin)).is_err());
    Ok(())
}
