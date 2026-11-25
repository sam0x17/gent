//! Refresh the node's signed, short-lived account lease at its pinned origin.
use super::*;
use gent_daemon::{config, entitlements};
use gent_protocol::service::{SignedEntitlements, transport_created_at};

async fn refresh(home: &Path) -> Result<()> {
    let cfg = crate::node_home::inspect(home)?;
    let Some(pin) = &cfg.service else {
        return entitlements::clear(home);
    };
    let directory = source::directory(home)?;
    let path = directory.join("session.json");
    let previous = Snapshot::read(&path)?;
    let Some(saved) = read(&path)? else {
        return entitlements::clear(home);
    };
    if renewal::check_pin(&saved, Some(pin)).is_err()
        || saved
            .session
            .as_ref()
            .is_none_or(|s| s.expires_at <= gent_daemon::store::now() as u64)
    {
        return entitlements::clear(home);
    }
    // Verify the original account and relay pins before using the transport credential.
    let Some(installation) = crate::cluster::installation(home)? else {
        return entitlements::clear(home);
    };
    ensure!(
        !installation.pending && account_pin(&installation.service)? == account_pin(&pin.origin)?,
        "account setup is pending"
    );
    let token = config::read_relay_credential(&home.join("relay.key"))?;
    ensure!(
        transport_created_at(&token).is_some(),
        "missing service transport credential"
    );
    let (status, value) = response(
        client()?
            .get(account_endpoint(home, &saved.service)?.join("v1/transport/entitlements")?)
            .bearer_auth(token),
    )
    .await?;
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return entitlements::clear(home);
    }
    let signed: SignedEntitlements = serde_json::from_value(success(status, value)?)?;
    // Serialize the final login recheck and commit with logout/account changes.
    let _lock = managed_file::lock(&directory.join("session.lock"))?;
    previous.verify()?;
    entitlements::install(home, &cfg, &signed)
}

pub(super) async fn maintain(home: &Path) {
    let mut last_error = None;
    loop {
        let result = refresh(home).await;
        let delay = if let Err(e) = result {
            let text = e.to_string();
            if last_error.as_ref() != Some(&text) {
                eprintln!("Gent account entitlements pending: {text}");
            }
            last_error = Some(text);
            30
        } else {
            last_error = None;
            180
        };
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};

    #[tokio::test]
    async fn rejected_login_invalidates_the_old_lease_before_replacement() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("node");
        config::initialize(&home, "login-replacement")?;
        let directory = source::directory(&home)?;
        managed_file::directory(&directory)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let service = format!("http://{}", listener.local_addr()?);
        let api = Router::new()
            .route(
                "/v1/auth/session",
                get(|| async { StatusCode::UNAUTHORIZED }),
            )
            .route(
                "/v1/auth/config",
                get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, api).await });
        let path = directory.join("session.json");
        save(
            &path,
            Some(&Saved {
                version: 1,
                service,
                token: candidate()?,
                phase: Phase::Active,
                session: Some(ServiceSession {
                    account_id: uuid::Uuid::new_v4().to_string(),
                    github_subject: "1".into(),
                    github_login: "fixture".into(),
                    created_at: now()? - 60,
                    expires_at: now()? + 3600,
                }),
            }),
        )?;
        let previous = Snapshot::read(&path)?;
        let lease = home.join("account-entitlements.json");
        config::write_private(&lease, b"old lease")?;
        let login = Command::Login {
            headless: true,
            no_browser: true,
            service: None,
        };
        assert!(execute_at(&directory, login, false).await.is_err());
        assert!(!lease.exists());
        assert!(previous.verify().is_err());
        let saved = read(&path)?.unwrap();
        assert!(saved.phase == Phase::Pending && saved.session.is_none());

        save(&path, None)?;
        config::write_private(&lease, b"orphaned lease")?;
        execute_at(&directory, Command::Logout, false).await?;
        assert!(!lease.exists());
        server.abort();
        Ok(())
    }
}
