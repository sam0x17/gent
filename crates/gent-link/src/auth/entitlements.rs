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
    // Credentials stay on the service origin recorded at enrollment.
    let Some(installation) = crate::cluster::installation(home)? else {
        return entitlements::clear(home);
    };
    ensure!(
        !installation.pending && origin(&installation.service)? == origin(&pin.origin)?,
        "account setup is pending"
    );
    let token = config::read_relay_credential(&home.join("relay.key"))?;
    ensure!(
        transport_created_at(&token).is_some(),
        "missing service transport credential"
    );
    let (status, value) = response(
        client()?
            .get(origin(&saved.service)?.join("v1/transport/entitlements")?)
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
