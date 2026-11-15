//! Keep an active service lease alive without retaining GitHub credentials.
//! A cancelled/lost renewal changes no bearer; the next authoritative GET
//! recovers its committed expiry. Logout shares the private session lock.
use super::*;
use gent_daemon::config::{self, ServiceConfig};
use gent_protocol::service::{
    SESSION_LIFETIME_SECONDS, SESSION_RENEWAL_WINDOW_SECONDS, SessionRenewal,
};

fn due(session: &ServiceSession, timestamp: u64) -> bool {
    session.expires_at <= timestamp.saturating_add(SESSION_RENEWAL_WINDOW_SECONDS)
}

fn validate(previous: &ServiceSession, current: &ServiceSession, timestamp: u64) -> Result<()> {
    ensure!(
        current.account_id == previous.account_id
            && current.github_subject == previous.github_subject
            && current.created_at == previous.created_at
            && current.expires_at >= previous.expires_at
            && current.expires_at > timestamp
            && current.expires_at <= timestamp.saturating_add(SESSION_LIFETIME_SECONDS + 60),
        "renewal changed the saved account or returned an invalid session lease"
    );
    Ok(())
}

fn check_pin(saved: &Saved, pin: Option<&ServiceConfig>) -> Result<()> {
    ensure!(
        saved.phase == Phase::Active,
        "finish gent auth login or gent auth logout before renewing"
    );
    let session = saved.session.as_ref().context("saved account is missing")?;
    if let Some(pin) = pin {
        ensure!(
            origin(&saved.service)? == origin(&pin.origin)? && session.account_id == pin.account_id,
            "daemon account renewal is pinned to the node's original account service"
        );
    }
    Ok(())
}

pub async fn renew(home: &Path, pin: Option<&ServiceConfig>) -> Result<Value> {
    let location = source::Location::open(home)?;
    let directory = &location.directory;
    let path = directory.join("session.json");
    // A missing login must not create an auth directory or start authentication.
    let saved = read(&path)?.context("sign in with gent auth login before renewing")?;
    location.check_saved(&saved)?;
    check_pin(&saved, pin)?;
    let _lock = managed_file::lock(&directory.join("session.lock"))?;
    let snapshot = Snapshot::read(&path)?;
    snapshot.private()?;
    let mut saved = read(&path)?.context("account login disappeared; sign in again")?;
    location.check_saved(&saved)?;
    snapshot.verify()?;
    check_pin(&saved, pin)?;
    let previous = saved.session.as_ref().expect("account checked");
    let client = client()?;
    let current = service_session(&client, &saved)
        .await?
        .context("session is expired or revoked; run gent auth login")?;
    validate(previous, &current, now()?)?;
    let was_due = due(&current, now()?);
    let renewed = if was_due {
        let (status, value) = response(
            client
                .post(origin(&saved.service)?.join("v1/auth/session/renew")?)
                .bearer_auth(&saved.token)
                .json(&SessionRenewal {
                    expected_expires_at: current.expires_at,
                }),
        )
        .await?;
        ensure!(
            status == StatusCode::OK,
            "session renewal was not accepted (HTTP {}); check gent auth status",
            status.as_u16()
        );
        let renewed: ServiceSession = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("invalid service renewal response"))?;
        validate(&current, &renewed, now()?)?;
        renewed
    } else {
        current.clone()
    };
    let extended = renewed.expires_at > previous.expires_at;
    let result = json!({"status":"active", "service":saved.service,
        "account":renewed, "renewed":extended, "renewal_due":due(&renewed, now()?)});
    saved.session = Some(renewed);
    snapshot.write(&(serde_json::to_string(&saved)? + "\n"))?;
    Ok(location.describe(result))
}

async fn maintain(home: &Path) {
    let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_error = None;
    loop {
        interval.tick().await;
        let outcome = async {
            let cfg = config::load(home)?;
            let Some(pin) = cfg.service else {
                return Ok(());
            };
            let location = source::Location::open(home)?;
            let saved = read(&location.directory.join("session.json"))?
                .context("sign in with gent auth login to renew this node's session")?;
            location.check_saved(&saved)?;
            check_pin(&saved, Some(&pin))?;
            if due(saved.session.as_ref().expect("account checked"), now()?) {
                crate::cluster::installation(home)?; // Recheck identity and relay pins.
                renew(home, Some(&pin)).await?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        match outcome {
            Ok(()) => last_error = None,
            Err(error) => {
                let error = error.to_string();
                if last_error.as_ref() != Some(&error) {
                    eprintln!("Gent account renewal pending: {error}");
                    last_error = Some(error);
                }
            }
        }
    }
}

pub async fn run_daemon(home: &Path) -> Result<()> {
    // Poll the daemon first so a missing configuration or held daemon lock fails
    // before maintenance. Dropping maintain cancels network waits on shutdown.
    tokio::select! {
        biased;
        result = gent_daemon::run(home) => result,
        _ = maintain(home) => unreachable!("maintenance continues until daemon shutdown"),
        _ = crate::node::maintain(home) => unreachable!("node removals continue until daemon shutdown"),
        _ = crate::integration::recovery::maintain(home) => unreachable!("host recovery continues until daemon shutdown"),
    }
}

#[cfg(test)]
mod tests;
