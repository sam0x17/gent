//! Account inbox publisher and passive desktop watch. Only the pinned login
//! authority sees its bearer. Local device cursors are independent per account.
use super::*;
#[cfg(target_os = "macos")]
use crate::desktop::notification_delivery::Destination;
#[cfg(not(target_os = "macos"))]
type Destination = Path;
use futures_util::StreamExt;
use gent_protocol::{
    OwnerOp,
    notifications::{Event, Failure, Notice},
};
use std::path::PathBuf;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, client::IntoClientRequest, protocol::WebSocketConfig},
};

fn active(home: &Path) -> Result<Option<Saved>> {
    Ok(
        read(&source::directory(home)?.join("session.json"))?.filter(|s| {
            s.phase == Phase::Active
                && s.session
                    .as_ref()
                    .is_some_and(|a| a.expires_at > gent_daemon::store::now() as u64)
        }),
    )
}

pub(crate) fn scope(home: &Path) -> Option<gent_protocol::notifications::Scope> {
    let saved = active(home).ok()??;
    Some(gent_protocol::notifications::Scope {
        account: saved.session?.account_id,
        origin: saved.service,
    })
}
async fn directory_name(home: &Path, op: OwnerOp, id: uuid::Uuid) -> String {
    let id = id.to_string();
    let directory = tokio::time::timeout(Duration::from_secs(2), crate::owner(home, op)).await;
    directory
        .ok()
        .and_then(Result::ok)
        .and_then(|value| {
            value.as_array()?.iter().find(|row| row["id"] == id)?["name"]
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or(id)
}

async fn display(home: &Path, destination: &Destination, notice: &Notice) -> Result<()> {
    let (title, message) = match &notice.event {
        Event::GoalResumed { chat, reason, .. } => {
            let name = directory_name(home, OwnerOp::Agents, *chat).await;
            (
                "Goal resumed",
                format!("{name} resumed after {}.", reason.label()),
            )
        }
        Event::UpdateInstalled { node, commit } => {
            let name = directory_name(home, OwnerOp::Nodes, *node).await;
            (
                "Gent updated",
                format!(
                    "{name} updated to {}.",
                    commit.chars().take(12).collect::<String>()
                ),
            )
        }
    };
    #[cfg(target_os = "macos")]
    {
        destination.display(notice.id, title, message).await
    }
    #[cfg(not(target_os = "macos"))]
    let mut command = {
        let mut c = tokio::process::Command::new("notify-send");
        c.arg("--app-name=Gent");
        #[cfg(target_os = "linux")]
        c.arg(format!(
            "--hint=string:desktop-entry:{}",
            crate::desktop::desktop_entry_id(home)
        ));
        c.arg("--icon")
            .arg(destination)
            .args(["--", title, &message]);
        c
    };
    #[cfg(not(target_os = "macos"))]
    {
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            command
                .kill_on_drop(true)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status(),
        )
        .await??;
        ensure!(result.success(), "desktop notification unavailable");
        Ok(())
    }
}

async fn publish(home: &Path) -> Result<()> {
    let Some(login) = active(home)? else {
        return Ok(());
    };
    let scope = gent_protocol::notifications::Scope {
        account: login
            .session
            .as_ref()
            .context("missing session")?
            .account_id
            .clone(),
        origin: login.service.clone(),
    };
    let pending = crate::owner(home, OwnerOp::NotificationPending { scope }).await?;
    let pending: Vec<Notice> = serde_json::from_value(pending)?;
    if pending.is_empty() {
        return Ok(());
    }
    let url = account_endpoint(home, &login.service)?.join("v1/notifications")?;
    let client = client()?;
    for notice in pending {
        if !still_signed_in(home, &login)? {
            break;
        }
        if notice.created_at >= now()? as i64 - 7 * 86400 {
            let (status, value) = response(
                client
                    .post(url.clone())
                    .bearer_auth(&login.token)
                    .json(&notice),
            )
            .await?;
            ensure!(
                success(status, value)?["accepted"] == true,
                "account notification pending"
            );
        }
        crate::owner(home, OwnerOp::NotificationSent { id: notice.id }).await?;
    }
    Ok(())
}

pub(crate) async fn publish_loop(home: &Path) {
    let mut pause = 5;
    loop {
        pause = if publish(home).await.is_ok() {
            15
        } else {
            (pause * 2).min(300)
        };
        tokio::time::sleep(Duration::from_secs(pause)).await;
    }
}

fn cursor_file(directory: &Path, origin: &Url, account: &str) -> PathBuf {
    directory.join(format!(
        "notification-cursor-{}",
        crate::babysitter::fingerprint(&[origin.as_str(), account])
    ))
}

fn cursor_paths(home: &Path, saved: &Saved) -> Result<(PathBuf, Option<PathBuf>)> {
    let account = &saved
        .session
        .as_ref()
        .context("missing session")?
        .account_id;
    let directory = source::directory(home)?;
    let pin = account_pin(&saved.service)?;
    let current = cursor_file(&directory, &pin, account);
    // Older clients allowed an explicit beta login and keyed its cursor to that URL.
    let beta = if ACCOUNT.contains(&pin) {
        Some(cursor_file(&directory, &origin(ACCOUNT.beta)?, account))
    } else {
        None
    };
    Ok((current, beta))
}

fn read_cursor(path: &Path) -> Result<u64> {
    let snapshot = Snapshot::read(path)?;
    snapshot.private()?;
    Ok(snapshot
        .text
        .as_deref()
        .map(str::trim)
        .unwrap_or("0")
        .parse()?)
}
fn still_signed_in(home: &Path, login: &Saved) -> Result<bool> {
    Ok(active(home)?.is_some_and(|s| s.token == login.token && s.service == login.service))
}
// An older desktop can advance its cursor past a newly introduced event kind.
fn supported(value: &Value) -> Result<Option<Notice>> {
    match value["event"]["kind"]
        .as_str()
        .context("missing notification kind")?
    {
        "goal_resumed"
            if value["event"]["reason"].is_string()
                && serde_json::from_value::<Failure>(value["event"]["reason"].clone()).is_err() =>
        {
            Ok(None)
        }
        "goal_resumed" | "update_installed" => Ok(Some(serde_json::from_value(value.clone())?)),
        _ => Ok(None),
    }
}
fn cursor_position(path: &Path, legacy: Option<&Path>) -> Result<u64> {
    let old = legacy.map(read_cursor).transpose()?.unwrap_or(0);
    Ok(old.max(read_cursor(path)?))
}

async fn collect(home: &Path, login: &Saved, destination: &Destination) -> Result<()> {
    let (path, legacy) = cursor_paths(home, login)?;
    let url = account_endpoint(home, &login.service)?.join("v1/notifications")?;
    let client = client()?;
    loop {
        if !still_signed_in(home, login)? {
            return Ok(());
        }
        let mut after = cursor_position(&path, legacy.as_deref())?;
        let (status, value) = response(
            client
                .get(url.clone())
                .bearer_auth(&login.token)
                .header("X-Gent-After", after.to_string()),
        )
        .await?;
        let value = success(status, value)?;
        let rows = value.as_array().context("invalid inbox page")?;
        ensure!(rows.len() <= 64, "oversized inbox page");
        for row in rows {
            if !still_signed_in(home, login)? {
                return Ok(());
            }
            let seq = row["sequence"].as_u64().context("invalid inbox sequence")?;
            ensure!(seq > after, "invalid inbox order");
            if let Some(notice) = supported(&row["notice"])? {
                display(home, destination, &notice).await?;
            }
            let state = Snapshot::read(&path)?;
            state.private()?;
            state.write(&seq.to_string())?;
            after = seq;
        }
        if rows.len() < 64 {
            return Ok(());
        }
    }
}

async fn watch(home: &Path, login: &Saved, destination: &Destination) -> Result<()> {
    let endpoint = account_endpoint(home, &login.service)?;
    let mut url = endpoint.join("v1/notifications/watch")?;
    url.set_scheme(if url.scheme() == "https" { "wss" } else { "ws" })
        .map_err(|_| anyhow::anyhow!("invalid watch URL"))?;
    let mut request = url.as_str().into_client_request()?;
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {}", login.token).parse()?);
    let config = WebSocketConfig::default()
        .max_message_size(Some(1024))
        .max_frame_size(Some(1024));
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(10),
        connect_async_with_config(request, Some(config), true),
    )
    .await??;
    collect(home, login, destination).await?;
    let mut auth_tick = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            frame=socket.next()=>match frame.context("watch closed")??{
                Message::Text(text) if text=="changed"=>collect(home,login,destination).await?,
                Message::Ping(_) | Message::Pong(_)=>{},
                _=>anyhow::bail!("account watch ended"),
            },
            _=auth_tick.tick()=>if !still_signed_in(home,login)? || account_endpoint(home, &login.service)? != endpoint {return Ok(())},
        }
    }
}
pub(crate) async fn desktop_loop(home: &Path, destination: &Destination) {
    let mut backoff = 1;
    loop {
        if let Ok(Some(login)) = active(home) {
            let since = std::time::Instant::now();
            let result = watch(home, &login, destination).await;
            backoff = if result.is_ok() || since.elapsed().as_secs() > 60 {
                1
            } else {
                (backoff * 2).min(300)
            };
        } else {
            backoff = 10;
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests;

#[cfg(all(test, target_os = "linux"))]
mod tests;
