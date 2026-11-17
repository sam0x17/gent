//! Untrusted relay hints wake reconciliation; they never advance local history.
use super::Relay;
use anyhow::{Context, Result, ensure};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::{
    sync::Notify,
    task::JoinHandle,
    time::{Instant, MissedTickBehavior},
};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, client::IntoClientRequest, protocol::WebSocketConfig},
};

const PING: &str = "gent-ping-v1";
const PONG: &str = "gent-pong-v1";
const COALESCE: Duration = Duration::from_millis(50);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Notice {
    version: u8,
    event: String,
}

pub(super) struct Listener {
    connected: Arc<AtomicBool>,
    task: JoinHandle<()>,
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.connected.store(false, Ordering::SeqCst);
        self.task.abort();
    }
}
impl Listener {
    pub(super) fn start(relay: Relay, wakeup: Arc<Notify>, connected: Arc<AtomicBool>) -> Self {
        let flag = connected.clone();
        let task = tokio::spawn(async move {
            let mut delay = Duration::from_secs(1);
            loop {
                let started = Instant::now();
                // Errors contain no application state and are not logged with
                // request headers, which carry the transport credential.
                let _ = listen(&relay, &wakeup, &flag).await;
                flag.store(false, Ordering::SeqCst);
                wakeup.notify_one();
                if started.elapsed() >= Duration::from_secs(30) {
                    delay = Duration::from_secs(1);
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
        });
        Self { connected, task }
    }
    pub(super) fn reconcile_after(&self) -> Duration {
        if self.connected.load(Ordering::SeqCst) {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(1)
        }
    }
}

async fn listen(relay: &Relay, wakeup: &Notify, connected: &AtomicBool) -> Result<()> {
    let mut url = relay.origin.join("v1/watch")?;
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("invalid push origin"))?;
    let mut request = url.as_str().into_client_request()?;
    request
        .headers_mut()
        .insert("X-Gent-Authority", "3".parse()?);
    request
        .headers_mut()
        .insert("Authorization", relay.authorization.clone());
    let config = WebSocketConfig::default()
        .read_buffer_size(4096)
        .write_buffer_size(0)
        .max_write_buffer_size(4096)
        .max_message_size(Some(1024))
        .max_frame_size(Some(1024));
    // This API performs one handshake and does not follow redirects. The same
    // origin validation and TLS trust as HTTP apply; credentials stay on origin.
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(5),
        connect_async_with_config(request, Some(config), true),
    )
    .await
    .context("push connection timed out")??;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut ready = false;
    let mut deadline = Instant::now() + Duration::from_secs(5);
    let mut dirty = false;
    let mut next_signal = Instant::now();
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => anyhow::bail!("push heartbeat expired"),
            _ = heartbeat.tick(), if ready => {
                tokio::time::timeout(Duration::from_secs(5), socket.send(Message::Text(PING.into()))).await??;
            }
            _ = tokio::time::sleep_until(next_signal), if dirty => {
                wakeup.notify_one();
                dirty = false;
                next_signal = Instant::now() + COALESCE;
            }
            frame = socket.next() => {
                match frame.context("push channel closed")?? {
                    Message::Text(text) if ready && text == PONG => {
                        deadline = Instant::now() + Duration::from_secs(45);
                    }
                    Message::Text(text) => {
                        let notice: Notice = serde_json::from_str(&text)?;
                        ensure!(notice.version == 1, "unsupported push version");
                        match notice.event.as_str() {
                            "ready" if !ready => {
                                ready = true;
                                deadline = Instant::now() + Duration::from_secs(45);
                                connected.store(true, Ordering::SeqCst);
                                // Reconcile after subscription to close the race
                                // with packets stored during the handshake.
                                wakeup.notify_one();
                            }
                            "changed" if ready => dirty = true,
                            _ => anyhow::bail!("invalid push event"),
                        }
                    }
                    Message::Ping(_) => { tokio::time::timeout(Duration::from_secs(5), socket.flush()).await??; }
                    Message::Pong(_) => {}
                    _ => anyhow::bail!("invalid push frame"),
                }
            }
        }
    }
}
