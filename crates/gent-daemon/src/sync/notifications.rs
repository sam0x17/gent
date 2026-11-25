//! The outbound watch carries mailbox hints and, after negotiation, peer
//! sessions. Only verified endpoint receipts advance confirmed history.
mod handshake;
pub(super) mod wss;
use super::{Relay, SharedStore, health::Health, schedule::Hints};
use anyhow::{Context, Result, ensure};
use futures_util::{SinkExt, StreamExt};
use gent_protocol::transport_watch::{MAX_BYTES, Notice, WatchAck};
use gent_protocol::transport_wss as wire;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::{sync::Notify, task::JoinHandle, time::Instant};
use tokio_tungstenite::tungstenite::Message;

const COALESCE: Duration = Duration::from_millis(50);

pub(super) struct Listener {
    pub(super) wss: wss::Wss,
    connected: Arc<AtomicBool>,
    task: JoinHandle<()>,
    stats_task: JoinHandle<()>,
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.connected.store(false, Ordering::SeqCst);
        self.task.abort();
        self.stats_task.abort();
    }
}
impl Listener {
    pub(super) fn start(
        relay: Relay,
        store: SharedStore,
        wakeup: Arc<Notify>,
        connected: Arc<AtomicBool>,
        hints: Arc<Hints>,
        health: Arc<Health>,
    ) -> Self {
        let wss = wss::Wss::new(health.stats.clone());
        health.set_wss(wss.metrics.clone());
        let route = wss.clone();
        let stats_task = tokio::spawn(wss.clone().stats_worker(store.clone()));
        let flag = connected.clone();
        let task = tokio::spawn(async move {
            let mut delay = Duration::from_secs(1);
            let mut take_over = true;
            loop {
                let started = Instant::now();
                // Errors contain no application state and are not logged with
                // request headers, which carry the transport credential.
                let result =
                    listen(&relay, &wakeup, &health, &hints, &route, &store, take_over).await;
                health.watch_ended(
                    result.as_ref().err().map(|e| safe_reason(e)),
                    started.elapsed(),
                );
                hints.set_passive(false);
                if flag.swap(false, Ordering::SeqCst) {
                    hints.all();
                }
                wakeup.notify_one();
                // A replacement owns the route now. Rejoin immediately for
                // hints and only claim a vacant route on future reconnects.
                if result.is_ok() {
                    take_over = false;
                    delay = Duration::from_secs(1);
                    continue;
                }
                if started.elapsed() >= Duration::from_secs(30) {
                    delay = Duration::from_secs(1);
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
        });
        Self {
            connected,
            task,
            stats_task,
            wss,
        }
    }
    pub(super) fn reconcile_after(&self) -> Duration {
        Duration::from_secs(5)
    }
}

fn safe_reason(error: &anyhow::Error) -> &'static str {
    if error
        .downcast_ref::<tokio::time::error::Elapsed>()
        .is_some()
    {
        "timeout"
    } else if let Some(error) = error.downcast_ref::<tokio_tungstenite::tungstenite::Error>() {
        match error {
            tokio_tungstenite::tungstenite::Error::Http(response)
                if response.status().as_u16() == 401 || response.status().as_u16() == 403 =>
            {
                "authorization"
            }
            tokio_tungstenite::tungstenite::Error::Http(_) => "http_handshake",
            tokio_tungstenite::tungstenite::Error::Io(_) => "connection",
            _ => "websocket_protocol",
        }
    } else {
        "closed_or_invalid_notice"
    }
}

async fn listen(
    relay: &Relay,
    wakeup: &Notify,
    health: &Health,
    hints: &Hints,
    route: &wss::Wss,
    store: &SharedStore,
    take_over: bool,
) -> Result<()> {
    let mut url = relay.origin.join("v1/watch")?;
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("invalid push origin"))?;
    let offered = scheme == "wss"
        && super::local(store.clone(), |s| {
            Ok(matches!(
                s.direct_settings()?.direct,
                crate::config::Direct::Auto
            ))
        })
        .await
        .unwrap_or(false);
    let (mut socket, negotiated, passive) =
        handshake::connect(relay, url.as_str(), offered, take_over).await?;
    let mut peer: Option<wss::Connection> = None;
    let mut ready = false;
    let mut verifying = false;
    let mut deadline = Instant::now() + Duration::from_secs(5);
    let mut dirty = false;
    let mut next_signal = Instant::now();
    let mut version = 1;
    let mut subscription = None;
    let mut seen = None;
    loop {
        tokio::select! {
            frame = async { peer.as_mut().expect("peer watch ready").next_send().await }, if peer.is_some() => {
                let frame = frame?;
                let bytes = frame.len();
                tokio::time::timeout(Duration::from_secs(3), socket.send(Message::Binary(frame.into()))).await??;
                peer.as_ref().expect("peer watch ready").sent(bytes);
            }
            _ = hints.subscription_changed.notified(), if ready && version == 2 => {
                let value = hints.subscription(passive);
                if subscription.as_ref() != Some(&value) {
                    let text = serde_json::to_string(&value)?;
                    tokio::time::timeout(Duration::from_secs(5), socket.send(Message::Text(text.into()))).await??;
                    subscription = Some(value);
                }
            }
            _ = health.verify_watch.notified(), if ready && !verifying => {
                // Only outstanding work or an explicit freshness request can
                // probe an apparently open route. Quiet sockets have no timer.
                tokio::time::timeout(Duration::from_secs(5), socket.send(Message::text("gent-ping-v1"))).await??;
                verifying = true;
                deadline = Instant::now() + Duration::from_secs(10);
            }
            _ = tokio::time::sleep_until(deadline), if !ready || verifying => anyhow::bail!("watch verification timed out"),
            _ = tokio::time::sleep_until(next_signal), if dirty => {
                wakeup.notify_one();
                dirty = false;
                next_signal = Instant::now() + COALESCE;
            }
            frame = socket.next() => {
                match frame.context("push channel closed")?? {
                    Message::Text(text) if ready && text == "gent-pong-v1" => verifying = false,
                    Message::Binary(bytes) => {
                        peer.as_mut().context("unnegotiated peer frame")?.received(&bytes, store)?;
                    }
                    Message::Text(text) => {
                        ensure!(text.len() <= MAX_BYTES, "oversized notification");
                        let notice: Notice = serde_json::from_str(&text)?;
                        ensure!((1..=2).contains(&notice.version) && notice.streams.len() <= gent_protocol::transport_watch::MAX_INTERESTS && notice.streams.iter().all(|s|s.valid()), "unsupported push version or bounds");
                        match notice.event.as_str() {
                            "ready" if !ready => {
                                ready = true;
                                version = notice.version;
                                if version == 2 && negotiated {
                                    peer = Some(wss::Connection::open(route));
                                }
                                hints.set_passive(passive && version == 2);
                                hints.subscription_changed.notify_one();
                                hints.reconnected();
                                health.connected.store(true, Ordering::SeqCst);
                                // Reconcile after subscription to close the race
                                // with packets stored during the handshake.
                                wakeup.notify_one();
                            }
                            "changed" if ready => {
                                ensure!(notice.serial.is_some() == (passive && version == 2) && notice.version == version, "invalid watch serial or version");
                                if seen.is_none() || notice.serial > seen {
                                    if notice.version == 1 || notice.all {
                                        hints.all();
                                        dirty = true;
                                    } else {
                                        dirty |= hints.changed(&notice.streams);
                                    }
                                    seen = notice.serial;
                                }
                                if let Some(serial) = notice.serial {
                                    let text = serde_json::to_string(&WatchAck { seen: serial })?;
                                    tokio::time::timeout(Duration::from_secs(5), socket.send(Message::Text(text.into()))).await??;
                                }
                            },
                            _ => anyhow::bail!("invalid push event"),
                        }
                    }
                    Message::Close(Some(reason)) if peer.is_some() && u16::from(reason.code) == wire::REPLACED => return Ok(()),
                    Message::Ping(_) => { tokio::time::timeout(Duration::from_secs(5), socket.flush()).await??; }
                    Message::Pong(_) => {}
                    _ => anyhow::bail!("invalid push frame"),
                }
            }
        }
    }
}
