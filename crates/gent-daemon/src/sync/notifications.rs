//! The outbound watch carries mailbox hints and, after negotiation, peer
//! sessions. Only verified endpoint receipts advance confirmed history.
pub(super) mod wss;
use super::{Relay, SharedStore, health::Health, schedule::Hints};
use anyhow::{Context, Result, ensure};
use futures_util::{SinkExt, StreamExt};
use gent_protocol::transport_watch::{MAX_BYTES, Notice, Subscription};
use gent_protocol::transport_wss as wire;
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

pub(super) struct Listener {
    pub(super) wss: wss::Wss,
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
    pub(super) fn start(
        relay: Relay,
        store: SharedStore,
        wakeup: Arc<Notify>,
        connected: Arc<AtomicBool>,
        hints: Arc<Hints>,
        health: Arc<Health>,
    ) -> Self {
        let wss = wss::Wss::default();
        health.set_wss(wss.metrics.clone());
        let route = wss.clone();
        let flag = connected.clone();
        let task = tokio::spawn(async move {
            let mut delay = Duration::from_secs(1);
            loop {
                let started = Instant::now();
                // Errors contain no application state and are not logged with
                // request headers, which carry the transport credential.
                let result = listen(&relay, &wakeup, &flag, &hints, &route, &store).await;
                health.watch_ended(
                    result.as_ref().err().map(|e| safe_reason(e)),
                    started.elapsed(),
                );
                flag.store(false, Ordering::SeqCst);
                wakeup.notify_one();
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
    connected: &AtomicBool,
    hints: &Hints,
    route: &wss::Wss,
    store: &SharedStore,
) -> Result<()> {
    let mut url = relay.origin.join("v1/watch")?;
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("invalid push origin"))?;
    let mut request = url.as_str().into_client_request()?;
    if let Some(cluster) = &relay.cluster {
        request
            .headers_mut()
            .insert("X-Gent-Cluster", cluster.parse()?);
    }
    request.headers_mut().insert("X-Gent-Watch", "2".parse()?);
    request
        .headers_mut()
        .insert("X-Gent-Authority", "3".parse()?);
    request
        .headers_mut()
        .insert("Authorization", relay.authorization.clone());
    let offered = scheme == "wss"
        && super::local(store.clone(), |s| {
            Ok(matches!(
                s.direct_settings()?.direct,
                crate::config::Direct::Auto
            ))
        })
        .await
        .unwrap_or(false);
    if offered {
        request
            .headers_mut()
            .insert(wire::HEADER, wire::OFFER.parse()?);
    }
    let limit = if offered { wire::MAX_FRAME } else { MAX_BYTES };
    let config = WebSocketConfig::default()
        .read_buffer_size(4096)
        .write_buffer_size(0)
        .max_write_buffer_size(limit * 2)
        .max_message_size(Some(limit))
        .max_frame_size(Some(limit));
    // This API performs one handshake and does not follow redirects. The same
    // origin validation and TLS trust as HTTP apply; credentials stay on origin.
    let (mut socket, response) = tokio::time::timeout(
        Duration::from_secs(5),
        connect_async_with_config(request, Some(config), true),
    )
    .await
    .context("push connection timed out")??;
    let negotiated = offered
        && response
            .headers()
            .get(wire::HEADER)
            .is_some_and(|value| value == wire::OFFER);
    let mut peer: Option<wss::Connection> = None;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut ready = false;
    let mut deadline = Instant::now() + Duration::from_secs(5);
    let mut dirty = false;
    let mut next_signal = Instant::now();
    let mut version = 1;
    let mut subscription = None;
    let mut subscribe = tokio::time::interval(Duration::from_secs(1));
    subscribe.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            frame = async { peer.as_mut().expect("peer watch ready").next_send().await }, if peer.is_some() => {
                let frame = frame?;
                let bytes = frame.len();
                tokio::time::timeout(Duration::from_secs(3), socket.send(Message::Binary(frame.into()))).await??;
                peer.as_ref().expect("peer watch ready").sent(bytes);
            }
            _ = subscribe.tick(), if ready && version == 2 => {
                let interests = hints.interests();
                if subscription.as_ref() != Some(&interests) {
                    let text = serde_json::to_string(&Subscription {version:2,interests:interests.clone()})?;
                    tokio::time::timeout(Duration::from_secs(5), socket.send(Message::Text(text.into()))).await??;
                    subscription = Some(interests);
                }
            }
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
                                hints.reconnected();
                                deadline = Instant::now() + Duration::from_secs(45);
                                connected.store(true, Ordering::SeqCst);
                                // Reconcile after subscription to close the race
                                // with packets stored during the handshake.
                                wakeup.notify_one();
                            }
                            "changed" if ready => {
                                if notice.version == 1 || notice.all {hints.all(); dirty = true;}
                                else {dirty |= hints.changed(&notice.streams);}
                            },
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
