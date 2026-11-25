//! Every request is scoped to one negotiated watch. Losing that watch drops
//! its queued sends and receipt waiters. The durable MLS outbox owns retries.
use crate::sync::{
    SharedStore, Stream, direct::session, health::Health, local, transfer::Prepared,
};
use anyhow::{Context, Result, ensure};
use gent_protocol::transport_wss::{Frame, Kind, Uuid};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

const CONCURRENT: usize = 4;
const COOLDOWN: Duration = Duration::from_secs(30);
const MAX_PEERS: usize = 64;
const REPLY_TIMEOUT: Duration = Duration::from_secs(4);
const _: () = assert!(session::MAX_FRAME_BYTES <= gent_protocol::transport_wss::MAX_SESSION);
const _: () = assert!(session::VERSION == 2);

#[derive(Default)]
pub(in crate::sync) struct Metrics {
    sent_bytes: AtomicU64,
    received_bytes: AtomicU64,
    stats_sent_frames: AtomicU64,
    stats_sent_bytes: AtomicU64,
    stats_received_frames: AtomicU64,
    stats_received_bytes: AtomicU64,
    confirmed_batches: AtomicU64,
    fallbacks: AtomicU64,
}
impl Metrics {
    pub(in crate::sync) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "sent_frame_bytes": self.sent_bytes.load(Ordering::Relaxed),
            "received_frame_bytes": self.received_bytes.load(Ordering::Relaxed),
            "stats_sent_frames": self.stats_sent_frames.load(Ordering::Relaxed),
            "stats_sent_frame_bytes": self.stats_sent_bytes.load(Ordering::Relaxed),
            "stats_received_frames": self.stats_received_frames.load(Ordering::Relaxed),
            "stats_received_frame_bytes": self.stats_received_bytes.load(Ordering::Relaxed),
            "confirmed_batches": self.confirmed_batches.load(Ordering::Relaxed),
            "fallbacks": self.fallbacks.load(Ordering::Relaxed),
        })
    }
}

struct Request {
    peer: Uuid,
    payload: Vec<u8>,
    reply: oneshot::Sender<Vec<u8>>,
}

struct StatsRequest {
    request: Request,
    dispatched: oneshot::Sender<()>,
}

struct Route {
    channel: mpsc::Sender<Request>,
    stats: mpsc::Sender<StatsRequest>,
    failed: Mutex<BTreeMap<Uuid, tokio::time::Instant>>,
}
impl Route {
    fn available(&self, peer: Uuid, now: tokio::time::Instant) -> bool {
        let mut failed = self.failed.lock().expect("peer cooldown lock poisoned");
        failed.retain(|_, until| *until > now);
        !failed.contains_key(&peer)
    }
    fn failed(&self, peer: Uuid, now: tokio::time::Instant) {
        let mut failed = self.failed.lock().expect("peer cooldown lock poisoned");
        failed.retain(|_, until| *until > now);
        if failed.len() == MAX_PEERS
            && !failed.contains_key(&peer)
            && let Some((&oldest, _)) = failed.iter().min_by_key(|(_, until)| **until)
        {
            failed.remove(&oldest);
        }
        failed.insert(peer, now + COOLDOWN);
    }
}

#[derive(Clone, Default)]
pub(in crate::sync) struct Wss {
    channel: Arc<Mutex<Option<Arc<Route>>>>,
    pub(super) metrics: Arc<Metrics>,
    stats: Arc<crate::sync::health::StatsWatch>,
}

impl Wss {
    pub(super) fn new(stats: Arc<crate::sync::health::StatsWatch>) -> Self {
        Self {
            stats,
            ..Default::default()
        }
    }
    // One side request at a time. Stats never marks a chat route failed or
    // waits for remote I/O on the ordinary transfer loop.
    pub(super) async fn stats_worker(self, store: SharedStore) {
        let tick = &self.stats.tick;
        let mut delay = COOLDOWN;
        loop {
            tokio::select! { _=tick.notified()=>{}, _=tokio::time::sleep(delay)=>{} }
            delay = COOLDOWN;
            for batch in 0..16 {
                let route = self
                    .channel
                    .lock()
                    .expect("peer watch lock poisoned")
                    .clone();
                let Some(route) = route else {
                    break;
                };
                let Ok(Some(sent)) = local(store.clone(), |s| s.next_stats_send()).await else {
                    delay = local(store.clone(), |s| s.stats_worker_delay())
                        .await
                        .unwrap_or(COOLDOWN);
                    break;
                };
                let (reply, result) = oneshot::channel();
                let (dispatch, dispatched) = oneshot::channel();
                let queued = route
                    .stats
                    .try_send(StatsRequest {
                        request: Request {
                            peer: sent.peer,
                            payload: sent.wire.clone(),
                            reply,
                        },
                        dispatched: dispatch,
                    })
                    .is_ok();
                // A busy local writer says nothing about a peer's reachability.
                // Start the remote receipt timer only when the writer admits
                // this frame. A cancelled admission cannot be sent later.
                if queued
                    && matches!(
                        tokio::time::timeout(REPLY_TIMEOUT, dispatched).await,
                        Ok(Ok(()))
                    )
                {
                    let response = tokio::time::timeout(REPLY_TIMEOUT, result)
                        .await
                        .ok()
                        .and_then(Result::ok);
                    let _ = local(store.clone(), move |s| {
                        s.finish_stats_send(&sent, response.as_deref())
                    })
                    .await;
                } else {
                    drop(result);
                    let _ = local(store.clone(), move |s| s.defer_stats_send(&sent)).await;
                    delay = Duration::from_millis(100);
                    break;
                }
                if batch == 15 {
                    tick.notify_one();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    pub(in crate::sync) async fn transfer(
        &self,
        store: &SharedStore,
        entry: &Stream,
        health: &Health,
        prepared: &mut Prepared,
    ) -> Option<Result<Option<session::Confirmed>>> {
        if !entry.outgoing || entry.configuration {
            return None;
        }
        let route = self
            .channel
            .lock()
            .expect("peer watch lock poisoned")
            .clone()?;
        let group = entry.group.clone();
        let peer = local(store.clone(), move |s| {
            Ok(Uuid::parse_str(&s.session_peer(&group, true)?)?)
        })
        .await
        .ok()?;
        if !route.available(peer, tokio::time::Instant::now()) {
            return None;
        }
        let channel = route.channel.clone();
        let result = session::push(
            store.clone(),
            &entry.group,
            prepared,
            |payload| async move {
                let (reply, result) = oneshot::channel();
                channel
                    .try_send(Request {
                        peer,
                        payload,
                        reply,
                    })
                    .map_err(|_| anyhow::anyhow!("peer watch busy or disconnected"))?;
                Ok(tokio::time::timeout(REPLY_TIMEOUT, result).await??)
            },
        )
        .await;
        match result {
            Ok(confirmed) => {
                if let Some(batch) = &confirmed {
                    health.record_transport(
                        &entry.group,
                        crate::sync::health::TransportPath::RelayWss,
                        crate::sync::health::TransportEvidence::SignedReceipt,
                        batch.last,
                    );
                    self.metrics
                        .confirmed_batches
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    health.idle(&entry.group);
                }
                Some(Ok(confirmed))
            }
            Err(_) => {
                route.failed(peer, tokio::time::Instant::now());
                self.metrics.fallbacks.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
}

struct PendingRequest {
    peer: Uuid,
    reply: oneshot::Sender<Vec<u8>>,
    stats: bool,
}
type Pending = BTreeMap<Uuid, PendingRequest>;
struct Reply {
    peer: Uuid,
    id: Uuid,
    receipt: Option<Vec<u8>>,
}
impl Reply {
    fn encode(self) -> Result<Vec<u8>> {
        let (kind, payload) = match &self.receipt {
            Some(receipt) => (Kind::Receipt, receipt.as_slice()),
            None => (Kind::Unavailable, &[][..]),
        };
        Ok(Frame {
            kind,
            peer: self.peer,
            id: self.id,
            payload,
        }
        .encode()?)
    }
}

pub(super) struct Connection {
    route: Wss,
    incoming: mpsc::Receiver<Request>,
    stats_incoming: mpsc::Receiver<StatsRequest>,
    pending: Pending,
    outgoing_stats: bool,
    receivers: JoinSet<Reply>,
    stats_receivers: JoinSet<Reply>,
}

impl Connection {
    pub(super) fn open(route: &Wss) -> Self {
        let (tx, incoming) = mpsc::channel(CONCURRENT);
        let (stats, stats_incoming) = mpsc::channel(1);
        *route.channel.lock().expect("peer watch lock poisoned") = Some(Arc::new(Route {
            channel: tx,
            stats,
            failed: Mutex::default(),
        }));
        route.stats.routes.send_modify(|n| *n += 1);
        route.stats.tick.notify_one();
        Self {
            route: route.clone(),
            incoming,
            stats_incoming,
            pending: Pending::new(),
            outgoing_stats: false,
            receivers: JoinSet::new(),
            stats_receivers: JoinSet::new(),
        }
    }

    // The watch loop owns the socket writer. Completed receipts get the first
    // available slot, including while unrelated peers are pushing new batches.
    pub(super) async fn next_send(&mut self) -> Result<Vec<u8>> {
        loop {
            self.pending.retain(|_, request| !request.reply.is_closed());
            let (request, stats) = tokio::select! {
                biased;
                reply = self.receivers.join_next(), if !self.receivers.is_empty() => {
                    self.outgoing_stats = false;
                    return reply.context("peer receiver stopped")??.encode();
                }
                reply = self.stats_receivers.join_next(), if !self.stats_receivers.is_empty() => {
                    self.outgoing_stats = true;
                    return reply.context("stats receiver stopped")??.encode();
                }
                request = self.incoming.recv() => {
                    let request = request.context("peer watch closed")?;
                    if request.reply.is_closed() || self.pending.len() >= CONCURRENT {
                        continue;
                    }
                    (request, false)
                }
                request = self.stats_incoming.recv(), if self.pending.is_empty() => {
                    let stats = request.context("statistics watch closed")?;
                    if stats.dispatched.send(()).is_err() {
                        continue;
                    }
                    (stats.request, true)
                }
                // A caller may abandon an outstanding ordinary transfer without
                // a receipt. Recheck the queue as soon as that slot is released.
                _ = async {
                    futures_util::future::select_all(self.pending.values_mut().map(|request| Box::pin(request.reply.closed()))).await;
                }, if !self.pending.is_empty() => continue,
            };
            let id = Uuid::new_v4();
            let frame = Frame {
                kind: Kind::Push,
                peer: request.peer,
                id,
                payload: &request.payload,
            }
            .encode()?;
            self.pending.insert(
                id,
                PendingRequest {
                    peer: request.peer,
                    reply: request.reply,
                    stats,
                },
            );
            self.outgoing_stats = stats;
            return Ok(frame);
        }
    }

    pub(super) fn received(&mut self, bytes: &[u8], store: &SharedStore) -> Result<()> {
        let frame = Frame::decode(bytes)?;
        // Unavailable responses have no payload. Attribute those by request ID
        // and authenticated route, including responses generated by the relay.
        let stats = frame.payload.starts_with(crate::encrypted::stats::MAGIC)
            || (frame.kind == Kind::Unavailable
                && self
                    .pending
                    .get(&frame.id)
                    .is_some_and(|r| r.stats && r.peer == frame.peer));
        if stats {
            self.route
                .metrics
                .stats_received_frames
                .fetch_add(1, Ordering::Relaxed);
            self.route
                .metrics
                .stats_received_bytes
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        self.route
            .metrics
            .received_bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        match frame.kind {
            Kind::Push => {
                let store = store.clone();
                let peer = frame.peer;
                let id = frame.id;
                if frame.payload.starts_with(crate::encrypted::stats::MAGIC) {
                    // An optional or oversized push cannot consume messaging's
                    // receiver slots or tear down the shared watch.
                    if !self.stats_receivers.is_empty()
                        || frame.payload.len() > crate::encrypted::stats::MAX_WIRE_BYTES
                    {
                        return Ok(());
                    }
                    let payload = frame.payload.to_vec();
                    self.stats_receivers.spawn(async move {
                        let receipt = local(store, move |s| s.accept_stats_send(peer, &payload))
                            .await
                            .ok();
                        Reply { peer, id, receipt }
                    });
                } else {
                    ensure!(
                        self.receivers.len() < CONCURRENT,
                        "peer watch receiver busy"
                    );
                    let payload = frame.payload.to_vec();
                    self.receivers.spawn(async move {
                        let receipt =
                            session::accept(store, session::Peer::Node(peer.to_string()), &payload)
                                .await
                                .ok();
                        Reply { peer, id, receipt }
                    });
                }
            }
            Kind::Receipt | Kind::Unavailable => {
                if self
                    .pending
                    .get(&frame.id)
                    .is_some_and(|r| r.peer == frame.peer)
                    && let Some(request) = self.pending.remove(&frame.id)
                    && frame.kind == Kind::Receipt
                {
                    // The session layer verifies the signed stream, reader,
                    // history and sequence before it can retire any ciphertext.
                    let _ = request.reply.send(frame.payload.to_vec());
                }
            }
        }
        Ok(())
    }

    pub(super) fn sent(&self, bytes: usize) {
        if self.outgoing_stats {
            self.route
                .metrics
                .stats_sent_frames
                .fetch_add(1, Ordering::Relaxed);
            self.route
                .metrics
                .stats_sent_bytes
                .fetch_add(bytes as u64, Ordering::Relaxed);
        }
        self.route
            .metrics
            .sent_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.route
            .channel
            .lock()
            .expect("peer watch lock poisoned")
            .take();
        self.route.stats.routes.send_modify(|n| *n -= 1);
    }
}

#[cfg(test)]
pub(in crate::sync) mod tests;
