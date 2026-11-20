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
    confirmed_batches: AtomicU64,
    fallbacks: AtomicU64,
}
impl Metrics {
    pub(in crate::sync) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "sent_frame_bytes": self.sent_bytes.load(Ordering::Relaxed),
            "received_frame_bytes": self.received_bytes.load(Ordering::Relaxed),
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

struct Route {
    channel: mpsc::Sender<Request>,
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
}

impl Wss {
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
                if confirmed.is_some() {
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

type Pending = BTreeMap<Uuid, (Uuid, oneshot::Sender<Vec<u8>>)>;
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
    pending: Pending,
    receivers: JoinSet<Reply>,
}

impl Connection {
    pub(super) fn open(route: &Wss) -> Self {
        let (tx, incoming) = mpsc::channel(CONCURRENT);
        *route.channel.lock().expect("peer watch lock poisoned") = Some(Arc::new(Route {
            channel: tx,
            failed: Mutex::default(),
        }));
        Self {
            route: route.clone(),
            incoming,
            pending: Pending::new(),
            receivers: JoinSet::new(),
        }
    }

    // The watch loop owns the socket writer. Completed receipts get the first
    // available slot, including while unrelated peers are pushing new batches.
    pub(super) async fn next_send(&mut self) -> Result<Vec<u8>> {
        loop {
            tokio::select! {
                biased;
                reply = self.receivers.join_next(), if !self.receivers.is_empty() => {
                    return reply.context("peer receiver stopped")??.encode();
                }
                request = self.incoming.recv() => {
                    let request = request.context("peer watch closed")?;
                    self.pending.retain(|_, (_, reply)| !reply.is_closed());
                    if request.reply.is_closed() || self.pending.len() >= CONCURRENT {
                        continue;
                    }
                    let id = Uuid::new_v4();
                    let frame = Frame { kind: Kind::Push, peer: request.peer, id, payload: &request.payload }.encode()?;
                    self.pending.insert(id, (request.peer, request.reply));
                    return Ok(frame);
                }
            }
        }
    }

    pub(super) fn received(&mut self, bytes: &[u8], store: &SharedStore) -> Result<()> {
        let frame = Frame::decode(bytes)?;
        self.route
            .metrics
            .received_bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        match frame.kind {
            Kind::Push => {
                // There are no detached jobs or payload queue behind the store.
                // A relay exceeding the negotiated receiver bound loses this watch.
                ensure!(
                    self.receivers.len() < CONCURRENT,
                    "peer watch receiver busy"
                );
                let store = store.clone();
                let peer = frame.peer;
                let id = frame.id;
                let payload = frame.payload.to_vec();
                self.receivers.spawn(async move {
                    let receipt =
                        session::accept(store, session::Peer::Node(peer.to_string()), &payload)
                            .await
                            .ok();
                    Reply { peer, id, receipt }
                });
            }
            Kind::Receipt | Kind::Unavailable => {
                if self
                    .pending
                    .get(&frame.id)
                    .is_some_and(|(peer, _)| *peer == frame.peer)
                    && let Some((_, reply)) = self.pending.remove(&frame.id)
                    && frame.kind == Kind::Receipt
                {
                    // The session layer verifies the signed stream, reader,
                    // history and sequence before it can retire any ciphertext.
                    let _ = reply.send(frame.payload.to_vec());
                }
            }
        }
        Ok(())
    }

    pub(super) fn sent(&self, bytes: usize) {
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
    }
}

#[cfg(test)]
pub(in crate::sync) mod tests;
