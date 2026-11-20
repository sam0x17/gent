//! Opportunistic peer delivery of the same durable MLS history as the mailbox.
use super::*;
use gent_protocol::transport_batch::Batch;
use iroh::{
    Endpoint, EndpointId, RelayMap, RelayMode, SecretKey,
    endpoint::{Connection, QuicTransportConfig, presets},
};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::{sync::Semaphore, task::JoinSet};

mod file_chunks;
mod legacy;
mod quic;
pub(crate) mod session;

const DIAL: Duration = Duration::from_millis(250);
const OPERATION: Duration = Duration::from_secs(3);
const BACKOFF: Duration = Duration::from_secs(30);

#[derive(Default)]
pub(crate) struct Metrics {
    sent: AtomicU64,
    received: AtomicU64,
    deliveries: AtomicU64,
    fallbacks: AtomicU64,
    connections: AtomicU64,
    reused: AtomicU64,
    streams: AtomicU64,
    dial_failures: AtomicU64,
    receipt_failures: AtomicU64,
    file_sent: AtomicU64,
    file_received: AtomicU64,
}
impl Metrics {
    pub(super) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "sent_packet_bytes": self.sent.load(Ordering::Relaxed),
            "received_packet_bytes": self.received.load(Ordering::Relaxed),
            "confirmed_batches": self.deliveries.load(Ordering::Relaxed),
            "fallbacks": self.fallbacks.load(Ordering::Relaxed),
            "connections_opened": self.connections.load(Ordering::Relaxed),
            "connections_reused": self.reused.load(Ordering::Relaxed),
            "binary_send_streams_opened": self.streams.load(Ordering::Relaxed),
            "dial_failures": self.dial_failures.load(Ordering::Relaxed),
            "receipt_failures": self.receipt_failures.load(Ordering::Relaxed),
            "sent_file_chunk_bytes": self.file_sent.load(Ordering::Relaxed),
            "received_file_chunk_bytes": self.file_received.load(Ordering::Relaxed),
            "scope": "Native QUIC process counters. Byte counts include binary batch framing on v2 and canonical packet bytes on v1. Excludes signed replies and QUIC overhead."
        })
    }
}

pub(crate) struct Direct {
    endpoint: Endpoint,
    connections: Arc<quic::Pool>,
    failed: Mutex<BTreeMap<EndpointId, Instant>>,
    in_flight: Semaphore,
    listener: JoinHandle<()>,
    files: file_chunks::Client,
    metrics: Arc<Metrics>,
}
impl Drop for Direct {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

impl Direct {
    pub(crate) async fn start(
        store: SharedStore,
        health: Arc<health::Health>,
    ) -> Result<Option<Arc<Self>>> {
        let settings = local(store.clone(), |s| s.direct_settings()).await?;
        if matches!(settings.direct, config::Direct::Off) {
            return Ok(None);
        }
        let relay = if settings.relays.is_empty() {
            RelayMode::Disabled
        } else {
            RelayMode::Custom(RelayMap::try_from_iter(
                settings.relays.iter().map(String::as_str),
            )?)
        };
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .alpns(vec![
                quic::ALPN.to_vec(),
                legacy::ALPN.to_vec(),
                file_chunks::ALPN.to_vec(),
            ])
            .transport_config(
                QuicTransportConfig::builder()
                    .max_concurrent_bidi_streams(1u32.into())
                    .max_concurrent_uni_streams(0u32.into())
                    .build(),
            )
            .clear_address_lookup()
            .relay_mode(relay)
            .bind()
            .await?;
        let metrics = Arc::new(Metrics::default());
        health.set_direct(metrics.clone());
        let connections = Arc::new(quic::Pool::default());
        let listener = tokio::spawn(listen(
            endpoint.clone(),
            connections.clone(),
            store,
            metrics.clone(),
        ));
        Ok(Some(Arc::new(Self {
            endpoint,
            connections,
            failed: Mutex::new(BTreeMap::new()),
            in_flight: Semaphore::new(quic::MAX_LINKS),
            listener,
            files: file_chunks::Client::default(),
            metrics,
        })))
    }

    pub(crate) async fn advertise(&self, store: SharedStore) -> Result<()> {
        let mut addr = self.endpoint.addr();
        addr.addrs = addr.addrs.into_iter().take(16).collect();
        local(store, move |s| s.advertise_direct(addr)).await
    }

    async fn connection(
        &self,
        addr: iroh::EndpointAddr,
        store: SharedStore,
    ) -> Result<Arc<quic::Link>> {
        if let Some(link) = self.connections.get(addr.id) {
            self.metrics.reused.fetch_add(1, Ordering::Relaxed);
            return Ok(link);
        }
        let conn = tokio::time::timeout(DIAL, quic::dial(&self.endpoint, addr)).await??;
        Ok(self
            .connections
            .install(self.endpoint.id(), conn, true, store, self.metrics.clone()))
    }

    fn fallback(&self, id: EndpointId) {
        self.metrics.fallbacks.fetch_add(1, Ordering::Relaxed);
        let mut failed = self.failed.lock().expect("direct backoff poisoned");
        failed.retain(|_, at| at.elapsed() < BACKOFF);
        failed.insert(id, Instant::now());
    }

    pub(crate) async fn transfer(
        &self,
        store: SharedStore,
        entry: &Stream,
        health: &health::Health,
        prepared: &mut transfer::Prepared,
    ) -> Option<Result<Option<session::Confirmed>>> {
        if entry.configuration || !entry.outgoing {
            return None;
        }
        let group = entry.group.clone();
        let addr = local(store.clone(), move |s| s.direct_target(&group))
            .await
            .ok()
            .flatten()?;
        let id = addr.id;
        if self
            .failed
            .lock()
            .expect("direct backoff poisoned")
            .get(&id)
            .is_some_and(|at| at.elapsed() < BACKOFF)
            && self.connections.get(id).is_none()
        {
            return None;
        }
        let _permit = self.in_flight.try_acquire().ok()?;
        let deadline = Instant::now() + OPERATION;
        let pending =
            match tokio::time::timeout_at(deadline, prepared.peer(store.clone(), &entry.group))
                .await
            {
                Ok(Ok(Some(pending))) => pending,
                Ok(Ok(None)) => {
                    health.idle(&entry.group);
                    return Some(Ok(None));
                }
                _ => {
                    self.metrics.fallbacks.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            };
        let link =
            match tokio::time::timeout_at(deadline, self.connection(addr, store.clone())).await {
                Ok(Ok(link)) => link,
                _ => {
                    self.metrics.dial_failures.fetch_add(1, Ordering::Relaxed);
                    self.fallback(id);
                    return None;
                }
            };
        let lane = link.reserve()?;
        let operation = async {
            if link.conn.alpn() == legacy::ALPN {
                let receipt = legacy::request(&link.conn, &entry.group, &pending.batch).await?;
                let sent = pending.batch.packets().iter().map(Vec::len).sum::<usize>();
                self.metrics.sent.fetch_add(sent as u64, Ordering::Relaxed);
                link.touch();
                pending.confirm(store, &entry.group, receipt).await
            } else {
                pending
                    .exchange(store, &entry.group, |bytes| {
                        link.exchange(lane, bytes, &self.metrics)
                    })
                    .await
            }
        };
        match tokio::time::timeout_at(deadline, operation).await {
            Ok(Ok(confirmed)) => {
                self.metrics.deliveries.fetch_add(1, Ordering::Relaxed);
                Some(Ok(Some(confirmed)))
            }
            _ => {
                self.metrics
                    .receipt_failures
                    .fetch_add(1, Ordering::Relaxed);
                link.conn.close(1u32.into(), b"retry through mailbox");
                self.fallback(id);
                None
            }
        }
    }
}

async fn listen(
    endpoint: Endpoint,
    pool: Arc<quic::Pool>,
    store: SharedStore,
    metrics: Arc<Metrics>,
) {
    let limit = Arc::new(Semaphore::new(quic::MAX_LINKS));
    let file_limit = Arc::new(Semaphore::new(2));
    let mut tasks = JoinSet::new();
    let mut prune = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            _ = prune.tick() => pool.prune(),
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let local_id = endpoint.id();
                let store = store.clone();
                let pool = pool.clone();
                let metrics = metrics.clone();
                let file_limit = file_limit.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(5), incoming).await else {
                        return;
                    };
                    let id = conn.remote_id();
                    if local(store.clone(), move |s| s.direct_allowed(id)).await.is_err() {
                        conn.close(1u32.into(), b"unrecognized node");
                    } else if conn.alpn() == quic::ALPN {
                        pool.install(local_id, conn, false, store, metrics);
                    } else if conn.alpn() == file_chunks::ALPN {
                        if let Ok(_file) = file_limit.try_acquire() {
                            let _ = file_chunks::serve(&conn, store, &metrics).await;
                        }
                        conn.close(0u32.into(), b"file session ended");
                    } else {
                        let _ = legacy::serve(&conn, store, metrics).await;
                        conn.close(0u32.into(), b"legacy session ended");
                    }
                });
            }
        }
    }
}
