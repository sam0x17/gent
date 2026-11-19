//! Opportunistic QUIC delivery of the exact durable MLS packets. Cloud fallback
//! remains authoritative for availability; only signed receipts retire history.
use super::*;
use base64::engine::general_purpose::STANDARD;
use gent_protocol::transport_batch::Batch;
use iroh::{
    Endpoint, EndpointId, RelayMap, RelayMode, SecretKey,
    endpoint::{Connection, presets},
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::{sync::Semaphore, task::JoinSet};

const ALPN: &[u8] = b"gent/mls-stream/1";
const LIMIT: usize = 3 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    group: String,
    batch: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u8,
    receipt: String,
}
#[derive(Default)]
pub(super) struct Metrics {
    sent: AtomicU64,
    received: AtomicU64,
    deliveries: AtomicU64,
    fallbacks: AtomicU64,
    connections: AtomicU64,
}
impl Metrics {
    pub(super) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"sent_packet_bytes":self.sent.load(Ordering::Relaxed),"received_packet_bytes":self.received.load(Ordering::Relaxed),"confirmed_batches":self.deliveries.load(Ordering::Relaxed),"fallbacks":self.fallbacks.load(Ordering::Relaxed),"connections_opened":self.connections.load(Ordering::Relaxed),"scope":"Authenticated native transport, process counters; packet bytes exclude QUIC and discovery overhead."})
    }
}
pub(crate) struct Direct {
    endpoint: Endpoint,
    connections: Mutex<BTreeMap<EndpointId, (Connection, Instant)>>,
    failed: Mutex<BTreeMap<EndpointId, Instant>>,
    listener: JoinHandle<()>,
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
            .alpns(vec![ALPN.to_vec()])
            .clear_address_lookup()
            .relay_mode(relay)
            .bind()
            .await?;
        let metrics = Arc::new(Metrics::default());
        health.set_direct(metrics.clone());
        let acceptor = endpoint.clone();
        let measured = metrics.clone();
        let listener = tokio::spawn(async move {
            let limit = Arc::new(Semaphore::new(16));
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                    incoming=acceptor.accept()=>{
                        let Some(incoming)=incoming else {break;};
                        let Ok(permit)=limit.clone().try_acquire_owned() else {incoming.refuse();continue;};
                        let store=store.clone();let metrics=measured.clone();let health=health.clone();
                        tasks.spawn(async move {
                            let _permit=permit;
                            if let Ok(Ok(conn))=tokio::time::timeout(Duration::from_secs(5),incoming).await {
                                let id=conn.remote_id();
                                if local(store.clone(),move|s|s.direct_allowed(id)).await.is_err() {conn.close(1u32.into(),b"unrecognized node");return;}
                                let _=serve(&conn,store,metrics,health).await;
                                conn.close(0u32.into(),b"direct session ended");
                            }
                        });
                    }
                }
            }
        });
        Ok(Some(Arc::new(Self {
            endpoint,
            connections: Mutex::new(BTreeMap::new()),
            failed: Mutex::new(BTreeMap::new()),
            listener,
            metrics,
        })))
    }
    pub(crate) async fn advertise(&self, store: SharedStore) -> Result<()> {
        let mut addr = self.endpoint.addr();
        addr.addrs = addr.addrs.into_iter().take(16).collect();
        local(store, move |s| s.advertise_direct(addr)).await
    }
    async fn connection(&self, addr: iroh::EndpointAddr) -> Result<Connection> {
        let id = addr.id;
        {
            let mut saved = self
                .connections
                .lock()
                .expect("direct connections poisoned");
            saved.retain(|_, (c, used)| {
                let alive = c.close_reason().is_none() && used.elapsed() < Duration::from_secs(60);
                if !alive {
                    c.close(0u32.into(), b"idle");
                }
                alive
            });
            if let Some((conn, used)) = saved.get_mut(&id) {
                *used = Instant::now();
                return Ok(conn.clone());
            }
        }
        let conn = tokio::time::timeout(
            Duration::from_millis(250),
            self.endpoint.connect(addr, ALPN),
        )
        .await??;
        let mut saved = self
            .connections
            .lock()
            .expect("direct connections poisoned");
        if saved.len() >= 16
            && let Some(old) = saved
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(id, _)| *id)
            && let Some((conn, _)) = saved.remove(&old)
        {
            conn.close(0u32.into(), b"connection limit");
        }
        saved.insert(id, (conn.clone(), Instant::now()));
        self.metrics.connections.fetch_add(1, Ordering::Relaxed);
        Ok(conn)
    }
    pub(crate) async fn transfer(
        &self,
        store: SharedStore,
        entry: &Stream,
        health: &health::Health,
        wakeup: Arc<Notify>,
    ) -> Option<Result<Option<u64>>> {
        if entry.configuration || !entry.outgoing {
            return None;
        }
        let group = entry.group.clone();
        let addr = local(store.clone(), move |s| {
            if matches!(s.direct_settings()?.direct, config::Direct::Off) {
                return Ok(None);
            }
            s.direct_target(&group)
        })
        .await
        .ok()
        .flatten()?;
        let id = addr.id;
        if self
            .failed
            .lock()
            .expect("direct backoff poisoned")
            .get(&id)
            .is_some_and(|at| at.elapsed() < Duration::from_secs(30))
        {
            return None;
        }
        let operation = async {
            let conn = self.connection(addr).await?;
            let receipt = request(&conn, &entry.group, &Batch::default()).await?;
            let group = entry.group.clone();
            let next = local(store.clone(), move |s| {
                let receipt = s
                    .transport_confirm(&group, false, Some(&receipt))?
                    .context("missing verified direct receipt")?;
                Ok(receipt.sequence() + 1)
            })
            .await?;
            let batch = super::transfer::outgoing::prepare(
                store.clone(),
                &entry.group,
                false,
                next,
                wakeup,
            )
            .await?;
            if batch.packets().is_empty() {
                health.idle(&entry.group);
                return Ok(None);
            }
            let receipt = request(&conn, &entry.group, &batch).await?;
            let last = next + batch.packets().len() as u64 - 1;
            ensure!(
                receipt.sequence() >= last,
                "direct receiver did not commit batch"
            );
            let group = entry.group.clone();
            local(store, move |s| {
                s.transport_confirm(&group, false, Some(&receipt))?;
                Ok(())
            })
            .await?;
            for packet in batch.packets() {
                self.metrics
                    .sent
                    .fetch_add(packet.len() as u64, Ordering::Relaxed);
                health.progress(&entry.group, true, crate::store::now());
            }
            self.metrics.deliveries.fetch_add(1, Ordering::Relaxed);
            Ok(Some(last))
        };
        match tokio::time::timeout(Duration::from_secs(3), operation).await {
            Ok(Ok(result)) => {
                self.failed
                    .lock()
                    .expect("direct backoff poisoned")
                    .remove(&id);
                Some(Ok(result))
            }
            _ => {
                self.metrics.fallbacks.fetch_add(1, Ordering::Relaxed);
                let mut failed = self.failed.lock().expect("direct backoff poisoned");
                failed.retain(|_, at| at.elapsed() < Duration::from_secs(30));
                failed.insert(id, Instant::now());
                if let Some((conn, _)) = self
                    .connections
                    .lock()
                    .expect("direct connections poisoned")
                    .remove(&id)
                {
                    conn.close(1u32.into(), b"retry through mailbox");
                }
                None
            }
        }
    }
}
async fn request(conn: &Connection, group: &[u8], batch: &Batch) -> Result<Receipt> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let body = serde_json::to_vec(&Request {
        version: 1,
        group: URL_SAFE_NO_PAD.encode(group),
        batch: STANDARD.encode(batch.encode()),
    })?;
    ensure!(body.len() <= LIMIT, "direct batch too large");
    send.write_all(&body).await?;
    send.finish()?;
    let response: Response = serde_json::from_slice(&recv.read_to_end(8192).await?)?;
    ensure!(response.version == 1, "unsupported direct response");
    Receipt::decode(&STANDARD.decode(response.receipt)?)
}
async fn serve(
    conn: &Connection,
    store: SharedStore,
    metrics: Arc<Metrics>,
    health: Arc<health::Health>,
) -> Result<()> {
    loop {
        let (mut send, mut recv) =
            tokio::time::timeout(Duration::from_secs(60), conn.accept_bi()).await??;
        tokio::time::timeout(Duration::from_secs(5), async {
            let body = recv.read_to_end(LIMIT).await?;
            let request: Request = serde_json::from_slice(&body)?;
            ensure!(
                request.version == 1 && request.group.len() <= 384,
                "invalid direct request"
            );
            let group = URL_SAFE_NO_PAD.decode(request.group)?;
            let batch = Batch::decode(&STANDARD.decode(request.batch)?)?;
            let bytes = batch.packets().iter().map(Vec::len).sum::<usize>();
            let count = batch.packets().len();
            let packets = batch
                .packets()
                .iter()
                .map(|b| Packet::decode(b))
                .collect::<Result<Vec<_>>>()?;
            let remote = conn.remote_id();
            let received_group = group.clone();
            let receipt = local(store.clone(), move |s| {
                s.direct_receive(remote, &received_group, packets)
            })
            .await?;
            metrics.received.fetch_add(bytes as u64, Ordering::Relaxed);
            for _ in 0..count {
                health.progress(&group, false, crate::store::now());
            }
            let bytes = serde_json::to_vec(&Response {
                version: 1,
                receipt: STANDARD.encode(receipt.encode()?),
            })?;
            send.write_all(&bytes).await?;
            send.finish()?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    }
}
