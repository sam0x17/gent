//! Opportunistic peer delivery of the same durable MLS history as the mailbox.
use super::*;
use crate::store::direct::{HelperPeer, NativeTarget};
use gent_protocol::transport_batch::Batch;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey, TransportAddr,
    endpoint::{Connection, QuicTransportConfig, presets},
};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::{sync::Semaphore, task::JoinSet};

pub(crate) mod board_html;
mod file_chunks;
mod helper_routes;
mod helper_service;
mod hosting;
mod legacy;
mod path;
mod pull;
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
    helper: Arc<iroh_relay::server::Metrics>,
}
impl Metrics {
    pub(super) fn snapshot(&self) -> serde_json::Value {
        let helper = &self.helper;
        serde_json::json!({
            "helper_forwarded_bytes": helper.bytes_sent.get(),
            "helper_received_bytes": helper.bytes_recv.get(),
            "helper_registrations": helper.accepts.get(),
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
            "scope": "Process totals for native QUIC and the local helper. Helper bytes count forwarded relay payload. Byte counts include binary batch framing on v2 and canonical packet bytes on v1. Excludes signed replies and QUIC overhead."
        })
    }
}

pub(crate) struct Direct {
    endpoint: Endpoint,
    connections: Arc<quic::Pool>,
    primary_relays: Vec<RelayUrl>,
    udp: bool,
    routes: helper_routes::Routes,
    hosting: hosting::Hosting,
    failed: Mutex<BTreeMap<EndpointId, Instant>>,
    in_flight: Semaphore,
    listener: JoinHandle<()>,
    files: pull::Pool,
    boards: pull::Pool,
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
        let (settings, node, wakeup) = local(store.clone(), |s| {
            Ok((
                s.configured_transport()?,
                s.local_node_id().to_owned(),
                s.sync_wakeup.clone(),
            ))
        })
        .await?;
        if matches!(settings.direct, config::Direct::Off) {
            return Ok(None);
        }
        let map = RelayMap::try_from_iter(settings.relays.iter().map(String::as_str))?;
        let primary_relays = map.urls::<Vec<_>>();
        // TCP-only nodes still need an endpoint ID even before their first
        // authenticated helper offer arrives. An empty custom map enables the
        // transport without contacting the public Iroh relay network.
        let relay = if primary_relays.is_empty() && settings.udp {
            RelayMode::Disabled
        } else {
            RelayMode::Custom(map)
        };
        let key = SecretKey::generate();
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(key.clone())
            .alpns(vec![
                quic::ALPN.to_vec(),
                legacy::ALPN.to_vec(),
                file_chunks::ALPN.to_vec(),
                board_html::ALPN.to_vec(),
            ])
            .transport_config(
                QuicTransportConfig::builder()
                    .max_concurrent_bidi_streams(1u32.into())
                    .max_concurrent_uni_streams(0u32.into())
                    .build(),
            )
            .clear_address_lookup()
            .relay_mode(relay);
        if !settings.udp {
            builder = builder.clear_ip_transports();
        }
        let endpoint = builder.bind().await?;
        let metrics = Arc::new(Metrics::default());
        health.set_direct(metrics.clone());
        let connections = Arc::new(quic::Pool::default());
        let udp = settings.udp;
        let hosting = hosting::Hosting::start(
            store.clone(),
            endpoint.id(),
            node,
            settings,
            metrics.helper.clone(),
            wakeup.clone(),
        );
        let routes = helper_routes::Routes::new(
            key,
            primary_relays.clone(),
            udp,
            store.clone(),
            metrics.clone(),
            wakeup,
        );
        let listener = tokio::spawn(listen(
            endpoint.clone(),
            connections.clone(),
            store.clone(),
            metrics.clone(),
        ));
        let transport = Arc::new(Self {
            endpoint,
            connections,
            primary_relays,
            udp,
            routes,
            hosting,
            failed: Mutex::new(BTreeMap::new()),
            in_flight: Semaphore::new(quic::MAX_LINKS),
            listener,
            files: pull::Pool::default(),
            boards: pull::Pool::default(),
            metrics,
        });
        let weak = Arc::downgrade(&transport);
        local(store, move |s| {
            s.board_transport = weak;
            Ok(())
        })
        .await?;
        Ok(Some(transport))
    }

    pub(crate) async fn advertise(&self, store: SharedStore) -> Result<()> {
        let mut addr = self.endpoint.addr();
        addr.addrs = addr.addrs.into_iter().take(16).collect();
        let offer = self.hosting.offer();
        let registrations = self.routes.registrations();
        let offers = local(store, move |s| {
            s.advertise_direct_with_helpers(addr, offer, registrations)?;
            s.helper_authorities()
        })
        .await?;
        self.routes.refresh(offers).await;
        Ok(())
    }

    fn primary_address(&self, mut addr: EndpointAddr) -> EndpointAddr {
        addr.addrs.retain(|a| match a {
            TransportAddr::Ip(_) => self.udp,
            TransportAddr::Relay(url) => self.primary_relays.contains(url),
            _ => false,
        });
        addr
    }

    fn primary_backoff(&self, id: EndpointId) {
        let mut failed = self.failed.lock().expect("direct backoff poisoned");
        failed.retain(|_, at| at.elapsed() < BACKOFF);
        failed.insert(id, Instant::now());
    }

    async fn primary_connection(
        &self,
        addr: EndpointAddr,
        store: SharedStore,
    ) -> Option<Arc<quic::Link>> {
        let id = addr.id;
        if let Some(link) = self.connections.get(id) {
            self.metrics.reused.fetch_add(1, Ordering::Relaxed);
            return Some(link);
        }
        let addr = self.primary_address(addr);
        let cooling = self
            .failed
            .lock()
            .expect("direct backoff poisoned")
            .get(&id)
            .is_some_and(|at| at.elapsed() < BACKOFF);
        if !addr.addrs.is_empty() && !cooling {
            if let Ok(Ok(conn)) = tokio::time::timeout(DIAL, quic::dial(&self.endpoint, addr)).await
            {
                return Some(self.connections.install(
                    self.endpoint.id(),
                    conn,
                    true,
                    store,
                    self.metrics.clone(),
                    None,
                ));
            }
            self.metrics.dial_failures.fetch_add(1, Ordering::Relaxed);
            self.primary_backoff(id);
        }
        None
    }

    async fn send_batch(
        &self,
        link: &quic::Link,
        store: SharedStore,
        group: &[u8],
        pending: &transfer::outgoing::Pending,
        health: &health::Health,
        deadline: Instant,
    ) -> Option<session::Confirmed> {
        let pin = link.pin.clone();
        let g = group.to_vec();
        let direct = selected_ip(&link.conn);
        tokio::time::timeout_at(
            deadline,
            local(store.clone(), move |s| {
                let peer = s.session_peer(&g, true)?;
                if let Some(pin) = pin {
                    authorize_session_path(s, &pin, &peer, direct)?;
                }
                Ok(())
            }),
        )
        .await
        .ok()?
        .ok()?;
        let lane = link.reserve()?;
        let before = path::Frames::read(&link.conn);
        let operation = async {
            if link.conn.alpn() == legacy::ALPN {
                let receipt = legacy::request(&link.conn, group, &pending.batch).await?;
                let sent = pending.batch.packets().iter().map(Vec::len).sum::<usize>();
                self.metrics.sent.fetch_add(sent as u64, Ordering::Relaxed);
                link.touch();
                pending.confirm(store, group, receipt).await
            } else {
                pending
                    .exchange(store, group, |bytes| {
                        link.exchange(lane, bytes, &self.metrics)
                    })
                    .await
            }
        };
        match tokio::time::timeout_at(deadline, operation).await {
            Ok(Ok(confirmed)) => {
                let path =
                    path::Frames::read(&link.conn).exchange(before, link.helper_id.as_deref());
                health.record_transport(
                    group,
                    path,
                    health::TransportEvidence::SignedReceipt,
                    // A concurrent carrier can advance the saved receipt beyond this batch.
                    confirmed.last,
                );
                self.metrics.deliveries.fetch_add(1, Ordering::Relaxed);
                Some(confirmed)
            }
            _ => {
                self.metrics
                    .receipt_failures
                    .fetch_add(1, Ordering::Relaxed);
                link.conn.close(1u32.into(), b"batch exchange failed");
                None
            }
        }
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
        let target = local(store.clone(), move |s| s.direct_target(&group))
            .await
            .ok()
            .flatten()?;
        let id = target.id();
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
        if let NativeTarget::Advertised(addr) = target
            && let Ok(Some(link)) =
                tokio::time::timeout_at(deadline, self.primary_connection(addr, store.clone()))
                    .await
        {
            if let Some(confirmed) = self
                .send_batch(
                    &link,
                    store.clone(),
                    &entry.group,
                    pending,
                    health,
                    deadline,
                )
                .await
            {
                return Some(Ok(Some(confirmed)));
            }
            if link.conn.close_reason().is_some() {
                self.primary_backoff(id);
            }
        }
        // An early primary failure leaves time to replay the same ciphertext
        // through a qualified helper inside the original delivery deadline.
        let helper_link = async {
            let candidates = local(store.clone(), move |s| s.helper_hints(id))
                .await
                .ok()?;
            self.routes.chat(id, &candidates).await
        };
        if Instant::now() < deadline
            && let Ok(Some(link)) = tokio::time::timeout_at(deadline, helper_link).await
            && let Some(confirmed) = self
                .send_batch(&link, store, &entry.group, pending, health, deadline)
                .await
        {
            return Some(Ok(Some(confirmed)));
        }
        self.metrics.fallbacks.fetch_add(1, Ordering::Relaxed);
        None
    }
}

fn selected_ip(conn: &Connection) -> bool {
    conn.paths()
        .iter()
        .any(|path| path.is_selected() && matches!(path.remote_addr(), TransportAddr::Ip(_)))
}

fn authorize_session_path(store: &Store, pin: &HelperPeer, peer: &str, direct: bool) -> Result<()> {
    if direct
        && store
            .direct_binding(pin.endpoint(), true)
            .is_ok_and(|(id, _)| id == peer)
    {
        return Ok(());
    }
    store.authorize_helper_peer(pin, Some(peer))
}

async fn listen(
    endpoint: Endpoint,
    pool: Arc<quic::Pool>,
    store: SharedStore,
    metrics: Arc<Metrics>,
) {
    let limit = Arc::new(Semaphore::new(quic::MAX_LINKS));
    let file_limit = Arc::new(Semaphore::new(2));
    let board_limit = Arc::new(Semaphore::new(4));
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
                let board_limit = board_limit.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(5), incoming).await else {
                        return;
                    };
                    let id = conn.remote_id();
                    if local(store.clone(), move |s| s.direct_allowed(id)).await.is_err() {
                        conn.close(1u32.into(), b"unrecognized node");
                    } else if conn.alpn() == quic::ALPN {
                        pool.install(local_id, conn, false, store, metrics, None);
                    } else if conn.alpn() == board_html::ALPN {
                        if let Ok(_board) = board_limit.try_acquire() {
                            let _ = board_html::serve(&conn, store).await;
                        }
                        conn.close(0u32.into(), b"board session ended");
                    } else if conn.alpn() == file_chunks::ALPN {
                        if let Ok(_file) = file_limit.try_acquire() {
                            let _ = file_chunks::serve(&conn, store, &metrics, None).await;
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
