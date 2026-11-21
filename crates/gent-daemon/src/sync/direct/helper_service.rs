//! Cluster-authenticated TCP relay and UDP QUIC address discovery.
use crate::{
    config,
    store::direct::HelperOffer,
    sync::{SharedStore, local},
};
use anyhow::{Context, Result, ensure};
use iroh::{EndpointId, RelayUrl};
use iroh_relay::{
    KeyCache,
    quic::ALPN_QUIC_ADDR_DISC,
    server::{
        Access, AccessControl, ClientRateLimit, ClientRequest, ConnectionId, Handlers, Metrics,
        RelayService,
        http_server::{BytesBody, TlsConfig},
    },
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpSocket},
    sync::{Semaphore, oneshot},
    task::{JoinHandle, JoinSet},
    time::{self, Instant},
};

const DEFAULT_PORT: u16 = 7842;
const MAX_ALIASES: usize = 8;
const MAX_CLIENTS: usize = 32;
const ESTABLISH: Duration = Duration::from_secs(5);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(8);
const RECHECK: Duration = Duration::from_secs(3);
const DB_TIMEOUT: Duration = Duration::from_secs(1);

type Binding = (String, [u8; 32]);

#[derive(Debug, Default)]
struct Registrations {
    closed: bool,
    live: BTreeMap<EndpointId, (ConnectionId, Binding)>,
}

impl Registrations {
    fn accepts(&self, id: EndpointId) -> bool {
        !self.closed && self.live.len() < MAX_CLIENTS && !self.live.contains_key(&id)
    }
}

struct Admission {
    store: SharedStore,
    own: EndpointId,
    node: String,
    registrations: Mutex<Registrations>,
    auth_slots: Arc<Semaphore>,
    sweep_slot: Arc<Semaphore>,
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admission").finish_non_exhaustive()
    }
}

impl Admission {
    fn new(store: SharedStore, own: EndpointId, node: String) -> Self {
        Self {
            store,
            own,
            node,
            registrations: Mutex::default(),
            auth_slots: Arc::new(Semaphore::new(4)),
            sweep_slot: Arc::new(Semaphore::new(1)),
        }
    }

    // Keep the permit in the blocking closure. A store operation that outlives
    // its caller's timeout cannot accumulate unbounded background work.
    async fn bindings(
        &self,
        ids: Vec<EndpointId>,
        fresh: bool,
    ) -> Result<BTreeMap<EndpointId, Binding>> {
        let slots = if fresh {
            &self.auth_slots
        } else {
            &self.sweep_slot
        };
        let permit = slots.clone().try_acquire_owned()?;
        let own = self.own;
        let node = self.node.clone();
        time::timeout(
            DB_TIMEOUT,
            local(self.store.clone(), move |store| {
                let _permit = permit;
                ensure!(
                    matches!(store.direct_settings()?.helper, config::Direct::Auto),
                    "helper disabled"
                );
                let host = store.direct_binding(own, false)?;
                ensure!(host.0 == node, "host endpoint belongs to a different node");
                Ok(ids
                    .into_iter()
                    .filter_map(|id| {
                        if id == own && !fresh {
                            Some((id, host.clone()))
                        } else {
                            store
                                .direct_binding(id, fresh)
                                .ok()
                                .map(|binding| (id, binding))
                        }
                    })
                    .collect())
            }),
        )
        .await?
    }

    async fn revalidate(&self, service: &RelayService) {
        let sessions = self.registrations.lock().unwrap().live.clone();
        if sessions.is_empty() {
            return;
        }
        let allowed = self
            .bindings(sessions.keys().copied().collect(), false)
            .await
            .unwrap_or_default();
        for (id, (connection, binding)) in sessions {
            if allowed.get(&id) != Some(&binding) {
                // A late result for an old connection must never evict its replacement.
                service.clients().disconnect(id, Some(connection));
            }
        }
    }

    fn close(&self) {
        self.registrations.lock().unwrap().closed = true;
    }
}

impl AccessControl for Admission {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let id = request.endpoint_id(); // authenticated by Iroh before this hook
        if !self.registrations.lock().unwrap().accepts(id) {
            return Access::Deny { reason: None };
        }
        if let Ok(mut allowed) = self.bindings(vec![id], true).await
            && let Some(binding) = allowed.remove(&id)
        {
            let mut state = self.registrations.lock().unwrap();
            if state.accepts(id) {
                state.live.insert(id, (request.connection_id(), binding));
                return Access::Allow;
            }
        }
        Access::Deny { reason: None }
    }

    fn on_disconnect(&self, id: EndpointId, connection: ConnectionId) {
        let mut state = self.registrations.lock().unwrap();
        if state
            .live
            .get(&id)
            .is_some_and(|(current, _)| *current == connection)
        {
            state.live.remove(&id);
        }
    }
}

fn sockets(
    ip: Ipv4Addr,
    port: Option<u16>,
    udp: bool,
    public: Option<SocketAddr>,
) -> io::Result<(TcpListener, Option<UdpSocket>)> {
    let bind = |p| -> io::Result<_> {
        let socket = TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;
        socket.bind((ip, p).into())?;
        let tcp = socket.listen(32)?;
        let local = tcp.local_addr()?;
        // The offer carries a single QAD port for every alias. A translated
        // TCP port gives us no UDP mapping valid for both aliases.
        let datagrams = if udp && public.is_none_or(|addr| addr.port() == local.port()) {
            Some(UdpSocket::bind(local)?)
        } else {
            None
        };
        Ok((tcp, datagrams))
    };
    let requested = port.unwrap_or(DEFAULT_PORT);
    let mut result = bind(requested);
    // An ephemeral TCP allocation can also collide with an existing UDP listener.
    if port.is_none() || requested == 0 {
        for _ in 0..8 {
            if !result
                .as_ref()
                .is_err_and(|e| e.kind() == io::ErrorKind::AddrInUse)
            {
                break;
            }
            result = bind(0);
        }
    }
    result
}

fn usable(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if !v4.is_unspecified() && !v4.is_multicast() && !v4.is_broadcast())
}

fn identity(
    node_id: String,
    ips: Vec<IpAddr>,
    port: u16,
    public: Option<SocketAddr>,
    has_qad_socket: bool,
) -> Result<(HelperOffer, rustls::ServerConfig)> {
    let mut local: Vec<_> = ips
        .into_iter()
        .filter(|ip| usable(*ip))
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    local.sort_by_key(|addr| (addr.ip().is_loopback(), *addr));
    local.dedup();
    if local.is_empty() {
        local.push((Ipv4Addr::LOCALHOST, port).into());
    }
    if let Some(public) = public {
        ensure!(
            usable(public.ip()) && public.port() != 0,
            "invalid public helper address"
        );
        local.retain(|addr| *addr != public);
        local.insert(0, public);
    }
    local.truncate(MAX_ALIASES);
    let mut sans: Vec<_> = local.iter().map(|addr| addr.ip().to_string()).collect();
    sans.sort();
    sans.dedup();
    let cert = rcgen::generate_simple_self_signed(sans)?;
    let der = cert.cert.der().clone();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![der.clone()],
        PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )?;
    let url = |addr: SocketAddr| format!("https://{addr}/").parse::<RelayUrl>();
    let offer = HelperOffer {
        helper_node: node_id,
        urls: local.into_iter().map(url).collect::<Result<_, _>>()?,
        generation: Sha256::digest(der.as_ref()).into(),
        cert_der: der.to_vec(),
        qad_port: has_qad_socket.then_some(port),
    };
    Ok((offer, tls))
}

// Iroh QAD uses the QUIC observed-address extension. This listener never
// opens streams or accepts application DATAGRAM frames.
fn qad_endpoint(socket: UdpSocket, mut tls: rustls::ServerConfig) -> Result<noq::Endpoint> {
    tls.alpn_protocols = vec![ALPN_QUIC_ADDR_DISC.to_vec()];
    let crypto = noq::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = noq::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = noq::TransportConfig::default();
    transport
        .send_observed_address_reports(true)
        .max_concurrent_uni_streams(0u8.into())
        .max_concurrent_bidi_streams(0u8.into())
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0)
        .max_idle_timeout(Some(Duration::from_secs(10).try_into()?));
    config
        .transport_config(Arc::new(transport))
        .max_incoming(32)
        .incoming_buffer_size(16 * 1024)
        .incoming_buffer_size_total(256 * 1024);
    socket.set_nonblocking(true)?;
    Ok(noq::Endpoint::new(
        Default::default(),
        Some(config),
        socket,
        noq::default_runtime().context("missing QAD runtime")?,
    )?)
}

async fn serve_qad(endpoint: noq::Endpoint, metrics: Arc<Metrics>) {
    let mut connections = JoinSet::new();
    while let Some(incoming) = endpoint.accept().await {
        while connections.try_join_next().is_some() {}
        if connections.len() >= MAX_CLIENTS {
            incoming.ignore();
        } else if !incoming.remote_address_validated() {
            if incoming.may_retry() {
                let _ = incoming.retry();
            } else {
                incoming.ignore();
            }
        } else {
            let metrics = metrics.clone();
            connections.spawn(async move {
                metrics.qad_incoming.inc();
                let Ok(Ok(conn)) = time::timeout(ESTABLISH, incoming).await else {
                    metrics.qad_incoming_error.inc();
                    return;
                };
                metrics.qad_connections.inc();
                match time::timeout(Duration::from_secs(120), conn.closed()).await {
                    Ok(noq::ConnectionError::LocallyClosed) => {}
                    Ok(noq::ConnectionError::ApplicationClosed(close))
                        if close.error_code == iroh_relay::quic::QUIC_ADDR_DISC_CLOSE_CODE => {}
                    Ok(_) => {
                        metrics.qad_connections_errored.inc();
                    }
                    Err(_) => conn.close(1u8.into(), b"finished"),
                }
                metrics.qad_connections_closed.inc();
            });
        }
        // Bound the rate of new handshake work as well as simultaneous QAD clients.
        time::sleep(Duration::from_millis(20)).await;
    }
    while connections.join_next().await.is_some() {}
}

pub(super) struct ListenerConfig {
    pub(super) advertised_ips: Vec<IpAddr>,
    pub(super) port: Option<u16>,
    pub(super) public_address: Option<SocketAddr>,
    pub(super) udp: bool,
}

pub(super) struct HelperService {
    offer: HelperOffer,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl HelperService {
    pub(super) async fn start(
        store: SharedStore,
        local_endpoint: EndpointId,
        node_id: String,
        listener: ListenerConfig,
        counters: Arc<Metrics>,
    ) -> Result<Self> {
        Self::bind(
            store,
            local_endpoint,
            node_id,
            listener,
            Ipv4Addr::UNSPECIFIED,
            counters,
        )
    }

    fn bind(
        store: SharedStore,
        local_endpoint: EndpointId,
        node_id: String,
        listener: ListenerConfig,
        bind_ip: Ipv4Addr,
        counters: Arc<Metrics>,
    ) -> Result<Self> {
        let (tcp, socket) = sockets(
            bind_ip,
            listener.port,
            listener.udp,
            listener.public_address,
        )?;
        let (offer, tls) = identity(
            node_id,
            listener.advertised_ips,
            tcp.local_addr()?.port(),
            listener.public_address,
            socket.is_some(),
        )?;
        let qad = socket.map(|s| qad_endpoint(s, tls.clone())).transpose()?;
        let admission = Arc::new(Admission::new(
            store,
            local_endpoint,
            offer.helper_node.clone(),
        ));
        let (stop, shutdown) = oneshot::channel();
        let task = tokio::spawn(serve(
            tcp,
            qad,
            TlsConfig::new(Arc::new(tls)),
            admission,
            counters,
            shutdown,
        ));
        Ok(Self { offer, stop, task })
    }

    pub(super) fn offer(&self) -> &HelperOffer {
        &self.offer
    }

    pub(super) async fn shutdown(self) {
        drop(self.stop);
        let _ = self.task.await;
    }
}

async fn serve(
    tcp: TcpListener,
    qad: Option<noq::Endpoint>,
    tls: TlsConfig,
    admission: Arc<Admission>,
    counters: Arc<Metrics>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut handlers = Handlers::default();
    handlers.insert(
        (http::Method::GET, "/ping"),
        Box::new(|_, res| Ok(res.body::<BytesBody>(Box::new(String::new()))?)),
    );
    let mut rate = ClientRateLimit::new(NonZeroU32::new(2 * 1024 * 1024).unwrap());
    rate.max_burst_bytes = NonZeroU32::new(256 * 1024);
    let service = RelayService::new(
        handlers,
        Default::default(),
        Some(rate),
        KeyCache::new(64),
        admission.clone(),
        counters.clone(),
    );
    let mut connections = JoinSet::new();
    let mut qad_task = qad.clone().map(|ep| tokio::spawn(serve_qad(ep, counters)));
    let mut check = time::interval(RECHECK);
    check.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut next_accept = Instant::now();
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = check.tick() => admission.revalidate(&service).await,
            Some(_) = connections.join_next() => {}
            incoming = async { time::sleep_until(next_accept).await; tcp.accept().await }, if connections.len() < 32 => {
                // Includes pre-registration sockets. An upgraded socket has its own Iroh establishment deadline.
                next_accept = Instant::now() + Duration::from_millis(50);
                if let Ok((io, _)) = incoming {
                    connections.spawn(service.clone().handle_connection(io, Some(tls.clone()), ESTABLISH));
                }
            }
        }
    }
    admission.close();
    drop(tcp);
    if let Some(ep) = &qad {
        ep.close(1u8.into(), b"shutdown");
    }
    let drain = async {
        // An admitted socket may still be between the access hook and registration.
        loop {
            service.shutdown().await;
            if admission.registrations.lock().unwrap().live.is_empty() {
                break;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        // Let pending TLS/HTTP setups finish their own deadline and record
        // their close in the caller's process-lifetime metrics.
        while connections.join_next().await.is_some() {}
        if let Some(task) = &mut qad_task {
            let _ = task.await;
        }
        if let Some(ep) = &qad {
            ep.wait_idle().await;
        }
    };
    if time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
        if let Some(task) = qad_task {
            task.abort();
        }
        eprintln!("Gent cluster helper reached its shutdown deadline");
    }
}

#[cfg(test)]
mod tests;
