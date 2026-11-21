//! One Iroh identity/socket per helper service, with its own relay map, trust
//! anchor and application connections. All enrolled peers share that socket.
use super::*;
use iroh::{EndpointAddr, NetReportConfig, RelayConfig, Watcher};
use iroh_relay::{RelayQuicConfig, tls::CaTlsConfig};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Kind {
    Chat,
    File,
}
impl Kind {
    fn alpn(self) -> &'static [u8] {
        match self {
            Self::Chat => quic::ALPN,
            Self::File => file_chunks::ALPN,
        }
    }
}

#[derive(Clone)]
pub(super) enum Application {
    Chat(Arc<quic::Link>),
    File(Connection),
}
#[derive(Clone)]
pub(super) struct Live {
    pub(super) application: Application,
    pub(super) proof: Arc<Proof>,
    dialed: bool,
}

type Pair = (EndpointId, Kind);

pub(super) struct Auxiliary {
    pub(super) offer: Arc<HelperOffer>,
    pub(super) endpoint: Endpoint,
    pub(super) relay_config: RelayConfig,
    active: tokio::sync::watch::Receiver<bool>,
    published: Mutex<Option<HelperRegistration>>,
    chats: quic::Pool,
    incoming_files: Arc<Mutex<BTreeMap<usize, Arc<Proof>>>>,
    live: Mutex<BTreeMap<Pair, Live>>,
    failures: Mutex<BTreeMap<Pair, Instant>>,
    opening: Mutex<BTreeSet<Pair>>,
    store: SharedStore,
    metrics: Arc<Metrics>,
}

impl Auxiliary {
    pub(super) async fn bind(
        key: SecretKey,
        offer: Arc<HelperOffer>,
        alias: &RelayUrl,
        udp: bool,
        store: SharedStore,
        metrics: Arc<Metrics>,
        active: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Self> {
        // One alias at a time. Two live home relay actors with the same
        // identity on different aliases would compete at the same server.
        let qad = offer
            .qad_port
            .filter(|_| udp)
            .and_then(|_| alias.port_or_known_default())
            .map(RelayQuicConfig::new);
        let relay_config = RelayConfig::new(alias.clone(), qad);
        let mut report = NetReportConfig::minimal();
        report.https_probes = true;
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .clear_address_lookup()
            .relay_mode(RelayMode::Custom(relay_config.clone().into()))
            .ca_tls_config(CaTlsConfig::custom_roots([offer.cert_der.clone().into()]))
            .net_report_config(report)
            .alpns(vec![Kind::Chat.alpn().to_vec(), Kind::File.alpn().to_vec()])
            .transport_config(
                QuicTransportConfig::builder()
                    .max_concurrent_bidi_streams(1u32.into())
                    .max_concurrent_uni_streams(0u32.into())
                    .datagram_receive_buffer_size(Some(4096))
                    .build(),
            );
        if !udp {
            builder = builder.clear_ip_transports();
        }
        Ok(Self {
            endpoint: builder.bind().await?,
            offer: offer.clone(),
            chats: quic::Pool::for_helper(offer.helper_node.clone()),
            published: Mutex::default(),
            active,
            relay_config,
            incoming_files: Arc::default(),
            live: Mutex::default(),
            failures: Mutex::default(),
            opening: Mutex::default(),
            store,
            metrics,
        })
    }

    pub(super) fn registration(&self) -> Option<HelperRegistration> {
        if !*self.active.borrow() {
            return None;
        }
        self.published
            .lock()
            .expect("helper registration poisoned")
            .clone()
    }

    pub(super) fn update_registration(&self) -> bool {
        let current = self.observed_registration();
        let mut published = self.published.lock().expect("helper registration poisoned");
        if !*self.active.borrow() {
            return false;
        }
        if !registration_changed(published.as_ref(), current.as_ref()) {
            return false;
        }
        *published = current;
        true
    }

    pub(super) fn withdraw_registration(&self) -> bool {
        self.published
            .lock()
            .expect("helper registration poisoned")
            .take()
            .is_some()
    }

    fn observed_registration(&self) -> Option<HelperRegistration> {
        let status = self.endpoint.home_relay_status().get();
        let report = self.endpoint.net_report().get()?;
        let (_, url, rtt) = report
            .relay_latency
            .iter()
            .filter(|(_, url, _)| {
                self.offer.urls.contains(url)
                    && status.iter().any(|s| s.url() == *url && s.is_connected())
            })
            .min_by_key(|(_, _, rtt)| *rtt)?;
        Some(HelperRegistration {
            helper_node: self.offer.helper_node.clone(),
            generation: self.offer.generation,
            url: url.clone(),
            rtt_ms: rtt.as_millis().min(60_000) as u32,
        })
    }

    pub(super) fn lookup(&self, peer: EndpointId, kind: Kind) -> Option<Live> {
        self.live
            .lock()
            .expect("helper links poisoned")
            .get(&(peer, kind))
            .filter(|s| s.proof.conn.close_reason().is_none())
            .cloned()
    }

    pub(super) fn cooling(&self, peer: EndpointId, kind: Kind) -> bool {
        self.failures
            .lock()
            .expect("helper backoff poisoned")
            .get(&(peer, kind))
            .is_some_and(|at| at.elapsed() < RETRY)
    }

    fn failure(&self, pair: Pair) {
        let mut failures = self.failures.lock().expect("helper backoff poisoned");
        failures.retain(|_, t| t.elapsed() < RETRY);
        if failures.len() < quic::MAX_LINKS * 4 {
            failures.insert(pair, Instant::now());
        }
    }

    pub(super) fn prune(&self) {
        self.chats.prune();
        self.live
            .lock()
            .expect("helper links poisoned")
            .retain(|(peer, kind), s| {
                if s.proof.conn.close_reason().is_some() {
                    self.failure((*peer, *kind));
                    return false;
                }
                *kind != Kind::Chat || self.chats.get(*peer).is_some()
            });
    }

    pub(super) fn in_use(&self) -> bool {
        !self.live.lock().expect("helper links poisoned").is_empty()
            || !self
                .incoming_files
                .lock()
                .expect("helper incoming files poisoned")
                .is_empty()
    }

    pub(super) fn keep_direct(&self) -> bool {
        let mut live = self.live.lock().expect("helper links poisoned");
        live.retain(|_, s| {
            s.proof.conn.close_reason().is_none() && s.proof.selected() == Some(PathKind::Direct)
        });
        let mut files = self
            .incoming_files
            .lock()
            .expect("helper incoming files poisoned");
        files.retain(|_, proof| {
            proof.conn.close_reason().is_none() && proof.selected() == Some(PathKind::Direct)
        });
        !live.is_empty() || !files.is_empty()
    }

    fn install(&self, proof: Arc<Proof>, kind: Kind, dialed: bool) -> Option<Live> {
        let conn = &proof.conn;
        let peer = conn.remote_id();
        let pair = (peer, kind);
        let mut live = self.live.lock().expect("helper links poisoned");
        if !*self.active.borrow() {
            return None;
        }
        if let Some(old) = live.get(&pair)
            && old.proof.conn.close_reason().is_none()
            && (old.dialed == dialed || old.dialed == (self.endpoint.id() < peer))
        {
            return Some(old.clone());
        }
        let application = match kind {
            Kind::Chat => {
                let link = self.chats.install(
                    self.endpoint.id(),
                    conn.clone(),
                    dialed,
                    self.store.clone(),
                    self.metrics.clone(),
                );
                if link.conn.stable_id() != conn.stable_id() {
                    return live
                        .get(&pair)
                        .filter(|s| s.proof.conn.stable_id() == link.conn.stable_id())
                        .cloned();
                }
                live.retain(|(id, k), existing| {
                    *k != Kind::Chat
                        || self.chats.get(*id).is_some_and(|saved| {
                            saved.conn.stable_id() == existing.proof.conn.stable_id()
                        })
                });
                Application::Chat(link)
            }
            Kind::File => {
                if !live.contains_key(&pair)
                    && live.keys().filter(|(_, k)| *k == Kind::File).count() >= 2
                {
                    return None;
                }
                Application::File(conn.clone())
            }
        };
        let saved = Live {
            application,
            proof,
            dialed,
        };
        live.insert(pair, saved.clone());
        self.failures
            .lock()
            .expect("helper backoff poisoned")
            .remove(&pair);
        Some(saved)
    }

    pub(super) async fn attempt(
        &self,
        peer: EndpointId,
        kind: Kind,
        url: Option<RelayUrl>,
    ) -> Option<(Application, Sample)> {
        let pair = (peer, kind);
        if let Some(live) = self.lookup(peer, kind) {
            if url.is_none() && live.proof.selected() != Some(PathKind::Direct) {
                return None;
            }
            if let Some(sample) = live.proof.measure().await
                && (sample.kind() == PathKind::Direct || url.is_some())
            {
                return Some((live.application, sample));
            }
            self.failure(pair);
            live.proof
                .conn
                .close(1u32.into(), b"helper qualification failed");
            return None;
        }
        let url = url?;
        if !*self.active.borrow() {
            return None;
        }
        {
            let mut opening = self.opening.lock().expect("helper dials poisoned");
            if opening.len() >= quic::MAX_LINKS || !opening.insert(pair) {
                return None;
            }
        }
        // Dropping the selection future must also release the per-pair dial slot.
        struct Opening<'a>(&'a Auxiliary, Pair);
        impl Drop for Opening<'_> {
            fn drop(&mut self) {
                self.0
                    .opening
                    .lock()
                    .expect("helper dials poisoned")
                    .remove(&self.1);
            }
        }
        let _opening = Opening(self, pair);
        let connected = tokio::time::timeout(ATTEMPT, async {
            let addr = EndpointAddr::new(peer).with_relay_url(url);
            let conn = self.endpoint.connect(addr, kind.alpn()).await.ok()?;
            if conn.remote_id() != peer || conn.alpn() != kind.alpn() {
                return None;
            }
            let proof = Arc::new(Proof::start(conn, self.offer.clone(), self.active.clone()));
            proof.measure().await?;
            let live = self.install(proof, kind, true)?;
            Some((live.application, live.proof.cached()?))
        })
        .await
        .ok()
        .flatten();
        if connected.is_none() {
            self.failure(pair);
        }
        connected
    }

    fn serve_file(&self, proof: Arc<Proof>, capacity: Arc<Semaphore>) {
        let Ok(permit) = capacity.try_acquire_owned() else {
            return;
        };
        let id = proof.conn.stable_id();
        let conn = proof.conn.clone();
        self.incoming_files
            .lock()
            .expect("helper incoming files poisoned")
            .insert(id, proof);
        let files = Arc::downgrade(&self.incoming_files);
        let store = self.store.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = file_chunks::serve(&conn, store, &metrics).await;
            if let Some(files) = files.upgrade() {
                files
                    .lock()
                    .expect("helper incoming files poisoned")
                    .remove(&id);
            }
        });
    }

    async fn admit(&self, incoming: iroh::endpoint::Incoming, files: Arc<Semaphore>) -> Option<()> {
        if !*self.active.borrow() {
            return None;
        }
        let conn = incoming.await.ok()?;
        let peer = conn.remote_id();
        let offered = self.offer.clone();
        local(self.store.clone(), move |s| {
            s.direct_allowed(peer)?;
            ensure!(
                s.helper_offers()?
                    .iter()
                    .any(|current| same_service(current, &offered)),
                "helper offer expired"
            );
            Ok(())
        })
        .await
        .ok()?;
        let proof = Arc::new(Proof::start(conn, self.offer.clone(), self.active.clone()));
        proof.measure().await?;
        if !*self.active.borrow() {
            return None;
        }
        match proof.conn.alpn() {
            alpn if alpn == Kind::Chat.alpn() => {
                self.install(proof, Kind::Chat, false)?;
            }
            alpn if alpn == Kind::File.alpn() => self.serve_file(proof, files),
            _ => return None,
        }
        Some(())
    }

    pub(super) async fn listen(self: Arc<Self>, limit: Arc<Semaphore>, files: Arc<Semaphore>) {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    let Ok(permit) = limit.clone().try_acquire_owned() else { incoming.refuse(); continue };
                    let aux = self.clone();
                    let files = files.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = tokio::time::timeout(ATTEMPT, aux.admit(incoming, files)).await;
                    });
                }
            }
        }
    }
}
