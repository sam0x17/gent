use super::*;
use crate::{encrypted, store::Store};
use futures_util::{SinkExt, StreamExt};
use iroh::{EndpointAddr, SecretKey, dns::DnsResolver};
use iroh_relay::{
    client::{Client, ClientBuilder, ConnectError},
    protos::{
        handshake,
        relay::{ClientToRelayMsg, RelayToClientMsg},
    },
    quic::QuicClient,
    tls::CaTlsConfig,
};
use rustls::pki_types::CertificateDer;
use std::os::unix::fs::PermissionsExt;

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

fn client_tls(offer: &HelperOffer) -> Result<rustls::ClientConfig> {
    Ok(
        CaTlsConfig::custom_roots([CertificateDer::from(offer.cert_der.clone())])
            .client_config(Arc::new(rustls::crypto::ring::default_provider()))?,
    )
}

fn fixture() -> Result<(tempfile::TempDir, SharedStore, SecretKey, String)> {
    let home = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let cfg = config::initialize(home.path(), "helper-test")?;
    let mut store = Store::open(home.path())?;
    let key = SecretKey::generate();
    store.advertise_direct_with_helpers(EndpointAddr::new(key.public()), None, Vec::new())?;
    Ok((home, Arc::new(Mutex::new(store)), key, cfg.node.id))
}

fn listener(udp: bool) -> ListenerConfig {
    ListenerConfig {
        advertised_ips: vec![LOOPBACK.into()],
        port: Some(0),
        public_address: None,
        udp,
    }
}

fn start(
    store: SharedStore,
    own: EndpointId,
    node: String,
    udp: bool,
) -> Result<(HelperService, Arc<Metrics>)> {
    let totals: Arc<Metrics> = Arc::default();
    let service = HelperService::bind(store, own, node, listener(udp), LOOPBACK, totals.clone())?;
    Ok((service, totals))
}

async fn ping(client: &mut Client) -> Result<()> {
    client.send(ClientToRelayMsg::Ping(*b"abcdefgh")).await?;
    while let Some(frame) = client.next().await {
        if matches!(frame?, RelayToClientMsg::Pong(p) if p == *b"abcdefgh") {
            return Ok(());
        }
    }
    anyhow::bail!("relay closed before pong")
}

#[tokio::test]
async fn established_registration_survives_idle_ad_expiry_but_not_key_rotation() -> Result<()> {
    let trial = async {
        let (home, store, key, node) = fixture()?;
        let (service, totals) = start(store.clone(), key.public(), node, false)?;
        let offer = service.offer();
        assert!(offer.qad_port.is_none());
        let url = offer.urls[0].clone();
        let tls = client_tls(offer)?;
        let connect = |key| {
            ClientBuilder::new(url.clone(), key, DnsResolver::new()).tls_client_config(tls.clone())
        };
        let mut live = connect(key.clone()).connect().await?;
        for refused in [SecretKey::generate(), key.clone()] {
            assert!(matches!(
                connect(refused).connect().await,
                Err(ConnectError::Handshake {
                    source: handshake::Error::ServerDeniedAuth { .. },
                    ..
                })
            ));
        }
        ping(&mut live).await?;
        let db = encrypted::open_database(home.path(), "state.sqlite3")?;
        db.execute("UPDATE direct_local SET expires_at=0", [])?;
        assert!(store.lock().unwrap().direct_allowed(key.public()).is_err());
        time::sleep(RECHECK + Duration::from_millis(200)).await;
        ping(&mut live).await?;
        let replacement = SecretKey::generate().public();
        store.lock().unwrap().advertise_direct_with_helpers(
            EndpointAddr::new(replacement),
            None,
            vec![],
        )?;
        while let Some(Ok(_)) = live.next().await {}
        assert_eq!(totals.accepts.get(), 1);
        service.shutdown().await;
        assert!(
            tokio::net::TcpStream::connect((LOOPBACK, url.port_or_known_default().unwrap()))
                .await
                .is_err()
        );
        Ok(())
    };
    time::timeout(Duration::from_secs(15), trial).await?
}

#[tokio::test]
async fn qad_reports_the_real_udp_socket_on_the_tls_port_with_hostname_verification() -> Result<()>
{
    let trial = async {
        let (_home, store, key, node) = fixture()?;
        let (service, totals) = start(store, key.public(), node, true)?;
        let offer = service.offer();
        let port = offer.qad_port.unwrap();
        assert_eq!(offer.urls[0].port_or_known_default(), Some(port));
        let socket = noq::Endpoint::client((LOOPBACK, 0).into())?;
        let addr = socket.local_addr()?;
        let probe = QuicClient::new(socket, client_tls(offer)?);
        assert!(
            probe
                .create_conn((LOOPBACK, port).into(), "not-advertised.invalid")
                .await
                .is_err()
        );
        let conn = probe
            .create_conn((LOOPBACK, port).into(), "127.0.0.1")
            .await?;
        let mut reports = conn.observed_external_addr();
        assert_eq!(reports.next().await, Some(addr));
        conn.close(iroh_relay::quic::QUIC_ADDR_DISC_CLOSE_CODE, b"done");
        service.shutdown().await;
        assert!(totals.qad_connections.get() > 0);
        assert_eq!(
            totals.qad_connections_closed.get(),
            totals.qad_connections.get()
        );
        assert_eq!(totals.accepts.get(), 0);
        assert_eq!(totals.bytes_sent.get(), 0);
        // Both protocols can immediately reclaim the fixed port.
        let _sockets = sockets(LOOPBACK, Some(port), true, None)?;
        Ok(())
    };
    time::timeout(Duration::from_secs(12), trial).await?
}

#[tokio::test]
async fn udp_collision_preserves_explicit_port_policy_and_tcp_only_still_works() -> Result<()> {
    let udp = UdpSocket::bind((LOOPBACK, 0))?;
    let port = udp.local_addr()?.port();
    assert_eq!(
        sockets(LOOPBACK, Some(port), true, None)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrInUse
    );
    let (tcp, socket) = sockets(LOOPBACK, Some(port), false, None)?;
    assert!(socket.is_none());
    assert_eq!(tcp.local_addr()?.port(), port);
    Ok(())
}

#[tokio::test]
async fn translated_public_port_preserves_https_aliases_and_omits_qad() -> Result<()> {
    let (_home, store, key, node) = fixture()?;
    // Occupy UDP on the local port so a spurious QAD bind would also break HTTPS.
    let reserved = UdpSocket::bind((LOOPBACK, 0))?;
    let local = reserved.local_addr()?;
    let public = SocketAddr::new(
        "192.0.2.1".parse()?,
        if local.port() == 443 { 8443 } else { 443 },
    );
    let settings = ListenerConfig {
        port: Some(local.port()),
        public_address: Some(public),
        ..listener(true)
    };
    let service = HelperService::bind(
        store,
        key.public(),
        node,
        settings,
        LOOPBACK,
        Arc::default(),
    )?;
    let offer = service.offer();
    assert_eq!(offer.qad_port, None);
    assert_eq!(
        offer.urls,
        vec![
            format!("https://{public}/").parse::<RelayUrl>()?,
            format!("https://{local}/").parse()?
        ]
    );
    let client = ClientBuilder::new(offer.urls[1].clone(), key, DnsResolver::new())
        .tls_client_config(client_tls(offer)?);
    let mut live = time::timeout(ESTABLISH, client.connect()).await??;
    time::timeout(ESTABLISH, ping(&mut live)).await??;
    service.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn default_port_collision_falls_back_to_a_matched_tcp_udp_pair() -> Result<()> {
    let _occupied = match UdpSocket::bind((LOOPBACK, DEFAULT_PORT)) {
        Ok(socket) => Some(socket),
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => None,
        Err(e) => return Err(e.into()),
    };
    let (tcp, udp) = sockets(LOOPBACK, None, true, None)?;
    let actual = tcp.local_addr()?;
    assert_ne!(actual.port(), DEFAULT_PORT);
    assert_eq!(udp.unwrap().local_addr()?, actual);
    Ok(())
}

#[test]
fn public_alias_and_local_addresses_share_a_fresh_bounded_certificate() -> Result<()> {
    let ips = (1..=12)
        .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
        .collect::<Vec<_>>();
    let public = Some("192.0.2.1:7842".parse()?);
    let (first, _) = identity("test".into(), ips.clone(), 7842, public, true)?;
    let (next, _) = identity("test".into(), ips, 7842, public, true)?;
    assert_ne!(first.generation, next.generation);
    assert_eq!(first.urls.len(), MAX_ALIASES);
    assert_eq!(first.qad_port, Some(7842));
    assert!(
        first
            .urls
            .iter()
            .any(|u| u.as_str() == "https://192.0.2.1:7842/")
    );
    let (_, cert) = x509_parser::parse_x509_certificate(&first.cert_der).unwrap();
    let sans = cert.subject_alternative_name()?.unwrap();
    for url in &first.urls {
        let ip: Ipv4Addr = url.host_str().unwrap().parse()?;
        assert!(sans.value.general_names.iter().any(|name| matches!(name,
            x509_parser::extensions::GeneralName::IPAddress(bytes) if **bytes == ip.octets())));
    }
    Ok(())
}

// Pair two real local stores without a daemon, mailbox or network login.
struct Owner<'a> {
    store: &'a mut Store,
    credential: String,
    cluster: String,
}

impl crate::pairing::Peer for Owner<'_> {
    async fn call(&mut self, action: gent_protocol::PairingOp) -> Result<serde_json::Value> {
        match self.store.handle(gent_protocol::Request::Owner {
            credential: self.credential.clone(),
            action: gent_protocol::OwnerOp::Pair {
                cluster_id: self.cluster.clone(),
                action,
            },
        }) {
            gent_protocol::Response::Ok(value) => Ok(value),
            gent_protocol::Response::Error(error) => anyhow::bail!("{error}"),
        }
    }
}

#[tokio::test]
async fn revoked_member_loses_existing_relay_session_while_host_stays_registered() -> Result<()> {
    use iroh_relay::protos::relay::Datagrams;
    let trial = async {
        let (home, store, host_key, node) = fixture()?;
        let joined = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let credential = config::read_private(&home.path().join("owner.key"))?;
        let mut cfg = config::load(home.path())?;
        cfg.relay = Some(config::RelayConfig {
            endpoint: "https://relay.example".into(),
            credential_file: "relay.key".into(),
        });
        config::write_private(&home.path().join("relay.key"), config::secret().as_bytes())?;
        config::save(home.path(), &cfg)?;
        let mut setup = Store::open(home.path())?;
        crate::pairing::join(
            joined.path(),
            crate::pairing::Options {
                replace_node: None,
                cluster: &cfg.cluster.id,
                name: "member",
                relay_endpoint: None,
            },
            &mut Owner {
                store: &mut setup,
                credential: credential.clone(),
                cluster: cfg.cluster.id.clone(),
            },
        )
        .await?;
        let member = config::load(joined.path())?.node.id;
        let peer_key = SecretKey::generate();
        // Seed the remote address checkpoint for this test using the real paired
        // link's signing key. MLS ingestion is covered by the store's wire tests.
        let db = encrypted::open_database(home.path(), "state.sqlite3")?;
        let address = crate::store::direct::Address {
            endpoint: EndpointAddr::new(peer_key.public()),
            expires_at: crate::store::now() + 180,
            offer: None,
            registrations: Vec::new(),
        };
        assert_eq!(db.execute("INSERT INTO direct_peers(peer,peer_key,endpoint,address,expires_at) SELECT peer,peer_key,?2,?3,?4 FROM network_links WHERE peer=?1",
            rusqlite::params![member, peer_key.public().to_string(), serde_json::to_vec(&address)?, address.expires_at])?, 1);

        let (service, totals) = start(store.clone(), host_key.public(), node, false)?;
        let tls = client_tls(service.offer())?;
        let connect = |key| {
            ClientBuilder::new(service.offer().urls[0].clone(), key, DnsResolver::new())
                .tls_client_config(tls.clone())
        };
        let mut a = connect(host_key.clone()).connect().await?;
        let mut b = connect(peer_key.clone()).connect().await?;
        let payload = Datagrams::from([0xab; 4096]);
        a.send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: peer_key.public(),
            datagrams: payload.clone(),
        })
        .await?;
        assert!(
            matches!(b.next().await.transpose()?, Some(RelayToClientMsg::Datagrams {remote_endpoint_id,datagrams}) if remote_endpoint_id == host_key.public() && datagrams == payload)
        );
        assert_eq!(totals.bytes_sent.get(), 4096);
        let removed = setup.handle(gent_protocol::Request::Owner {
            credential,
            action: gent_protocol::OwnerOp::RemoveNode { node_id: member },
        });
        ensure!(
            matches!(removed, gent_protocol::Response::Ok(_)),
            "member removal failed"
        );
        while let Some(Ok(_)) = b.next().await {}
        assert!(matches!(
            connect(peer_key).connect().await,
            Err(ConnectError::Handshake {
                source: handshake::Error::ServerDeniedAuth { .. },
                ..
            })
        ));
        ping(&mut a).await?;
        service.shutdown().await;
        Ok(())
    };
    time::timeout(Duration::from_secs(20), trial).await?
}

#[tokio::test(start_paused = true)]
async fn full_registry_denies_admission_and_stale_slots_cannot_block_shutdown() -> Result<()> {
    let (_home, store, own, node) = fixture()?;
    let gate = Arc::new(Admission::new(store, own.public(), node.clone()));
    let request = ClientRequest::new(
        own.public(),
        Default::default(),
        http::Request::new(()).into_parts().0,
    );
    {
        let mut state = gate.registrations.lock().unwrap();
        for _ in 0..MAX_CLIENTS {
            // No corresponding Iroh actor exists for these synthetic stale slots.
            state.live.insert(
                SecretKey::generate().public(),
                (request.connection_id(), (node.clone(), [0; 32])),
            );
        }
    }
    assert!(matches!(
        gate.on_connect(&request).await,
        Access::Deny { .. }
    ));
    let (tcp, _) = sockets(LOOPBACK, Some(0), false, None)?;
    let (_, tls) = identity(
        node,
        vec![LOOPBACK.into()],
        tcp.local_addr()?.port(),
        None,
        false,
    )?;
    let (stop, shutdown) = oneshot::channel();
    drop(stop);
    let start = Instant::now();
    time::timeout(
        DRAIN_TIMEOUT + Duration::from_secs(1),
        serve(
            tcp,
            None,
            TlsConfig::new(Arc::new(tls)),
            gate,
            Arc::default(),
            shutdown,
        ),
    )
    .await?;
    assert!(start.elapsed() <= DRAIN_TIMEOUT);
    Ok(())
}

#[test]
fn invalid_public_aliases_cannot_be_advertised() {
    for addr in [
        "[::1]:7842",
        "0.0.0.0:7842",
        "239.0.0.1:7842",
        "255.255.255.255:7842",
        "192.0.2.1:0",
    ] {
        assert!(
            identity(
                "test".into(),
                vec![LOOPBACK.into()],
                7842,
                Some(addr.parse().unwrap()),
                true
            )
            .is_err(),
            "{addr}"
        );
    }
}

#[tokio::test]
async fn live_session_expires_with_signed_authority_even_when_the_address_is_fresh() -> Result<()> {
    use gent_crypto::peer::ConfigurationSigner;
    let (home, store, key, node) = fixture()?;
    let (service, _) = start(store, key.public(), node, false)?;
    let client = ClientBuilder::new(
        service.offer().urls[0].clone(),
        key.clone(),
        DnsResolver::new(),
    )
    .tls_client_config(client_tls(service.offer())?);
    let mut live = client.connect().await?;
    ping(&mut live).await?;

    let db = encrypted::open_database(home.path(), "state.sqlite3")?;
    let now = crate::store::now() as u64;
    let identity = crate::runtime::Identity::load_or_create(
        home.path(),
        &config::load(home.path())?,
        &db,
        now,
    )?;
    let current = identity.state(&db)?;
    let signer = identity.owner.as_ref().unwrap();
    let mut renewal = current.renew(signer, now)?.state;
    renewal.expires_at = now + 1;
    identity.apply(&db, signer.sign_revision(&current, renewal)?)?;
    time::timeout(RECHECK * 2 + DB_TIMEOUT, async {
        while let Some(Ok(_)) = live.next().await {}
    })
    .await?;
    assert!(matches!(
        client.connect().await,
        Err(ConnectError::Handshake {
            source: handshake::Error::ServerDeniedAuth { .. },
            ..
        })
    ));
    service.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn shutdown_closes_a_pending_tls_connection_in_the_process_totals() -> Result<()> {
    let (_home, store, key, node) = fixture()?;
    let (service, totals) = start(store, key.public(), node, false)?;
    let port = service.offer().urls[0].port_or_known_default().unwrap();
    let socket = tokio::net::TcpStream::connect((LOOPBACK, port)).await?;
    time::timeout(ESTABLISH, async {
        while totals.http_connections.get() == 0 {
            time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    tokio::join!(service.shutdown(), async {
        time::sleep(Duration::from_millis(50)).await;
        drop(socket);
    });
    assert_eq!(totals.http_connections.get(), 1);
    assert_eq!(totals.http_connections_closed.get(), 1);
    assert_eq!(totals.accepts.get(), 0);
    Ok(())
}

#[tokio::test]
async fn endpoint_registration_and_counters_survive_listener_replacement() -> Result<()> {
    let trial = async {
        let (_home, store, key, node) = fixture()?;
        let totals: Arc<Metrics> = Arc::default();
        let mut previous_generation = None;
        for expected in 1..=2 {
            let service = HelperService::bind(
                store.clone(),
                key.public(),
                node.clone(),
                listener(false),
                LOOPBACK,
                totals.clone(),
            )?;
            let offer = service.offer();
            assert_ne!(previous_generation, Some(offer.generation));
            previous_generation = Some(offer.generation);
            let ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(key.clone())
                .clear_ip_transports()
                .clear_address_lookup()
                .relay_mode(iroh::RelayMode::custom(offer.urls.clone()))
                .ca_tls_config(CaTlsConfig::custom_roots([CertificateDer::from(
                    offer.cert_der.clone(),
                )]))
                .bind()
                .await?;
            ep.online().await;
            service.shutdown().await;
            ep.close().await;
            assert_eq!(totals.accepts.get(), expected);
            assert_eq!(totals.disconnects.get(), expected);
        }
        Ok(())
    };
    time::timeout(Duration::from_secs(15), trial).await?
}
