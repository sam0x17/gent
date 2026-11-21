use super::*;
use iroh::EndpointAddr;
use sha2::{Digest, Sha256};

fn offer() -> HelperOffer {
    HelperOffer {
        helper_node: uuid::Uuid::new_v4().to_string(),
        urls: ["https://127.0.0.1:7000/", "https://127.0.0.2:8000/"]
            .map(|u| u.parse().unwrap())
            .to_vec(),
        cert_der: vec![7],
        generation: Sha256::digest([7]).into(),
        qad_port: None,
    }
}
fn leg(o: &HelperOffer, alias: usize, rtt_ms: u32) -> HelperRegistration {
    HelperRegistration {
        helper_node: o.helper_node.clone(),
        generation: o.generation,
        url: o.urls[alias].clone(),
        rtt_ms,
    }
}

#[test]
fn shortlist_uses_both_legs_and_checks_each_alias_and_generation() {
    let a = offer();
    let b = offer();
    let first = HelperCandidate {
        offer: a.clone(),
        local: leg(&a, 0, 8),
        remote: leg(&a, 1, 150),
    };
    let second = HelperCandidate {
        offer: b.clone(),
        local: leg(&b, 0, 30),
        remote: leg(&b, 1, 30),
    };
    assert!(
        legs(&b, &second.local, &second).unwrap().0 < legs(&a, &first.local, &first).unwrap().0
    );
    let mut stale = first.clone();
    stale.remote.generation[0] ^= 1;
    assert!(legs(&a, &first.local, &stale).is_none());
    stale = first.clone();
    stale.remote.helper_node = b.helper_node;
    assert!(legs(&a, &first.local, &stale).is_none());
    stale = first.clone();
    stale.remote.url = "https://127.0.0.3:7000/".parse().unwrap();
    assert!(legs(&a, &first.local, &stale).is_none());
    assert!(legs(&a, &leg(&a, 1, 3), &first).is_none());
}

#[test]
fn incumbent_survives_jitter_but_not_a_material_improvement() {
    let ms = Duration::from_millis;
    assert!(!worth_switching(ms(100), ms(83)));
    assert!(!worth_switching(ms(3), ms(2)));
    assert!(worth_switching(ms(161), ms(63)));
    let o = offer();
    let a = leg(&o, 0, 20);
    assert!(!registration_changed(Some(&a), Some(&leg(&o, 0, 21))));
    assert!(registration_changed(Some(&a), Some(&leg(&o, 1, 20))));
    assert!(registration_changed(Some(&a), None));
    assert!(registration_changed(None, Some(&a)));
}

async fn loopback_pair() -> (Endpoint, Endpoint, Connection, Connection) {
    async fn endpoint() -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .clear_address_lookup()
            .relay_mode(RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .alpns(vec![quic::ALPN.to_vec()])
            .bind()
            .await
            .unwrap()
    }
    let (a, b) = tokio::join!(endpoint(), endpoint());
    let addr = EndpointAddr::new(b.id()).with_ip_addr(b.bound_sockets()[0]);
    let (out, inc) = tokio::join!(a.connect(addr, quic::ALPN), async {
        b.accept().await.unwrap().await.unwrap()
    });
    (a, b, out.unwrap(), inc)
}

#[tokio::test]
async fn path_echo_qualifies_pinned_peer_on_the_application_connection_only() {
    let (_a, b, out, inc) = loopback_pair().await;
    assert_eq!(out.remote_id(), b.id());
    let service = Arc::new(offer());
    let (keep, active) = tokio::sync::watch::channel(true);
    let left = Proof::start(out.clone(), service.clone(), active.clone());
    let right = Proof::start(inc.clone(), service, active);
    let (left_sample, right_sample) = tokio::join!(left.measure(), right.measure());
    assert_eq!(left_sample.unwrap().kind(), PathKind::Direct);
    assert_eq!(right_sample.unwrap().kind(), PathKind::Direct);
    let frames = out.stats().frame_tx.datagram;
    assert!(left.measure().await.is_some());
    assert_eq!(out.stats().frame_tx.datagram, frames);
    assert_eq!(out.stats().frame_tx.stream, 0);
    keep.send_replace(false);
    // Loss of the offer keeps exactly this authenticated direct connection.
    let send = async {
        let (mut tx, mut rx) = out.open_bi().await.unwrap();
        tx.write_all(b"after withdrawal").await.unwrap();
        tx.finish().unwrap();
        rx.read_to_end(16).await.unwrap()
    };
    let receive = async {
        let (mut tx, mut rx) = inc.accept_bi().await.unwrap();
        let body = rx.read_to_end(16).await.unwrap();
        tx.write_all(&body).await.unwrap();
        tx.finish().unwrap();
    };
    let (echo, ()) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(send, receive)
    })
    .await
    .unwrap();
    assert_eq!(echo, b"after withdrawal");
}

#[tokio::test]
async fn authenticated_peer_echo_from_a_different_helper_is_rejected() {
    let (_a, _b, out, inc) = loopback_pair().await;
    let (_keep, active) = tokio::sync::watch::channel(true);
    let left = Proof::start(out, Arc::new(offer()), active.clone());
    let _right = Proof::start(inc, Arc::new(offer()), active);
    assert!(left.measure().await.is_none());
    assert!(left.cached().is_none());
}

#[tokio::test]
async fn tcp_only_registration_uses_live_tls_and_wakes_on_helper_loss() -> Result<()> {
    use super::super::helper_service::{HelperService, ListenerConfig};
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir()?;
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700))?;
    let cfg = config::initialize(home.path(), "helper-client-tests")?;
    let mut store = Store::open(home.path())?;
    let key = SecretKey::generate();
    store.advertise_direct(EndpointAddr::new(key.public()))?;
    let store = Arc::new(Mutex::new(store));
    let service = HelperService::start(
        store.clone(),
        key.public(),
        cfg.node.id,
        ListenerConfig {
            advertised_ips: vec!["127.0.0.1".parse()?],
            port: Some(0),
            public_address: None,
            udp: false,
        },
        Arc::default(),
    )
    .await?;
    let wake = Arc::new(Notify::new());
    let routes = Routes::new(key, vec![], false, store, Arc::default(), wake.clone());
    let trusted = service.offer().clone();
    let mut wrong = trusted.clone();
    let unrelated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])?;
    wrong.cert_der = unrelated.cert.der().to_vec();
    wrong.generation = Sha256::digest(&wrong.cert_der).into();
    routes.refresh(vec![wrong]).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), wake.notified())
            .await
            .is_err()
    );
    assert!(routes.registrations().is_empty());
    routes.refresh(vec![trusted.clone()]).await;
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if !routes.registrations().is_empty() {
                break;
            }
            wake.notified().await;
        }
    })
    .await?;
    let regs = routes.registrations();
    assert_eq!(regs.len(), 1);
    assert_eq!(regs[0].generation, trusted.generation);
    assert!(trusted.urls.contains(&regs[0].url));
    let aux = routes.helpers.lock().unwrap().active[&trusted.helper_node]
        .get()
        .unwrap();
    assert!(aux.endpoint.bound_sockets().is_empty());
    service.shutdown().await;
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if routes.registrations().is_empty() {
                break;
            }
            wake.notified().await;
        }
    })
    .await?;
    Ok(())
}
