use super::*;
use crate::store::direct::{Address, HelperOffer, HelperRegistration};
use iroh::{EndpointAddr, SecretKey};

fn endpoint() -> EndpointAddr {
    EndpointAddr::new(SecretKey::generate().public())
}

fn offer(node: &str) -> HelperOffer {
    let ips = ["127.0.0.1", "192.0.2.1"];
    let cert = rcgen::generate_simple_self_signed(ips.map(str::to_owned).to_vec()).unwrap();
    let der = cert.cert.der().to_vec();
    HelperOffer {
        helper_node: node.into(),
        urls: ips
            .map(|ip| format!("https://{ip}:4100").parse().unwrap())
            .to_vec(),
        generation: Sha256::digest(&der).into(),
        cert_der: der,
        qad_port: Some(4100),
    }
}

fn leg(offer: &HelperOffer, alias: usize, rtt_ms: u32) -> HelperRegistration {
    HelperRegistration {
        helper_node: offer.helper_node.clone(),
        url: offer.urls[alias].clone(),
        generation: offer.generation,
        rtt_ms,
    }
}

#[tokio::test]
async fn direct_queue_uses_only_the_peer_codec_and_existing_control_retention() {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    let s = &mut pair.stores[0];
    let service = offer(s.identity.node.id());
    let addr = endpoint();
    for version in 1..=7 {
        s.db.execute(
            "UPDATE wire_peers SET version=?1,confirmed_at=?2",
            params![version, now()],
        )
        .unwrap();
        s.db.execute("DELETE FROM direct_advertised", []).unwrap();
        s.advertise_direct_with_helpers(
            addr.clone(),
            Some(service.clone()),
            vec![leg(&service, 0, 1)],
        )
        .unwrap();
        let row = s.db.query_row("SELECT body,traffic,retire_after FROM network_events WHERE json_extract(CAST(body AS TEXT),'$.event.kind')='direct'",[],
            |r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?))).optional().unwrap();
        if version < 5 {
            assert!(row.is_none());
            continue;
        }
        let (bytes, traffic, retire_after) = row.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let address = &body["event"]["address"];
        assert_eq!(body["version"], version);
        assert_eq!(address["endpoint"], serde_json::to_value(&addr).unwrap());
        assert_eq!(address.get("offer").is_some(), version == 7);
        assert_eq!(address.get("registrations").is_some(), version == 7);
        assert_eq!(traffic, "control");
        assert_eq!(
            retire_after,
            address["expires_at"].as_i64().unwrap() + history::RETENTION
        );
        s.db.execute("DELETE FROM network_events", []).unwrap();
    }
}

#[tokio::test]
async fn helper_advertisement_rejects_bad_certificate_aliases_and_unbounded_fields() {
    let mut pair = Pair::new().await;
    let s = &mut pair.stores[0];
    let addr = endpoint();
    let h = offer(s.identity.node.id());
    for bad in [
        HelperOffer {
            helper_node: uuid::Uuid::new_v4().to_string(),
            ..h.clone()
        },
        HelperOffer {
            generation: [0; 32],
            ..h.clone()
        },
        HelperOffer {
            qad_port: Some(0),
            ..h.clone()
        },
        HelperOffer {
            urls: vec![],
            ..h.clone()
        },
        HelperOffer {
            urls: vec![h.urls[0].clone(); 9],
            ..h.clone()
        },
        HelperOffer {
            cert_der: vec![0; 8193],
            ..h.clone()
        },
        HelperOffer {
            cert_der: vec![0],
            generation: Sha256::digest([0]).into(),
            ..h.clone()
        },
    ] {
        assert!(
            s.advertise_direct_with_helpers(addr.clone(), Some(bad), vec![])
                .is_err()
        );
    }
    for invalid in [
        "https://192.0.2.2:4100",
        "http://127.0.0.1",
        "https://localhost",
        "https://127.0.0.1/path/",
        "https://user@127.0.0.1",
        "https://127.0.0.1/?key=foo",
        "https://0.0.0.0",
    ] {
        let mut bad = h.clone();
        bad.urls = vec![invalid.parse().unwrap()];
        assert!(
            s.advertise_direct_with_helpers(addr.clone(), Some(bad), vec![])
                .is_err()
        );
    }
    for regs in [
        vec![leg(&h, 0, 1); 17],
        vec![leg(&h, 0, 1); 2],
        vec![leg(&h, 0, 60_001)],
    ] {
        assert!(
            s.advertise_direct_with_helpers(addr.clone(), Some(h.clone()), regs)
                .is_err()
        );
    }
    assert!(s.helper_offers().unwrap().is_empty());
    assert!(s.direct_allowed(addr.id).is_err());

    let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
    params.not_before = rcgen::date_time_ymd(2000, 1, 1);
    params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    let cert = params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap();
    let der = cert.der().to_vec();
    let expired = HelperOffer {
        urls: vec![h.urls[0].clone()],
        generation: Sha256::digest(&der).into(),
        cert_der: der,
        ..h
    };
    s.advertise_direct_with_helpers(addr.clone(), Some(expired), vec![])
        .unwrap();
    assert!(s.helper_offers().unwrap().is_empty());
    s.direct_allowed(addr.id).unwrap();
}

#[tokio::test]
async fn helper_candidates_join_independent_legs_and_current_service_across_restart() {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    let [a, b] = [endpoint(), endpoint()];
    let h1 = offer(pair.stores[0].identity.node.id());
    let h2 = offer(pair.stores[1].identity.node.id());
    let legs = vec![leg(&h1, 0, 1), leg(&h2, 0, 12)];
    pair.stores[0]
        .advertise_direct_with_helpers(a.clone(), Some(h1.clone()), legs.clone())
        .unwrap();
    pair.stores[1]
        .advertise_direct_with_helpers(b.clone(), Some(h2.clone()), vec![])
        .unwrap();
    pair.pump();
    assert_eq!(pair.stores[0].helper_offers().unwrap().len(), 2);
    assert!(pair.stores[0].helper_candidates(b.id).unwrap().is_empty());
    let remote = vec![leg(&h1, 1, 100), leg(&h2, 1, 11)];
    pair.stores[1]
        .advertise_direct_with_helpers(b.clone(), Some(h2.clone()), remote.clone())
        .unwrap();
    pair.pump();
    pair.reopen(0);
    let candidates = pair.stores[0].helper_candidates(b.id).unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].offer, h2);
    assert_eq!(candidates[0].local, legs[1]);
    assert_eq!(candidates[0].remote, remote[1]);
    assert_eq!(candidates[1].offer, h1);
    assert!(
        pair.stores[0]
            .helper_candidates(endpoint().id)
            .unwrap()
            .is_empty()
    );
    // Rotate the operator's certificate at the same URLs. The other leg
    // still refers to the old generation and cannot nominate H2.
    let rotated = offer(&h2.helper_node);
    pair.stores[1]
        .advertise_direct_with_helpers(b.clone(), Some(rotated.clone()), vec![leg(&rotated, 1, 2)])
        .unwrap();
    pair.pump();
    assert!(pair.stores[0].helper_candidates(b.id).unwrap().is_empty());
    let mut wrong_alias = leg(&rotated, 0, 3);
    wrong_alias.url = "https://192.0.2.2:4100/".parse().unwrap();
    pair.stores[0]
        .advertise_direct_with_helpers(a.clone(), None, vec![wrong_alias])
        .unwrap();
    assert!(pair.stores[0].helper_candidates(b.id).unwrap().is_empty());
    pair.stores[0]
        .advertise_direct_with_helpers(a, None, vec![leg(&rotated, 0, 3)])
        .unwrap();
    assert_eq!(pair.stores[0].helper_candidates(b.id).unwrap().len(), 1);
    // Simulate a removed/replaced link key even if the old advertisement and
    // both qualifications are still present and unexpired on disk.
    let key = pair.stores[1].identity.node.public_key();
    assert_eq!(
        pair.stores[0].direct_binding(b.id, true).unwrap(),
        (h2.helper_node.clone(), key)
    );
    pair.stores[0]
        .db
        .execute("UPDATE network_links SET peer_key=zeroblob(32)", [])
        .unwrap();
    assert!(pair.stores[0].helper_offers().unwrap().is_empty());
    assert!(pair.stores[0].helper_candidates(b.id).unwrap().is_empty());
    assert!(pair.stores[0].direct_binding(b.id, false).is_err());
    pair.stores[0]
        .db
        .execute("UPDATE network_links SET peer_key=?1", [key])
        .unwrap();
    pair.stores[0]
        .execute(Request::Owner {
            credential: config::read_private(&pair.homes[0].path().join("owner.key")).unwrap(),
            action: OwnerOp::RemoveNode {
                node_id: h2.helper_node,
            },
        })
        .unwrap();
    assert!(pair.stores[0].helper_offers().unwrap().is_empty());
    assert!(pair.stores[0].helper_candidates(b.id).unwrap().is_empty());
    assert!(pair.stores[0].direct_binding(b.id, false).is_err());
}

#[tokio::test]
async fn helper_expiry_withdrawal_and_session_admission_are_key_bound() {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    let a = endpoint();
    let b = endpoint();
    let owner = pair.stores[0].identity.node.id().to_owned();
    let service = offer(&owner);
    pair.stores[0]
        .advertise_direct_with_helpers(a.clone(), Some(service.clone()), vec![leg(&service, 0, 1)])
        .unwrap();
    pair.stores[1]
        .advertise_direct_with_helpers(b.clone(), None, vec![leg(&service, 1, 2)])
        .unwrap();
    pair.pump();
    let receiver = &mut pair.stores[1];
    assert_eq!(receiver.helper_candidates(a.id).unwrap().len(), 1);
    for id in [a.id, b.id] {
        receiver.direct_allowed(id).unwrap();
    }
    receiver
        .db
        .execute("UPDATE direct_peers SET expires_at=0", [])
        .unwrap();
    assert!(receiver.helper_offers().unwrap().is_empty());
    assert!(receiver.helper_candidates(a.id).unwrap().is_empty());
    assert!(receiver.direct_allowed(a.id).is_err());
    receiver.direct_binding(a.id, false).unwrap();
    let session =
        receiver.network_session(&receiver.db, receiver.identity.state(&receiver.db).unwrap());
    let incoming = |endpoint, expires_at, offer| Address {
        endpoint,
        expires_at,
        offer,
        registrations: vec![],
    };
    assert!(
        session
            .receive_direct(
                &owner,
                incoming(a.clone(), session.timestamp + 601, Some(service.clone()))
            )
            .is_err()
    );
    let mut impersonation = service.clone();
    impersonation.helper_node = session.identity.node.id().into();
    assert!(
        session
            .receive_direct(
                &owner,
                incoming(a.clone(), session.timestamp + 180, Some(impersonation))
            )
            .is_err()
    );
    session
        .receive_direct(&owner, incoming(endpoint(), session.timestamp - 1, None))
        .unwrap();
    assert!(receiver.direct_binding(a.id, false).is_err());
    session
        .receive_direct(
            &owner,
            incoming(a.clone(), session.timestamp + 180, Some(service.clone())),
        )
        .unwrap();
    session
        .receive_direct(&owner, incoming(a.clone(), session.timestamp + 180, None))
        .unwrap();
    assert!(receiver.helper_offers().unwrap().is_empty());
    receiver.direct_allowed(a.id).unwrap();
    // A remote cannot turn a claim on our own endpoint ID into a target.
    session
        .receive_direct(&owner, incoming(b.clone(), session.timestamp + 180, None))
        .unwrap();
    assert!(receiver.direct_allowed(b.id).is_err());
    assert!(receiver.helper_candidates(b.id).is_err());
}

#[tokio::test]
async fn helper_idle_renewal_and_rtt_jitter_do_not_enqueue_control_traffic() {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    let a = endpoint();
    let h = offer(pair.stores[0].identity.node.id());
    pair.stores[0]
        .advertise_direct_with_helpers(a.clone(), Some(h.clone()), vec![leg(&h, 0, 7)])
        .unwrap();
    pair.pump();
    let sender = &mut pair.stores[0];
    sender
        .db
        .execute("UPDATE direct_advertised SET expires_at=0", [])
        .unwrap();
    sender
        .db
        .execute(
            "UPDATE node_presence SET issued_at=NULL,verified_at=NULL",
            [],
        )
        .unwrap();
    let mut reordered = h.clone();
    reordered.urls.reverse();
    sender
        .advertise_direct_with_helpers(a.clone(), Some(reordered), vec![leg(&h, 0, 8)])
        .unwrap();
    let queued = |s: &Store| {
        s.db.query_row("SELECT count(*) FROM network_events", [], |r| {
            r.get::<_, usize>(0)
        })
        .unwrap()
    };
    assert_eq!(queued(sender), 0);
    sender
        .advertise_direct_with_helpers(a, Some(h), vec![])
        .unwrap();
    assert_eq!(queued(sender), 1);
}

#[tokio::test]
async fn helper_passive_expiry_after_idle_stays_quiet_until_bidirectional_refresh_on_send() {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    let endpoints = [endpoint(), endpoint()];
    let services = pair.stores.each_ref().map(|s| offer(s.identity.node.id()));
    let publish = |s: &mut Store, i: usize, reachable: &[HelperOffer]| {
        let legs = reachable
            .iter()
            .map(|service| leg(service, i, 10))
            .collect();
        s.advertise_direct_with_helpers(endpoints[i].clone(), Some(services[i].clone()), legs)
            .unwrap();
    };
    for (i, s) in pair.stores.iter_mut().enumerate() {
        publish(s, i, &services);
    }
    pair.pump();
    for (i, s) in pair.stores.iter_mut().enumerate() {
        assert_eq!(s.helper_candidates(endpoints[1 - i].id).unwrap().len(), 2);
        // Age the leases by over 180s. Leave codec proof current first to
        // ensure the V7 publish path itself suppresses a passive withdrawal.
        s.db.execute_batch(
            "UPDATE direct_peers SET expires_at=expires_at-200;
            UPDATE direct_advertised SET expires_at=expires_at-200;
            UPDATE direct_local SET expires_at=expires_at-200;
            UPDATE node_presence SET verified_at=NULL, issued_at=NULL, next_probe_at=0;",
        )
        .unwrap();
        let own = std::slice::from_ref(&services[i]);
        publish(s, i, own);
        assert_eq!(s.helper_offers().unwrap(), own);
        assert!(s.helper_candidates(endpoints[1 - i].id).unwrap().is_empty());
        let changes = s.db.total_changes();
        for _ in 0..3 {
            publish(s, i, own);
        }
        assert_eq!(
            s.db.total_changes(),
            changes,
            "unchanged local row was rewritten"
        );
        let count: usize =
            s.db.query_row("SELECT count(*) FROM network_events", [], |r| r.get(0))
                .unwrap();
        assert_eq!(count, 0, "passive slot expiry created mailbox traffic");
        s.db.execute("UPDATE wire_peers SET confirmed_at=confirmed_at-200", [])
            .unwrap();
    }
    pair.send(vec![]).unwrap();
    for _ in 0..5 {
        for (i, s) in pair.stores.iter_mut().enumerate() {
            s.presence_tick().unwrap();
            // Model a successful registration only after a fresh offer returns.
            let reachable = s.helper_offers().unwrap();
            publish(s, i, &reachable);
        }
        pair.pump();
        if pair
            .stores
            .iter()
            .enumerate()
            .all(|(i, s)| s.helper_candidates(endpoints[1 - i].id).unwrap().len() == 2)
        {
            return;
        }
    }
    panic!("real work did not refresh the service and both registrations");
}
