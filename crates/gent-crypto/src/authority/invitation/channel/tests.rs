use super::*;
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000;

fn service() -> ServiceBinding {
    ServiceBinding {
        account_id: Uuid::new_v4().to_string(),
        account_origin: "https://accounts.example.test".into(),
        relay_origin: "https://relay.example.test".into(),
    }
}
fn options() -> Options {
    Options {
        service: service(),
        purpose: Purpose::NewNode,
        can_configure: true,
    }
}
fn fixture() -> (OwnerKey, NodeIdentity, VerifiedState, OwnerInvitation) {
    let owner = OwnerKey::generate().unwrap();
    let issuer = NodeIdentity::generate().unwrap();
    let state = owner
        .create_cluster("private cluster", &issuer, "owner node", NOW)
        .unwrap();
    let invite = OwnerInvitation::issue(&owner, &state, &issuer, options(), NOW).unwrap();
    (owner, issuer, state, invite)
}
fn pending(invite: &OwnerInvitation, node: &NodeIdentity) -> (Channel, PendingClaim, Vec<Vec<u8>>) {
    let (init, hello) = Initiator::start(invite.invitation(), NOW).unwrap();
    let (pending, reply) = invite.respond(&hello, NOW).unwrap();
    assert_eq!(hello.noise.len(), HANDSHAKE_BYTES);
    assert_eq!(reply.len(), HANDSHAKE_BYTES);
    let (channel, claim) = init.finish(&reply, node, "joining node", NOW).unwrap();
    (channel, pending, claim)
}
fn connected(invite: &OwnerInvitation) -> (Channel, Channel) {
    let node = NodeIdentity::generate().unwrap();
    let (client, pending, claim) = pending(invite, &node);
    let server = pending
        .accept(&claim, NOW, |offer, claimed| {
            assert_eq!(offer, invite.invitation().offer());
            assert_eq!(claimed.id, node.id());
            assert_eq!(claimed.key, node.public_key());
            assert_eq!(claimed.name, "joining node");
            Ok(())
        })
        .unwrap();
    assert_eq!(server.node(), client.node());
    assert_eq!(server.handshake_hash(), client.handshake_hash());
    (client, server)
}

#[test]
fn invitation_storage_preserves_keys_and_rejects_conflicts_without_echoing_secrets() {
    let (_, _, _, invite) = fixture();
    let owner_bytes = invite.encode().unwrap();
    let restored = OwnerInvitation::decode(&owner_bytes).unwrap();
    let file = restored.invitation().encode().unwrap();
    let joining = Invitation::decode(&file).unwrap();
    assert_eq!(joining.offer(), invite.invitation().offer());
    assert_eq!(
        *joining.expose_routing_secret(),
        *invite.invitation().routing
    );
    assert_ne!(*invite.invitation().routing, *invite.invitation().psk);
    assert!(!String::from_utf8_lossy(&file).contains("\"private\""));
    let (init, hello) = Initiator::start(&joining, NOW).unwrap();
    let (pending, reply) = restored.respond(&hello, NOW).unwrap();
    let (_, claim) = init
        .finish(&reply, &NodeIdentity::generate().unwrap(), "joined", NOW)
        .unwrap();
    pending.accept(&claim, NOW, |_, _| Ok(())).unwrap();

    let mut changed: Value = serde_json::from_slice(&owner_bytes).unwrap();
    changed["private"][0] = json!(changed["private"][0].as_u64().unwrap() ^ 8);
    assert!(OwnerInvitation::decode(&serde_jcs::to_vec(&changed).unwrap()).is_err());
    let mut changed: Value = serde_json::from_slice(&file).unwrap();
    changed["routing"][0] = json!(changed["routing"][0].as_u64().unwrap() ^ 1);
    assert!(Invitation::decode(&serde_jcs::to_vec(&changed).unwrap()).is_err());
    changed["psk"] = json!("secret-that-must-never-appear-in-an-error");
    let error = Invitation::decode(&serde_jcs::to_vec(&changed).unwrap())
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "invalid invitation file");
    assert!(Invitation::decode(&vec![b' '; MAX_INVITATION_BYTES + 1]).is_err());
    assert!(Invitation::decode(&[file.as_slice(), b"\n"].concat()).is_err());
    assert!(Invitation::decode(&owner_bytes).is_err());
    assert!(OwnerInvitation::decode(&file).is_err());
}

#[test]
fn offer_authenticates_every_field_and_requires_the_transferred_anchor() {
    let (_, _, state, invite) = fixture();
    let signed = invite.invitation().offer();
    let original = serde_json::to_value(signed).unwrap();
    let mutations = [
        ("/offer/version", json!(2)),
        ("/offer/id", json!(Uuid::new_v4().to_string())),
        ("/offer/issuer_id", json!(Uuid::new_v4().to_string())),
        ("/offer/issuer_key/0", json!(0)),
        (
            "/offer/anchor/cluster_id",
            json!(Uuid::new_v4().to_string()),
        ),
        ("/offer/anchor/genesis_hash/0", json!(0)),
        ("/offer/anchor/owner_key/0", json!(0)),
        (
            "/offer/service/account_id",
            json!(Uuid::new_v4().to_string()),
        ),
        (
            "/offer/service/account_origin",
            json!("https://other.example.test"),
        ),
        (
            "/offer/service/relay_origin",
            json!("https://other.example.test"),
        ),
        ("/offer/responder_key/0", json!(0)),
        ("/offer/routing_digest/0", json!(0)),
        ("/offer/can_configure", json!(false)),
        ("/offer/issued_at", json!(NOW - 1)),
        ("/offer/expires_at", json!(NOW + 1)),
        ("/signature/0", json!(0)),
    ];
    for (path, replacement) in mutations {
        let mut changed = original.clone();
        let target = changed.pointer_mut(path).unwrap();
        *target = if *target == replacement {
            json!(1)
        } else {
            replacement
        };
        let changed = SignedOffer::decode(&serde_jcs::to_vec(&changed).unwrap()).unwrap();
        assert!(
            changed.verify(state.anchor(), NOW).is_err(),
            "accepted modified {path}"
        );
    }
    let (_, _, other, _) = fixture();
    assert!(signed.verify(other.anchor(), NOW).is_err());
    assert!(signed.verify(state.anchor(), NOW - 1).is_err());
    assert!(signed.verify(state.anchor(), NOW + OFFER_LIFETIME).is_err());
    assert!(SignedOffer::decode(&[signed.encode().unwrap(), b" ".to_vec()].concat()).is_err());
}

#[test]
fn signed_offer_cannot_extend_the_issue_time_bound_into_its_identifier() {
    let (owner, _, state, invite) = fixture();
    let mut changed = invite.invitation().offer().clone();
    changed.offer.issued_at += 1;
    changed.offer.expires_at += 1;
    changed.signature = owner
        .0
        .sign(&signing_input(OFFER_DOMAIN, &changed.offer, MAX_OFFER_BYTES).unwrap())
        .to_bytes()
        .to_vec();
    assert!(
        changed
            .verify(state.anchor(), NOW + 1)
            .unwrap_err()
            .to_string()
            .contains("issue time")
    );
}

#[test]
fn issuance_checks_owner_membership_origins_and_continuation_identity() {
    let (owner, issuer, mut state, _) = fixture();
    let outsider = NodeIdentity::generate().unwrap();
    assert!(
        OwnerInvitation::issue(
            &OwnerKey::generate().unwrap(),
            &state,
            &issuer,
            options(),
            NOW
        )
        .is_err()
    );
    assert!(OwnerInvitation::issue(&owner, &state, &outsider, options(), NOW).is_err());
    assert!(
        OwnerInvitation::issue(&owner, &state, &issuer, options(), NOW + MAX_STATE_LIFETIME)
            .is_err()
    );
    for bad in [
        "http://relay.example.test",
        "https://user@relay.example.test",
        "https://relay.example.test/path",
        "https://relay.example.test?x=1",
        "https://relay.example.test#secret",
        "https://relay.example.test/",
        "https://RELAY.example.test",
        "http://localhost:8000",
    ] {
        let mut opts = options();
        opts.service.relay_origin = bad.into();
        assert!(
            OwnerInvitation::issue(&owner, &state, &issuer, opts, NOW).is_err(),
            "accepted {bad}"
        );
    }
    let mut local = service();
    local.account_origin = "http://127.0.0.1:8000".into();
    local.relay_origin = "http://[::1]:8001".into();
    local.validate().unwrap();
    local.account_origin = "https://accounts.example.test".into();
    assert!(local.validate().is_err());
    let enrollment = outsider
        .request_enrollment(state.anchor(), state.checkpoint(), "joining node", NOW)
        .unwrap();
    let next = state
        .enroll_configurator(&owner, &enrollment, enrollment.fingerprint().unwrap(), NOW)
        .unwrap();
    state.apply_chain(&[next], NOW).unwrap();
    let mut opts = options();
    opts.purpose = Purpose::Continue {
        node: ClaimedNode {
            id: outsider.id().into(),
            key: outsider.public_key(),
            name: "joining node".into(),
        },
    };
    let invite = OwnerInvitation::issue(&owner, &state, &issuer, opts, NOW).unwrap();
    let (_, pending, claim) = pending(&invite, &outsider);
    pending.accept(&claim, NOW, |_, _| Ok(())).unwrap();
    let (init, hello) = Initiator::start(invite.invitation(), NOW).unwrap();
    let (_, reply) = invite.respond(&hello, NOW).unwrap();
    assert!(
        init.finish(
            &reply,
            &NodeIdentity::generate().unwrap(),
            "joining node",
            NOW
        )
        .is_err()
    );
    let mut opts = options();
    opts.purpose = invite.invitation.offer.offer.purpose.clone();
    opts.can_configure = false;
    assert!(OwnerInvitation::issue(&owner, &state, &issuer, opts, NOW).is_err());
}

#[test]
fn encrypted_messages_cover_empty_fragment_boundaries_and_maximum_pairing_frame() {
    let (_, _, _, invite) = fixture();
    let (mut client, mut server) = connected(&invite);
    for size in [
        0,
        1,
        CHUNK_BYTES - 1,
        CHUNK_BYTES,
        CHUNK_BYTES + 1,
        MAX_MESSAGE_BYTES,
    ] {
        let message: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
        let encrypted = client.seal(&message, NOW).unwrap();
        assert!(encrypted.iter().all(|f| f.len() <= MAX_NOISE_BYTES));
        assert_eq!(*server.open(&encrypted, NOW).unwrap(), message);
        let reply = server.seal(&message, NOW).unwrap();
        assert_eq!(*client.open(&reply, NOW).unwrap(), message);
    }
    let plaintext = b"private-cluster-policy-and-enrollment-metadata";
    let wire = client.seal(plaintext, NOW).unwrap();
    assert!(
        !wire
            .concat()
            .windows(plaintext.len())
            .any(|w| w == plaintext)
    );
    assert_eq!(&*server.open(&wire, NOW).unwrap(), plaintext);
}

#[test]
fn wrong_secret_attempt_or_pinned_owner_cannot_complete_the_handshake() {
    let (_, _, _, invite) = fixture();
    let mut file: Value = serde_json::from_slice(&invite.invitation.encode().unwrap()).unwrap();
    file["psk"][0] = json!(file["psk"][0].as_u64().unwrap() ^ 1);
    let wrong = Invitation::decode(&serde_jcs::to_vec(&file).unwrap()).unwrap();
    let (_, hello) = Initiator::start(&wrong, NOW).unwrap();
    assert!(invite.respond(&hello, NOW).is_err());
    let (_, mut hello) = Initiator::start(invite.invitation(), NOW).unwrap();
    hello.attempt = Uuid::new_v4().to_string();
    assert!(invite.respond(&hello, NOW).is_err());
    let (_, _, _, other) = fixture();
    let (_, hello) = Initiator::start(invite.invitation(), NOW).unwrap();
    assert!(other.respond(&hello, NOW).is_err());
    let (init, hello) = Initiator::start(invite.invitation(), NOW).unwrap();
    let (_, mut reply) = invite.respond(&hello, NOW).unwrap();
    reply[47] ^= 1;
    assert!(
        init.finish(&reply, &NodeIdentity::generate().unwrap(), "node", NOW)
            .is_err()
    );
}

#[test]
fn admission_callback_is_required_and_new_sessions_cannot_replay_claims() {
    let (_, _, _, invite) = fixture();
    let node = NodeIdentity::generate().unwrap();
    let (_, rejected, wire) = pending(&invite, &node);
    assert!(
        rejected
            .accept(&wire, NOW, |_, _| anyhow::bail!(
                "durable claim write failed"
            ))
            .is_err()
    );
    let (one, pending_one, wire_one) = pending(&invite, &node);
    let (two, pending_two, wire_two) = pending(&invite, &node);
    assert_ne!(one.handshake_hash(), two.handshake_hash());
    assert!(
        pending_two
            .accept(&wire_one, NOW, |_, _| panic!(
                "replayed claim reached admission"
            ))
            .is_err()
    );
    let server = pending_one.accept(&wire_one, NOW, |_, _| Ok(())).unwrap();
    assert_eq!(server.node().key, node.public_key());
    assert_ne!(wire_one, wire_two);
    let (_, expired, wire) = pending(&invite, &node);
    assert!(
        expired
            .accept(&wire, NOW + 60, |_, _| panic!(
                "expired claim reached admission"
            ))
            .is_err()
    );
}

#[test]
fn a_valid_channel_still_requires_an_authentic_bound_node_claim() {
    let (_, _, _, invite) = fixture();
    let node = NodeIdentity::generate().unwrap();
    for attack in 0..9 {
        let (mut init, hello) = Initiator::start(invite.invitation(), NOW).unwrap();
        let (pending, reply) = invite.respond(&hello, NOW).unwrap();
        read_handshake(&mut init.noise, &reply).unwrap();
        let mut client = Channel::new(init.offer, init.noise, NOW).unwrap();
        let mut claim =
            SignedClaim::create(&client.offer, client.handshake, &node, "joining node", NOW)
                .unwrap();
        match attack {
            0 => claim.claim.invitation = Uuid::new_v4().to_string(),
            1 => claim.claim.offer[0] ^= 1,
            2 => {
                claim = SignedClaim::create(&client.offer, [0; 32], &node, "joining node", NOW)
                    .unwrap();
            }
            3 => claim.claim.node.id = Uuid::new_v4().to_string(),
            4 => claim.claim.node.key = NodeIdentity::generate().unwrap().public_key(),
            5 => claim.claim.node.name = "substituted name".into(),
            6 => claim.claim.issued_at += 1,
            7 => claim.signature[0] ^= 1,
            8 => claim.claim.expires_at = NOW + 61,
            _ => unreachable!(),
        }
        let bytes = encode(&claim, MAX_REQUEST_BYTES).unwrap();
        let wire = client.seal(&bytes, NOW).unwrap();
        assert!(
            pending
                .accept(&wire, NOW, |_, _| panic!("invalid claim reached admission"))
                .is_err(),
            "accepted attack {attack}"
        );
    }
}

#[test]
fn admission_can_bind_one_node_across_reconnects_and_refuse_other_claimants() {
    let (_, _, _, invite) = fixture();
    let first = NodeIdentity::generate().unwrap();
    let restored = NodeIdentity::from_secret_bytes(first.id(), &first.expose_secret()).unwrap();
    let second = NodeIdentity::generate().unwrap();
    let mut saved: Option<ClaimedNode> = None;
    for (node, expected) in [
        (&first, true),
        (&restored, true),
        (&second, false),
        (&restored, true),
    ] {
        let (_, pending, wire) = pending(&invite, node);
        let result = pending.accept(&wire, NOW, |_, node| {
            if let Some(saved) = &saved {
                ensure!(saved == node, "invitation already claimed");
            } else {
                saved = Some(node.clone());
            }
            Ok(())
        });
        assert_eq!(result.is_ok(), expected);
        assert_eq!(saved.as_ref().unwrap().key, first.public_key());
    }
    // This exercises the admission boundary, not durable storage or its races.
}

#[test]
fn handshake_replay_has_fresh_responder_keys_and_never_reuses_an_old_claim() {
    let (_, _, _, invite) = fixture();
    let (init, hello) = Initiator::start(invite.invitation(), NOW).unwrap();
    let (first, reply) = invite.respond(&hello, NOW).unwrap();
    let (second, other_reply) = invite.respond(&hello, NOW).unwrap();
    assert_ne!(reply, other_reply);
    let (_, claim) = init
        .finish(&reply, &NodeIdentity::generate().unwrap(), "joining", NOW)
        .unwrap();
    assert!(
        second
            .accept(&claim, NOW, |_, _| panic!("replayed claim admitted"))
            .is_err()
    );
    first.accept(&claim, NOW, |_, _| Ok(())).unwrap();
}

#[test]
fn incomplete_oversized_and_early_data_frames_are_refused_before_admission() {
    let (_, _, _, invite) = fixture();
    for size in [0, 31, 47, 49, MAX_NOISE_BYTES + 1] {
        let (_, mut hello) = Initiator::start(invite.invitation(), NOW).unwrap();
        hello.noise.resize(size, 0);
        assert!(invite.respond(&hello, NOW).is_err());
    }
    for frames in [
        vec![],
        vec![vec![0; TAG_BYTES]],
        vec![vec![0; MAX_NOISE_BYTES + 1]],
        vec![vec![0; 25]; MAX_FRAGMENTS + 1],
    ] {
        let (_, mut server) = connected(&invite);
        assert!(server.open(&frames, NOW).is_err());
        assert!(server.seal(b"closed", NOW).is_err());
    }
    assert!(Initiator::start(invite.invitation(), NOW - 1).is_err());
    assert!(Initiator::start(invite.invitation(), NOW + OFFER_LIFETIME).is_err());
    let late = NOW + OFFER_LIFETIME - 1;
    let (init, hello) = Initiator::start(invite.invitation(), late).unwrap();
    let (pending, reply) = invite.respond(&hello, late).unwrap();
    let (mut client, claim) = init
        .finish(&reply, &NodeIdentity::generate().unwrap(), "late", late)
        .unwrap();
    let mut server = pending.accept(&claim, late, |_, _| Ok(())).unwrap();
    server
        .open(&client.seal(b"just in time", late).unwrap(), late)
        .unwrap();
    assert!(server.seal(b"offer expired", late + 1).is_err());
}

#[test]
fn replay_reflection_reordering_corruption_and_cross_session_frames_close_the_channel() {
    let (_, _, _, invite) = fixture();
    for attack in 0..6 {
        let (mut client, mut server) = connected(&invite);
        let original = client.seal(&vec![42; CHUNK_BYTES + 1], NOW).unwrap();
        let mut bad = original.clone();
        match attack {
            0 => {
                server.open(&original, NOW).unwrap();
            }
            1 => {
                bad.swap(0, 1);
            }
            2 => {
                bad[1][0] ^= 1;
            }
            3 => {
                bad.pop();
            }
            4 => {
                bad = server.seal(b"reflected reply", NOW).unwrap();
            }
            5 => {
                let (mut other, _) = connected(&invite);
                bad = other.seal(b"different session", NOW).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(server.open(&bad, NOW).is_err(), "accepted attack {attack}");
        assert!(
            server.open(&original, NOW).is_err(),
            "channel reopened after attack {attack}"
        );
        assert!(server.seal(b"no reply after failure", NOW).is_err());
    }
}

#[test]
fn authenticated_malformed_fragment_headers_never_expose_partial_operations() {
    let (_, _, _, invite) = fixture();
    for (version, total, offset, count) in [
        (2, 1, 0, 1),
        (1, 1, 1, 1),
        (1, MAX_MESSAGE_BYTES + 1, 0, 1),
        (1, 2, 0, 1),
        (1, CHUNK_BYTES + 1, 0, 1),
        (1, 0, 0, 1),
    ] {
        let (mut client, mut server) = connected(&invite);
        let mut payload = vec![version];
        payload.extend_from_slice(&(total as u32).to_be_bytes());
        payload.extend_from_slice(&(offset as u32).to_be_bytes());
        payload.extend_from_slice(&vec![7; count]);
        let mut wire = vec![0; payload.len() + TAG_BYTES];
        client
            .noise
            .as_mut()
            .unwrap()
            .write_message(&payload, &mut wire)
            .unwrap();
        assert!(server.open(&[wire], NOW).is_err());
        assert!(server.seal(b"no partial response", NOW).is_err());
    }
}

#[test]
fn session_expiry_clock_and_directional_budgets_fail_closed() {
    let (_, _, _, invite) = fixture();
    for timestamp in [NOW - 1, NOW + SESSION_LIFETIME, NOW + OFFER_LIFETIME] {
        let (mut client, _) = connected(&invite);
        assert!(client.seal(b"expired", timestamp).is_err());
        assert!(client.seal(b"cannot restore time", NOW).is_err());
    }
    let (mut client, mut server) = connected(&invite);
    client.sent_bytes = MAX_SESSION_BYTES - 2;
    server.received_bytes = MAX_SESSION_BYTES - 2;
    let last = client.seal(b"ok", NOW).unwrap();
    assert_eq!(&*server.open(&last, NOW).unwrap(), b"ok");
    assert!(client.seal(b"x", NOW).is_err());
    let (mut client, mut server) = connected(&invite);
    server.received_bytes = MAX_SESSION_BYTES;
    assert!(server.open(&client.seal(b"x", NOW).unwrap(), NOW).is_err());
    let (mut client, mut server) = connected(&invite);
    client.sent_messages = MAX_SESSION_MESSAGES - 1;
    server.received_messages = MAX_SESSION_MESSAGES - 1;
    server.open(&client.seal(b"", NOW).unwrap(), NOW).unwrap();
    assert!(client.seal(b"", NOW).is_err());
    let (mut other, _) = connected(&invite);
    assert!(server.open(&other.seal(b"", NOW).unwrap(), NOW).is_err());
    let (mut client, _) = connected(&invite);
    assert!(client.seal(&vec![0; MAX_MESSAGE_BYTES + 1], NOW).is_err());
}

#[test]
fn low_order_and_noncanonical_zero_equivalent_points_are_rejected() {
    use snow::resolvers::CryptoResolver;
    let dh = resolver::Resolver
        .resolve_dh(&snow::params::DHChoice::Curve25519)
        .unwrap();
    let mut points = vec![[0; 32]];
    let mut one = [0; 32];
    one[0] = 1;
    points.push(one);
    for first in [0xec, 0xed, 0xee] {
        let mut p = [0xff; 32];
        p[0] = first;
        p[31] = 0x7f;
        points.push(p);
    }
    for point in points {
        assert!(validate_public_key(&point).is_err());
        let mut output = [99; 32];
        assert!(dh.dh(&point, &mut output).is_err());
        assert_eq!(output, [99; 32]);
    }
    assert!(dh.dh(&[0; 31], &mut [0; 32]).is_err());
}

#[test]
fn cacophony_noise_vector_matches_handshake_hash_and_both_transport_directions() {
    let vector: Value = serde_json::from_str(include_str!("nkpsk0-cacophony.json")).unwrap();
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let bytes = |key: &str| hex(vector[key].as_str().unwrap());
    let psk: [u8; 32] = hex(vector["init_psks"][0].as_str().unwrap())
        .try_into()
        .unwrap();
    let init_ephemeral = bytes("init_ephemeral");
    let responder_private = bytes("resp_static");
    let responder_public = bytes("init_remote_static");
    let resp_ephemeral = bytes("resp_ephemeral");
    let prologue = bytes("init_prologue");
    let mut init = builder()
        .prologue(&prologue)
        .unwrap()
        .psk(0, &psk)
        .unwrap()
        .remote_public_key(&responder_public)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&init_ephemeral)
        .build_initiator()
        .unwrap();
    let mut resp = builder()
        .prologue(&prologue)
        .unwrap()
        .psk(0, &psk)
        .unwrap()
        .local_private_key(&responder_private)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&resp_ephemeral)
        .build_responder()
        .unwrap();
    let messages = vector["messages"].as_array().unwrap();
    for (i, message) in messages[..2].iter().enumerate() {
        let (sender, receiver) = if i == 0 {
            (&mut init, &mut resp)
        } else {
            (&mut resp, &mut init)
        };
        let plain = hex(message["payload"].as_str().unwrap());
        let expected = hex(message["ciphertext"].as_str().unwrap());
        let mut out = vec![0; MAX_NOISE_BYTES];
        let n = sender.write_message(&plain, &mut out).unwrap();
        assert_eq!(&out[..n], expected);
        let n = receiver.read_message(&expected, &mut out).unwrap();
        assert_eq!(&out[..n], plain);
    }
    assert_eq!(init.get_handshake_hash(), bytes("handshake_hash"));
    assert_eq!(resp.get_handshake_hash(), bytes("handshake_hash"));
    let mut init = init.into_transport_mode().unwrap();
    let mut resp = resp.into_transport_mode().unwrap();
    for (i, message) in messages[2..].iter().enumerate() {
        let (sender, receiver) = if i % 2 == 0 {
            (&mut init, &mut resp)
        } else {
            (&mut resp, &mut init)
        };
        let plain = hex(message["payload"].as_str().unwrap());
        let expected = hex(message["ciphertext"].as_str().unwrap());
        let mut out = vec![0; MAX_NOISE_BYTES];
        let n = sender.write_message(&plain, &mut out).unwrap();
        assert_eq!(&out[..n], expected);
        let n = receiver.read_message(&expected, &mut out).unwrap();
        assert_eq!(&out[..n], plain);
    }
}
