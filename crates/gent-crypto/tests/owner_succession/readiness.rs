use super::*;
use gent_crypto::succession::readiness::{MAX_READINESS_BYTES, SignedReadiness};

struct Ready {
    owner: OwnerKey,
    nodes: Vec<NodeIdentity>,
    state: VerifiedState,
    key: OwnerKey,
    candidate: SignedOwnerCandidate,
    grants: Vec<SignedConfigurationGrant>,
    report: SignedReadiness,
}

fn ready(count: usize) -> Ready {
    let (owner, first, state) = fixture();
    let mut nodes: Vec<_> = first.into_iter().collect();
    let mut signed = state.signed().clone();
    for _ in nodes.len()..count {
        let node = NodeIdentity::generate().unwrap();
        let mut member = signed.state.nodes.values().next().unwrap().clone();
        member.signing_key = node.public_key();
        signed.state.nodes.insert(node.id().into(), member);
        nodes.push(node);
    }
    resign(&mut signed, &owner);
    let state = VerifiedState::restore(
        state.anchor().clone(),
        signed.verified_checkpoint(state.anchor()).unwrap(),
        signed,
    )
    .unwrap();
    let key = OwnerKey::generate().unwrap();
    let candidate = nodes[1]
        .prepare_owner_candidate(&state, &key, &uuid::Uuid::new_v4().to_string(), NOW)
        .unwrap();
    let mut connections = Vec::new();
    for node in nodes.iter().filter(|n| n.id() != nodes[1].id()) {
        // Exercise the largest permitted group IDs, not just the runtime's
        // current shorter IDs, at the maximum enrolled-node count.
        let mut group = vec![255; 256];
        group[..36].copy_from_slice(node.id().as_bytes());
        let grant = owner
            .authorize_standby_configuration_stream(
                &state,
                &candidate,
                &group,
                [255; 32],
                node.id(),
                NOW,
            )
            .unwrap();
        let receipt = node.sign_stream_receipt(&group, 0, [255; 32]).unwrap();
        connections.push((grant, receipt));
    }
    let report = nodes[1]
        .sign_owner_readiness(&state, &key, &candidate, &connections, NOW + 1)
        .unwrap();
    connections.sort_by(|a, b| a.0.grant.reader.cmp(&b.0.grant.reader));
    Ready {
        owner,
        nodes,
        state,
        key,
        candidate,
        grants: connections.into_iter().map(|(g, _)| g).collect(),
        report,
    }
}

fn resign_report(report: &mut SignedReadiness, node: &NodeIdentity, key: &OwnerKey) {
    let wire = serde_jcs::to_vec(&report.readiness).unwrap();
    let mut input = b"gent/owner-readiness/v1\0".to_vec();
    input.extend_from_slice(&wire);
    report.node_signature = SigningKey::from_bytes(&node.expose_secret())
        .sign(&input)
        .to_bytes()
        .to_vec();
    let mut input = b"gent/owner-readiness-key/v1\0".to_vec();
    input.extend_from_slice(&wire);
    report.key_signature = SigningKey::from_bytes(&key.expose_secret())
        .sign(&input)
        .to_bytes()
        .to_vec();
}

#[test]
fn readiness_requires_both_candidate_keys_and_the_current_approval_window() {
    let f = ready(3);
    let wire = f.report.encode().unwrap();
    assert_eq!(SignedReadiness::decode(&wire).unwrap(), f.report);
    let check =
        |report: &SignedReadiness, time| report.verify(&f.state, &f.candidate, &f.grants, time);
    check(&f.report, NOW + 1).unwrap();
    assert!(check(&f.report, NOW).is_err());
    assert!(check(&f.report, f.candidate.candidate.expires_at).is_err());
    for change in 0..6 {
        let mut report = f.report.clone();
        match change {
            0 => report.node_signature[0] ^= 1,
            1 => report.key_signature[0] ^= 1,
            2 => report.readiness.candidate[0] ^= 1,
            3 => report.readiness.version += 1,
            4 => report.readiness.expires_at += 1,
            _ => report.readiness.issued_at = NOW - 1,
        }
        if change > 1 {
            resign_report(&mut report, &f.nodes[1], &f.key);
        }
        assert!(check(&report, NOW + 1).is_err(), "mutation {change}");
    }
    let mut state = f.state.clone();
    state
        .apply_chain(&[state.renew(&f.owner, NOW + 2).unwrap()], NOW + 2)
        .unwrap();
    assert!(
        f.report
            .verify(&state, &f.candidate, &f.grants, NOW + 2)
            .is_err()
    );
    let mut noncanonical = wire.clone();
    noncanonical.push(b'\n');
    assert!(SignedReadiness::decode(&noncanonical).is_err());
    assert!(SignedReadiness::decode(&vec![b' '; MAX_READINESS_BYTES + 1]).is_err());
}

#[test]
fn authentic_successor_reports_cannot_omit_peers_or_substitute_receipts_or_grants() {
    let f = ready(3);
    for change in 0..8 {
        let mut report = f.report.clone();
        let mut grants = f.grants.clone();
        match change {
            0 => {
                report.readiness.peers.pop();
                grants.pop();
            }
            1 => report.readiness.peers[1] = report.readiness.peers[0].clone(),
            2 => report.readiness.peers.swap(0, 1),
            3 => report.readiness.peers[0].grant[0] ^= 1,
            4 => {
                report.readiness.peers[0].receipt = f.nodes[1]
                    .sign_stream_receipt(&grants[0].grant.group, 0, grants[0].grant.origin)
                    .unwrap()
            }
            5 => {
                let node = f
                    .nodes
                    .iter()
                    .find(|n| n.id() == grants[0].grant.reader)
                    .unwrap();
                report.readiness.peers[0].receipt = node
                    .sign_stream_receipt(&grants[0].grant.group, 1, grants[0].grant.origin)
                    .unwrap();
            }
            6 => grants.swap(0, 1),
            _ => grants[0].grant.origin[0] ^= 1,
        }
        resign_report(&mut report, &f.nodes[1], &f.key);
        assert!(
            report
                .verify(&f.state, &f.candidate, &grants, NOW + 1)
                .is_err(),
            "mutation {change}"
        );
    }
}

#[test]
fn readiness_covers_all_1024_enrolled_nodes_within_the_transport_record_budget() {
    let f = ready(1024);
    assert_eq!(f.report.readiness.peers.len(), 1023);
    let wire = f.report.encode().unwrap();
    assert!(wire.len() <= MAX_READINESS_BYTES);
    assert!(wire.len() + 64 * 1024 < 2 * 1024 * 1024);
    SignedReadiness::decode(&wire)
        .unwrap()
        .verify(&f.state, &f.candidate, &f.grants, NOW + 1)
        .unwrap();
    let mut oversized = f.report.clone();
    oversized
        .readiness
        .peers
        .push(oversized.readiness.peers[0].clone());
    assert!(oversized.encode().is_err());
}
