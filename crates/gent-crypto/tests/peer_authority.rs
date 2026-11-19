#![cfg(feature = "invitation")]
use gent_crypto::{
    configuration_log::WriteCapability,
    peer::{NodeSigner, envelope},
    *,
};
use gent_protocol::configuration_log::{Commit, Head, Header};
use uuid::Uuid;

const NOW: u64 = 1_800_000_000;

#[path = "peer_authority/hosting.rs"]
mod hosting;

fn header(
    state: &VerifiedState,
    head: &Head,
    node: &NodeIdentity,
    next: &WriteCapability,
) -> Header {
    Header {
        version: 1,
        cluster: state.anchor().cluster_id.clone(),
        origin: node.id().into(),
        operation: Uuid::new_v4().to_string(),
        intent: [3; 32],
        previous: head.clone(),
        next_write_key: next.public_key(),
    }
}

fn commit(state: &SignedState, key: &WriteCapability, next: &WriteCapability) -> Commit {
    key.seal(
        state.state.peer.as_ref().unwrap().header.clone(),
        &envelope::seal(state, next).unwrap(),
    )
    .unwrap()
}

fn fixture() -> (OwnerKey, Vec<NodeIdentity>, VerifiedState) {
    let owner = OwnerKey::generate().unwrap();
    let nodes: Vec<_> = (0..3).map(|_| NodeIdentity::generate().unwrap()).collect();
    let mut state = owner
        .create_cluster("private cluster", &nodes[0], "creating node", NOW)
        .unwrap();
    state
        .advance_history(&[state
            .delegate_configuration(&owner, nodes[0].id(), true, NOW)
            .unwrap()])
        .unwrap();
    for (i, node) in nodes.iter().enumerate().skip(1) {
        let request = node
            .request_enrollment(state.anchor(), state.checkpoint(), "peer", NOW)
            .unwrap();
        let next = if i == 1 {
            state.enroll_configurator(&owner, &request, request.fingerprint().unwrap(), NOW)
        } else {
            state.enroll(&owner, &request, request.fingerprint().unwrap(), NOW)
        }
        .unwrap();
        state.advance_history(&[next]).unwrap();
    }
    (owner, nodes, state)
}

#[test]
fn encrypted_migration_and_surviving_peer_administer_without_owner_secret() {
    let (owner, nodes, old) = fixture();
    let admission = WriteCapability::generate().unwrap();
    let next = WriteCapability::generate().unwrap();
    let initial = Head {
        sequence: old.checkpoint().revision,
        digest: [9; 32],
        write_key: admission.public_key(),
    };
    let candidate = old
        .migrate_to_peers(
            &owner,
            &nodes[0],
            header(&old, &initial, &nodes[0], &next),
            NOW,
        )
        .unwrap();
    let record = commit(&candidate, &admission, &next);
    let mut peer = envelope::open(&nodes[1], &old, &initial, &record).unwrap();
    let restricted = envelope::open(&nodes[2], &old, &initial, &record).unwrap();
    assert!(restricted.capability.is_none());
    assert!(peer.capability.is_some());
    assert_eq!(peer.state.state().nodes, old.state().nodes);
    assert_eq!(
        serde_json::to_value(&peer.state.state().policy).unwrap(),
        serde_json::to_value(&old.state().policy).unwrap()
    );
    assert!(peer.state.renew(&owner, NOW).is_err());
    assert!(
        old.clone()
            .advance_history(std::slice::from_ref(&candidate))
            .is_err()
    );
    assert!(
        old.clone()
            .apply_chain(std::slice::from_ref(&candidate), NOW)
            .is_err()
    );
    drop(owner); // No owner key participates in any subsequent operation.

    let newcomer = NodeIdentity::generate().unwrap();
    let request = newcomer
        .request_enrollment(
            peer.state.anchor(),
            peer.state.checkpoint(),
            "new peer",
            NOW,
        )
        .unwrap();
    let next = WriteCapability::generate().unwrap();
    let signer =
        NodeSigner::new(&nodes[1], header(&peer.state, &peer.head, &nodes[1], &next)).unwrap();
    let candidate = peer
        .state
        .enroll_configurator(&signer, &request, request.fingerprint().unwrap(), NOW)
        .unwrap();
    let record = commit(&candidate, peer.capability.as_ref().unwrap(), &next);
    peer = envelope::open(&nodes[1], &peer.state, &peer.head, &record).unwrap();
    assert!(peer.state.state().nodes[newcomer.id()].can_configure);

    // The creating node can be removed without electing or handing off an owner.
    let next = WriteCapability::generate().unwrap();
    let signer =
        NodeSigner::new(&nodes[1], header(&peer.state, &peer.head, &nodes[1], &next)).unwrap();
    let candidate = peer.state.revoke_node(&signer, nodes[0].id(), NOW).unwrap();
    let record = commit(&candidate, peer.capability.as_ref().unwrap(), &next);
    assert!(envelope::open(&nodes[0], &peer.state, &peer.head, &record).is_err());
    peer = envelope::open(&nodes[1], &peer.state, &peer.head, &record).unwrap();
    assert!(peer.state.state().retired_nodes.contains(nodes[0].id()));
    let next = WriteCapability::generate().unwrap();
    let signer =
        NodeSigner::new(&nodes[1], header(&peer.state, &peer.head, &nodes[1], &next)).unwrap();
    assert!(peer.state.renew(&signer, NOW + MAX_STATE_LIFETIME).is_ok());
}

#[test]
fn restrictions_rotation_and_committed_head_are_enforced() {
    let (owner, nodes, old) = fixture();
    let admission = WriteCapability::generate().unwrap();
    let next = WriteCapability::generate().unwrap();
    let initial = Head {
        sequence: old.checkpoint().revision,
        digest: [9; 32],
        write_key: admission.public_key(),
    };
    let candidate = old
        .migrate_to_peers(
            &owner,
            &nodes[0],
            header(&old, &initial, &nodes[0], &next),
            NOW,
        )
        .unwrap();
    let record = commit(&candidate, &admission, &next);
    let peer = envelope::open(&nodes[1], &old, &initial, &record).unwrap();
    let restricted_signer = NodeSigner::new(
        &nodes[2],
        header(
            &peer.state,
            &peer.head,
            &nodes[2],
            &WriteCapability::generate().unwrap(),
        ),
    )
    .unwrap();
    assert!(peer.state.renew(&restricted_signer, NOW).is_err());

    let rotated = WriteCapability::generate().unwrap();
    let signer = NodeSigner::new(
        &nodes[0],
        header(&peer.state, &peer.head, &nodes[0], &rotated),
    )
    .unwrap();
    let restriction = peer
        .state
        .delegate_configuration(&signer, nodes[1].id(), false, NOW)
        .unwrap();
    let record = commit(&restriction, &next, &rotated);
    let restricted = envelope::open(&nodes[1], &peer.state, &peer.head, &record).unwrap();
    assert!(restricted.capability.is_none());
    let signer = NodeSigner::new(
        &nodes[1],
        header(
            &restricted.state,
            &restricted.head,
            &nodes[1],
            &WriteCapability::generate().unwrap(),
        ),
    )
    .unwrap();
    assert!(restricted.state.renew(&signer, NOW).is_err());
    let mut wrong_head = peer.head.clone();
    wrong_head.digest[0] ^= 1;
    assert!(envelope::open(&nodes[1], &peer.state, &wrong_head, &record).is_err());
    assert!(envelope::open(&nodes[1], &restricted.state, &restricted.head, &record).is_err());
    let mut tampered = record.clone();
    tampered.signature[0] ^= 1;
    assert!(envelope::open(&nodes[1], &peer.state, &peer.head, &tampered).is_err());
    let mut tampered = restriction;
    tampered.state.name = "forged".into();
    let record = commit(&tampered, &next, &rotated);
    assert!(envelope::open(&nodes[1], &peer.state, &peer.head, &record).is_err());
}
