use super::*;
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn hosted_administrators_cannot_replace_the_last_native_writer() {
    let (owner, nodes, mut old) = fixture();
    old.apply_chain(
        &[old
            .host_node(&owner, nodes[1].id(), nodes[2].id(), NOW)
            .unwrap()],
        NOW,
    )
    .unwrap();
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
    let mut peer = envelope::open(&nodes[0], &old, &initial, &record).unwrap();
    let rotated = WriteCapability::generate().unwrap();
    let signer = NodeSigner::new(
        &nodes[0],
        header(&peer.state, &peer.head, &nodes[0], &rotated),
    )
    .unwrap();
    for result in [
        peer.state
            .delegate_configuration(&signer, nodes[0].id(), false, NOW),
        peer.state.revoke_node(&signer, nodes[0].id(), NOW),
        peer.state
            .host_node(&signer, nodes[0].id(), nodes[2].id(), NOW),
    ] {
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("native configuration administrator")
        );
    }
    // A correctly signed malformed revision must also fail on receiving peers,
    // independently of the mutation helpers used by the writer.
    let mut forged = peer.state.renew(&signer, NOW).unwrap();
    forged
        .state
        .nodes
        .get_mut(nodes[0].id())
        .unwrap()
        .can_configure = false;
    let mut bytes = b"gent/cluster-state/v1\0".to_vec();
    bytes.extend(serde_jcs::to_vec(&forged.state).unwrap());
    forged.signature = SigningKey::from_bytes(&nodes[0].expose_secret())
        .sign(&bytes)
        .to_bytes()
        .to_vec();
    assert!(forged.verified_checkpoint(peer.state.anchor()).is_err());

    let candidate = peer
        .state
        .delegate_configuration(&signer, nodes[2].id(), true, NOW)
        .unwrap();
    let record = commit(&candidate, peer.capability.as_ref().unwrap(), &rotated);
    peer = envelope::open(&nodes[0], &peer.state, &peer.head, &record).unwrap();
    let next = WriteCapability::generate().unwrap();
    let signer =
        NodeSigner::new(&nodes[0], header(&peer.state, &peer.head, &nodes[0], &next)).unwrap();
    // A second native administrator makes each transition safe. Hosting does
    // not erase the original node's configuration grant.
    assert!(
        peer.state
            .delegate_configuration(&signer, nodes[0].id(), false, NOW)
            .is_ok()
    );
    assert!(peer.state.revoke_node(&signer, nodes[0].id(), NOW).is_ok());
    let hosted = peer
        .state
        .host_node(&signer, nodes[0].id(), nodes[2].id(), NOW)
        .unwrap();
    assert!(hosted.state.nodes[nodes[0].id()].can_configure);
}
