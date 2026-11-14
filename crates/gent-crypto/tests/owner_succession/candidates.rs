use super::*;

#[test]
fn separate_keys_bind_one_enrolled_successor_and_preserve_exact_delayed_completion() {
    let (root, nodes, mut state) = fixture();
    let next = OwnerKey::generate().unwrap();
    let request = uuid::Uuid::new_v4().to_string();
    let candidate = nodes[1]
        .prepare_owner_candidate(&state, &next, &request, NOW)
        .unwrap();
    let candidate = SignedOwnerCandidate::decode(&candidate.encode().unwrap()).unwrap();
    let authorization = state
        .authorize_owner_candidate(&root, &candidate, NOW + 1)
        .unwrap();
    let authorization = SignedOwnerTransition::decode(&authorization.encode().unwrap()).unwrap();
    let update = state
        .accept_owner_authorization(&next, &candidate, &authorization, NOW + 1)
        .unwrap();
    let late = NOW + CANDIDATE_LIFETIME + 1;
    assert!(candidate.verify(&state, late).is_err());
    assert!(
        state
            .authorize_owner_candidate(&root, &candidate, late)
            .is_err()
    );
    assert_eq!(
        state
            .accept_owner_authorization(&next, &candidate, &authorization, late)
            .unwrap()
            .encode()
            .unwrap(),
        update.encode().unwrap()
    );
    assert!(
        state
            .accept_owner_authorization(&root, &candidate, &authorization, NOW + 1)
            .is_err()
    );
    assert!(
        state
            .accept_owner_authorization(&next, &candidate, &authorization, NOW)
            .is_err()
    );
    let anchor = state.anchor().clone();
    let policy = state.state().policy.clone();
    let membership = state.state().nodes.clone();
    state.apply_chain(&[update], NOW + 1).unwrap();
    assert_eq!(state.anchor(), &anchor);
    assert_eq!(
        serde_jcs::to_vec(&state.state().policy).unwrap(),
        serde_jcs::to_vec(&policy).unwrap()
    );
    assert_eq!(state.state().nodes, membership);
    assert_eq!(
        state.state().owner_transitions[0]
            .transition
            .successor
            .as_ref()
            .unwrap()
            .node
            .id,
        nodes[1].id()
    );
    assert!(state.renew(&root, NOW + 2).is_err());
    state
        .apply_chain(&[state.renew(&next, NOW + 2).unwrap()], NOW + 2)
        .unwrap();
    assert!(state.revoke_node(&next, nodes[1].id(), NOW + 2).is_err());
    // The previously active node can be retired after a later bound handoff.
    let third = OwnerKey::generate().unwrap();
    let candidate = nodes[0]
        .prepare_owner_candidate(&state, &third, &uuid::Uuid::new_v4().to_string(), NOW + 3)
        .unwrap();
    let authorization = state
        .authorize_owner_candidate(&next, &candidate, NOW + 3)
        .unwrap();
    let update = state
        .accept_owner_authorization(&third, &candidate, &authorization, NOW + 3)
        .unwrap();
    state.apply_chain(&[update], NOW + 3).unwrap();
    state
        .apply_chain(
            &[state.revoke_node(&third, nodes[1].id(), NOW + 4).unwrap()],
            NOW + 4,
        )
        .unwrap();
}

#[test]
fn candidates_require_both_signatures_current_membership_and_fresh_separate_keys() {
    let (root, nodes, state) = fixture();
    let next = OwnerKey::generate().unwrap();
    let request = uuid::Uuid::new_v4().to_string();
    let candidate = nodes[1]
        .prepare_owner_candidate(&state, &next, &request, NOW)
        .unwrap();
    for change in 0..9 {
        let mut bad = candidate.clone();
        match change {
            0 => bad.node_signature[0] ^= 1,
            1 => bad.key_signature[0] ^= 1,
            2 => bad.candidate.node.id = nodes[0].id().into(),
            3 => bad.candidate.node.signing_key = nodes[0].public_key(),
            4 => bad.candidate.owner_key = root.public_key(),
            5 => bad.candidate.id = uuid::Uuid::nil().to_string(),
            6 => bad.candidate.base.state_hash[0] ^= 1,
            7 => bad.candidate.anchor.genesis_hash[0] ^= 1,
            _ => bad.candidate.expires_at += 1,
        }
        assert!(bad.verify(&state, NOW).is_err(), "mutation {change}");
        assert!(state.authorize_owner_candidate(&root, &bad, NOW).is_err());
    }
    let outsider = NodeIdentity::generate().unwrap();
    assert!(
        outsider
            .prepare_owner_candidate(&state, &next, &request, NOW)
            .is_err()
    );
    assert!(
        nodes[1]
            .prepare_owner_candidate(&state, &root, &request, NOW)
            .is_err()
    );
    let node_key = OwnerKey::from_secret_bytes(&nodes[0].expose_secret());
    assert!(
        nodes[1]
            .prepare_owner_candidate(&state, &node_key, &request, NOW)
            .is_err()
    );
    assert!(
        nodes[1]
            .prepare_owner_candidate(&state, &next, &request, NOW - 1)
            .is_err()
    );
    let mut advanced = state.clone();
    advanced
        .apply_chain(&[state.renew(&root, NOW + 1).unwrap()], NOW + 1)
        .unwrap();
    assert!(
        advanced
            .authorize_owner_candidate(&root, &candidate, NOW + 1)
            .is_err()
    );
    let mut revoked = state.clone();
    revoked
        .apply_chain(
            &[state.revoke_node(&root, nodes[1].id(), NOW + 1).unwrap()],
            NOW + 1,
        )
        .unwrap();
    assert!(
        nodes[1]
            .prepare_owner_candidate(&revoked, &next, &request, NOW + 1)
            .is_err()
    );
    assert!(
        nodes[1]
            .prepare_owner_candidate(&state, &next, &request, state.state().expires_at)
            .is_err()
    );
}

#[test]
fn authorization_rejects_signed_substitution_and_competing_candidates() {
    let (root, nodes, state) = fixture();
    let next = OwnerKey::generate().unwrap();
    let candidate = nodes[1]
        .prepare_owner_candidate(&state, &next, &uuid::Uuid::new_v4().to_string(), NOW)
        .unwrap();
    let original = state
        .authorize_owner_candidate(&root, &candidate, NOW + 1)
        .unwrap();
    for change in 0..8 {
        let mut bad = original.clone();
        match change {
            0 => bad.transition.successor.as_mut().unwrap().node.id = nodes[0].id().into(),
            1 => {
                bad.transition.successor.as_mut().unwrap().node.signing_key = nodes[0].public_key()
            }
            2 => bad.transition.successor.as_mut().unwrap().candidate[0] ^= 1,
            3 => bad.transition.successor = None,
            4 => bad.transition.epoch += 1,
            5 => bad.transition.previous[0] ^= 1,
            6 => bad.transition.issued_at = candidate.candidate.expires_at,
            _ => bad.transition.owner_key = OwnerKey::generate().unwrap().public_key(),
        }
        resign_transition(&mut bad, &root);
        assert!(
            state.verify_owner_authorization(&candidate, &bad).is_err(),
            "mutation {change}"
        );
        assert!(
            state
                .accept_owner_authorization(&next, &candidate, &bad, NOW + CANDIDATE_LIFETIME)
                .is_err()
        );
    }
    let competing = nodes[1]
        .prepare_owner_candidate(&state, &next, &uuid::Uuid::new_v4().to_string(), NOW)
        .unwrap();
    assert!(
        state
            .verify_owner_authorization(&competing, &original)
            .is_err()
    );
    let mut tampered = original.clone();
    tampered.signature[0] ^= 1;
    assert!(
        state
            .verify_owner_authorization(&candidate, &tampered)
            .is_err()
    );
}
