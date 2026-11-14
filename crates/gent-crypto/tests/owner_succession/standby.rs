use super::*;

#[test]
fn standby_grants_bind_exact_candidates_without_changing_ordinary_encoding() {
    let (owner, nodes, state) = fixture();
    let key = OwnerKey::generate().unwrap();
    let candidate = nodes[1]
        .prepare_owner_candidate(&state, &key, &uuid::Uuid::new_v4().to_string(), NOW)
        .unwrap();
    let ordinary = owner
        .authorize_configuration_stream(
            &state,
            b"ordinary",
            [1; 32],
            (nodes[0].id(), nodes[1].id()),
            NOW,
        )
        .unwrap();
    assert!(
        !String::from_utf8(ordinary.encode().unwrap())
            .unwrap()
            .contains("owner_candidate")
    );
    assert!(ordinary.can_publish(&state).unwrap());
    assert!(ordinary.verify_owner_candidate(&candidate).is_err());
    let grant = owner
        .authorize_standby_configuration_stream(
            &state,
            &candidate,
            b"standby",
            [2; 32],
            nodes[0].id(),
            NOW,
        )
        .unwrap();
    grant.verify_initial(&state, NOW).unwrap();
    grant.verify_owner_candidate(&candidate).unwrap();
    assert!(!grant.can_publish(&state).unwrap());
    assert_eq!(
        SignedConfigurationGrant::decode(&grant.encode().unwrap()).unwrap(),
        grant
    );
    for changed in 0..5 {
        let mut forged = grant.clone();
        match changed {
            0 => forged.grant.owner_candidate = None,
            1 => forged.grant.owner_candidate = Some([0; 32]),
            2 => forged.grant.origin[0] ^= 1,
            3 => forged.grant.base.revision += 1,
            _ => forged.grant.writer = nodes[0].id().into(),
        }
        assert!(forged.verify(state.anchor()).is_err());
    }
    let mut bad = candidate.clone();
    bad.node_signature[0] ^= 1;
    assert!(
        owner
            .authorize_standby_configuration_stream(
                &state,
                &bad,
                b"standby",
                [2; 32],
                nodes[0].id(),
                NOW
            )
            .is_err()
    );
    assert!(
        owner
            .authorize_standby_configuration_stream(
                &state,
                &candidate,
                b"standby",
                [2; 32],
                nodes[0].id(),
                NOW + CANDIDATE_LIFETIME
            )
            .is_err()
    );
    assert!(
        key.authorize_standby_configuration_stream(
            &state,
            &candidate,
            b"standby",
            [2; 32],
            nodes[0].id(),
            NOW
        )
        .is_err()
    );
}

#[test]
fn only_the_selected_bound_handoff_enables_its_standby_streams() {
    let (owner, nodes, mut state) = fixture();
    let key = OwnerKey::generate().unwrap();
    let candidate = nodes[1]
        .prepare_owner_candidate(&state, &key, &uuid::Uuid::new_v4().to_string(), NOW)
        .unwrap();
    let grant = owner
        .authorize_standby_configuration_stream(
            &state,
            &candidate,
            b"standby",
            [2; 32],
            nodes[0].id(),
            NOW,
        )
        .unwrap();
    let mut other = state.clone();
    other
        .apply_chain(&[other.transfer_owner(&owner, &key, NOW).unwrap()], NOW)
        .unwrap();
    assert!(!grant.can_publish(&other).unwrap());
    let competitor = nodes[1]
        .prepare_owner_candidate(&state, &key, &uuid::Uuid::new_v4().to_string(), NOW)
        .unwrap();
    assert!(grant.verify_owner_candidate(&competitor).is_err());
    let auth = state
        .authorize_owner_candidate(&owner, &competitor, NOW)
        .unwrap();
    other = state.clone();
    other
        .apply_chain(
            &[state
                .accept_owner_authorization(&key, &competitor, &auth, NOW)
                .unwrap()],
            NOW,
        )
        .unwrap();
    assert!(!grant.can_publish(&other).unwrap());
    let auth = state
        .authorize_owner_candidate_with_journal(&owner, &candidate, [7; 32], NOW)
        .unwrap();
    state
        .apply_chain(
            &[state
                .accept_owner_authorization(&key, &candidate, &auth, NOW)
                .unwrap()],
            NOW,
        )
        .unwrap();
    assert!(grant.can_publish(&state).unwrap());
    state
        .apply_chain(&[state.renew(&key, NOW + 1).unwrap()], NOW + 1)
        .unwrap();
    assert!(grant.can_publish(&state).unwrap());
    let next = OwnerKey::generate().unwrap();
    let next_candidate = nodes[0]
        .prepare_owner_candidate(&state, &next, &uuid::Uuid::new_v4().to_string(), NOW + 2)
        .unwrap();
    let auth = state
        .authorize_owner_candidate(&key, &next_candidate, NOW + 2)
        .unwrap();
    state
        .apply_chain(
            &[state
                .accept_owner_authorization(&next, &next_candidate, &auth, NOW + 2)
                .unwrap()],
            NOW + 2,
        )
        .unwrap();
    assert!(grant.can_publish(&state).unwrap());
}
