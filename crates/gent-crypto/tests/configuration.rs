use gent_crypto::{NodeIdentity, OwnerKey, SignedConfigurationGrant};

#[test]
fn configuration_grants_require_owner_authority_and_exact_initial_checkpoint() {
    let now = 1_800_000_000;
    let owner = OwnerKey::generate().unwrap();
    let writer = NodeIdentity::generate().unwrap();
    let reader = NodeIdentity::generate().unwrap();
    let mut state = owner
        .create_cluster("grants", &writer, "first", now)
        .unwrap();
    let request = reader
        .request_enrollment(state.anchor(), state.checkpoint(), "second", now)
        .unwrap();
    let update = state
        .enroll(&owner, &request, request.fingerprint().unwrap(), now)
        .unwrap();
    state.apply_chain(&[update], now).unwrap();
    let grant = owner
        .authorize_configuration_stream(&state, b"group", [1; 32], (writer.id(), reader.id()), now)
        .unwrap();
    grant.verify_initial(&state, now).unwrap();
    assert_eq!(
        grant,
        SignedConfigurationGrant::decode(&grant.encode().unwrap()).unwrap()
    );
    assert!(
        grant
            .verify_initial(&state, state.state().expires_at)
            .is_err()
    );
    // The signed pin remains usable for configuration-only recovery after expiry.
    grant.verify(state.anchor()).unwrap();
    let renewed = state.renew(&owner, now + 1).unwrap();
    state.apply_chain(&[renewed], now + 1).unwrap();
    assert!(grant.verify_initial(&state, now + 1).is_err());
    let wrong = OwnerKey::generate().unwrap();
    assert!(
        wrong
            .authorize_configuration_stream(
                &state,
                b"group",
                [1; 32],
                (writer.id(), reader.id()),
                now + 1
            )
            .is_err()
    );
    assert!(
        owner
            .authorize_configuration_stream(
                &state,
                b"group",
                [1; 32],
                (writer.id(), writer.id()),
                now + 1
            )
            .is_err()
    );
}

#[test]
fn configuration_grants_bind_group_origin_keys_roles_and_cluster() {
    let now = 1_800_000_000;
    let owner = OwnerKey::generate().unwrap();
    let writer = NodeIdentity::generate().unwrap();
    let reader = NodeIdentity::generate().unwrap();
    let mut state = owner
        .create_cluster("grants", &writer, "first", now)
        .unwrap();
    let request = reader
        .request_enrollment(state.anchor(), state.checkpoint(), "second", now)
        .unwrap();
    let next = state
        .enroll(&owner, &request, request.fingerprint().unwrap(), now)
        .unwrap();
    state.apply_chain(&[next], now).unwrap();
    let signed = owner
        .authorize_configuration_stream(&state, b"group", [1; 32], (writer.id(), reader.id()), now)
        .unwrap();
    for field in 0..7 {
        let mut changed = signed.clone();
        match field {
            0 => changed.grant.group.push(1),
            1 => changed.grant.origin[0] ^= 1,
            2 => changed.grant.writer_key[0] ^= 1,
            3 => changed.grant.reader_key[0] ^= 1,
            4 => std::mem::swap(&mut changed.grant.reader, &mut changed.grant.writer),
            5 => changed.grant.anchor.cluster_id = reader.id().into(),
            _ => changed.grant.base.state_hash[0] ^= 1,
        }
        assert!(changed.verify(state.anchor()).is_err());
    }
    let mut noncanonical = signed.encode().unwrap();
    noncanonical.push(b' ');
    assert!(SignedConfigurationGrant::decode(&noncanonical).is_err());
}
