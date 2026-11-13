use ed25519_dalek::{Signer, SigningKey};
use gent_crypto::*;
use gent_protocol::{MAX_RELAY_GRANT_LIFETIME, Policy, RelayGrant};
use uuid::Uuid;

const NOW: u64 = 1_800_000_000;

fn fixture() -> (OwnerKey, VerifiedState, String, Policy) {
    let owner = OwnerKey::generate().unwrap();
    let node = NodeIdentity::generate().unwrap();
    let state = owner.create_cluster("relay", &node, "node", NOW).unwrap();
    let id = Uuid::new_v4().to_string();
    let mut policy = Policy::default();
    policy.relay_grants.insert(
        id.clone(),
        RelayGrant {
            intermediary: Uuid::new_v4().to_string(),
            target: Uuid::new_v4().to_string(),
            issued_at: NOW,
            expires_at: NOW + 3600,
        },
    );
    (owner, state, id, policy)
}

// Bypass the signing API to test receiver-side chain validation against a
// correctly signed revision that violates a transition invariant.
fn resign(owner: &OwnerKey, signed: &mut SignedState) {
    let mut input = b"gent/cluster-state/v1\0".to_vec();
    input.extend(serde_jcs::to_vec(&signed.state).unwrap());
    signed.signature = SigningKey::from_bytes(&owner.expose_secret())
        .sign(&input)
        .to_bytes()
        .to_vec();
}

#[test]
fn legacy_empty_policy_and_signed_state_keep_their_canonical_bytes() {
    let (owner, state, _, _) = fixture();
    assert_eq!(
        serde_jcs::to_vec(&Policy::default()).unwrap(),
        br#"{"groups":{},"rules":[]}"#
    );
    let mut legacy = serde_json::to_value(state.signed()).unwrap();
    assert!(legacy["state"].get("retired_relay_grants").is_none());
    assert!(legacy["state"]["policy"].get("relay_grants").is_none());
    // Sign the legacy JSON object itself, without going through the new types.
    let mut input = b"gent/cluster-state/v1\0".to_vec();
    input.extend(serde_jcs::to_vec(&legacy["state"]).unwrap());
    legacy["signature"] = serde_json::json!(
        SigningKey::from_bytes(&owner.expose_secret())
            .sign(&input)
            .to_bytes()
            .to_vec()
    );
    let bytes = serde_jcs::to_vec(&legacy).unwrap();
    let decoded = SignedState::decode(&bytes).unwrap();
    assert_eq!(decoded.encode().unwrap(), bytes);
    VerifiedState::bootstrap(state.anchor().clone(), decoded).unwrap();
}

#[test]
fn relay_grants_are_bounded_immutable_and_permanently_retired() {
    let (owner, mut state, id, policy) = fixture();
    let next = state.set_policy(&owner, policy.clone(), NOW).unwrap();
    state.apply_chain(&[next], NOW).unwrap();
    let mut altered = policy.clone();
    altered.relay_grants.get_mut(&id).unwrap().expires_at += 1;
    assert!(state.set_policy(&owner, altered, NOW).is_err());
    let next = state.set_policy(&owner, Policy::default(), NOW).unwrap();
    assert!(next.state.retired_relay_grants.contains(&id));
    state.apply_chain(&[next], NOW).unwrap();
    assert!(state.set_policy(&owner, policy.clone(), NOW).is_err());
    let mut fresh = policy;
    let grant = fresh.relay_grants.remove(&id).unwrap();
    fresh.relay_grants.insert(Uuid::new_v4().to_string(), grant);
    assert!(state.set_policy(&owner, fresh, NOW).is_ok());
}

#[test]
fn signed_chain_cannot_edit_grants_or_drop_retirement_history() {
    let (owner, mut state, id, policy) = fixture();
    let next = state.set_policy(&owner, policy, NOW).unwrap();
    state.apply_chain(&[next], NOW).unwrap();
    let before = state.checkpoint().clone();
    let mut bad = state.renew(&owner, NOW).unwrap();
    bad.state.policy.relay_grants.get_mut(&id).unwrap().target = Uuid::new_v4().to_string();
    resign(&owner, &mut bad);
    assert!(state.apply_chain(&[bad], NOW).is_err());
    let retired = state.set_policy(&owner, Policy::default(), NOW).unwrap();
    let mut bad = retired.clone();
    bad.state.retired_relay_grants.clear();
    resign(&owner, &mut bad);
    assert!(state.apply_chain(&[bad], NOW).is_err());
    assert_eq!(state.checkpoint(), &before);
    state.apply_chain(&[retired], NOW).unwrap();
    let mut bad = state.renew(&owner, NOW).unwrap();
    bad.state.retired_relay_grants.clear();
    resign(&owner, &mut bad);
    assert!(state.apply_chain(&[bad], NOW).is_err());
}

#[test]
fn invalid_lifetimes_endpoints_and_future_issuance_are_rejected() {
    let (owner, state, id, policy) = fixture();
    for lifetime in [0, MAX_RELAY_GRANT_LIFETIME + 1] {
        let mut bad = policy.clone();
        bad.relay_grants.get_mut(&id).unwrap().expires_at = NOW + lifetime;
        assert!(validate_policy(&bad).is_err());
    }
    let mut bad = policy.clone();
    let grant = bad.relay_grants.get_mut(&id).unwrap();
    grant.target.clone_from(&grant.intermediary);
    assert!(validate_policy(&bad).is_err());
    bad.relay_grants.get_mut(&id).unwrap().target = Uuid::nil().to_string();
    assert!(validate_policy(&bad).is_err());
    let mut future = policy;
    future.relay_grants.get_mut(&id).unwrap().issued_at = NOW + 1;
    assert!(state.set_policy(&owner, future, NOW).is_err());
}
