use ed25519_dalek::{Signer, SigningKey};
use gent_crypto::*;
use gent_protocol::{Permission, Policy, Selector, administration::*};
use uuid::Uuid;
const NOW: u64 = 1_800_000_000;
fn fixture() -> (OwnerKey, VerifiedState, String, Policy) {
    let owner = OwnerKey::generate().unwrap();
    let node = NodeIdentity::generate().unwrap();
    let state = owner.create_cluster("admin", &node, "node", NOW).unwrap();
    let id = Uuid::new_v4().to_string();
    let mut policy = Policy::default();
    policy.admin_grants.insert(
        id.clone(),
        AdminGrant {
            administrator: Uuid::new_v4().to_string(),
            actor: Selector::All,
            peer: Selector::SameNode,
            permissions: vec![Permission::Send],
            issued_at: NOW,
            expires_at: NOW + 60,
        },
    );
    (owner, state, id, policy)
}
fn resign(owner: &OwnerKey, signed: &mut SignedState) {
    let mut input = b"gent/cluster-state/v1\0".to_vec();
    input.extend(serde_jcs::to_vec(&signed.state).unwrap());
    signed.signature = SigningKey::from_bytes(&owner.expose_secret())
        .sign(&input)
        .to_bytes()
        .to_vec();
}
#[test]
fn administration_grants_are_immutable_retired_and_verified_on_receipt() {
    let (owner, mut state, id, policy) = fixture();
    let next = state.set_policy(&owner, policy.clone(), NOW).unwrap();
    state.apply_chain(&[next], NOW).unwrap();
    let mut changed = policy.clone();
    changed.admin_grants.get_mut(&id).unwrap().peer = Selector::All;
    assert!(state.set_policy(&owner, changed.clone(), NOW).is_err());
    let mut forged = state.renew(&owner, NOW).unwrap();
    forged.state.policy = changed;
    resign(&owner, &mut forged);
    assert!(state.apply_chain(&[forged], NOW).is_err());
    let retired = state.set_policy(&owner, Policy::default(), NOW).unwrap();
    assert!(retired.state.retired_admin_grants.contains(&id));
    let mut forged = retired.clone();
    forged.state.retired_admin_grants.clear();
    resign(&owner, &mut forged);
    assert!(state.apply_chain(&[forged], NOW).is_err());
    state.apply_chain(&[retired], NOW).unwrap();
    assert!(state.set_policy(&owner, policy, NOW).is_err());
    let mut forged = state.renew(&owner, NOW).unwrap();
    forged.state.retired_admin_grants.clear();
    resign(&owner, &mut forged);
    assert!(state.apply_chain(&[forged], NOW).is_err());
}
#[test]
fn administration_grants_reject_invalid_scope_lifetime_and_permissions() {
    let (owner, state, id, policy) = fixture();
    for lifetime in [0, MAX_ADMIN_GRANT_LIFETIME + 1] {
        let mut bad = policy.clone();
        bad.admin_grants.get_mut(&id).unwrap().expires_at = NOW + lifetime;
        assert!(validate_policy(&bad).is_err());
    }
    for permissions in [vec![], vec![Permission::Send, Permission::Send]] {
        let mut bad = policy.clone();
        bad.admin_grants.get_mut(&id).unwrap().permissions = permissions;
        assert!(validate_policy(&bad).is_err());
    }
    let mut bad = policy.clone();
    bad.admin_grants.get_mut(&id).unwrap().peer = Selector::Group("missing".into());
    assert!(validate_policy(&bad).is_err());
    let mut future = policy;
    future.admin_grants.get_mut(&id).unwrap().issued_at = NOW + 1;
    assert!(state.set_policy(&owner, future, NOW).is_err());
    let empty = serde_json::to_value(state.signed()).unwrap();
    assert!(empty["state"].get("retired_admin_grants").is_none());
    assert!(empty["state"]["policy"].get("admin_grants").is_none());
}
