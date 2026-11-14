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
            selector_rules: false,
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
    let mut widened = policy.clone();
    widened.admin_grants.get_mut(&id).unwrap().selector_rules = true;
    assert!(state.set_policy(&owner, widened, NOW).is_err());
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
    assert!(
        serde_json::to_value(&policy).unwrap()["admin_grants"][&id]
            .get("selector_rules")
            .is_none()
    );
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

#[test]
fn group_grants_are_immutable_and_cannot_reuse_permission_or_retired_identities() {
    let (owner, mut state, permission_id, mut policy) = fixture();
    assert!(
        serde_json::to_value(&policy)
            .unwrap()
            .get("group_admin_grants")
            .is_none()
    );
    policy.groups.insert("team".into(), vec![]);
    let id = Uuid::new_v4().to_string();
    let grant = GroupAdminGrant {
        administrator: Uuid::new_v4().to_string(),
        group: "team".into(),
        members: Selector::SameNode,
        actions: vec![GroupAction::Add],
        issued_at: NOW,
        expires_at: NOW + 60,
    };
    policy.group_admin_grants.insert(id.clone(), grant.clone());
    let next = state.set_policy(&owner, policy.clone(), NOW).unwrap();
    state.apply_chain(&[next], NOW).unwrap();
    let mut changed = policy.clone();
    changed
        .group_admin_grants
        .get_mut(&id)
        .unwrap()
        .actions
        .push(GroupAction::Remove);
    assert!(state.set_policy(&owner, changed.clone(), NOW).is_err());
    let mut forged = state.renew(&owner, NOW).unwrap();
    forged.state.policy = changed;
    resign(&owner, &mut forged);
    assert!(state.apply_chain(&[forged], NOW).is_err());
    // Swapping grant kinds cannot sidestep identity immutability or retirement.
    for group_to_permission in [true, false] {
        let mut swapped = policy.clone();
        if group_to_permission {
            swapped.group_admin_grants.remove(&id);
            swapped
                .admin_grants
                .insert(id.clone(), policy.admin_grants[&permission_id].clone());
        } else {
            swapped.admin_grants.remove(&permission_id);
            swapped
                .group_admin_grants
                .insert(permission_id.clone(), grant.clone());
        }
        assert!(state.set_policy(&owner, swapped.clone(), NOW).is_err());
        let mut forged = state.renew(&owner, NOW).unwrap();
        forged.state.policy = swapped;
        resign(&owner, &mut forged);
        assert!(state.apply_chain(&[forged], NOW).is_err());
    }
    let mut removed = policy.clone();
    removed.group_admin_grants.clear();
    let retired = state.set_policy(&owner, removed, NOW).unwrap();
    assert!(retired.state.retired_admin_grants.contains(&id));
    let mut forged = retired.clone();
    forged.state.retired_admin_grants.clear();
    resign(&owner, &mut forged);
    assert!(state.apply_chain(&[forged], NOW).is_err());
    state.apply_chain(&[retired], NOW).unwrap();
    assert!(state.set_policy(&owner, policy, NOW).is_err());
}

#[test]
fn group_grants_validate_target_scope_actions_and_lifetime() {
    let (owner, state, id, mut policy) = fixture();
    let grant = GroupAdminGrant {
        administrator: Uuid::new_v4().to_string(),
        group: "team".into(),
        members: Selector::All,
        actions: vec![GroupAction::Add, GroupAction::Remove],
        issued_at: NOW,
        expires_at: NOW + 60,
    };
    policy.group_admin_grants.insert(id.clone(), grant.clone());
    policy.groups.insert("team".into(), vec![]);
    assert!(validate_policy(&policy).is_err()); // Shared ID namespace.
    policy.admin_grants.clear();
    validate_policy(&policy).unwrap();
    for mode in 0..6 {
        let mut bad = policy.clone();
        let g = bad.group_admin_grants.get_mut(&id).unwrap();
        match mode {
            0 => g.group = "missing".into(),
            1 => g.members = Selector::Group("missing".into()),
            2 => g.actions.clear(),
            3 => g.actions = vec![GroupAction::Add, GroupAction::Add],
            4 => g.expires_at = g.issued_at,
            _ => g.expires_at = g.issued_at + MAX_ADMIN_GRANT_LIFETIME + 1,
        }
        assert!(validate_policy(&bad).is_err());
    }
    policy.group_admin_grants.get_mut(&id).unwrap().issued_at = NOW + 1;
    assert!(state.set_policy(&owner, policy, NOW).is_err());
}
