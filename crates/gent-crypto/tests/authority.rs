use gent_crypto::*;
use gent_protocol::{Effect, Permission, Policy, Rule, Selector};

const NOW: u64 = 1_800_000_000;

fn fixture() -> (OwnerKey, NodeIdentity, VerifiedState) {
    let owner = OwnerKey::generate().unwrap();
    let node = NodeIdentity::generate().unwrap();
    let state = owner
        .create_cluster("test cluster", &node, "first", NOW)
        .unwrap();
    (owner, node, state)
}

fn request(node: &NodeIdentity, state: &VerifiedState, now: u64) -> SignedEnrollment {
    node.request_enrollment(state.anchor(), state.checkpoint(), "new node", now)
        .unwrap()
}

#[test]
fn paired_node_proves_possession_and_reconnects_from_secret_storage() {
    let (owner, _, mut state) = fixture();
    let node = NodeIdentity::generate().unwrap();
    let request = request(&node, &state, NOW);
    let approved = request.fingerprint().unwrap();
    let encoded = request.encode().unwrap();
    let received = SignedEnrollment::decode(&encoded).unwrap();
    let next = state.enroll(&owner, &received, approved, NOW).unwrap();
    state.apply_chain(&[next], NOW).unwrap();
    let restored = NodeIdentity::from_secret_bytes(node.id(), &node.expose_secret()).unwrap();
    assert_eq!(restored.public_key(), node.public_key());
    assert!(
        state
            .authorize_node(restored.id(), &restored.public_key(), NOW)
            .is_ok()
    );
    assert!(state.enroll(&owner, &received, approved, NOW).is_err());
    let owner_restored = OwnerKey::from_secret_bytes(&owner.expose_secret());
    assert!(state.renew(&owner_restored, NOW + 1).is_ok());
}

#[test]
fn substituted_request_key_name_or_fingerprint_is_rejected() {
    let (owner, _, state) = fixture();
    let node = NodeIdentity::generate().unwrap();
    let approved_request = request(&node, &state, NOW);
    let pin = approved_request.fingerprint().unwrap();
    let attacker = NodeIdentity::generate().unwrap();
    let replacement = request(&attacker, &state, NOW);
    assert!(state.enroll(&owner, &replacement, pin, NOW).is_err());
    let mut renamed = approved_request.clone();
    renamed.request.member.name = "a trusted-looking name".into();
    assert!(renamed.fingerprint().is_err());
    let mut substituted = approved_request.clone();
    substituted.request.member.signing_key = attacker.public_key();
    assert!(substituted.fingerprint().is_err());
    let mut forged = approved_request;
    forged.signature[0] ^= 1;
    assert!(state.enroll(&owner, &forged, pin, NOW).is_err());
}

#[test]
fn relay_cannot_replace_pinned_owner_genesis_or_policy() {
    let (_, _, state) = fixture();
    let (other_owner, other_node, attacker) = fixture();
    assert!(VerifiedState::bootstrap(state.anchor().clone(), attacker.signed().clone()).is_err());
    let mut anchor = state.anchor().clone();
    anchor.genesis_hash[0] ^= 1;
    assert!(VerifiedState::bootstrap(anchor, state.signed().clone()).is_err());
    let mut altered = state.signed().clone();
    altered.state.policy.rules.push(Rule {
        actor: Selector::All,
        peer: Selector::All,
        permission: Permission::Send,
        effect: Effect::Allow,
    });
    assert!(VerifiedState::bootstrap(state.anchor().clone(), altered).is_err());
    assert!(state.renew(&other_owner, NOW).is_err());
    let other_cluster = other_owner
        .create_cluster("other", &other_node, "other", NOW)
        .unwrap();
    let request = request(&other_node, &state, NOW);
    assert!(
        other_cluster
            .enroll(&other_owner, &request, request.fingerprint().unwrap(), NOW)
            .is_err()
    );
}

#[test]
fn rollback_gaps_and_forks_are_rejected_without_losing_checkpoint() {
    let (owner, _, mut state) = fixture();
    let genesis = state.signed().clone();
    let mut follower = state.clone();
    let first = state.renew(&owner, NOW + 1).unwrap();
    let fork = state.renew(&owner, NOW + 2).unwrap();
    state
        .apply_chain(std::slice::from_ref(&first), NOW + 1)
        .unwrap();
    let second = state.renew(&owner, NOW + 3).unwrap();
    let before = follower.checkpoint().clone();
    assert!(
        follower
            .apply_chain(std::slice::from_ref(&second), NOW + 3)
            .is_err()
    );
    assert_eq!(follower.checkpoint(), &before);
    follower.apply_chain(&[first], NOW + 1).unwrap();
    let before = follower.checkpoint().clone();
    assert!(follower.apply_chain(&[fork], NOW + 2).is_err());
    assert!(follower.apply_chain(&[genesis], NOW + 2).is_err());
    assert_eq!(follower.checkpoint(), &before);
    follower.apply_chain(&[second], NOW + 3).unwrap();
}

#[test]
fn complete_chain_is_checked_before_any_authority_changes() {
    let (owner, _, state) = fixture();
    let mut writer = state.clone();
    let one = writer.renew(&owner, NOW + 1).unwrap();
    writer
        .apply_chain(std::slice::from_ref(&one), NOW + 1)
        .unwrap();
    let mut two = writer.renew(&owner, NOW + 2).unwrap();
    two.signature[0] ^= 1;
    let mut follower = state.clone();
    assert!(follower.apply_chain(&[one, two], NOW + 2).is_err());
    assert_eq!(follower.checkpoint(), state.checkpoint());
}

#[test]
fn expired_state_can_sync_but_cannot_authorize_delivery() {
    let (owner, node, state) = fixture();
    let after_expiry = NOW + MAX_STATE_LIFETIME;
    assert!(
        state
            .authorize_node(node.id(), &node.public_key(), after_expiry)
            .is_err()
    );
    assert!(
        state
            .authorize_node(node.id(), &node.public_key(), NOW - 1)
            .is_err()
    );
    let mut follower = VerifiedState::restore(
        state.anchor().clone(),
        state.checkpoint().clone(),
        state.signed().clone(),
    )
    .unwrap();
    let first = state.renew(&owner, after_expiry).unwrap();
    let mut writer = state.clone();
    writer
        .apply_chain(std::slice::from_ref(&first), after_expiry)
        .unwrap();
    let second = writer
        .renew(&owner, after_expiry + MAX_STATE_LIFETIME)
        .unwrap();
    // An old intermediate revision is valid history, but cannot be the final authority.
    assert!(
        follower
            .apply_chain(
                std::slice::from_ref(&first),
                after_expiry + MAX_STATE_LIFETIME
            )
            .is_err()
    );
    follower.advance_history(&[first]).unwrap();
    assert!(
        follower
            .authorize_node(
                node.id(),
                &node.public_key(),
                after_expiry + MAX_STATE_LIFETIME
            )
            .is_err()
    );
    follower
        .apply_chain(&[second], after_expiry + MAX_STATE_LIFETIME)
        .unwrap();
    assert!(
        follower
            .authorize_node(
                node.id(),
                &node.public_key(),
                after_expiry + MAX_STATE_LIFETIME
            )
            .is_ok()
    );
}

#[test]
fn expired_future_and_stale_enrollment_requests_fail() {
    let (owner, _, mut state) = fixture();
    let node = NodeIdentity::generate().unwrap();
    let old = request(&node, &state, NOW);
    assert!(
        state
            .enroll(
                &owner,
                &old,
                old.fingerprint().unwrap(),
                NOW + REQUEST_LIFETIME
            )
            .is_err()
    );
    let future = request(&node, &state, NOW + 1);
    assert!(
        state
            .enroll(&owner, &future, future.fingerprint().unwrap(), NOW)
            .is_err()
    );
    let next = state.renew(&owner, NOW + 1).unwrap();
    state.apply_chain(&[next], NOW + 1).unwrap();
    assert!(
        state
            .enroll(&owner, &old, old.fingerprint().unwrap(), NOW + 1)
            .is_err()
    );
}

#[test]
fn rotation_and_revocation_do_not_resurrect_old_identities() {
    let (owner, _, mut state) = fixture();
    let node = NodeIdentity::generate().unwrap();
    let enrollment = request(&node, &state, NOW);
    let next = state
        .enroll(&owner, &enrollment, enrollment.fingerprint().unwrap(), NOW)
        .unwrap();
    state.apply_chain(&[next], NOW).unwrap();
    let replacement = node.replacement().unwrap();
    let rotation = request(&replacement, &state, NOW);
    let next = state
        .rotate_node_key(&owner, &rotation, rotation.fingerprint().unwrap(), NOW)
        .unwrap();
    state.apply_chain(&[next], NOW).unwrap();
    assert!(
        state
            .authorize_node(node.id(), &node.public_key(), NOW)
            .is_err()
    );
    assert!(
        state
            .authorize_node(node.id(), &replacement.public_key(), NOW)
            .is_ok()
    );
    let restore_old_key = request(&node, &state, NOW);
    assert!(
        state
            .rotate_node_key(
                &owner,
                &restore_old_key,
                restore_old_key.fingerprint().unwrap(),
                NOW
            )
            .is_err()
    );
    let next = state.revoke_node(&owner, node.id(), NOW).unwrap();
    state.apply_chain(&[next], NOW).unwrap();
    assert!(
        state
            .authorize_node(node.id(), &replacement.public_key(), NOW)
            .is_err()
    );
    let fresh_key_same_id = node.replacement().unwrap();
    let reenroll = request(&fresh_key_same_id, &state, NOW);
    assert!(
        state
            .enroll(&owner, &reenroll, reenroll.fingerprint().unwrap(), NOW)
            .is_err()
    );
    let different_id_old_key =
        NodeIdentity::from_secret_bytes(&uuid::Uuid::new_v4().to_string(), &node.expose_secret())
            .unwrap();
    let reenroll = request(&different_id_old_key, &state, NOW);
    assert!(
        state
            .enroll(&owner, &reenroll, reenroll.fingerprint().unwrap(), NOW)
            .is_err()
    );
}

#[test]
fn persisted_checkpoint_rejects_signed_but_older_state() {
    let (owner, _, mut state) = fixture();
    let old = state.signed().clone();
    let next = state.renew(&owner, NOW + 1).unwrap();
    state.apply_chain(&[next], NOW + 1).unwrap();
    assert!(
        VerifiedState::restore(state.anchor().clone(), state.checkpoint().clone(), old).is_err()
    );
    let canonical = state.signed().encode().unwrap();
    let restored = VerifiedState::restore(
        state.anchor().clone(),
        state.checkpoint().clone(),
        SignedState::decode(&canonical).unwrap(),
    )
    .unwrap();
    assert_eq!(restored.checkpoint(), state.checkpoint());
}

#[test]
fn ambiguous_oversized_or_unknown_wire_fields_are_rejected() {
    let (_, _, state) = fixture();
    let canonical = state.signed().encode().unwrap();
    assert_eq!(
        SignedState::decode(&canonical).unwrap().encode().unwrap(),
        canonical
    );
    let mut spaced = canonical.clone();
    spaced.push(b' ');
    assert!(SignedState::decode(&spaced).is_err());
    assert!(SignedState::decode(&vec![b' '; MAX_STATE_BYTES + 1]).is_err());
    let mut value = serde_json::to_value(state.signed()).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(SignedState::decode(&serde_jcs::to_vec(&value).unwrap()).is_err());
    let node_id = state.state().nodes.keys().next().unwrap();
    let member = serde_jcs::to_string(&state.state().nodes[node_id]).unwrap();
    let text = String::from_utf8(canonical).unwrap();
    let entry = format!("\"{node_id}\":{member}");
    let duplicated = text.replace(&entry, &format!("{entry},{entry}"));
    assert_ne!(duplicated, text);
    assert!(SignedState::decode(duplicated.as_bytes()).is_err());
}

#[test]
fn invalid_policy_authority_reuse_and_last_node_removal_fail() {
    let (owner, first, state) = fixture();
    assert!(state.revoke_node(&owner, first.id(), NOW).is_err());
    let aliased =
        NodeIdentity::from_secret_bytes(&uuid::Uuid::new_v4().to_string(), &owner.expose_secret())
            .unwrap();
    assert!(owner.create_cluster("bad", &aliased, "bad", NOW).is_err());
    let mut policy = Policy::default();
    policy.rules.push(Rule {
        actor: Selector::All,
        peer: Selector::Group("missing".into()),
        permission: Permission::Receive,
        effect: Effect::Allow,
    });
    assert!(state.set_policy(&owner, policy, NOW).is_err());
    assert!(state.renew(&owner, NOW - 1).is_err());
    assert!(
        owner
            .create_cluster("overflow", &first, "node", u64::MAX)
            .is_err()
    );
}

#[test]
fn agent_ids_bind_the_hosting_node_and_unambiguous_inputs() {
    let node = uuid::Uuid::new_v4().to_string();
    let other = uuid::Uuid::new_v4().to_string();
    let nonce = uuid::Uuid::new_v4();
    let agent = agent_id(&node, nonce).unwrap();
    assert_eq!(agent, agent_id(&node, nonce).unwrap());
    assert_ne!(agent, agent_id(&other, nonce).unwrap());
    assert_ne!(agent, agent_id(&node, uuid::Uuid::new_v4()).unwrap());
    assert!(agent_id(&node, uuid::Uuid::nil()).is_err());
    assert!(agent_id("not-a-node", nonce).is_err());
    assert_ne!(
        scoped_id(b"a", &[b"bc", b"d"]),
        scoped_id(b"a", &[b"b", b"cd"])
    );
    assert_ne!(scoped_id(b"a", &[b"bc"]), scoped_id(b"ab", &[b"c"]));
}

#[test]
fn legacy_agent_certificates_require_exact_owner_cluster_agent_and_node() {
    let (owner, node, state) = fixture();
    let agent = uuid::Uuid::new_v4().to_string();
    let certificate = owner
        .bind_legacy_agent(&state, &agent, node.id(), NOW)
        .unwrap();
    certificate
        .verify(state.anchor(), &agent, node.id())
        .unwrap();
    let (other_owner, other_node, other_state) = fixture();
    assert!(
        certificate
            .verify(other_state.anchor(), &agent, node.id())
            .is_err()
    );
    assert!(
        certificate
            .verify(state.anchor(), &agent, other_node.id())
            .is_err()
    );
    assert!(
        certificate
            .verify(state.anchor(), other_node.id(), node.id())
            .is_err()
    );
    assert!(
        owner
            .bind_legacy_agent(&state, &agent, other_node.id(), NOW)
            .is_err()
    );
    assert!(
        other_owner
            .bind_legacy_agent(&state, &agent, node.id(), NOW)
            .is_err()
    );
    assert!(
        owner
            .bind_legacy_agent(&state, &agent, node.id(), state.state().expires_at + 1)
            .is_err()
    );
    let mut altered = certificate.clone();
    altered.binding.agent = other_node.id().into();
    assert!(
        altered
            .verify(state.anchor(), other_node.id(), node.id())
            .is_err()
    );
    let mut altered = certificate;
    altered.signature[0] ^= 1;
    assert!(altered.verify(state.anchor(), &agent, node.id()).is_err());
}
