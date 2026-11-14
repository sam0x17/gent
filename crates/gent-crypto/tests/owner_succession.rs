use ed25519_dalek::{Signer, SigningKey};
use gent_crypto::{succession::*, *};
use gent_protocol::{Effect, Permission, Rule, Selector};

const NOW: u64 = 1_800_000_000;

fn fixture() -> (OwnerKey, [NodeIdentity; 2], VerifiedState) {
    let owner = OwnerKey::generate().unwrap();
    let nodes = [
        NodeIdentity::generate().unwrap(),
        NodeIdentity::generate().unwrap(),
    ];
    let mut state = owner
        .create_cluster("succession", &nodes[0], "first", NOW)
        .unwrap();
    let request = nodes[1]
        .request_enrollment(state.anchor(), state.checkpoint(), "second", NOW)
        .unwrap();
    let update = state
        .enroll(&owner, &request, request.fingerprint().unwrap(), NOW)
        .unwrap();
    state.apply_chain(&[update], NOW).unwrap();
    (owner, nodes, state)
}

fn resign(state: &mut SignedState, owner: &OwnerKey) {
    let mut bytes = b"gent/cluster-state/v1\0".to_vec();
    bytes.extend(serde_jcs::to_vec(&state.state).unwrap());
    state.signature = SigningKey::from_bytes(&owner.expose_secret())
        .sign(&bytes)
        .to_bytes()
        .to_vec();
}

fn resign_transition(transition: &mut SignedOwnerTransition, owner: &OwnerKey) {
    let mut bytes = b"gent/owner-succession/v1\0".to_vec();
    bytes.extend(serde_jcs::to_vec(&transition.transition).unwrap());
    transition.signature = SigningKey::from_bytes(&owner.expose_secret())
        .sign(&bytes)
        .to_bytes()
        .to_vec();
}

#[test]
fn legacy_encoding_stays_unchanged_and_successors_preserve_the_original_anchor() {
    let (root, _, mut state) = fixture();
    let anchor = state.anchor().clone();
    let bytes = state.signed().encode().unwrap();
    assert!(
        !String::from_utf8(bytes.clone())
            .unwrap()
            .contains("owner_transitions")
    );
    assert_eq!(state.state().version, 1);
    assert_eq!(state.owner_epoch(), 0);
    let restored = VerifiedState::restore(
        anchor.clone(),
        state.checkpoint().clone(),
        SignedState::decode(&bytes).unwrap(),
    )
    .unwrap();
    assert_eq!(restored.signed().encode().unwrap(), bytes);
    let successor = OwnerKey::generate().unwrap();
    let handoff = state.transfer_owner(&root, &successor, NOW + 1).unwrap();
    let checkpoint = handoff.verified_checkpoint(&anchor).unwrap();
    state
        .apply_chain(std::slice::from_ref(&handoff), NOW + 1)
        .unwrap();
    assert_eq!(state.anchor(), &anchor);
    assert_eq!(state.checkpoint(), &checkpoint);
    assert_eq!(state.state().version, 2);
    assert_eq!(state.owner_epoch(), 1);
    assert_eq!(state.state().owner_key, successor.public_key());
    assert!(state.renew(&root, NOW + 2).is_err());
    let next = state.renew(&successor, NOW + 2).unwrap();
    state.apply_chain(&[next], NOW + 2).unwrap();
    let second = OwnerKey::generate().unwrap();
    let next = state.transfer_owner(&successor, &second, NOW + 3).unwrap();
    state.apply_chain(&[next], NOW + 3).unwrap();
    assert_eq!(state.owner_epoch(), 2);
    assert_eq!(state.anchor(), &anchor);
    assert!(state.renew(&successor, NOW + 4).is_err());
    VerifiedState::restore(anchor, state.checkpoint().clone(), state.signed().clone()).unwrap();
}

#[test]
fn valid_retired_signatures_cannot_drop_replace_or_skip_an_accepted_owner_epoch() {
    let (root, _, original) = fixture();
    let successor = OwnerKey::generate().unwrap();
    let alternate = OwnerKey::generate().unwrap();
    let mut state = original.clone();
    let update = state.transfer_owner(&root, &successor, NOW + 1).unwrap();
    state.apply_chain(&[update], NOW + 1).unwrap();
    let before = state.checkpoint().clone();
    let mut dropped = original.renew(&root, NOW + 2).unwrap();
    dropped.state.revision = before.revision + 1;
    dropped.state.previous = Some(before.state_hash);
    resign(&mut dropped, &root);
    // This is a valid historical signature, but not a valid next epoch.
    dropped.verified_checkpoint(state.anchor()).unwrap();
    assert!(state.apply_chain(&[dropped], NOW + 2).is_err());
    let mut fork = original.transfer_owner(&root, &alternate, NOW + 1).unwrap();
    fork.state.revision = before.revision + 1;
    fork.state.previous = Some(before.state_hash);
    resign(&mut fork, &alternate);
    fork.verified_checkpoint(state.anchor()).unwrap();
    assert!(state.apply_chain(&[fork], NOW + 2).is_err());
    let transition = state
        .transfer_owner(&successor, &alternate, NOW + 2)
        .unwrap();
    let mut forged_successor = transition.clone();
    resign_transition(
        forged_successor.state.owner_transitions.last_mut().unwrap(),
        &root,
    );
    resign(&mut forged_successor, &alternate);
    assert!(
        forged_successor
            .verified_checkpoint(state.anchor())
            .is_err()
    );
    let mut skipped = original.clone();
    assert!(skipped.apply_chain(&[transition], NOW + 2).is_err());
    assert_eq!(skipped.checkpoint(), original.checkpoint());
    assert_eq!(state.checkpoint(), &before);
}

#[test]
fn handoff_requires_exact_checkpoint_and_cannot_hide_policy_or_membership_changes() {
    let (root, _, original) = fixture();
    let successor = OwnerKey::generate().unwrap();
    let handoff = original.transfer_owner(&root, &successor, NOW + 1).unwrap();
    let mut newer = original.clone();
    newer
        .apply_chain(&[original.renew(&root, NOW + 1).unwrap()], NOW + 1)
        .unwrap();
    let mut stale = handoff.clone();
    stale.state.revision = newer.checkpoint().revision + 1;
    stale.state.previous = Some(newer.checkpoint().state_hash);
    resign(&mut stale, &successor);
    stale.verified_checkpoint(original.anchor()).unwrap();
    assert!(newer.apply_chain(&[stale], NOW + 1).is_err());
    for field in 0..3 {
        let mut changed = handoff.clone();
        match field {
            0 => changed.state.name = "hidden rename".into(),
            1 => {
                changed
                    .state
                    .nodes
                    .values_mut()
                    .next()
                    .unwrap()
                    .can_configure = true
            }
            _ => changed.state.policy.rules.push(Rule {
                actor: Selector::All,
                peer: Selector::All,
                permission: Permission::Send,
                effect: Effect::Allow,
            }),
        }
        resign(&mut changed, &successor);
        changed.verified_checkpoint(original.anchor()).unwrap();
        let mut receiver = original.clone();
        assert!(receiver.apply_chain(&[changed], NOW + 1).is_err());
        assert_eq!(receiver.checkpoint(), original.checkpoint());
    }
}

#[test]
fn chain_binds_anchor_epoch_previous_record_new_key_time_and_both_signatures() {
    let (root, _, original) = fixture();
    let successor = OwnerKey::generate().unwrap();
    let handoff = original.transfer_owner(&root, &successor, NOW + 1).unwrap();
    for field in 0..9 {
        let mut changed = handoff.clone();
        let link = &mut changed.state.owner_transitions[0];
        match field {
            0 => link.transition.anchor.genesis_hash[0] ^= 1,
            1 => link.transition.epoch += 1,
            2 => link.transition.previous[0] ^= 1,
            3 => link.transition.owner_key = root.public_key(),
            4 => link.transition.issued_at = NOW + 2,
            5 => link.transition.base.state_hash[0] ^= 1,
            6 => link.signature[0] ^= 1,
            7 => changed.state.version = 1,
            _ => changed.state.owner_key = root.public_key(),
        }
        resign(&mut changed, &successor);
        assert!(
            changed.verified_checkpoint(original.anchor()).is_err(),
            "accepted mutation {field}"
        );
    }
    let mut wrong = handoff.clone();
    resign_transition(&mut wrong.state.owner_transitions[0], &successor);
    resign(&mut wrong, &successor);
    assert!(wrong.verified_checkpoint(original.anchor()).is_err());
    let mut missing_possession = handoff.clone();
    resign(&mut missing_possession, &root);
    assert!(
        missing_possession
            .verified_checkpoint(original.anchor())
            .is_err()
    );
    let bytes = handoff.state.owner_transitions[0].encode().unwrap();
    assert_eq!(
        SignedOwnerTransition::decode(&bytes).unwrap(),
        handoff.state.owner_transitions[0]
    );
    let mut noncanonical = bytes;
    noncanonical.push(b'\n');
    assert!(SignedOwnerTransition::decode(&noncanonical).is_err());
}

#[test]
fn owner_keys_cannot_reuse_current_former_active_node_or_retired_node_keys() {
    let (root, nodes, mut state) = fixture();
    assert!(state.transfer_owner(&root, &root, NOW).is_err());
    let node_key = OwnerKey::from_secret_bytes(&nodes[1].expose_secret());
    assert!(state.transfer_owner(&root, &node_key, NOW).is_err());
    state
        .apply_chain(
            &[state.revoke_node(&root, nodes[1].id(), NOW).unwrap()],
            NOW,
        )
        .unwrap();
    assert!(state.transfer_owner(&root, &node_key, NOW).is_err());
    let successor = OwnerKey::generate().unwrap();
    let mut reused = state.transfer_owner(&root, &successor, NOW).unwrap();
    reused.state.owner_key = node_key.public_key();
    reused.state.owner_transitions[0].transition.owner_key = node_key.public_key();
    resign_transition(&mut reused.state.owner_transitions[0], &root);
    resign(&mut reused, &node_key);
    assert!(reused.verified_checkpoint(state.anchor()).is_err());
    state
        .apply_chain(
            &[state.transfer_owner(&root, &successor, NOW).unwrap()],
            NOW,
        )
        .unwrap();
    assert!(state.transfer_owner(&successor, &root, NOW).is_err());
    let former_as_node =
        NodeIdentity::from_secret_bytes(nodes[1].id(), &root.expose_secret()).unwrap();
    assert!(
        former_as_node
            .request_enrollment(state.anchor(), state.checkpoint(), "reused", NOW)
            .is_err()
    );
}

#[test]
fn expired_handoffs_and_invalid_batches_preserve_freshness_and_atomicity() {
    let (root, _, original) = fixture();
    let successor = OwnerKey::generate().unwrap();
    let late = NOW + MAX_STATE_LIFETIME + 1;
    let update = original.transfer_owner(&root, &successor, late).unwrap();
    assert!(original.require_fresh(late).is_err());
    let mut receiver = original.clone();
    receiver
        .apply_chain(std::slice::from_ref(&update), late)
        .unwrap();
    receiver.require_fresh(late).unwrap();
    let mut broken = receiver.renew(&successor, late + 1).unwrap();
    broken.signature[0] ^= 1;
    let mut batch = original.clone();
    assert!(
        batch
            .apply_chain(&[update.clone(), broken], late + 1)
            .is_err()
    );
    assert_eq!(batch.checkpoint(), original.checkpoint());
    batch
        .advance_history(std::slice::from_ref(&update))
        .unwrap();
    assert!(batch.require_fresh(late + MAX_STATE_LIFETIME).is_err());
    assert!(original.transfer_owner(&root, &successor, NOW - 1).is_err());
    assert!(
        original
            .transfer_owner(&root, &successor, (1 << 53) - 1)
            .is_err()
    );
}

#[test]
fn retired_owner_cannot_create_current_grants_or_legacy_registrations() {
    let (root, nodes, mut state) = fixture();
    let endpoints = (nodes[0].id(), nodes[1].id());
    let agent = uuid::Uuid::new_v4().to_string();
    let old_binding = root
        .bind_legacy_agent(&state, &agent, nodes[0].id(), NOW)
        .unwrap();
    let old_grant = root
        .authorize_configuration_stream(&state, b"old", [1; 32], endpoints, NOW)
        .unwrap();
    let successor = OwnerKey::generate().unwrap();
    state
        .apply_chain(
            &[state.transfer_owner(&root, &successor, NOW + 1).unwrap()],
            NOW + 1,
        )
        .unwrap();
    old_binding
        .verify(state.anchor(), &agent, nodes[0].id())
        .unwrap();
    assert!(
        old_binding
            .verify_current(&state, &agent, nodes[0].id())
            .is_err()
    );
    old_grant.verify(state.anchor()).unwrap();
    assert!(old_grant.verify_initial(&state, NOW + 1).is_err());
    assert!(
        root.bind_legacy_agent(&state, &agent, nodes[0].id(), NOW + 1)
            .is_err()
    );
    assert!(
        root.authorize_configuration_stream(&state, b"new", [2; 32], endpoints, NOW + 1)
            .is_err()
    );
    successor
        .bind_legacy_agent(&state, &agent, nodes[0].id(), NOW + 1)
        .unwrap()
        .verify_current(&state, &agent, nodes[0].id())
        .unwrap();
    successor
        .authorize_configuration_stream(&state, b"new", [2; 32], endpoints, NOW + 1)
        .unwrap()
        .verify_initial(&state, NOW + 1)
        .unwrap();
    let mut forged = old_grant;
    forged.grant.base = state.checkpoint().clone();
    let mut input = b"gent/configuration-grant/v1\0".to_vec();
    input.extend(serde_jcs::to_vec(&forged.grant).unwrap());
    forged.signature = SigningKey::from_bytes(&root.expose_secret())
        .sign(&input)
        .to_bytes()
        .to_vec();
    forged.verify(state.anchor()).unwrap();
    assert!(forged.verify_initial(&state, NOW + 1).is_err());
}

#[test]
fn succession_history_is_bounded_without_breaking_final_epoch_operations() {
    let (mut owner, nodes, mut state) = fixture();
    for i in 1..=MAX_OWNER_TRANSITIONS {
        let successor = OwnerKey::generate().unwrap();
        let update = state
            .transfer_owner(&owner, &successor, NOW + i as u64)
            .unwrap();
        state.apply_chain(&[update], NOW + i as u64).unwrap();
        owner = successor;
    }
    let now = NOW + MAX_OWNER_TRANSITIONS as u64;
    assert_eq!(state.owner_epoch() as usize, MAX_OWNER_TRANSITIONS);
    assert!(
        state
            .transfer_owner(&owner, &OwnerKey::generate().unwrap(), now)
            .is_err()
    );
    state
        .apply_chain(&[state.renew(&owner, now).unwrap()], now)
        .unwrap();
    owner
        .authorize_configuration_stream(
            &state,
            b"final",
            [3; 32],
            (nodes[0].id(), nodes[1].id()),
            now,
        )
        .unwrap()
        .verify_initial(&state, now)
        .unwrap();
    let agent = uuid::Uuid::new_v4().to_string();
    owner
        .bind_legacy_agent(&state, &agent, nodes[0].id(), now)
        .unwrap()
        .verify_current(&state, &agent, nodes[0].id())
        .unwrap();
    #[cfg(feature = "invitation")]
    invitation_check(&owner, &state, &nodes[0], now);
}

#[cfg(feature = "invitation")]
fn invitation_options() -> invitation::Options {
    invitation::Options {
        service: invitation::ServiceBinding {
            account_id: uuid::Uuid::new_v4().to_string(),
            account_origin: "https://accounts.example".into(),
            relay_origin: "https://relay.example".into(),
        },
        purpose: invitation::Purpose::NewNode,
        can_configure: false,
        replaces: None,
    }
}

#[cfg(feature = "invitation")]
fn invitation_check(owner: &OwnerKey, state: &VerifiedState, node: &NodeIdentity, now: u64) {
    let issued =
        invitation::OwnerInvitation::issue(owner, state, node, invitation_options(), now).unwrap();
    let decoded = invitation::Invitation::decode(&issued.invitation().encode().unwrap()).unwrap();
    decoded.offer().verify_current(state, now).unwrap();
    let joining = NodeIdentity::generate().unwrap();
    let (initiator, hello) = invitation::channel::Initiator::start(&decoded, now).unwrap();
    let (pending, reply) = issued.respond(&hello, now).unwrap();
    let (mut client, claim) = initiator.finish(&reply, &joining, "joining", now).unwrap();
    let mut server = pending
        .accept(&claim, now, |offer, candidate| {
            offer.verify_current(state, now)?;
            assert_eq!(candidate.id, joining.id());
            Ok(())
        })
        .unwrap();
    let packets = server.seal(b"successor invitation channel", now).unwrap();
    assert_eq!(
        &*client.open(&packets, now).unwrap(),
        b"successor invitation channel"
    );
}

#[cfg(feature = "invitation")]
#[test]
fn invitations_require_the_current_epoch_while_historical_proofs_remain_verifiable() {
    let (root, nodes, mut state) = fixture();
    let old =
        invitation::OwnerInvitation::issue(&root, &state, &nodes[0], invitation_options(), NOW)
            .unwrap();
    let successor = OwnerKey::generate().unwrap();
    state
        .apply_chain(
            &[state.transfer_owner(&root, &successor, NOW + 1).unwrap()],
            NOW + 1,
        )
        .unwrap();
    old.invitation()
        .offer()
        .verify(state.anchor(), NOW + 1)
        .unwrap();
    assert!(
        old.invitation()
            .offer()
            .verify_current(&state, NOW + 1)
            .is_err()
    );
    assert!(
        invitation::OwnerInvitation::issue(&root, &state, &nodes[0], invitation_options(), NOW + 1)
            .is_err()
    );
    invitation_check(&successor, &state, &nodes[0], NOW + 1);
}
