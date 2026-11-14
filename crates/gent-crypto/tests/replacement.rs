use gent_crypto::*;
use gent_protocol::{Effect, Permission, Policy, Rule, Selector};

const NOW: u64 = 1_800_000_000;

fn fixture(configure: bool) -> (OwnerKey, NodeIdentity, VerifiedState) {
    let owner = OwnerKey::generate().unwrap();
    let writer = NodeIdentity::generate().unwrap();
    let mut state = owner
        .create_cluster("replace", &writer, "owner", NOW)
        .unwrap();
    let old = NodeIdentity::generate().unwrap();
    let request = old
        .request_enrollment(state.anchor(), state.checkpoint(), "lost", NOW)
        .unwrap();
    assert!(
        !String::from_utf8(request.encode().unwrap())
            .unwrap()
            .contains("replaces")
    );
    let update = if configure {
        state.enroll_configurator(&owner, &request, request.fingerprint().unwrap(), NOW)
    } else {
        state.enroll(&owner, &request, request.fingerprint().unwrap(), NOW)
    }
    .unwrap();
    state.apply_chain(&[update], NOW).unwrap();
    let policy = Policy {
        rules: vec![Rule {
            actor: Selector::Node(old.id().into()),
            peer: Selector::All,
            permission: Permission::Send,
            effect: Effect::Allow,
        }],
        ..Default::default()
    };
    let update = state.set_policy(&owner, policy, NOW).unwrap();
    state.apply_chain(&[update], NOW).unwrap();
    (owner, old, state)
}

fn request(new: &NodeIdentity, old: &NodeIdentity, state: &VerifiedState) -> SignedEnrollment {
    new.request_replacement(
        state.anchor(),
        state.checkpoint(),
        "replacement",
        ReplacedNode {
            id: old.id().into(),
            signing_key: old.public_key(),
        },
        NOW,
    )
    .unwrap()
}

#[test]
fn replacement_is_one_revision_with_fresh_identity_and_bounded_administration() {
    for (old_admin, allow_admin) in [(false, false), (false, true), (true, false), (true, true)] {
        let (owner, old, mut state) = fixture(old_admin);
        let new = NodeIdentity::generate().unwrap();
        let before = state.clone();
        let request = request(&new, &old, &state);
        let fingerprint = request.fingerprint().unwrap();
        assert!(state.enroll(&owner, &request, fingerprint, NOW).is_err());
        assert!(
            state
                .enroll_configurator(&owner, &request, fingerprint, NOW)
                .is_err()
        );
        assert!(
            state
                .rotate_node_key(&owner, &request, fingerprint, NOW)
                .is_err()
        );
        let update = state
            .replace_node(&owner, &request, fingerprint, allow_admin, NOW)
            .unwrap();
        state.apply_chain(&[update], NOW).unwrap();
        assert_eq!(
            state.checkpoint().revision,
            before.checkpoint().revision + 1
        );
        assert_eq!(state.state().nodes.len(), before.state().nodes.len());
        assert_eq!(
            serde_json::to_value(&state.state().policy).unwrap(),
            serde_json::to_value(&before.state().policy).unwrap()
        );
        assert!(state.state().retired_nodes.contains(old.id()));
        assert!(state.state().retired_keys.contains(&old.public_key()));
        assert!(
            state
                .authorize_node(old.id(), &old.public_key(), NOW)
                .is_err()
        );
        state
            .authorize_node(new.id(), &new.public_key(), NOW)
            .unwrap();
        assert_eq!(
            state.state().nodes[new.id()].can_configure,
            old_admin && allow_admin
        );
        assert!(
            state
                .replace_node(&owner, &request, fingerprint, allow_admin, NOW)
                .is_err()
        );
    }
}

#[test]
fn replacement_binds_target_key_checkpoint_and_approval_and_never_reuses_retired_keys() {
    let (owner, old, state) = fixture(true);
    let new = NodeIdentity::generate().unwrap();
    let signed = request(&new, &old, &state);
    let fingerprint = signed.fingerprint().unwrap();
    let mut changed = signed.clone();
    changed.request.replaces.as_mut().unwrap().id = NodeIdentity::generate().unwrap().id().into();
    assert!(changed.fingerprint().is_err());
    changed = signed.clone();
    changed.request.replaces.as_mut().unwrap().signing_key = new.public_key();
    assert!(changed.fingerprint().is_err());
    assert!(
        state
            .replace_node(&owner, &signed, [0; 32], true, NOW)
            .is_err()
    );
    assert!(
        state
            .replace_node(
                &owner,
                &signed,
                fingerprint,
                true,
                signed.request.expires_at
            )
            .is_err()
    );
    assert!(
        old.request_replacement(
            state.anchor(),
            state.checkpoint(),
            "same",
            ReplacedNode {
                id: old.id().into(),
                signing_key: old.public_key()
            },
            NOW
        )
        .is_err()
    );
    let changed_key = old.replacement().unwrap();
    let key_request = request(&new, &changed_key, &state);
    assert!(
        state
            .replace_node(
                &owner,
                &key_request,
                key_request.fingerprint().unwrap(),
                true,
                NOW
            )
            .is_err()
    );
    let mut advanced = state.clone();
    advanced
        .apply_chain(&[state.renew(&owner, NOW).unwrap()], NOW)
        .unwrap();
    assert!(
        advanced
            .replace_node(&owner, &signed, fingerprint, true, NOW)
            .is_err()
    );
    let replacement = state
        .replace_node(&owner, &signed, fingerprint, true, NOW)
        .unwrap();
    advanced = state.clone();
    advanced.apply_chain(&[replacement], NOW).unwrap();
    let reused = NodeIdentity::from_secret_bytes(
        NodeIdentity::generate().unwrap().id(),
        &old.expose_secret(),
    )
    .unwrap();
    let reused_request = request(&reused, &new, &advanced);
    assert!(
        advanced
            .replace_node(
                &owner,
                &reused_request,
                reused_request.fingerprint().unwrap(),
                true,
                NOW
            )
            .is_err()
    );
}
