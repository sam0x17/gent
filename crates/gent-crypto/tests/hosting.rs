use gent_crypto::{peer::ConfigurationSigner, *};

const NOW: u64 = 1_800_000_000;

struct Fixture {
    owner: OwnerKey,
    nodes: Vec<NodeIdentity>,
    state: VerifiedState,
}

impl Fixture {
    fn new() -> Self {
        let owner = OwnerKey::generate().unwrap();
        let nodes: Vec<_> = (0..4).map(|_| NodeIdentity::generate().unwrap()).collect();
        let mut state = owner
            .create_cluster("hosting", &nodes[0], "parent", NOW)
            .unwrap();
        for node in &nodes[1..] {
            let request = node
                .request_enrollment(state.anchor(), state.checkpoint(), "node", NOW)
                .unwrap();
            let next = state
                .enroll(&owner, &request, request.fingerprint().unwrap(), NOW)
                .unwrap();
            state.apply_chain(&[next], NOW).unwrap();
        }
        Self {
            owner,
            nodes,
            state,
        }
    }

    fn host(&mut self, child: usize, parent: usize) {
        let next = self
            .state
            .host_node(
                &self.owner,
                self.nodes[child].id(),
                self.nodes[parent].id(),
                NOW,
            )
            .unwrap();
        self.state.apply_chain(&[next], NOW).unwrap();
    }
}

#[test]
fn hosting_preserves_keys_configuration_grants_and_logical_membership() {
    let mut f = Fixture::new();
    let next = f
        .state
        .delegate_configuration(&f.owner, f.nodes[1].id(), true, NOW)
        .unwrap();
    f.state.apply_chain(&[next], NOW).unwrap();
    let before = f.state.state().nodes.clone();
    f.host(1, 0);
    f.host(2, 0);
    f.host(1, 0); // An identical mapping is allowed.
    for (index, node) in f.nodes.iter().enumerate() {
        let member = &f.state.state().nodes[node.id()];
        assert_eq!(member.signing_key, before[node.id()].signing_key);
        assert_eq!(member.can_configure, before[node.id()].can_configure);
        assert_eq!(
            f.state.transport_host(node.id()).unwrap(),
            if matches!(index, 1 | 2) {
                f.nodes[0].id()
            } else {
                node.id()
            }
        );
        assert!(
            f.state
                .authorize_node(node.id(), &node.public_key(), NOW)
                .is_ok()
        );
    }
    assert!(
        f.state
            .authorize_node(f.nodes[1].id(), &f.nodes[0].public_key(), NOW)
            .is_err()
    );
    let restored = VerifiedState::restore(
        f.state.anchor().clone(),
        f.state.checkpoint().clone(),
        SignedState::decode(&f.state.signed().encode().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        restored.transport_host(f.nodes[1].id()).unwrap(),
        f.nodes[0].id()
    );
}

#[test]
fn chat_carriers_use_mapping_and_node_authentication_enforces_freshness() {
    let mut f = Fixture::new();
    f.host(1, 0);
    let child = f.nodes[1].id();
    assert!(
        f.state
            .authorize_chat_carrier(child, f.nodes[0].id())
            .is_ok()
    );
    for carrier in [child, f.nodes[2].id(), "missing"] {
        assert!(f.state.authorize_chat_carrier(child, carrier).is_err());
    }
    assert!(
        f.state
            .authorize_chat_carrier(f.nodes[2].id(), f.nodes[2].id())
            .is_ok()
    );
    assert!(
        f.state
            .authorize_chat_carrier(f.nodes[2].id(), f.nodes[0].id())
            .is_err()
    );
    assert!(
        f.state
            .authorize_chat_carrier("missing", f.nodes[0].id())
            .is_err()
    );
    assert!(
        f.state
            .authorize_node(f.nodes[0].id(), &f.nodes[0].public_key(), NOW)
            .is_ok()
    );
    assert!(
        f.state
            .authorize_node(f.nodes[0].id(), &f.nodes[1].public_key(), NOW)
            .is_err()
    );
    for now in [NOW - 1, NOW + MAX_STATE_LIFETIME] {
        assert!(
            f.state
                .authorize_node(f.nodes[0].id(), &f.nodes[0].public_key(), now)
                .is_err()
        );
    }
    let next = f.state.revoke_node(&f.owner, child, NOW).unwrap();
    f.state.apply_chain(&[next], NOW).unwrap();
    assert!(f.state.transport_host(child).is_err());
    assert!(
        f.state
            .authorize_chat_carrier(child, f.nodes[0].id())
            .is_err()
    );
}

#[test]
fn invalid_hosting_graphs_and_reassignment_are_rejected() {
    let mut f = Fixture::new();
    let missing = NodeIdentity::generate().unwrap();
    for (child, parent) in [
        (f.nodes[1].id(), f.nodes[1].id()),
        (f.nodes[1].id(), missing.id()),
        (missing.id(), f.nodes[0].id()),
    ] {
        assert!(f.state.host_node(&f.owner, child, parent, NOW).is_err());
    }
    f.host(1, 0);
    for (child, parent) in [(1, 2), (2, 1), (0, 1), (0, 2)] {
        assert!(
            f.state
                .host_node(&f.owner, f.nodes[child].id(), f.nodes[parent].id(), NOW)
                .is_err()
        );
    }
    // Check signed-state validation independently of the mutation helper.
    for parent in [f.nodes[2].id(), f.nodes[1].id(), missing.id()] {
        let mut state = f.state.renew(&f.owner, NOW).unwrap().state;
        state.nodes.get_mut(f.nodes[2].id()).unwrap().hosted_by = Some(parent.into());
        assert!(f.owner.sign_revision(&f.state, state).is_err());
    }
    // A valid graph still cannot unset or reassign an established mapping.
    for parent in [None, Some(f.nodes[2].id().to_owned())] {
        let mut state = f.state.renew(&f.owner, NOW).unwrap().state;
        state.nodes.get_mut(f.nodes[1].id()).unwrap().hosted_by = parent;
        let signed = f.owner.sign_revision(&f.state, state).unwrap();
        let mut follower = f.state.clone();
        assert!(follower.apply_chain(&[signed], NOW).is_err());
        assert_eq!(follower.checkpoint(), f.state.checkpoint());
    }
}

#[test]
fn parent_removal_requires_retiring_children_first() {
    let mut f = Fixture::new();
    f.host(1, 0);
    f.host(2, 0);
    let before = f.state.checkpoint().clone();
    assert!(f.state.revoke_node(&f.owner, f.nodes[0].id(), NOW).is_err());
    assert_eq!(f.state.checkpoint(), &before);
    for i in [1, 2, 0] {
        let next = f.state.revoke_node(&f.owner, f.nodes[i].id(), NOW).unwrap();
        f.state.apply_chain(&[next], NOW).unwrap();
        assert!(f.state.state().retired_nodes.contains(f.nodes[i].id()));
        assert!(
            f.state
                .state()
                .retired_keys
                .contains(&f.nodes[i].public_key())
        );
    }
}

#[test]
fn key_rotation_and_child_replacement_preserve_hosting() {
    let mut f = Fixture::new();
    f.host(1, 0);
    let rotated = NodeIdentity::from_secret_bytes(
        f.nodes[1].id(),
        &NodeIdentity::generate().unwrap().expose_secret(),
    )
    .unwrap();
    let request = rotated
        .request_enrollment(f.state.anchor(), f.state.checkpoint(), "rotated", NOW)
        .unwrap();
    let next = f
        .state
        .rotate_node_key(&f.owner, &request, request.fingerprint().unwrap(), NOW)
        .unwrap();
    f.state.apply_chain(&[next], NOW).unwrap();
    assert_eq!(
        f.state.transport_host(rotated.id()).unwrap(),
        f.nodes[0].id()
    );
    assert!(
        f.state
            .authorize_node(rotated.id(), &f.nodes[1].public_key(), NOW)
            .is_err()
    );
    let replacement = NodeIdentity::generate().unwrap();
    for (id, key, permitted) in [
        (f.nodes[0].id(), f.nodes[0].public_key(), false),
        (rotated.id(), rotated.public_key(), true),
    ] {
        let request = replacement
            .request_replacement(
                f.state.anchor(),
                f.state.checkpoint(),
                "replacement",
                ReplacedNode {
                    id: id.into(),
                    signing_key: key,
                },
                NOW,
            )
            .unwrap();
        let result = f.state.replace_node(
            &f.owner,
            &request,
            request.fingerprint().unwrap(),
            false,
            NOW,
        );
        if permitted {
            f.state.apply_chain(&[result.unwrap()], NOW).unwrap();
            assert_eq!(
                f.state.transport_host(replacement.id()).unwrap(),
                f.nodes[0].id()
            );
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn old_member_encoding_is_unchanged_and_enrollment_cannot_request_hosting() {
    let f = Fixture::new();
    let value = serde_json::to_value(&f.state.state().nodes[f.nodes[0].id()]).unwrap();
    assert!(value.get("hosted_by").is_none());
    let member: NodeMember = serde_json::from_value(value).unwrap();
    assert_eq!(member.hosted_by, None);
    let node = NodeIdentity::generate().unwrap();
    let mut request = node
        .request_enrollment(f.state.anchor(), f.state.checkpoint(), "new", NOW)
        .unwrap();
    request.request.member.hosted_by = Some(f.nodes[0].id().into());
    assert!(
        request
            .fingerprint()
            .unwrap_err()
            .to_string()
            .contains("separate configuration edit")
    );
}

#[test]
fn bound_owner_and_owner_candidates_must_remain_native() {
    let mut f = Fixture::new();
    f.host(2, 3);
    let next = OwnerKey::generate().unwrap();
    assert!(
        f.nodes[2]
            .prepare_owner_candidate(&f.state, &next, &uuid::Uuid::new_v4().to_string(), NOW)
            .unwrap_err()
            .to_string()
            .contains("native node")
    );
    let candidate = f.nodes[1]
        .prepare_owner_candidate(&f.state, &next, &uuid::Uuid::new_v4().to_string(), NOW)
        .unwrap();
    let authorization = f
        .state
        .authorize_owner_candidate(&f.owner, &candidate, NOW)
        .unwrap();
    let update = f
        .state
        .accept_owner_authorization(&next, &candidate, &authorization, NOW)
        .unwrap();
    f.state.apply_chain(&[update], NOW).unwrap();
    assert!(
        f.state
            .host_node(&next, f.nodes[1].id(), f.nodes[0].id(), NOW)
            .unwrap_err()
            .to_string()
            .contains("active owner node")
    );
    assert!(
        f.state
            .host_node(&next, f.nodes[0].id(), f.nodes[1].id(), NOW)
            .is_ok()
    );
    let mut malformed = f.state.renew(&next, NOW).unwrap().state;
    malformed.nodes.get_mut(f.nodes[1].id()).unwrap().hosted_by = Some(f.nodes[0].id().into());
    assert!(next.sign_revision(&f.state, malformed).is_err());
}
