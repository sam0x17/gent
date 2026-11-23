use ed25519_dalek::{Signer, SigningKey};
use gent_crypto::{recovery::*, *};
use serde_json::json;

const NOW: u64 = 1_800_000_000;

#[test]
fn valid_node_signature_cannot_substitute_another_owner_signed_genesis() {
    let (owner, nodes, state) = fixture();
    let baseline = RecoveryBaseline::new(&state, NOW).unwrap();
    let other = owner
        .create_cluster_with_id(
            (&state.anchor().cluster_id, "different genesis"),
            &nodes[0],
            "first",
            gent_protocol::Policy::default(),
            NOW,
        )
        .unwrap();
    let mut forged = report(&nodes[0], &state, &baseline, NOW);
    forged.observation.state = other.signed().clone();
    // Both signatures are valid under the pinned owner and member keys.
    forged
        .observation
        .state
        .verified_checkpoint(&baseline.challenge.anchor)
        .unwrap();
    let mut input = b"gent/recovery-observation/v1\0".to_vec();
    input.extend(serde_jcs::to_vec(&forged.observation).unwrap());
    forged.signature = SigningKey::from_bytes(&nodes[0].expose_secret())
        .sign(&input)
        .to_bytes()
        .to_vec();
    assert!(
        forged
            .verify(&baseline.challenge, NOW)
            .unwrap_err()
            .to_string()
            .contains("genesis")
    );
}

fn fixture() -> (OwnerKey, [NodeIdentity; 2], VerifiedState) {
    let owner = OwnerKey::generate().unwrap();
    let nodes = [
        NodeIdentity::generate().unwrap(),
        NodeIdentity::generate().unwrap(),
    ];
    let mut state = owner
        .create_cluster("recovery", &nodes[0], "first", NOW)
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

fn report(
    node: &NodeIdentity,
    state: &VerifiedState,
    baseline: &RecoveryBaseline,
    now: u64,
) -> SignedRecoveryObservation {
    node.observe_recovery(state, &baseline.challenge, now)
        .unwrap()
}

#[test]
fn all_nodes_can_report_expired_authority_without_renewing_or_authorizing_replacement() {
    let (_, nodes, state) = fixture();
    let late = NOW + MAX_STATE_LIFETIME + 1;
    assert!(state.require_fresh(late).is_err());
    let baseline = RecoveryBaseline::new(&state, late).unwrap();
    let mut review = RecoveryReviewer::new(
        RecoveryBaseline::decode(&baseline.encode().unwrap()).unwrap(),
        late,
    )
    .unwrap();
    for node in &nodes {
        let signed = report(node, &state, &baseline, late);
        let decoded = SignedRecoveryObservation::decode(&signed.encode().unwrap()).unwrap();
        assert_eq!(
            decoded.verify(&baseline.challenge, late).unwrap(),
            *state.checkpoint()
        );
        review.observe(&decoded, late).unwrap();
    }
    let result = review.finish(late).unwrap();
    assert!(result.all_match_baseline && result.missing_nodes.is_empty());
    assert!(result.observations.iter().all(|o| o.state_expired));
    assert!(
        !result.authorizes_owner_change
            && !result.proves_writer_stopped
            && !result.proves_global_freshness
    );
    assert!(state.require_fresh(late).is_err());
    let unsigned = serde_json::to_vec(&result).unwrap();
    assert!(SignedState::decode(&unsigned).is_err());
    assert!(SignedEnrollment::decode(&unsigned).is_err());
}

#[test]
fn missing_duplicates_stale_and_newer_reports_do_not_select_a_winner() {
    let (owner, nodes, state) = fixture();
    let mut newer = state.clone();
    newer
        .apply_chain(&[state.renew(&owner, NOW + 1).unwrap()], NOW + 1)
        .unwrap();
    let baseline = RecoveryBaseline::new(&state, NOW + 2).unwrap();
    let mut review = RecoveryReviewer::new(baseline.clone(), NOW + 2).unwrap();
    let first = report(&nodes[0], &state, &baseline, NOW + 2);
    review.observe(&first, NOW + 2).unwrap();
    assert!(review.observe(&first, NOW + 2).is_err());
    let partial = review.finish(NOW + 2).unwrap();
    assert_eq!(partial.missing_nodes, [nodes[1].id()]);
    assert!(!partial.all_match_baseline);
    let mut review = RecoveryReviewer::new(baseline.clone(), NOW + 2).unwrap();
    review.observe(&first, NOW + 2).unwrap();
    review
        .observe(&report(&nodes[1], &newer, &baseline, NOW + 2), NOW + 2)
        .unwrap();
    let result = review.finish(NOW + 2).unwrap();
    assert!(!result.all_match_baseline && result.missing_nodes.is_empty());
    assert!(
        result
            .observations
            .iter()
            .any(|r| r.relation == CheckpointRelation::Ahead)
    );
    let latest = RecoveryBaseline::new(&newer, NOW + 2).unwrap();
    let mut review = RecoveryReviewer::new(latest.clone(), NOW + 2).unwrap();
    review
        .observe(&report(&nodes[0], &state, &latest, NOW + 2), NOW + 2)
        .unwrap();
    let result = review.finish(NOW + 2).unwrap();
    assert_eq!(result.observations[0].relation, CheckpointRelation::Behind);
    assert!(!result.proves_global_freshness);
}

#[test]
fn signed_forks_are_reported_at_the_baseline_and_at_later_revisions() {
    let (owner, nodes, state) = fixture();
    let mut left = state.clone();
    let mut right = state.clone();
    left.apply_chain(&[state.renew(&owner, NOW + 1).unwrap()], NOW + 1)
        .unwrap();
    right
        .apply_chain(&[state.renew(&owner, NOW + 2).unwrap()], NOW + 2)
        .unwrap();
    for base in [&state, &left] {
        let baseline = RecoveryBaseline::new(base, NOW + 3).unwrap();
        let mut review = RecoveryReviewer::new(baseline.clone(), NOW + 3).unwrap();
        review
            .observe(&report(&nodes[0], &left, &baseline, NOW + 3), NOW + 3)
            .unwrap();
        review
            .observe(&report(&nodes[1], &right, &baseline, NOW + 3), NOW + 3)
            .unwrap();
        let result = review.finish(NOW + 3).unwrap();
        assert_eq!(result.conflicting_revisions, [left.checkpoint().revision]);
        assert!(!result.all_match_baseline && !result.authorizes_owner_change);
    }
}

#[test]
fn changed_payload_signature_challenge_cluster_and_time_are_rejected() {
    let (_, nodes, state) = fixture();
    let baseline = RecoveryBaseline::new(&state, NOW).unwrap();
    let signed = report(&nodes[0], &state, &baseline, NOW);
    for (pointer, replacement) in [
        ("/observation/version", json!(2)),
        ("/observation/observer", json!(nodes[1].id())),
        (
            "/observation/observer_key/0",
            json!(signed.observation.observer_key[0] ^ 1),
        ),
        ("/observation/state/state/name", json!("changed")),
        (
            "/observation/challenge/id",
            json!(uuid::Uuid::new_v4().to_string()),
        ),
        ("/observation/observed_at", json!(NOW + 1)),
        ("/signature/0", json!(signed.signature[0] ^ 1)),
    ] {
        let mut value = serde_json::to_value(&signed).unwrap();
        *value.pointer_mut(pointer).unwrap() = replacement;
        let changed: SignedRecoveryObservation = serde_json::from_value(value).unwrap();
        assert!(
            changed.verify(&baseline.challenge, NOW).is_err(),
            "accepted {pointer}"
        );
    }
    let other = RecoveryBaseline::new(&state, NOW).unwrap();
    assert!(signed.verify(&other.challenge, NOW).is_err());
    assert!(signed.verify(&baseline.challenge, NOW - 1).is_err());
    assert!(
        signed
            .verify(&baseline.challenge, NOW + OBSERVATION_LIFETIME)
            .is_err()
    );
    let (_, _, foreign) = fixture();
    let foreign = RecoveryBaseline::new(&foreign, NOW).unwrap();
    assert!(
        nodes[0]
            .observe_recovery(&state, &foreign.challenge, NOW)
            .is_err()
    );
    let mut forged = baseline.clone();
    forged.challenge.base.state_hash[0] ^= 1;
    assert!(forged.verify(NOW).is_err());
    let bytes = signed.encode().unwrap();
    let mut padded = bytes.clone();
    padded.push(b'\n');
    assert!(SignedRecoveryObservation::decode(&padded).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["new_owner"] = json!(nodes[1].public_key());
    assert!(SignedRecoveryObservation::decode(&serde_jcs::to_vec(&value).unwrap()).is_err());
    assert!(SignedRecoveryObservation::decode(&vec![b' '; MAX_OBSERVATION_BYTES + 1]).is_err());
}

#[test]
fn revoked_unknown_and_changed_node_keys_cannot_count_as_baseline_witnesses() {
    let (owner, nodes, state) = fixture();
    let baseline = RecoveryBaseline::new(&state, NOW).unwrap();
    let stranger = NodeIdentity::generate().unwrap();
    assert!(
        stranger
            .observe_recovery(&state, &baseline.challenge, NOW)
            .is_err()
    );
    let mut revoked = state.clone();
    revoked
        .apply_chain(
            &[state.revoke_node(&owner, nodes[1].id(), NOW).unwrap()],
            NOW,
        )
        .unwrap();
    assert!(
        nodes[1]
            .observe_recovery(&revoked, &baseline.challenge, NOW)
            .is_err()
    );
    let current = RecoveryBaseline::new(&revoked, NOW).unwrap();
    let old_report = report(&nodes[1], &state, &current, NOW);
    assert!(
        RecoveryReviewer::new(current, NOW)
            .unwrap()
            .observe(&old_report, NOW)
            .is_err()
    );
    let generated = NodeIdentity::generate().unwrap();
    let replacement =
        NodeIdentity::from_secret_bytes(nodes[1].id(), &generated.expose_secret()).unwrap();
    let enrollment = replacement
        .request_enrollment(state.anchor(), state.checkpoint(), "replacement", NOW)
        .unwrap();
    let mut rotated = state.clone();
    let update = state
        .rotate_node_key(&owner, &enrollment, enrollment.fingerprint().unwrap(), NOW)
        .unwrap();
    rotated.apply_chain(&[update], NOW).unwrap();
    let changed = report(&replacement, &rotated, &baseline, NOW);
    assert!(
        RecoveryReviewer::new(baseline, NOW)
            .unwrap()
            .observe(&changed, NOW)
            .is_err()
    );
}

#[test]
fn review_rechecks_deadline_and_state_expiry_at_completion() {
    let (_, nodes, state) = fixture();
    let just_before_expiry = NOW + MAX_STATE_LIFETIME - 1;
    let baseline = RecoveryBaseline::new(&state, just_before_expiry).unwrap();
    let mut review = RecoveryReviewer::new(baseline.clone(), just_before_expiry).unwrap();
    for node in &nodes {
        review
            .observe(
                &report(node, &state, &baseline, just_before_expiry),
                just_before_expiry,
            )
            .unwrap();
    }
    assert!(
        review
            .finish(just_before_expiry + 1)
            .unwrap()
            .observations
            .iter()
            .all(|r| r.state_expired)
    );
    let review = RecoveryReviewer::new(baseline.clone(), just_before_expiry).unwrap();
    assert!(review.finish(baseline.challenge.expires_at).is_err());
    let mut too_long = baseline.challenge.clone();
    too_long.expires_at += 1;
    assert!(too_long.validate(just_before_expiry).is_err());
}
