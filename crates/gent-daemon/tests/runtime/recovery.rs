use super::*;
use gent_crypto::recovery::{RecoveryBaseline, RecoveryReviewer, SignedRecoveryObservation};

fn challenge(f: &mut Fixture) -> RecoveryBaseline {
    serde_json::from_value(ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::RecoveryChallenge,
    )))
    .unwrap()
}

fn witness(f: &mut Fixture, baseline: &RecoveryBaseline) -> SignedRecoveryObservation {
    serde_json::from_value(ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::RecoveryObserve {
            challenge: String::from_utf8(baseline.challenge.encode().unwrap()).unwrap(),
        },
    )))
    .unwrap()
}

#[test]
fn evidence_requires_owner_rpc_and_preserves_authority_across_restart() {
    let mut f = Fixture::new();
    f.set(permit());
    let before = challenge(&mut f);
    let identity = fs::read(f.home.path().join("identity.key")).unwrap();
    let actions = [
        OwnerOp::RecoveryChallenge,
        OwnerOp::RecoveryObserve {
            challenge: String::from_utf8(before.challenge.encode().unwrap()).unwrap(),
        },
    ];
    for action in actions {
        for key in [&f.keys[0], "wrong-owner"] {
            assert!(matches!(
                owner(&mut f.store, key, action.clone()),
                Response::Error(_)
            ));
        }
        // Agent requests cannot deserialize the owner operation at all.
        assert!(serde_json::from_value::<AgentOp>(serde_json::to_value(action).unwrap()).is_err());
    }
    let report = witness(&mut f, &before);
    assert_eq!(
        report.observation.state.encode().unwrap(),
        before.state.encode().unwrap()
    );
    let mut reviewer = RecoveryReviewer::new(before.clone(), now() as u64).unwrap();
    reviewer.observe(&report, now() as u64).unwrap();
    assert!(reviewer.finish(now() as u64).unwrap().all_match_baseline);
    f.store = Store::open(f.home.path()).unwrap();
    let after = challenge(&mut f);
    assert_ne!(after.challenge.id, before.challenge.id);
    assert_eq!(after.challenge.base, before.challenge.base);
    assert_eq!(
        after.state.encode().unwrap(),
        before.state.encode().unwrap()
    );
    assert_eq!(
        fs::read(f.home.path().join("identity.key")).unwrap(),
        identity
    );
    assert_eq!(
        witness(&mut f, &before)
            .verify(&before.challenge, now() as u64)
            .unwrap(),
        before.challenge.base
    );
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM authority_history", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn expired_authority_can_be_reported_but_never_renewed_by_evidence_collection() {
    let mut f = Fixture::new();
    let fresh = challenge(&mut f);
    let late = fresh.state.state.expires_at + 1;
    f.db()
        .execute("UPDATE request_clock SET floor=?1", [late])
        .unwrap();
    let baseline = challenge(&mut f);
    assert_eq!(baseline.challenge.issued_at, late);
    assert_eq!(baseline.challenge.base, fresh.challenge.base);
    assert_eq!(
        baseline.state.encode().unwrap(),
        fresh.state.encode().unwrap()
    );
    let report = witness(&mut f, &baseline);
    let mut reviewer = RecoveryReviewer::new(baseline, late).unwrap();
    reviewer.observe(&report, late).unwrap();
    let review = reviewer.finish(late).unwrap();
    assert!(review.all_match_baseline && review.observations[0].state_expired);
    assert!(!review.authorizes_owner_change);
    assert!(matches!(
        agent(&mut f.store, &f.keys[0], AgentOp::Inbox),
        Response::Error(_)
    ));
    assert_eq!(
        ok(owner(&mut f.store, &f.owner_rpc, OwnerOp::Status))["authority"]["fresh"],
        false
    );
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM authority_history", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn daemon_refuses_foreign_expired_and_noncanonical_challenges() {
    let mut f = Fixture::new();
    let mut foreign = Fixture::new();
    let baseline = challenge(&mut f);
    let other = challenge(&mut foreign);
    let own = String::from_utf8(baseline.challenge.encode().unwrap()).unwrap();
    for invalid in [
        String::from_utf8(other.challenge.encode().unwrap()).unwrap(),
        format!("{own}\n"),
    ] {
        assert!(matches!(
            owner(
                &mut f.store,
                &f.owner_rpc,
                OwnerOp::RecoveryObserve { challenge: invalid }
            ),
            Response::Error(_)
        ));
    }
    f.db()
        .execute(
            "UPDATE request_clock SET floor=?1",
            [baseline.challenge.expires_at],
        )
        .unwrap();
    assert!(matches!(
        owner(
            &mut f.store,
            &f.owner_rpc,
            OwnerOp::RecoveryObserve { challenge: own }
        ),
        Response::Error(_)
    ));
    assert_eq!(challenge(&mut f).challenge.base, baseline.challenge.base);
}
