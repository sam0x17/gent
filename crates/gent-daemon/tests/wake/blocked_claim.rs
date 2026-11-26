use super::*;
use gent_protocol::{notifications::Failure, wake::VERIFIED_BLOCKED_MAX_AGE_SECS};

fn fixture() -> (Fixture, i64) {
    let f = Fixture::new();
    let clock = gent_daemon::store::now() + 60;
    f.db()
        .execute("UPDATE request_clock SET floor=?1", [clock])
        .unwrap();
    (f, clock)
}

fn blocked(f: &Fixture, turn: Uuid, failed_at: i64) -> OwnerOp {
    OwnerOp::BabysitterVerifiedBlockedClaim {
        agent_credential: f.keys[1].clone(),
        thread_id: uuid::uuid!("ce98cd69-e88d-43ed-a23a-ca8cb147c0d6"),
        goal: "a".repeat(64),
        turn,
        failed_at,
        reason: Failure::Capacity,
    }
}

fn routine(turn: Uuid, failed_at: i64) -> AgentOp {
    AgentOp::BabysitterClaim {
        goal: "a".repeat(64),
        turn,
        failed_at,
        reason: Failure::Capacity,
    }
}

#[test]
fn retrospective_claim_is_owner_only_and_expires_at_the_failure_boundary() {
    let (mut f, clock) = fixture();
    let turn = Uuid::new_v4();
    let cutoff = clock - VERIFIED_BLOCKED_MAX_AGE_SECS;
    for invalid in [i64::MIN, 0, cutoff - 1, clock + 1, i64::MAX] {
        let op = blocked(&f, turn, invalid);
        assert!(ok(f.owner(op))["claim"].is_null());
    }
    assert!(ok(f.agent(1, routine(turn, clock - 7201)))["claim"].is_null());
    assert!(error(f.owner(blocked(&f, Uuid::nil(), cutoff))).contains("identity"));
    let valid = blocked(&f, turn, cutoff);
    let mut bogus = valid.clone();
    if let OwnerOp::BabysitterVerifiedBlockedClaim { goal, .. } = &mut bogus {
        *goal = "invalid fingerprint".into();
    }
    assert!(error(f.owner(bogus)).contains("identity"));
    let mut unbound = valid.clone();
    if let OwnerOp::BabysitterVerifiedBlockedClaim {
        agent_credential, ..
    } = &mut unbound
    {
        *agent_credential = config::secret();
    }
    assert!(error(f.owner(unbound)).contains("register"));
    assert!(serde_json::from_value::<AgentOp>(serde_json::to_value(&valid).unwrap()).is_err());
    assert!(
        error(f.store.handle(Request::Owner {
            credential: f.keys[1].clone(),
            action: valid.clone(),
        }))
        .contains("unauthorized")
    );

    let result = ok(f.owner(valid.clone()));
    let attempt = serde_json::from_value(result["claim"].clone()).unwrap();
    let check = AgentOp::BabysitterCheck { attempt };
    f.store = Store::open(f.home.path()).unwrap();
    assert!(ok(f.owner(valid))["claim"].is_null());
    assert_eq!(ok(f.agent(0, check.clone()))["eligible"], false);
    assert_eq!(ok(f.agent(1, check.clone()))["eligible"], true);
    f.advance(1);
    assert_eq!(ok(f.agent(1, check))["eligible"], false);
}

#[test]
fn routine_and_verified_claims_share_durable_backoff_and_one_attempt() {
    let (mut f, clock) = fixture();
    let turn = Uuid::new_v4();
    let claim = blocked(&f, turn, clock);
    let first = ok(f.owner(claim));
    assert!(first["claim"].is_string());
    assert!(ok(f.agent(1, routine(turn, clock)))["claim"].is_null());

    f.advance(1);
    let newer = Uuid::new_v4();
    let failed = clock + 1;
    let next = blocked(&f, newer, failed);
    assert!(ok(f.agent(1, routine(newer, failed)))["claim"].is_null());
    f.store = Store::open(f.home.path()).unwrap();
    f.advance(14);
    assert!(ok(f.owner(next.clone()))["claim"].is_null());
    f.advance(1);
    assert!(ok(f.owner(blocked(&f, newer, failed + 1)))["claim"].is_null());
    assert!(ok(f.owner(next.clone()))["claim"].is_string());
    assert!(ok(f.agent(1, routine(newer, failed)))["claim"].is_null());
    assert!(ok(f.owner(next))["claim"].is_null());
}

#[test]
fn legacy_outstanding_claim_keeps_its_two_hour_cutoff_after_update() {
    let (mut f, clock) = fixture();
    let result = ok(f.agent(1, routine(Uuid::new_v4(), clock - 7200)));
    let attempt = serde_json::from_value(result["claim"].clone()).unwrap();
    let check = AgentOp::BabysitterCheck { attempt };
    f.db()
        .execute(
            "ALTER TABLE babysitter_attempts DROP COLUMN valid_until",
            [],
        )
        .unwrap();
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(ok(f.agent(1, check.clone()))["eligible"], true);
    f.advance(1);
    assert_eq!(ok(f.agent(1, check))["eligible"], false);
}
