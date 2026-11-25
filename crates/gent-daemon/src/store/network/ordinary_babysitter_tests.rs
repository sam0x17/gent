use super::*;
use gent_protocol::{babysitter::ChatOrigin, notifications::Failure};
use uuid::Uuid;

fn claim(turn: Uuid, failed_at: i64, origin: ChatOrigin) -> AgentOp {
    AgentOp::BabysitterChatClaim {
        turn,
        failed_at,
        reason: Failure::ToolSchema,
        origin,
    }
}
fn operator(turn: Uuid, at: i64) -> AgentOp {
    claim(
        turn,
        at,
        ChatOrigin::Operator {
            turn,
            started_at: at - 1,
            client_id: None,
        },
    )
}

#[tokio::test]
async fn ordinary_claims_survive_restarts_and_bound_each_operator_chain() -> Result<()> {
    let mut p = Pair::new().await;
    let mut now = now() + 5;
    p.stores[0]
        .db
        .execute("UPDATE request_clock SET floor=?1", [now])?;
    let first = Uuid::now_v7();
    let op = operator(first, now);
    assert!(p.agent(0, op.clone())?["claim"].is_null());
    config::set_ordinary_babysitter_enabled(p.homes[0].path(), true)?;
    let goal_first = Uuid::now_v7();
    let goal_claim = AgentOp::BabysitterClaim {
        goal: "a".repeat(64),
        turn: goal_first,
        failed_at: now,
        reason: Failure::RequestPayload,
    };
    assert!(p.agent(0, goal_claim)?["claim"].is_string());
    assert!(p.agent(0, operator(goal_first, now))?["claim"].is_null());
    let claimed = p.agent(0, op.clone())?;
    let mut attempt = serde_json::from_value(claimed["claim"].clone())?;
    let goal = AgentOp::BabysitterClaim {
        goal: "a".repeat(64),
        turn: first,
        failed_at: now,
        reason: Failure::ToolSchema,
    };
    assert!(p.agent(0, goal)?["claim"].is_null());
    for wait in [15, 60, 120] {
        // No submitted receipt. A lost claim/check/send acknowledgement never
        // authorizes another send for the same native turn.
        p.reopen(0);
        assert!(p.agent(0, op.clone())?["claim"].is_null());
        let check = AgentOp::BabysitterChatCheck { attempt };
        assert_eq!(p.agent(0, check.clone())?["eligible"], true);
        assert_eq!(p.agent(0, check)?["eligible"], false);
        let next = claim(Uuid::now_v7(), now, ChatOrigin::Continuation { attempt });
        assert!(p.agent(0, next.clone())?["claim"].is_null());
        now += wait;
        p.stores[0]
            .db
            .execute("UPDATE request_clock SET floor=?1", [now])?;
        let result = p.agent(0, next.clone())?;
        if wait == 120 {
            assert!(result["claim"].is_null());
        } else {
            attempt = serde_json::from_value(result["claim"].clone())?;
            assert!(p.agent(0, next)?["claim"].is_null());
        }
    }
    assert!(p.agent(0, operator(Uuid::now_v7(), now))?["claim"].is_string());
    Ok(())
}

#[tokio::test]
async fn ordinary_checks_apply_both_preferences_entitlement_and_freshness() -> Result<()> {
    let mut p = Pair::new().await;
    let h = p.homes[0].path().to_path_buf();
    let clock = now();
    config::set_ordinary_babysitter_enabled(&h, true)?;
    config::write_private(&h.join("babysitter-disabled"), b"")?;
    let turn = Uuid::now_v7();
    for op in [
        operator(turn, clock - 601),
        operator(turn, clock + 11),
        claim(
            turn,
            clock,
            ChatOrigin::Operator {
                turn,
                started_at: clock + 1,
                client_id: None,
            },
        ),
        claim(
            turn,
            clock,
            ChatOrigin::Continuation {
                attempt: Uuid::new_v4(),
            },
        ),
    ] {
        assert!(p.agent(0, op)?["claim"].is_null());
    }
    let attempt = serde_json::from_value(p.agent(0, operator(turn, clock))?["claim"].clone())?;
    let check = AgentOp::BabysitterChatCheck { attempt };
    config::set_ordinary_babysitter_enabled(&h, false)?;
    assert_eq!(p.agent(0, check.clone())?["eligible"], false);
    config::set_ordinary_babysitter_enabled(&h, true)?;
    std::fs::remove_file(h.join("test-entitlement"))?;
    assert_eq!(p.agent(0, check.clone())?["eligible"], false);
    assert!(p.agent(0, operator(Uuid::now_v7(), clock))?["claim"].is_null());
    crate::entitlements::grant_test(&h, &p.stores[0].config);
    p.agent(
        0,
        AgentOp::Babysit {
            enabled: Some(false),
        },
    )?;
    assert!(p.agent(0, operator(Uuid::now_v7(), clock))?["claim"].is_null());
    p.agent(
        0,
        AgentOp::Babysit {
            enabled: Some(true),
        },
    )?;
    assert_eq!(p.agent(0, check)?["eligible"], false);
    assert!(p.agent(0, operator(Uuid::now_v7(), clock))?["claim"].is_string());
    Ok(())
}

#[tokio::test]
async fn ordinary_probe_authenticates_and_reads_under_a_reserved_sqlite_writer() -> Result<()> {
    let mut pair = Pair::new().await;
    config::set_ordinary_babysitter_enabled(pair.homes[0].path(), true)?;
    let turn = Uuid::now_v7();
    let probe = AgentOp::BabysitterChatProbe {
        turn,
        operator: turn,
        failed_at: now(),
    };
    let mut writer = rusqlite::Connection::open(pair.stores[0].db.path().unwrap())?;
    let lock = writer.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    pair.stores[0].db.busy_timeout(std::time::Duration::ZERO)?;
    assert_eq!(pair.agent(0, probe.clone())?["inspect"], true);
    assert!(
        pair.stores[0]
            .execute(Request::Agent {
                credential: config::secret(),
                action: probe,
            })
            .is_err()
    );
    lock.rollback()?;
    Ok(())
}

#[tokio::test]
async fn ordinary_chain_expires_from_original_failure_even_when_latest_failure_is_fresh()
-> Result<()> {
    let mut pair = Pair::new().await;
    config::set_ordinary_babysitter_enabled(pair.homes[0].path(), true)?;
    let base = now() + 5;
    pair.stores[0]
        .db
        .execute("UPDATE request_clock SET floor=?1", [base])?;
    let turn = Uuid::now_v7();
    let attempt = serde_json::from_value(
        pair.agent(
            0,
            claim(
                turn,
                base,
                ChatOrigin::Operator {
                    turn,
                    started_at: base - 7200,
                    client_id: None,
                },
            ),
        )?["claim"]
            .clone(),
    )?;
    assert_eq!(
        pair.agent(0, AgentOp::BabysitterChatCheck { attempt })?["eligible"],
        true
    );
    let later = base + 1801;
    pair.stores[0]
        .db
        .execute("UPDATE request_clock SET floor=?1", [later])?;
    let next = Uuid::now_v7();
    let failed = later - 16;
    assert_eq!(
        pair.agent(
            0,
            AgentOp::BabysitterChatProbe {
                turn: next,
                operator: turn,
                failed_at: failed
            }
        )?["inspect"],
        false
    );
    assert!(
        pair.agent(0, claim(next, failed, ChatOrigin::Continuation { attempt }))?["claim"]
            .is_null()
    );
    Ok(())
}
