use super::*;
use gent_protocol::{
    babysitter::{ChatOrigin, MAX_CHAT_INPUTS},
    notifications::Failure,
    wake::WakeTarget,
};
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
    operator_inputs(turn, at, None, &[])
}

fn operator_inputs(turn: Uuid, at: i64, first: Option<&str>, additional: &[&str]) -> AgentOp {
    claim(
        turn,
        at,
        ChatOrigin::Operator {
            turn,
            started_at: at - 1,
            client_id: first.map(String::from),
            additional_client_ids: additional.iter().map(|&id| String::from(id)).collect(),
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
async fn operator_claim_bounds_every_input_and_preserves_legacy_single_inputs() -> Result<()> {
    let mut p = Pair::new().await;
    config::set_ordinary_babysitter_enabled(p.homes[0].path(), true)?;
    let clock = now();
    let max_bytes = "é".repeat(128);
    let too_long = format!("{max_bytes}a");
    let ids: Vec<String> = (1..=MAX_CHAT_INPUTS)
        .map(|i| format!("input-{i}"))
        .collect();
    let additional: Vec<&str> = ids.iter().map(String::as_str).collect();
    for (first, rest) in [
        (None, &["second"][..]),
        (Some(" \t"), &["second"][..]),
        (Some("first"), &["", "third"][..]),
        (Some("first"), &["second", " \n"][..]),
        (Some("first"), &["second", "first"][..]),
        (Some("first"), &["second", "second"][..]),
        (Some(too_long.as_str()), &[][..]),
        (Some(too_long.as_str()), &["second"][..]),
        (Some("first"), &[too_long.as_str()][..]),
        (Some("first"), additional.as_slice()),
    ] {
        let op = operator_inputs(Uuid::now_v7(), clock, first, rest);
        assert_eq!(
            p.agent(0, op)?,
            json!({"claim": null}),
            "first={first:?} rest={rest:?}"
        );
    }
    for (first, rest) in [
        (None, &[][..]),
        (Some(""), &[][..]),
        (Some("  "), &[][..]),
        (Some("first"), &[max_bytes.as_str()][..]),
        (Some(max_bytes.as_str()), &additional[..MAX_CHAT_INPUTS - 1]),
    ] {
        let op = operator_inputs(Uuid::now_v7(), clock, first, rest);
        assert!(
            p.agent(0, op)?["claim"].is_string(),
            "first={first:?} rest={rest:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn operator_claim_rejects_own_wake_and_ordinary_attempt_in_each_position() -> Result<()> {
    let mut p = Pair::new().await;
    config::set_ordinary_babysitter_enabled(p.homes[1].path(), true)?;
    let sent = p.send(vec![])?;
    p.pump();
    let clock = now();
    let message: String = serde_json::from_value(sent["message_id"].clone())?;
    let wake = Uuid::new_v4().to_string();
    let host = WakeTarget::Codex {
        thread_id: Uuid::now_v7().to_string(),
    };
    let direct = p.agent(
        1,
        AgentOp::WakeDirectClaim {
            message_id: message.clone(),
            attempt_id: wake.clone(),
            target: host.clone(),
        },
    )?;
    assert_eq!(direct["may_submit"], true);
    let ordinary: String =
        serde_json::from_value(p.agent(1, operator(Uuid::now_v7(), clock))?["claim"].clone())?;

    let turn = Uuid::now_v7();
    for attempt in [&wake, &ordinary] {
        let single = operator_inputs(turn, clock, Some(attempt), &[]);
        assert_eq!(p.agent(1, single)?, json!({"claim":null}));
        for pos in 0..3 {
            let mut ids = ["first", "second", "third"];
            ids[pos] = attempt;
            let op = operator_inputs(turn, clock, Some(ids[0]), &ids[1..]);
            assert_eq!(p.agent(1, op)?, json!({"claim":null}), "position {pos}");
        }
    }
    // Rejected claims leave the turn available for a valid proof.
    assert!(
        p.agent(1, operator_inputs(turn, clock, Some("first"), &["second"]))?["claim"].is_string()
    );

    // The host can acknowledge submission before recording an observed turn.
    let submitted = Uuid::now_v7();
    p.agent(
        1,
        AgentOp::WakeSubmitted {
            message_id: message.clone(),
            attempt_id: wake.clone(),
            submission_id: submitted.to_string(),
        },
    )?;
    assert_eq!(
        p.agent(1, operator(submitted, clock))?,
        json!({"claim":null})
    );
    let observed = Uuid::now_v7();
    p.agent(
        1,
        AgentOp::WakeDirectObserve {
            message_id: message,
            attempt_id: wake.clone(),
            target: host,
            turn_id: observed.to_string(),
        },
    )?;
    let clean_ids = operator_inputs(observed, clock, Some("first"), &["second"]);
    assert_eq!(p.agent(1, clean_ids)?, json!({"claim":null}));

    assert!(
        p.agent(
            1,
            claim(
                observed,
                clock,
                ChatOrigin::ThreadHandoff {
                    item: Uuid::now_v7(),
                    started_at: clock,
                }
            )
        )?["claim"]
            .is_null()
    );

    // A second local agent shares the database, including all three matching
    // pieces of evidence, but owns none of them.
    let other = config::secret();
    p.stores[1].execute(Request::Agent {
        credential: other.clone(),
        action: AgentOp::Register {
            name: "other".into(),
            provider: "test".into(),
        },
    })?;
    for turn in [submitted, observed] {
        let result = p.stores[1].execute(Request::Agent {
            credential: other.clone(),
            action: operator_inputs(turn, clock, Some(&ordinary), &[&wake]),
        })?;
        assert!(result["claim"].is_string());
    }
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
                additional_client_ids: vec![],
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
                    additional_client_ids: vec![],
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

#[tokio::test]
async fn handoff_receipts_and_retry_pause_belong_to_the_authenticated_registration() -> Result<()> {
    let mut p = Pair::new().await;
    config::set_ordinary_babysitter_enabled(p.homes[0].path(), true)?;
    let clock = now() + 5;
    p.stores[0]
        .db
        .execute("UPDATE request_clock SET floor=?1", [clock])?;
    let request = |item| {
        claim(
            Uuid::now_v7(),
            clock,
            ChatOrigin::ThreadHandoff {
                item,
                started_at: clock - 1,
            },
        )
    };
    let item = Uuid::now_v7();
    let first = request(item);
    // A second authenticated registration deliberately claims identical native IDs first.
    let other = config::secret();
    for action in [
        AgentOp::Register {
            name: "other".into(),
            provider: "codex".into(),
        },
        first.clone(),
    ] {
        let result = p.stores[0].execute(Request::Agent {
            credential: other.clone(),
            action,
        })?;
        assert!(result["agent"]["id"].is_string() || result["claim"].is_string());
    }
    let attempt = serde_json::from_value(p.agent(0, first.clone())?["claim"].clone())?;
    let check = AgentOp::BabysitterChatCheck { attempt };
    assert_eq!(p.agent(0, check.clone())?["eligible"], true);
    // Reopen after admission with no acknowledgement of the native send.
    p.reopen(0);
    assert_eq!(p.agent(0, check)?["eligible"], false);
    let next = request(Uuid::now_v7());
    p.stores[0]
        .db
        .execute("UPDATE request_clock SET floor=?1", [clock + 14])?;
    assert!(p.agent(0, next.clone())?["claim"].is_null());
    p.stores[0]
        .db
        .execute("UPDATE request_clock SET floor=?1", [clock + 15])?;
    let failed_auto = claim(Uuid::now_v7(), clock, ChatOrigin::Continuation { attempt });
    assert!(p.agent(0, failed_auto)?["claim"].is_null());
    assert!(p.agent(0, first)?["claim"].is_null());
    assert!(p.agent(0, request(item))?["claim"].is_null()); // Same item, different root.
    assert!(p.agent(0, next)?["claim"].is_string()); // Same fresh failure, now due.

    // Previous binaries prune the parent table without knowing handoff storage.
    p.stores[0].db.execute(
        "DELETE FROM babysitter_chat_attempts WHERE claimed_at<?1",
        [clock + 16],
    )?;
    assert!(
        !p.stores[0]
            .db
            .prepare("SELECT 1 FROM babysitter_chat_handoffs")?
            .exists([])?
    );
    Ok(())
}
