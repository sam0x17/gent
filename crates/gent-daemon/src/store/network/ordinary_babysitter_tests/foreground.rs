use super::*;
use gent_protocol::babysitter::{ForegroundInput, ForegroundInputs};

fn root(count: usize, at: i64) -> ForegroundInputs {
    ForegroundInputs {
        thread: Uuid::now_v7(),
        turn: Uuid::now_v7(),
        started_at: at - 100,
        inputs: (0..count)
            .map(|idx| ForegroundInput {
                client: Uuid::new_v4(),
                sha256: format!("{idx:064x}"),
                received_at_ms: (at - 95 + idx as i64) * 1000,
            })
            .collect(),
    }
}

fn record(p: &Pair, proof: &ForegroundInputs, index: usize) -> Result<()> {
    let input = &proof.inputs[index];
    let at = input.received_at_ms / 1000;
    let message = Uuid::new_v4().to_string();
    let payload = json!({"message_id":message,"agent":p.agents[0],"attempt_id":input.client,
        "direct":{"reply_request_id":Uuid::now_v7(),"input_hash":input.sha256,
            "turn_id":proof.turn,"finished":true,"response_hash":null,"response_message_id":null},
        "target":{"host":"codex","thread_id":proof.thread},"state":"submitted","submission_id":proof.turn,
        "inbox_seen_at":at,"claimed_at":at,"updated_at":at});
    p.stores[0].db.execute("INSERT INTO wake_dispatches(message_id,agent,attempt_id,claimed_at,payload) VALUES(?1,?2,?3,?4,?5)",params![message,p.agents[0],input.client.to_string(),at,payload.to_string()])?;
    Ok(())
}

fn request(proof: &ForegroundInputs, now: i64) -> AgentOp {
    claim(proof.turn, now, ChatOrigin::ForegroundInputs(proof.clone()))
}

#[tokio::test]
async fn mixed_foreground_matches_journal_order_with_overlapping_receipt_windows() -> Result<()> {
    let mut p = Pair::new().await;
    config::set_ordinary_babysitter_enabled(p.homes[0].path(), true)?;
    let at = now();
    let mut proof = root(3, at);
    proof.inputs[1].received_at_ms = (at - 10) * 1000;
    proof.inputs[2].received_at_ms = proof.inputs[1].received_at_ms;
    record(&p, &proof, 1)?;
    record(&p, &proof, 2)?;
    // Both deliveries fit both receipt clocks. Only claim order distinguishes them.
    for (first, second, allowed) in [(20, 30, false), (30, 30, false), (30, 20, true)] {
        for (input, age) in proof.inputs[1..].iter().zip([first, second]) {
            p.stores[0].db.execute(
                "UPDATE wake_dispatches SET claimed_at=?1, payload=json_set(payload,'$.claimed_at',?1)
                 WHERE attempt_id=?2", params![at-age,input.client.to_string()],
            )?;
        }
        assert_eq!(
            !p.agent(0, request(&proof, at))?["claim"].is_null(),
            allowed
        );
    }
    Ok(())
}

#[tokio::test]
async fn mixed_foreground_requires_every_scoped_receipt_and_rejects_ambiguous_inputs() -> Result<()>
{
    let mut p = Pair::new().await;
    config::set_ordinary_babysitter_enabled(p.homes[0].path(), true)?;
    let at = now();
    let proof = root(3, at);
    record(&p, &proof, 1)?;
    assert!(p.agent(0, request(&proof, at))?["claim"].is_null());
    record(&p, &proof, 2)?;
    for i in 0..9 {
        let mut bad = proof.clone();
        match i {
            0 => bad.inputs.swap(0, 1),
            1 => bad.inputs.swap(1, 2),
            2 => bad.inputs[2].sha256 = bad.inputs[0].sha256.clone(),
            3 => bad.inputs[2].client = bad.inputs[1].client,
            4 => bad.thread = Uuid::new_v4(),
            5 => {
                bad.inputs.pop();
            }
            6 => bad.inputs[0].received_at_ms = bad.inputs[1].received_at_ms,
            7 => bad.inputs[1].received_at_ms -= 1000,
            8 => bad.inputs[1].received_at_ms += 1000,
            _ => unreachable!(),
        }
        assert_eq!(
            p.agent(0, request(&bad, at))?,
            json!({"claim":null}),
            "control {i}"
        );
    }
    let pure = operator_inputs(
        proof.turn,
        at,
        Some(&proof.inputs[0].client.to_string()),
        &[
            &proof.inputs[1].client.to_string(),
            &proof.inputs[2].client.to_string(),
        ],
    );
    assert!(p.agent(0, pure)?["claim"].is_null());
    let attempt = serde_json::from_value(p.agent(0, request(&proof, at))?["claim"].clone())?;
    p.reopen(0);
    assert!(p.agent(0, request(&proof, at))?["claim"].is_null());
    let check = AgentOp::BabysitterChatCheck { attempt };
    assert_eq!(p.agent(0, check.clone())?["eligible"], true);
    assert_eq!(p.agent(0, check)?["eligible"], false);
    p.stores[0]
        .db
        .execute("UPDATE request_clock SET floor=?1", [at + 61])?;
    assert!(
        p.agent(
            0,
            claim(
                Uuid::now_v7(),
                at + 61,
                ChatOrigin::Continuation { attempt }
            )
        )?["claim"]
            .is_null()
    );
    let mut replay = root(2, at);
    replay.inputs[0] = proof.inputs[0].clone();
    record(&p, &replay, 1)?;
    assert!(p.agent(0, request(&replay, at))?["claim"].is_null());
    Ok(())
}

#[tokio::test]
async fn mixed_foreground_honors_bound_and_chat_opt_out_at_admission() -> Result<()> {
    let mut p = Pair::new().await;
    let at = now();
    let proof = root(MAX_CHAT_INPUTS, at);
    for i in 1..proof.inputs.len() {
        record(&p, &proof, i)?;
    }
    assert!(p.agent(0, request(&proof, at))?["claim"].is_null());
    config::set_ordinary_babysitter_enabled(p.homes[0].path(), true)?;
    let mut too_many = proof.clone();
    too_many.inputs.push(proof.inputs[1].clone());
    assert!(p.agent(0, request(&too_many, at))?["claim"].is_null());
    let attempt = serde_json::from_value(p.agent(0, request(&proof, at))?["claim"].clone())?;
    p.agent(
        0,
        AgentOp::Babysit {
            enabled: Some(false),
        },
    )?;
    p.agent(
        0,
        AgentOp::Babysit {
            enabled: Some(true),
        },
    )?;
    assert_eq!(
        p.agent(0, AgentOp::BabysitterChatCheck { attempt })?["eligible"],
        false
    );
    Ok(())
}

#[tokio::test]
async fn foreground_steers_before_a_finished_delivery_get_only_one_retry() -> Result<()> {
    let mut p = Pair::new().await;
    config::set_ordinary_babysitter_enabled(p.homes[0].path(), true)?;
    let now = now();
    // One user opener, four foreground steers, then one finished Gent delivery.
    let proof = root(6, now);
    record(&p, &proof, 5)?;
    let direct = &proof.inputs[5];
    let mut same_payload = proof.clone();
    same_payload.inputs[2].sha256.clone_from(&direct.sha256);
    assert!(p.agent(0, request(&same_payload, now))?["claim"].is_null());
    let mut ambiguous_clock = proof.clone();
    ambiguous_clock.inputs[4].received_at_ms = direct.received_at_ms;
    assert!(p.agent(0, request(&ambiguous_clock, now))?["claim"].is_null());

    // A prefix ID used by any other Gent dispatch cannot be counted as foreground.
    let mut other = root(2, now);
    other.inputs[1].client = proof.inputs[2].client;
    record(&p, &other, 1)?;
    assert!(p.agent(0, request(&proof, now))?["claim"].is_null());
    p.stores[0].db.execute(
        "DELETE FROM wake_dispatches WHERE attempt_id=?1",
        [other.inputs[1].client.to_string()],
    )?;

    let response = p.agent(0, request(&proof, now))?;
    assert!(
        response["claim"].is_string(),
        "mixed foreground claim rejected"
    );
    let attempt: Uuid = serde_json::from_value(response["claim"].clone())?;
    assert_eq!(
        p.agent(0, AgentOp::BabysitterChatCheck { attempt })?["eligible"],
        true
    );
    p.reopen(0);
    assert!(p.agent(0, request(&proof, now))?["claim"].is_null());
    p.stores[0]
        .db
        .execute("UPDATE request_clock SET floor=?1", [now + 61])?;
    assert!(
        p.agent(
            0,
            claim(
                Uuid::now_v7(),
                now + 61,
                ChatOrigin::Continuation { attempt }
            )
        )?["claim"]
            .is_null()
    );
    Ok(())
}

#[tokio::test]
async fn steers_between_confirmed_deliveries_keep_one_ordinary_retry() -> Result<()> {
    let mut p = Pair::new().await;
    config::set_ordinary_babysitter_enabled(p.homes[0].path(), true)?;
    let at = now();
    let proof = root(7, at);
    for index in [1, 4, 5, 6] {
        record(&p, &proof, index)?;
    }

    let mut ambiguous = proof.clone();
    ambiguous.inputs[2].received_at_ms = proof.inputs[1].received_at_ms;
    assert!(p.agent(0, request(&ambiguous, at))?["claim"].is_null());
    let mut copied = proof.clone();
    copied.inputs[2].sha256.clone_from(&proof.inputs[1].sha256);
    assert!(p.agent(0, request(&copied, at))?["claim"].is_null());

    let attempt = serde_json::from_value(p.agent(0, request(&proof, at))?["claim"].clone())?;
    assert_eq!(
        p.agent(0, AgentOp::BabysitterChatCheck { attempt })?["eligible"],
        true
    );
    p.reopen(0);
    assert!(p.agent(0, request(&proof, at))?["claim"].is_null());
    assert!(
        p.agent(
            0,
            claim(Uuid::now_v7(), at, ChatOrigin::Continuation { attempt })
        )?["claim"]
            .is_null()
    );
    Ok(())
}

#[tokio::test]
async fn first_wake_claim_can_share_the_user_openers_second() -> Result<()> {
    let mut p = Pair::new().await;
    config::set_ordinary_babysitter_enabled(p.homes[0].path(), true)?;
    let at = now();
    let mut proof = root(5, at);
    for (input, offset) in proof.inputs.iter_mut().zip([633, 4065, 9524, 14271, 20000]) {
        input.received_at_ms = (at - 40) * 1000 + offset;
    }
    for i in 1..proof.inputs.len() {
        record(&p, &proof, i)?;
    }
    let opener = proof.inputs[0].received_at_ms.div_euclid(1000);
    let first = proof.inputs[1].client.to_string();
    let set_claim = |p: &Pair, when: i64| {
        p.stores[0].db.execute(
            "UPDATE wake_dispatches SET claimed_at=?1, payload=json_set(payload,'$.claimed_at',?1)
         WHERE attempt_id=?2",
            params![when, first],
        )
    };
    set_claim(&p, opener - 1)?;
    assert!(p.agent(0, request(&proof, at))?["claim"].is_null());
    set_claim(&p, opener)?;
    let mut same_second = proof.clone();
    same_second.inputs[1].received_at_ms = opener * 1000 + 990;
    assert!(p.agent(0, request(&same_second, at))?["claim"].is_null());

    let attempt = serde_json::from_value(p.agent(0, request(&proof, at))?["claim"].clone())?;
    assert_eq!(
        p.agent(0, AgentOp::BabysitterChatCheck { attempt })?["eligible"],
        true
    );
    p.reopen(0);
    assert!(p.agent(0, request(&proof, at))?["claim"].is_null());
    Ok(())
}
