use super::*;

struct Direct {
    message: String,
    attempt: String,
    target: WakeTarget,
    turn: String,
}
impl Direct {
    fn claim(&self) -> AgentOp {
        AgentOp::WakeDirectClaim {
            message_id: self.message.clone(),
            attempt_id: self.attempt.clone(),
            target: self.target.clone(),
        }
    }
    fn read(&self) -> AgentOp {
        AgentOp::WakeDirectRead {
            message_id: self.message.clone(),
            attempt_id: self.attempt.clone(),
            target: self.target.clone(),
        }
    }
    fn observe(&self) -> AgentOp {
        AgentOp::WakeDirectObserve {
            message_id: self.message.clone(),
            attempt_id: self.attempt.clone(),
            target: self.target.clone(),
            turn_id: self.turn.clone(),
        }
    }
    fn complete(&self, text: &str) -> AgentOp {
        AgentOp::WakeDirectComplete {
            message_id: self.message.clone(),
            attempt_id: self.attempt.clone(),
            target: self.target.clone(),
            turn_id: self.turn.clone(),
            text: text.into(),
        }
    }
    fn pending(&self) -> AgentOp {
        AgentOp::WakeDirectPending {
            target: self.target.clone(),
        }
    }
}
fn relay(f: &mut Fixture, files: Vec<FilePart>) -> Direct {
    let attachment = ok(f.agent(
        0,
        AgentOp::RelayAttach {
            target: f.agents[1].clone(),
            request_id: Uuid::now_v7().to_string(),
        },
    ));
    let message = ok(f.agent(
        0,
        AgentOp::RelaySend {
            attachment_id: attachment["attachment"]["id"].as_str().unwrap().into(),
            request_id: Uuid::now_v7().to_string(),
            text: "Please review the tone.".into(),
            files,
            file_ids: vec![],
        },
    ))["message_id"]
        .as_str()
        .unwrap()
        .into();
    Direct {
        message,
        attempt: Uuid::new_v4().to_string(),
        target: WakeTarget::Codex {
            thread_id: Uuid::now_v7().to_string(),
        },
        turn: Uuid::now_v7().to_string(),
    }
}

#[test]
fn direct_relay_routes_one_normal_native_answer_across_restart() {
    let mut f = Fixture::new();
    let d = relay(&mut f, vec![]);
    let first = ok(f.agent(1, d.claim()));
    assert_eq!(first["may_submit"], true);
    assert_eq!(first["delivery"]["automatic_reply"], true);
    let delivery: gent_protocol::wake::WakeDelivery =
        serde_json::from_value(first["delivery"].clone()).unwrap();
    assert!(delivery.prompt().ends_with("Please review the tone."));
    assert!(!delivery.prompt().contains("gent_inbox"));
    assert_eq!(ok(f.agent(1, d.claim()))["may_submit"], false);
    assert!(error(f.agent(1, d.complete("too soon"))).contains("another native turn"));
    assert_eq!(ok(f.agent(1, d.read()))["eligible"], true);
    ok(f.agent(1, d.observe()));
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(
        ok(f.agent(1, d.pending()))["pending"][0]["record"]["direct"]["turn_id"],
        d.turn
    );
    ok(f.agent(1, d.observe()));
    assert!(error(f.agent(2, d.observe())).contains("unavailable"));
    let original = ok(f.agent(1, d.complete("The tone is consistent.")));
    f.store = Store::open(f.home.path()).unwrap();
    let repeated = ok(f.agent(1, d.complete("The tone is consistent.")));
    assert_eq!(repeated["message_id"], original["message_id"]);
    assert_eq!(repeated["duplicate"], true);
    assert!(error(f.agent(1, d.complete("changed answer"))).contains("changed on retry"));
    let inbox = ok(f.agent(0, AgentOp::Inbox));
    assert_eq!(inbox.as_array().unwrap().len(), 1);
    assert_eq!(inbox[0]["text"], "The tone is consistent.");
    assert_eq!(inbox[0]["relay"]["kind"], "complete");
    assert!(
        ok(f.agent(1, d.pending()))["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn native_response_is_atomic_and_does_not_duplicate_manual_completion() {
    for manual in [false, true] {
        let mut f = Fixture::new();
        let d = relay(&mut f, vec![]);
        ok(f.agent(1, d.claim()));
        ok(f.agent(1, d.observe()));
        if manual {
            ok(f.agent(
                1,
                AgentOp::RelayRespond {
                    turn_id: d.message.clone(),
                    request_id: Uuid::now_v7().to_string(),
                    text: "manual file response".into(),
                    files: vec![],
                    file_ids: vec![],
                    outcome: RelayResponseKind::Complete,
                },
            ));
        } else {
            f.db().execute_batch("CREATE TRIGGER fail_direct_finish BEFORE UPDATE ON wake_dispatches WHEN json_extract(NEW.payload,'$.direct.finished')=1 BEGIN SELECT RAISE(FAIL,'injected'); END;").unwrap();
            assert!(error(f.agent(1, d.complete("normal response"))).contains("injected"));
            assert!(
                ok(f.agent(0, AgentOp::Inbox))
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            f.db()
                .execute_batch("DROP TRIGGER fail_direct_finish")
                .unwrap();
        }
        ok(f.agent(1, d.complete("normal response")));
        let inbox = ok(f.agent(0, AgentOp::Inbox));
        assert_eq!(inbox.as_array().unwrap().len(), 1);
        assert_eq!(
            inbox[0]["text"],
            if manual {
                "manual file response"
            } else {
                "normal response"
            }
        );
    }
}

#[test]
fn direct_content_and_responses_recheck_permissions_and_native_binding() {
    let mut f = Fixture::new();
    let mut d = relay(&mut f, vec![]);
    ok(f.agent(1, d.claim()));
    let host = d.target.clone();
    d.target = WakeTarget::ClaudeCode {
        session_id: Uuid::new_v4().to_string(),
    };
    assert!(error(f.agent(1, d.observe())).contains("unavailable"));
    d.target = host;
    ok(f.agent(1, d.observe()));
    let turn = d.turn.clone();
    d.turn = Uuid::now_v7().to_string();
    assert!(error(f.agent(1, d.observe())).contains("native turn changed"));
    assert!(error(f.agent(1, d.complete("wrong"))).contains("another native turn"));
    d.turn = turn;
    ok(f.owner(OwnerOp::SetPolicy {
        policy: Policy {
            rules: vec![Rule {
                actor: Selector::All,
                peer: Selector::All,
                permission: Permission::Receive,
                effect: Effect::Deny,
            }],
            ..Default::default()
        },
    }));
    assert_eq!(ok(f.agent(1, d.read()))["eligible"], false);
    assert!(
        ok(f.agent(1, d.pending()))["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(error(f.agent(1, d.complete("blocked"))).contains("unavailable"));
    ok(f.owner(OwnerOp::SetPolicy {
        policy: Policy {
            rules: [Permission::Enumerate, Permission::Send, Permission::Receive]
                .map(|permission| Rule {
                    actor: Selector::All,
                    peer: Selector::All,
                    permission,
                    effect: Effect::Allow,
                })
                .into(),
            ..Default::default()
        },
    }));
    ok(f.agent(1, d.complete("restored")));
}

#[test]
fn inline_files_remain_readable_until_relay_completion() {
    let mut f = Fixture::new();
    let d = relay(
        &mut f,
        vec![FilePart {
            name: "file.txt".into(),
            media_type: "text/plain".into(),
            data_base64: "aGk=".into(),
        }],
    );
    let claim = ok(f.agent(1, d.claim()));
    assert_eq!(claim["delivery"]["message"]["files"][0]["data_base64"], "");
    ok(f.agent(1, d.observe()));
    assert_eq!(
        ok(f.agent(1, AgentOp::Inbox))[0]["files"][0]["data_base64"],
        "aGk="
    );
    ok(f.agent(1, d.complete("read it")));
    assert!(
        ok(f.agent(1, AgentOp::Inbox))
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn cancelled_turn_finishes_once_and_its_response_does_not_reply_again() {
    let mut f = Fixture::new();
    let d = relay(&mut f, vec![]);
    ok(f.agent(1, d.claim()));
    ok(f.agent(1, d.observe()));
    ok(f.agent(
        0,
        AgentOp::RelayCancel {
            turn_id: d.message.clone(),
            request_id: Uuid::now_v7().to_string(),
        },
    ));
    ok(f.agent(1, d.complete("Stopped at the user's request.")));
    let reply = ok(f.agent(0, AgentOp::Inbox));
    assert_eq!(reply[0]["relay"]["kind"], "cancelled");
    let r = Direct {
        message: reply[0]["id"].as_str().unwrap().into(),
        attempt: Uuid::new_v4().to_string(),
        target: WakeTarget::Codex {
            thread_id: Uuid::now_v7().to_string(),
        },
        turn: Uuid::now_v7().to_string(),
    };
    let claim = ok(f.agent(0, r.claim()));
    assert_eq!(claim["delivery"]["automatic_reply"], false);
    ok(f.agent(0, r.observe()));
    assert_eq!(f.show(&r.message)["direct"]["finished"], true);
    ok(f.agent(0, r.complete("must not send back")));
    assert!(
        ok(f.agent(1, AgentOp::Inbox))
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn direct_dispatch_does_not_repeat_recorded_work_or_bypass_expiry() {
    let mut f = Fixture::new();
    let d = relay(&mut f, vec![]);
    ok(f.agent(
        1,
        AgentOp::WorkBegin {
            message_id: d.message.clone(),
            expect_revision: 0,
            description: "already started".into(),
        },
    ));
    assert!(error(f.agent(1, d.claim())).contains("recorded work"));
    assert_eq!(f.count(), 0);
    let mut f = Fixture::new();
    let d = relay(&mut f, vec![]);
    ok(f.agent(1, d.claim()));
    ok(f.agent(1, d.observe()));
    f.db()
        .execute(
            "UPDATE messages SET payload=json_set(payload,'$.expires_at',0) WHERE id=?1",
            [&d.message],
        )
        .unwrap();
    assert!(
        ok(f.agent(1, d.pending()))["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(error(f.agent(1, d.complete("late response"))).contains("unavailable"));
}

#[test]
fn rename_keeps_original_input_hash_for_native_recovery() {
    let mut f = Fixture::new();
    let d = relay(&mut f, vec![]);
    let first = ok(f.agent(1, d.claim()));
    let identity = ok(f.agent(0, AgentOp::Identity));
    ok(f.agent(
        0,
        AgentOp::Rename {
            name: "new label".into(),
            expected_generation: identity["registration_generation"].as_u64().unwrap(),
        },
    ));
    let pending = ok(f.agent(1, d.pending()));
    assert_eq!(
        pending["pending"][0]["record"]["direct"]["input_hash"],
        first["record"]["direct"]["input_hash"]
    );
    // A not-yet-submitted snapshot is no longer current; it must not be rewritten.
    assert_eq!(ok(f.agent(1, d.read()))["eligible"], false);
    // An input already in the native queue still has the original immutable hash.
    ok(f.agent(1, d.observe()));
    ok(f.agent(1, d.complete("same request")));
}

#[test]
fn manual_inbox_intake_stops_native_history_scans_without_reauthorizing_submission() {
    let mut f = Fixture::new();
    let d = Direct {
        message: f.send(),
        attempt: Uuid::new_v4().to_string(),
        target: WakeTarget::Codex {
            thread_id: Uuid::now_v7().to_string(),
        },
        turn: Uuid::now_v7().to_string(),
    };
    let identity = ok(f.agent(1, AgentOp::Identity));
    assert_eq!(identity["inbox_delivery"]["waiting_for_host"], 1);
    let claim = ok(f.agent(1, d.claim()));
    assert_eq!(
        ok(f.agent(1, d.pending()))["pending"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        ok(f.agent(1, AgentOp::Identity))["inbox_delivery"]["latest"]["delivery_status"],
        "submission_uncertain"
    );
    ok(f.agent(1, Fixture::submitted(&d.message, &claim)));
    assert_eq!(
        ok(f.agent(1, AgentOp::Identity))["inbox_delivery"]["latest"]["delivery_status"],
        "submitted_not_seen"
    );
    ok(f.agent(1, AgentOp::Inbox));
    assert_eq!(
        ok(f.agent(1, AgentOp::Identity))["inbox_delivery"]["latest"]["delivery_status"],
        "seen"
    );
    assert!(
        ok(f.agent(1, d.pending()))["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(ok(f.agent(1, d.claim()))["may_submit"], false);
    assert!(f.show(&d.message)["direct"]["turn_id"].is_null());
}

#[test]
fn retrospective_receipt_requires_one_finished_dispatch_to_the_bound_codex_turn() {
    let mut f = Fixture::new();
    let d = relay(&mut f, vec![]);
    let WakeTarget::Codex { thread_id } = &d.target else {
        unreachable!()
    };
    let thread = Uuid::parse_str(thread_id).unwrap();
    let turn = Uuid::parse_str(&d.turn).unwrap();
    let lookup = |credential: &str, thread_id, turn| OwnerOp::WakeDirectTurnEvidence {
        agent_credential: credential.into(),
        thread_id,
        turn,
    };
    let op = lookup(&f.keys[1], thread, turn);
    let first = ok(f.agent(1, d.claim()));
    assert!(ok(f.owner(op.clone())).is_null());
    ok(f.agent(
        1,
        AgentOp::WakeSubmitted {
            message_id: d.message.clone(),
            attempt_id: d.attempt.clone(),
            submission_id: d.turn.clone(),
        },
    ));
    ok(f.agent(1, d.observe()));
    assert!(
        ok(f.owner(op.clone())).is_null(),
        "relay has no final receipt"
    );
    ok(f.agent(1, d.complete("private native reply")));
    f.store = Store::open(f.home.path()).unwrap();
    let expected = serde_json::json!({
        "attempt_id": d.attempt, "input_hash": first["record"]["direct"]["input_hash"],
    });
    assert_eq!(ok(f.owner(op.clone())), expected);
    for wrong in [
        lookup(&f.keys[0], thread, turn),
        lookup(&f.keys[1], Uuid::new_v4(), turn),
        lookup(&f.keys[1], thread, Uuid::new_v4()),
    ] {
        assert!(ok(f.owner(wrong)).is_null());
    }
    let bad_owner = f.store.handle(Request::Owner {
        credential: f.keys[1].clone(),
        action: op.clone(),
    });
    assert!(error(bad_owner).contains("unauthorized"));
    assert!(serde_json::from_value::<AgentOp>(serde_json::to_value(&op).unwrap()).is_err());

    // Even a retained final receipt cannot reconcile conflicting host IDs,
    // another adapter, or a missing observation.
    let original = f.show(&d.message);
    for (field, value) in [
        ("submission_id", serde_json::json!(Uuid::new_v4())),
        (
            "target",
            serde_json::json!({"host":"claude_code", "session_id": thread}),
        ),
        ("inbox_seen_at", Value::Null),
        ("updated_at", serde_json::json!(i64::MAX)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        f.db()
            .execute(
                "UPDATE wake_dispatches SET payload=?1 WHERE message_id=?2",
                params![changed.to_string(), d.message],
            )
            .unwrap();
        assert!(ok(f.owner(op.clone())).is_null(), "{field}");
    }
    f.db()
        .execute(
            "UPDATE wake_dispatches SET payload=?1 WHERE message_id=?2",
            params![original.to_string(), d.message],
        )
        .unwrap();

    // A second observed input makes this native turn ambiguous, even if only
    // the first relay has finished. Removing a receipt never synthesizes proof.
    f.advance(6);
    let mut other = relay(&mut f, vec![]);
    other.target = d.target.clone();
    other.turn.clone_from(&d.turn);
    ok(f.agent(1, other.claim()));
    ok(f.agent(
        1,
        AgentOp::WakeSubmitted {
            message_id: other.message.clone(),
            attempt_id: other.attempt.clone(),
            submission_id: other.turn.clone(),
        },
    ));
    assert!(ok(f.owner(op.clone())).is_null());
    ok(f.agent(1, other.observe()));
    assert!(ok(f.owner(op.clone())).is_null());
    f.db()
        .execute(
            "DELETE FROM wake_dispatches WHERE message_id=?1",
            [&other.message],
        )
        .unwrap();
    assert_eq!(ok(f.owner(op.clone())), expected);
    f.db()
        .execute(
            "DELETE FROM wake_dispatches WHERE message_id=?1",
            [&d.message],
        )
        .unwrap();
    assert!(ok(f.owner(op)).is_null());
}
