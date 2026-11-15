use super::*;

const WEEK: i64 = 7 * 86400;

fn status(f: &mut Fixture) -> Value {
    ok(f.owner(OwnerOp::WakeStatus))
}

fn clean(f: &mut Fixture, dry_run: bool) -> Value {
    ok(f.owner(OwnerOp::WakeClean { dry_run }))
}

fn observed(f: &mut Fixture) -> (String, AgentOp, Value) {
    let message = f.send();
    let claim = Fixture::claim(&message);
    let result = ok(f.agent(1, claim.clone()));
    ok(f.agent(1, AgentOp::Inbox));
    (message, claim, result)
}

#[test]
fn history_retirement_keeps_uncertainty_and_never_reauthorizes_old_work() {
    let mut f = Fixture::new();
    let (uncertain, uncertain_claim, uncertain_result) = observed(&mut f);
    f.advance(5);
    let (delivered, claim, result) = observed(&mut f);
    let submitted = Fixture::submitted(&delivered, &result);
    ok(f.agent(1, submitted.clone()));
    let request: String = f
        .db()
        .query_row(
            "SELECT request_id FROM messages WHERE id=?1",
            [&delivered],
            |r| r.get(0),
        )
        .unwrap();
    f.advance(5);
    let unobserved = f.send();
    let unobserved_claim = ok(f.agent(1, Fixture::claim(&unobserved)));
    ok(f.agent(1, Fixture::submitted(&unobserved, &unobserved_claim)));
    f.advance(9 * 86400);
    assert_eq!(status(&mut f)["eligible"], 0, "message is still retained");
    let preview = ok(f.owner(OwnerOp::HistoryClean { dry_run: true }));
    assert_eq!(preview["messages_removed"], 3);
    assert_eq!(f.count(), 3);
    let cleaned = ok(f.owner(OwnerOp::HistoryClean { dry_run: false }));
    assert_eq!(cleaned["messages_removed"], 3);
    assert_eq!(status(&mut f)["eligible"], 1);
    assert_eq!(clean(&mut f, false)["records_removed"], 1);
    assert_eq!(f.count(), 2);
    assert_eq!(status(&mut f)["uncertain"], 1);
    assert_eq!(status(&mut f)["submitted_without_inbox_observation"], 1);
    f.store = Store::open(f.home.path()).unwrap();
    ok(f.owner(OwnerOp::Renew));
    // The OS clock remains behind the persisted floor after reopening.
    assert!(error(f.agent(1, claim)).contains("unavailable"));
    assert!(error(f.agent(1, Fixture::claim(&delivered))).contains("unavailable"));
    assert!(error(f.agent(1, submitted)).contains("unavailable"));
    let recipient = f.agents[1].clone();
    assert!(
        error(f.agent(
            0,
            AgentOp::Send {
                recipient,
                request_id: request,
                text: "private request content".into(),
                files: vec![],
                file_ids: vec![],
            }
        ))
        .contains("expired")
    );
    assert_eq!(ok(f.agent(1, uncertain_claim))["may_submit"], false);
    assert_eq!(f.show(&uncertain)["state"], "uncertain");
    // A late native receipt is evidence, not a new dispatch. Retain it for a
    // full week from this update, even though its message has already retired.
    ok(f.agent(1, Fixture::submitted(&uncertain, &uncertain_result)));
    assert_eq!(clean(&mut f, false)["records_removed"], 0);
    f.advance(WEEK - 1);
    assert_eq!(clean(&mut f, true)["records_removed"], 0);
    f.advance(1);
    assert_eq!(clean(&mut f, true)["records_removed"], 1);
    assert_eq!(f.count(), 2);
    assert_eq!(clean(&mut f, false)["records_removed"], 1);
    assert_eq!(f.show(&unobserved)["inbox_seen_at"], Value::Null);
}

// Seed already-retired records to exercise storage boundaries without thousands
// of synthetic messages. Live claims and history retirement are covered above.
fn retired(f: &mut Fixture, count: usize) -> Vec<String> {
    let (message, _, result) = observed(f);
    ok(f.agent(1, Fixture::submitted(&message, &result)));
    let template = f.show(&message);
    f.advance(9 * 86400);
    ok(f.owner(OwnerOp::HistoryClean { dry_run: false }));
    assert_eq!(clean(f, false)["records_removed"], 1);
    assert_eq!(f.count(), 0);
    let mut db = f.db();
    let tx = db.transaction().unwrap();
    let mut ids = Vec::new();
    for _ in 0..count {
        let mut record = template.clone();
        let id = Uuid::new_v4().to_string();
        record["message_id"] = id.clone().into();
        record["attempt_id"] = Uuid::new_v4().to_string().into();
        tx.execute(
            "INSERT INTO wake_dispatches VALUES(?1,?2,?3,?4,?5)",
            params![
                id,
                record["agent"].as_str().unwrap(),
                record["attempt_id"].as_str().unwrap(),
                record["claimed_at"].as_i64().unwrap(),
                record.to_string(),
            ],
        )
        .unwrap();
        ids.push(id);
    }
    tx.commit().unwrap();
    ids.sort();
    ids
}

#[test]
fn cleanup_is_bounded_and_maintenance_finishes_the_next_batch() {
    let mut f = Fixture::new();
    retired(&mut f, 130);
    let before = status(&mut f);
    assert_eq!(before["eligible"], 130);
    assert_eq!(before["available_records"], 16_384 - 130);
    let preview = clean(&mut f, true);
    assert_eq!(preview["records_removed"], 128);
    assert_eq!(preview["more_due"], 2);
    assert_eq!(status(&mut f), before);
    let actual = clean(&mut f, false);
    assert_eq!(actual["records_removed"], 128);
    assert_eq!(actual["more_due"], 2);
    f.store = Store::open(f.home.path()).unwrap();
    f.store.maintain().unwrap();
    assert_eq!(f.count(), 0);
}

#[test]
fn legacy_admission_must_close_even_when_all_other_conditions_hold() {
    let mut f = Fixture::new();
    retired(&mut f, 1);
    f.db()
        .execute("UPDATE request_clock SET legacy_until=floor+1", [])
        .unwrap();
    assert_eq!(status(&mut f)["eligible"], 0);
    assert_eq!(clean(&mut f, false)["records_removed"], 0);
    f.advance(1);
    assert_eq!(clean(&mut f, false)["records_removed"], 1);
}

#[test]
fn corruption_and_delete_failure_preserve_the_entire_cleanup_transaction() {
    let mut f = Fixture::new();
    let ids = retired(&mut f, 3);
    let saved = f.show(&ids[2]);
    // Valid JSON and a plausible state cannot hide inconsistent evidence.
    f.db().execute("UPDATE wake_dispatches SET payload=json_set(payload,'$.submission_id',NULL) WHERE message_id=?1", [&ids[2]]).unwrap();
    assert!(error(f.owner(OwnerOp::WakeStatus)).contains("inconsistent"));
    for dry_run in [true, false] {
        assert!(error(f.owner(OwnerOp::WakeClean { dry_run })).contains("inconsistent"));
        assert_eq!(f.count(), 3);
    }
    f.db()
        .execute(
            "UPDATE wake_dispatches SET payload=?1 WHERE message_id=?2",
            params![saved.to_string(), ids[2]],
        )
        .unwrap();
    f.db()
        .execute_batch(
            "CREATE TRIGGER reject_second_delete BEFORE DELETE ON wake_dispatches
        WHEN (SELECT COUNT(*) FROM wake_dispatches)=2
        BEGIN SELECT RAISE(ABORT,'injected delete failure'); END;",
        )
        .unwrap();
    assert!(error(f.owner(OwnerOp::WakeClean { dry_run: false })).contains("injected delete"));
    assert_eq!(f.count(), 3, "first deletion must roll back");
    f.db()
        .execute_batch("DROP TRIGGER reject_second_delete")
        .unwrap();
    assert_eq!(clean(&mut f, false)["records_removed"], 3);
}

#[test]
fn cleanup_cannot_refund_recent_claim_budgets() {
    let mut f = Fixture::new();
    let (message, _, result) = observed(&mut f);
    ok(f.agent(1, Fixture::submitted(&message, &result)));
    assert_eq!(clean(&mut f, false)["records_removed"], 0);
    let next = f.send();
    assert!(error(f.agent(1, Fixture::claim(&next))).contains("budget"));
    assert_eq!(f.count(), 1);
}
