use super::*;
use std::io::Write;

#[test]
fn automatic_steers_require_all_scoped_sources_and_the_immediate_parent() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let thread = Uuid::new_v4().to_string();
    let turn = Uuid::new_v4();
    let root = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let f = Failed {
        thread: thread.clone(),
        turn,
        root,
        path: dir.path().join(format!("rollout-test-{thread}.jsonl")),
        started: 100,
        ended: 1649,
        error: "fixture".into(),
        reason: Failure::RequestPayload,
        goal: Value::Null,
        legacy_history: false,
        handoff_parent: true,
    };
    let event = |p: Value| json!({"type":"event_msg","payload":p});
    let source = |id: &str| {
        json!({"type":"response_item","payload":{"type":"message","role":"user","id":id,
        "internal_chat_message_metadata_passthrough":{"turn_id":turn,"content_item_kinds":["user.text"],
        "content_item_metadata":[{"provenance":{"type":"user"}}]}}})
    };
    let receipt = |id: &str, client: &str| {
        event(
            json!({"type":"item_completed","thread_id":thread,"turn_id":turn,
        "item":{"type":"UserMessage","id":id,"client_id":client}}),
        )
    };
    let settings = event(json!({"type":"thread_settings_applied","thread_id":thread}));
    let rows = vec![
        json!({"type":"session_meta","payload":{"id":thread}}),
        event(
            json!({"type":"task_complete","turn_id":root,"completed_at":96,"error":{"message":"parent"}}),
        ),
        event(
            json!({"type":"task_started","turn_id":turn,"started_at":100,
            "turn_attribution":{"turn_trigger":TRIGGER,"turn_id":turn,"parent_turn_id":root,"root_turn_id":root}}),
        ),
        source("original-message"),
        receipt("original", &attempt.to_string()),
        settings.clone(),
        source("steer-message"),
        receipt("steer", "fresh"),
        event(
            json!({"type":"task_complete","turn_id":turn,"started_at":100,"completed_at":1649,"error":{"message":"fixture"}}),
        ),
    ];
    let observe = |rows: &[Value]| -> Result<Option<ChatOrigin>> {
        let mut file = File::create(&f.path)?;
        for row in rows {
            writeln!(file, "{row}")?;
        }
        Ok(read(&f)?.map(|(origin, _, _)| origin))
    };
    assert_eq!(
        observe(&rows)?,
        Some(ChatOrigin::SteeredContinuation {
            attempt,
            root,
            parent: root,
            started_at: 100,
            parent_failed_at: 96,
            additional_client_ids: vec!["fresh".into()]
        })
    );
    for (i, path, value) in [
        (1, "/turn_id", json!(turn)),
        (1, "/error", Value::Null),
        (2, "/turn_attribution/parent_turn_id", json!(Uuid::new_v4())),
        (
            3,
            "/internal_chat_message_metadata_passthrough/turn_id",
            json!(root),
        ),
        (4, "/item/client_id", json!("unadmitted")),
        (6, "/id", json!("original-message")),
        (
            6,
            "/internal_chat_message_metadata_passthrough/content_item_metadata/0/provenance/type",
            json!("harness"),
        ),
        (7, "/turn_id", json!(root)),
        (7, "/thread_id", json!("foreign")),
        (7, "/item/id", json!("original")),
        (7, "/item/client_id", Value::Null),
    ] {
        let mut bad = rows.clone();
        *bad[i]["payload"].pointer_mut(path).unwrap() = value;
        assert!(observe(&bad)?.is_none(), "row {i} {path}");
    }
    for (i, row) in [
        (2, settings.clone()),
        (9, settings),
        (
            6,
            event(json!({"type":"user_message","client_id":"unscoped"})),
        ),
        (6, source("unpaired")),
        (7, source("unpaired")),
        (6, event(json!({"type":"thread_goal_cleared"}))),
        (6, event(json!({"type":"turn_aborted","turn_id":turn}))),
        (9, receipt("manual", "later")),
    ] {
        let mut bad = rows.clone();
        bad.insert(i, row);
        assert!(observe(&bad)?.is_none(), "offset {i}");
    }
    let mut old = rows;
    old.drain(6..8);
    old[3]["payload"]["internal_chat_message_metadata_passthrough"] =
        json!({"content_item_metadata":false});
    assert_eq!(observe(&old)?, Some(ChatOrigin::Continuation { attempt }));
    Ok(())
}
