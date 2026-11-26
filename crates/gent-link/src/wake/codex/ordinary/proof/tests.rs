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
        previous_turns: Vec::new(),
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
        Ok(read(&f, false)?.map(|(origin, _, _)| origin))
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
    let mut with_parent_receipt = rows.clone();
    with_parent_receipt.insert(
        2,
        event(
            json!({"type":"item_completed","thread_id":thread,"turn_id":root,
        "item":{"type":"CommandExecution","id":"late-parent","status":"failed"}}),
        ),
    );
    assert_eq!(observe(&with_parent_receipt)?, observe(&rows)?);
    with_parent_receipt[2]["payload"]["turn_id"] = json!(turn);
    assert!(observe(&with_parent_receipt)?.is_none());
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

#[test]
fn mixed_foreground_binds_the_first_admission_and_every_ordered_text_receipt() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let thread = Uuid::now_v7().to_string();
    let turn = Uuid::now_v7();
    let failed = Failed {
        path: dir.path().join(format!("rollout-fixture-{thread}.jsonl")),
        thread: thread.clone(),
        root: turn,
        turn,
        started: 100,
        ended: 110,
        reason: Failure::ToolSchema,
        error: "fixture".into(),
        goal: Value::Null,
        previous_turns: Vec::new(),
        legacy_history: false,
        handoff_parent: true,
    };
    let clients = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    let mut rows = vec![
        json!({"type":"session_meta","payload":{"id":thread,"history_mode":"paginated"}}),
        json!({"type":"event_msg","payload":{"type":"task_started","started_at":100,"turn_id":turn,
            "root_turn_id":turn,"turn_attribution":{"turn_id":turn,"root_turn_id":turn,"turn_trigger":"user"}}}),
        json!({"type":"turn_context","payload":{"turn_id":turn,"root_turn_id":turn}}),
    ];
    for (i, client) in clients.iter().enumerate() {
        rows.push(json!({"type":"response_item","payload":{"type":"message","role":"user","id":format!("message-{i}"),
            "content":[{"type":"input_text","text":format!("input {i}")}],
            "internal_chat_message_metadata_passthrough":{"turn_id":turn,"content_item_kinds":["user.text"],
            "content_item_metadata":[{"provenance":{"type":"user"}}]}}}));
        rows.push(json!({"type":"event_msg","timestamp":format!("1970-01-01T00:01:4{i}.012Z"),"payload":{
            "type":"item_completed","thread_id":thread,"turn_id":turn,"item":{"type":"UserMessage","id":format!("receipt-{i}"),
            "client_id":client,"content":[{"type":"text","text":format!("input {i}")}]}}}));
    }
    rows.push(
        json!({"type":"event_msg","payload":{"type":"task_complete","turn_id":turn,
        "started_at":100,"completed_at":110,"error":{"message":"fixture"}}}),
    );
    let observe = |rows: &[Value]| -> Result<Option<ChatOrigin>> {
        let mut f = File::create(&failed.path)?;
        for row in rows {
            writeln!(f, "{row}")?;
        }
        Ok(read(&failed, false)?.map(|(origin, _, _)| origin))
    };
    let Some(ChatOrigin::ForegroundInputs(proof)) = observe(&rows)? else {
        panic!("missing scoped proof")
    };
    assert_eq!(
        proof.inputs.iter().map(|i| i.client).collect::<Vec<_>>(),
        clients
    );
    assert_eq!(proof.inputs[1].received_at_ms, 101012);
    for (i, field, val) in [
        (1, "/payload/turn_attribution/turn_trigger", json!(TRIGGER)),
        (2, "/payload/root_turn_id", json!(Uuid::new_v4())),
        (
            3,
            "/payload/internal_chat_message_metadata_passthrough/turn_id",
            json!(Uuid::new_v4()),
        ),
        (
            5,
            "/payload/internal_chat_message_metadata_passthrough/content_item_metadata/0/provenance/type",
            json!("harness"),
        ),
        (6, "/payload/item/content/0/text", json!("changed")),
        (7, "/payload/id", json!("message-1")),
        (8, "/payload/thread_id", json!(Uuid::new_v4())),
        (8, "/timestamp", json!("invalid")),
    ] {
        let mut changed = rows.clone();
        *changed[i].pointer_mut(field).unwrap() = val;
        assert!(
            !matches!(observe(&changed)?, Some(ChatOrigin::ForegroundInputs(_))),
            "{field}"
        );
    }
    for at in [2, 4, 5, rows.len()] {
        let mut changed = rows.clone();
        changed.insert(at, rows[3].clone());
        assert!(
            !matches!(observe(&changed)?, Some(ChatOrigin::ForegroundInputs(_))),
            "unpaired input at {at}"
        );
    }
    let mut stopped = rows.clone();
    stopped.insert(
        7,
        json!({"type":"event_msg","payload":{"type":"turn_aborted","turn_id":turn}}),
    );
    assert!(observe(&stopped)?.is_none());
    Ok(())
}

#[test]
fn mixed_goal_foreground_work_yields_to_native_decisions_and_thread_messages() -> Result<()> {
    let allows = |payload: Value| {
        babysit::rollout::ordinary_work(
            &serde_json::to_vec(&json!({"type":"event_msg","payload":payload}))?,
            "thread",
            "turn",
        )
    };
    assert!(allows(
        json!({"type":"item_completed","thread_id":"thread","turn_id":"turn",
        "item":{"type":"Reasoning"}})
    )?);
    for payload in [
        json!({"type":"function_call","name":"functions.update_goal"}),
        json!({"type":"reasoning","internal_chat_message_metadata_passthrough":{
            "executed_tool_calls":[{"name":"request_user_input"}]}}),
        json!({"type":"item_completed","item":{"type":"RequestUserInput","questions":[]}}),
        json!({"type":"item_completed","item":{"type":"McpToolCall","tool":"create_goal"}}),
        json!({"type":"item_completed","item":{"type":"FunctionCallOutput",
            "namespace":"codex_tui","name":"send_message_to_thread"}}),
        json!({"type":"task_started","thread_id":"other"}),
    ] {
        assert!(!allows(payload)?);
    }
    Ok(())
}
