use super::*;

struct Fixture {
    _dir: tempfile::TempDir,
    failed: Failed,
    item: Uuid,
    rows: Vec<Value>,
}

impl Fixture {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let thread = Uuid::now_v7().to_string();
        let turn = Uuid::now_v7();
        let item = Uuid::now_v7();
        let path = dir.path().join(format!("rollout-test-{thread}.jsonl"));
        let failed = Failed::from_head(
            &thread,
            path,
            &json!({
                "id":turn,"rootTurnId":turn,"startedAt":2,"completedAt":5,"status":"failed",
                "error":{"message":"Model at capacity","codexErrorInfo":"serverOverloaded"}
            }),
            0..=6,
            Value::Null,
            false,
            true,
        )
        .unwrap();
        let ingress = json!({"type":"function_call_output","namespace":"codex_tui",
            "name":"send_message_to_thread","id":format!("fco_{item}"),
            "internal_chat_message_metadata_passthrough":{"turn_id":turn}});
        let receipt = json!({"type":"FunctionCallOutput","id":ingress["id"],
            "name":ingress["name"],"namespace":ingress["namespace"]});
        let rows = vec![
            json!({"type":"session_meta","payload":{"id":thread,"history_mode":"paginated"}}),
            json!({"type":"event_msg","payload":{"type":"task_started","started_at":2,
            "turn_id":turn,"turn_attribution":{"turn_id":turn,"root_turn_id":turn}}}),
            json!({"type":"turn_context","payload":{"turn_id":turn,"root_turn_id":turn}}),
            json!({"type":"response_item","payload":ingress}),
            json!({"type":"event_msg","payload":{"type":"item_completed",
            "turn_id":turn,"thread_id":thread,"item":receipt}}),
            json!({"type":"event_msg","payload":{"type":"task_complete","started_at":2,
            "completed_at":5,"turn_id":turn,"error":{"message":failed.error}}}),
        ];
        Ok(Self {
            _dir: dir,
            failed,
            item,
            rows,
        })
    }

    fn origin(&self, rows: &[Value]) -> Result<Option<ChatOrigin>> {
        use std::io::Write;
        let mut f = File::create(&self.failed.path)?;
        for row in rows {
            writeln!(f, "{row}")?;
        }
        Ok(read(&self.failed)?.map(|(o, _, _)| o))
    }
}

#[test]
fn named_pair_requires_the_first_admission_and_uninterrupted_work() -> Result<()> {
    let f = Fixture::new()?;
    assert_eq!(
        f.origin(&f.rows)?,
        Some(ChatOrigin::ThreadHandoff {
            item: f.item,
            started_at: 2
        })
    );
    let mut tail = f.rows.clone();
    tail.push(json!({"type":"event_msg","payload":{"type":"item_completed","turn_id":f.failed.turn,
        "thread_id":f.failed.thread,"item":{"type":"CommandExecution","id":"cmd","status":"failed","source":"unified_exec_startup"}}}));
    assert_eq!(f.origin(&tail)?, f.origin(&f.rows)?);
    tail.last_mut().unwrap()["payload"]["item"]["source"] = json!("user_shell");
    assert_eq!(f.origin(&tail)?, None);
    for (i, pointer, v) in [
        (1, "/payload/turn_attribution/turn_trigger", json!("goal")),
        (2, "/payload/turn_id", json!(Uuid::now_v7())),
        (3, "/payload/type", json!("function_call")),
        (3, "/payload/call_id", json!("invoked")),
        (
            3,
            "/payload/internal_chat_message_metadata_passthrough/turn_id",
            json!(Uuid::now_v7()),
        ),
        (4, "/payload/thread_id", json!(Uuid::now_v7())),
        (4, "/payload/item/name", json!("another_tool")),
        (
            4,
            "/payload/item/id",
            json!(format!("fco_{}", Uuid::now_v7())),
        ),
    ] {
        let mut rows = f.rows.clone();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        rows[i].pointer_mut(parent).unwrap()[key] = v;
        assert_eq!(f.origin(&rows)?, None, "{i} {pointer}");
    }
    let mut later = f.rows.clone();
    later.insert(
        3,
        json!({"type":"response_item","payload":{"type":"reasoning"}}),
    );
    assert_eq!(f.origin(&later)?, None);
    for extra in [
        f.rows[4].clone(),
        json!({"type":"event_msg","payload":{"type":"turn_aborted"}}),
        json!({"type":"event_msg","payload":{"type":"thread_settings_applied"}}),
        json!({"type":"response_item","payload":{"type":"function_call","name":"request_user_input","call_id":"call"}}),
        json!({"type":"response_item","payload":{"type":"message","role":"assistant",
            "internal_chat_message_metadata_passthrough":{"executed_tool_calls":[{"name":"functions.update_goal"}]}}}),
        json!({"type":"event_msg","payload":{"type":"item_completed","turn_id":f.failed.turn,
            "thread_id":f.failed.thread,"item":{"type":"CommandExecution","id":"cmd","status":"completed","source":"user_shell"}}}),
    ] {
        for index in [5, 6] {
            let mut rows = f.rows.clone();
            rows.insert(index, extra.clone());
            assert_eq!(f.origin(&rows)?, None, "{extra} at {index}");
        }
    }
    Ok(())
}

#[test]
fn proven_human_inputs_take_precedence_with_complete_or_inconclusive_named_items() -> Result<()> {
    let f = Fixture::new()?;
    for trigger in [Value::Null, json!("user"), json!("composer")] {
        for paired in [true, false] {
            let mut rows = f.rows.clone();
            rows[1]["payload"]["turn_attribution"]["turn_trigger"] = trigger.clone();
            if !paired {
                rows.remove(3);
            }
            let user = |id| {
                json!({"type":"event_msg","payload":{"type":"item_completed",
                "turn_id":f.failed.turn,"thread_id":f.failed.thread,
                "item":{"type":"UserMessage","id":format!("item-{id}"),"client_id":id}}})
            };
            rows.insert(3, user("first"));
            let mut additional_client_ids = Vec::new();
            if !trigger.is_null() {
                rows.insert(rows.len() - 1, user("steer"));
                additional_client_ids.push("steer".to_owned());
            }
            assert_eq!(
                f.origin(&rows)?,
                Some(ChatOrigin::Operator {
                    turn: f.failed.turn,
                    started_at: 2,
                    client_id: Some("first".into()),
                    additional_client_ids
                })
            );
        }
    }
    Ok(())
}

#[test]
fn declared_tools_and_delayed_commands_preserve_a_named_handoff() -> Result<()> {
    let f = Fixture::new()?;
    let prior = Uuid::now_v7();
    let command = |owner, start, end| {
        json!({"type":"event_msg","payload":{
            "type":"item_completed","thread_id":f.failed.thread,"turn_id":owner,
            "started_at_ms":start,"completed_at_ms":end,
            "item":{"type":"CommandExecution","status":"failed","id":"command","source":"unified_exec_startup"}
        }})
    };
    let mut rows = vec![
        f.rows[0].clone(),
        json!({"type":"event_msg","payload":{"type":"task_complete","turn_id":prior,"started_at":0,"completed_at":1}}),
        command(prior, 50, 1750),
        f.rows[1].clone(),
        json!({"type":"response_item","payload":{"type":"message","role":"developer","id":"msg_fixture",
            "internal_chat_message_metadata_passthrough":{"turn_id":f.failed.turn,"content_item_kinds":["tools.incremental_update"]}}}),
        json!({"type":"response_item","payload":{"type":"additional_tools","id":"at_fixture",
            "role":"developer","tools":[{"type":"namespace","name":"functions","tools":[{"name":"exec","type":"custom"}]}]}}),
        json!({"type":"world_state","payload":{"full":false,"state":{"top_level_tools":{"functions.exec":"a".repeat(40)}}}}),
        f.rows[2].clone(),
        f.rows[3].clone(),
        f.rows[4].clone(),
        command(f.failed.turn, 2500, 2750),
        f.rows[5].clone(),
    ];
    let origin = f.origin(&f.rows)?;
    assert_eq!(f.origin(&rows)?, origin);
    rows.push(command(prior, 500, 6000));
    rows.push(command(f.failed.turn, 3000, 7000));
    assert_eq!(f.origin(&rows)?, origin);

    for (index, pointer, value) in [
        (1, "/payload/turn_id", json!(Uuid::now_v7())),
        (2, "/payload/item/source", json!("user_shell")),
        (2, "/payload/started_at_ms", json!(2100)),
        (
            4,
            "/payload/internal_chat_message_metadata_passthrough/turn_id",
            json!(prior),
        ),
        (
            4,
            "/payload/internal_chat_message_metadata_passthrough/content_item_kinds",
            json!(["user.goal"]),
        ),
        (5, "/payload/role", json!("user")),
        (5, "/payload/tools/0/tools/0/type", json!("function_call")),
        (5, "/payload/tools/0/tools/0/name", json!("another")),
        (6, "/payload/full", json!(true)),
        (10, "/payload/item/source", json!("user_shell")),
        (12, "/payload/started_at_ms", json!(2500)),
        (12, "/payload/turn_id", json!(Uuid::now_v7())),
        (12, "/payload/thread_id", json!(Uuid::now_v7())),
        (12, "/payload/item/source", json!("user_shell")),
    ] {
        let mut changed = rows.clone();
        *changed[index].pointer_mut(pointer).unwrap() = value;
        assert_eq!(f.origin(&changed)?, None, "row {index} {pointer}");
    }
    for i in [4, 5, 6] {
        let mut incomplete = rows.clone();
        incomplete.remove(i);
        assert_eq!(f.origin(&incomplete)?, None, "incomplete tool list");
    }
    let mut manual = rows.clone();
    manual.push(json!({"type":"event_msg","payload":{"type":"thread_settings_applied","thread_id":f.failed.thread}}));
    assert_eq!(f.origin(&manual)?, None);
    let mut operator = rows;
    operator.insert(10,json!({"type":"event_msg","payload":{"type":"item_completed",
        "thread_id":f.failed.thread,"turn_id":f.failed.turn,"item":{"type":"UserMessage","id":"user","client_id":"client"}}}));
    assert_eq!(
        f.origin(&operator)?,
        None,
        "a foreign tail requires the named handoff proof"
    );
    Ok(())
}
