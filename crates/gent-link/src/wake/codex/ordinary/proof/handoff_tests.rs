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
        self.read(rows, false)
    }

    fn read(&self, rows: &[Value], direct_handoff: bool) -> Result<Option<ChatOrigin>> {
        use std::io::Write;
        let mut f = File::create(&self.failed.path)?;
        for row in rows {
            writeln!(f, "{row}")?;
        }
        Ok(read(&self.failed, direct_handoff)?.map(|(o, _, _)| o))
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

#[test]
fn named_root_binds_all_notifications_and_never_falls_back_to_human() -> Result<()> {
    for count in [1, 3] {
        let mut f = Fixture::new()?;
        let mut rows = f.rows.clone();
        let terminal = rows.pop().unwrap();
        rows[1]["payload"]["root_turn_id"] = json!(f.failed.turn);
        for i in 0..count {
            let text = format!("fixture {i}");
            rows.push(json!({"type":"response_item","payload":{"type":"message","role":"user",
                "id":format!("message-{i}"),"content":[{"type":"input_text","text":text}],
                "internal_chat_message_metadata_passthrough":{"turn_id":f.failed.turn,
                "content_item_kinds":["user.text"],"content_item_metadata":[{"provenance":{"type":"user"}}]}}}));
            rows.push(json!({"type":"event_msg","timestamp":format!("1970-01-01T00:00:03.{i}00Z"),
                "payload":{"type":"item_completed","thread_id":f.failed.thread,"turn_id":f.failed.turn,
                "item":{"id":format!("item-{i}"),"type":"UserMessage","client_id":Uuid::new_v4(),
                "content":[{"type":"text","text":text}]}}}));
        }
        rows.push(terminal);
        let Some(ChatOrigin::DirectHandoff { item, proof }) = f.read(&rows, true)? else {
            panic!("missing handoff")
        };
        assert_eq!(item, f.item);
        assert_eq!(proof.inputs.len(), count);
        for (i, input) in proof.inputs.iter().enumerate() {
            assert_eq!(
                json!(input.client),
                rows[6 + i * 2]["payload"]["item"]["client_id"]
            );
        }
        // An old daemon, a host missing thread ancestry, or an unpaired input
        // cannot turn this known machine opener into an operator retry budget.
        assert!(f.read(&rows, false)?.is_none());
        f.failed.handoff_parent = false;
        assert!(f.read(&rows, true)?.is_none());
        f.failed.handoff_parent = true;
        for (i, path, value) in [
            (1, "/payload/root_turn_id", json!(Uuid::new_v4())),
            (3, "/payload/name", json!("different")),
            (4, "/payload/thread_id", json!(Uuid::new_v4())),
            (
                5,
                "/payload/internal_chat_message_metadata_passthrough/turn_id",
                json!(Uuid::new_v4()),
            ),
            (
                5,
                "/payload/internal_chat_message_metadata_passthrough/content_item_kinds/0",
                json!("user.file"),
            ),
            (6, "/payload/item/content/0/text", json!("different")),
            (6, "/payload/item/id", json!(" ")),
        ] {
            let mut bad = rows.clone();
            *bad[i].pointer_mut(path).unwrap() = value;
            assert!(f.read(&bad, true)?.is_none(), "{i} {path}");
        }
        for row in [
            rows[5].clone(),
            rows[6].clone(),
            json!({"type":"event_msg","payload":{"type":"thread_rolled_back"}}),
            json!({"type":"event_msg","payload":{"type":"turn_aborted"}}),
            json!({"type":"event_msg","payload":{"type":"thread_goal_updated"}}),
            json!({"type":"event_msg","payload":{"type":"thread_settings_applied"}}),
            json!({"type":"response_item","payload":{"type":"function_call","name":"request_user_input_async","call_id":"q"}}),
            json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":f.failed.thread,
                "turn_id":f.failed.turn,"item":{"type":"AgentMessage","questions":[]}}}),
        ] {
            for at in [rows.len() - 1, rows.len()] {
                let mut bad = rows.clone();
                bad.insert(at, row.clone());
                assert!(f.read(&bad, true)?.is_none());
            }
        }
    }
    Ok(())
}
