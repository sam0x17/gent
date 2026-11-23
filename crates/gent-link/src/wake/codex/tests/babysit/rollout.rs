use super::*;
use std::io::{BufWriter, Write};

const PAYLOAD: &str = r#"{"error":{"type":"invalid_request_error","code":"invalid_request_error","message":"Invalid request payload","param":"5431"}}"#;

#[tokio::test]
async fn only_delayed_background_receipts_from_earlier_turns_allow_resume() -> Result<()> {
    let node = Node::start().await?;
    for case in [
        "resume",
        "foreign thread",
        "current turn",
        "missing thread",
        "missing turn",
        "nil turn",
        "malformed turn",
        "unknown turn",
        "prior start only",
        "rollback",
        "missing item id",
        "unknown item",
        "user item",
        "subagent interrupted",
        "command in progress",
        "command failed",
        "goal metadata",
        "nested goal metadata",
        "in-turn goal decision",
        "mismatched completion",
        "goal update",
        "user input",
        "new task",
        "unknown record",
        "receipt appended during recheck",
    ] {
        let thread = Uuid::now_v7().to_string();
        let prior = Uuid::now_v7();
        let mut state = Read::new(&thread);
        let end = gent_daemon::store::now() - 700;
        let start = end - 10;
        let turn = state.turn["id"].clone();
        let path = node
            .root
            .path()
            .join(format!("rollout-synthetic-{thread}.jsonl"));
        state.meta["path"] = json!(path);
        state.goal["status"] = json!("blocked");
        state.goal["createdAt"] = json!(start - 100);
        state.goal["updatedAt"] = json!(end);
        state.turn["startedAt"] = json!(start);
        state.turn["completedAt"] = json!(end);
        state.turn["error"] = json!({"message":PAYLOAD,"codexErrorInfo":"other"});
        let event = |payload: Value| json!({"type":"event_msg","payload":payload});
        let mut rows = vec![json!({"type":"session_meta","payload":{"id":thread}})];
        rows.push(event(
            json!({"type":"task_started","turn_id":prior,"started_at":start-5}),
        ));
        if case != "prior start only" {
            rows.push(event(
                json!({"type":"task_complete","turn_id":prior,"completed_at":start-1}),
            ));
        }
        if case == "rollback" {
            rows.push(event(json!({"type":"thread_rolled_back","num_turns":2})));
        }
        rows.push(event(
            json!({"type":"task_started","turn_id":turn,"started_at":start,
            "turn_attribution":{"turn_trigger":"goal","turn_id":turn}}),
        ));
        if case == "in-turn goal decision" {
            rows.push(json!({"type":"response_item","payload":{"type":"function_call","name":"update_goal"}}));
        }
        rows.push(event(
            json!({"type":"task_complete","turn_id":turn,"started_at":start,
            "completed_at":end + i64::from(case == "mismatched completion"),
            "error":{"message":PAYLOAD,"codex_error_info":"other"}}),
        ));
        let receipt = |delay: i64, turn: Uuid, item: Value| {
            let time = chrono::DateTime::from_timestamp(end + delay, 0).unwrap();
            json!({"timestamp":time.to_rfc3339(),"type":"event_msg","payload":{
                "type":"item_completed","thread_id":thread,"turn_id":turn,
                "completed_at_ms":time.timestamp_millis(),"item":item}})
        };
        let mut first = receipt(
            221,
            prior,
            json!({"type":"SubAgentActivity",
            "kind":"completed","id":"subagent-completed-fixture"}),
        );
        let mut second = receipt(
            676,
            prior,
            json!({"type":"CommandExecution",
            "status":"completed","id":"command-fixture"}),
        );
        let mut after = state.clone();
        match case {
            "foreign thread" => second["payload"]["thread_id"] = json!(Uuid::now_v7()),
            "current turn" => second["payload"]["turn_id"] = turn.clone(),
            "missing thread" => {
                first["payload"]
                    .as_object_mut()
                    .unwrap()
                    .remove("thread_id");
            }
            "missing turn" => {
                second["payload"].as_object_mut().unwrap().remove("turn_id");
            }
            "nil turn" => second["payload"]["turn_id"] = json!(Uuid::nil()),
            "malformed turn" => second["payload"]["turn_id"] = json!("invalid"),
            "unknown turn" => first["payload"]["turn_id"] = json!(Uuid::now_v7()),
            "missing item id" => {
                first["payload"]["item"]
                    .as_object_mut()
                    .unwrap()
                    .remove("id");
            }
            "unknown item" => second["payload"]["item"]["type"] = json!("FutureItem"),
            "user item" => second["payload"]["item"]["type"] = json!("UserMessage"),
            "subagent interrupted" => first["payload"]["item"]["kind"] = json!("interrupted"),
            "command in progress" => second["payload"]["item"]["status"] = json!("in_progress"),
            "command failed" => second["payload"]["item"]["status"] = json!("failed"),
            "goal metadata" => second["payload"]["goal"] = state.goal.clone(),
            "nested goal metadata" => {
                second["payload"]["item"]["internal_chat_message_metadata_passthrough"] =
                    json!({"executed_tool_calls":[{"name":"update_goal"}]})
            }
            "receipt appended during recheck" => after.append_on_queue_read = Some(first.clone()),
            _ => {}
        }
        rows.push(first);
        match case {
            "goal update" => rows.push(event(
                json!({"type":"thread_goal_updated","threadId":thread,"goal":state.goal}),
            )),
            "user input" => rows
                .push(json!({"type":"response_item","payload":{"type":"message","role":"user"}})),
            "new task" => rows.push(event(
                json!({"type":"task_started","turn_id":Uuid::now_v7()}),
            )),
            "unknown record" => rows.push(event(json!({"type":"future_event"}))),
            _ => {}
        }
        rows.push(second);
        let mut file = BufWriter::new(std::fs::File::create(path)?);
        for row in rows {
            writeln!(file, "{row}")?;
        }
        file.flush()?;
        let observed = exercise(&node, state, after, false, 2).await?;
        assert_eq!(observed.resumes, usize::from(case == "resume"), "{case}");
        assert_eq!(observed.notices, observed.resumes, "{case}");
    }
    Ok(())
}

#[tokio::test]
async fn user_started_long_turn_with_late_goal_and_ordinary_wrappers_resumes_once() -> Result<()> {
    let node = Node::start().await?;
    for case in [
        "resume",
        "override during recheck",
        "nested block",
        "queued input",
    ] {
        let thread = Uuid::now_v7().to_string();
        let mut state = Read::new(&thread);
        let path = node
            .root
            .path()
            .join(format!("rollout-synthetic-{thread}.jsonl"));
        state.meta["path"] = json!(path);
        state.goal["status"] = json!("blocked");
        state.goal["createdAt"] = state.goal["updatedAt"].clone();
        state.turn["error"] = json!({"message":PAYLOAD});
        let turn = &state.turn["id"];
        let mut w = BufWriter::new(std::fs::File::create(&path)?);
        let mut record = |kind: &str, payload: Value| -> Result<()> {
            serde_json::to_writer(&mut w, &json!({"type":kind,"payload":payload}))?;
            w.write_all(b"\n")?;
            Ok(())
        };
        record("session_meta", json!({"id":thread}))?;
        record(
            "event_msg",
            json!({"type":"task_started","turn_id":turn,"started_at":state.turn["startedAt"],"turn_attribution":{"turn_id":turn,"turn_trigger":"user"}}),
        )?;
        record(
            "response_item",
            json!({"type":"message","role":"user","internal_chat_message_metadata_passthrough":{"content_item_kinds":["user.goal"]}}),
        )?;
        let mut active = state.goal.clone();
        active["status"] = json!("active");
        record(
            "event_msg",
            json!({"type":"thread_goal_updated","threadId":thread,"goal":active}),
        )?;
        let output = "fixture ".repeat(7000);
        for i in 0..174 {
            record(
                "response_item",
                json!({"type":"custom_tool_call","name":"exec","call_id":format!("e{i}"),"input":"text(1)"}),
            )?;
            record(
                "response_item",
                json!({"type":"custom_tool_call_output","call_id":format!("e{i}"),"output":output}),
            )?;
            record(
                "response_item",
                json!({"type":"function_call","name":"wait","call_id":format!("w{i}"),"arguments":"{}"}),
            )?;
            record(
                "response_item",
                json!({"type":"function_call_output","call_id":format!("w{i}"),"output":"done"}),
            )?;
        }
        if case == "nested block" {
            record(
                "response_item",
                json!({"type":"custom_tool_call_output","internal_chat_message_metadata_passthrough":{"executed_tool_calls":[{"name":"update_goal","arguments":{"status":"blocked"}}]}}),
            )?;
        }
        record(
            "event_msg",
            json!({"type":"task_complete","turn_id":turn,"started_at":state.turn["startedAt"],"completed_at":state.turn["completedAt"],"error":{"message":PAYLOAD}}),
        )?;
        w.flush()?;
        assert!(path.metadata()?.len() > 9 * 1024 * 1024);
        let mut after = state.clone();
        if case == "queued input" {
            after.queue.push(json!({"id":"queued"}));
        }
        if case == "override during recheck" {
            after.append_on_queue_read = Some(
                json!({"type":"event_msg","payload":{"type":"thread_goal_updated","threadId":thread,"goal":state.goal}}),
            );
        }
        let observed = exercise(&node, state, after, false, 2).await?;
        assert_eq!(observed.resumes, usize::from(case == "resume"), "{case}");
        assert_eq!(observed.notices, observed.resumes, "{case}");
    }
    Ok(())
}
