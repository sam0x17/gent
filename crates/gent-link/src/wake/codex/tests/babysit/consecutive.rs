use super::*;
use std::io::Write;

// All IDs and terminal rows are local fixtures. Keep the incident's 844-second
// separation relative to now so the real claim and freshness checks run.
fn failure(state: &Read, started: i64, ended: i64, path: &str) -> Value {
    let mut turn = state.turn.clone();
    turn["id"] = json!(Uuid::now_v7());
    turn["startedAt"] = json!(started);
    turn["completedAt"] = json!(ended);
    let error = json!({"error":{"message":format!("Unknown parameter: '{path}'."),
        "type":"invalid_request_error","code":"unknown_parameter","param":path}});
    turn["error"] = json!({"message":error.to_string(),"codexErrorInfo":"other"});
    turn
}

fn event(payload: Value) -> Value {
    json!({"type":"event_msg","payload":payload})
}

fn response(payload: Value) -> Value {
    json!({"type":"response_item","payload":payload})
}

fn start(turn: &Value, trigger: Value) -> Value {
    event(
        json!({"type":"task_started","turn_id":turn["id"],"started_at":turn["startedAt"],
        "turn_attribution":{"turn_id":turn["id"],"turn_trigger":trigger}}),
    )
}

fn terminal(turn: &Value) -> Value {
    event(
        json!({"type":"task_complete","turn_id":turn["id"],"started_at":turn["startedAt"],
        "completed_at":turn["completedAt"],"error":{"message":turn["error"]["message"],"codex_error_info":"other"}}),
    )
}

fn foreground(thread: &str, turn: &Value, case: &str) -> Vec<Value> {
    let id = &turn["id"];
    let receipt =
        |item| event(json!({"type":"item_completed","thread_id":thread,"turn_id":id,"item":item}));
    let message = |role: &str, kind: &str| {
        response(json!({"type":"message","role":role,
        "internal_chat_message_metadata_passthrough":{"turn_id":id,"content_item_kinds":[kind]}}))
    };
    let mut rows = vec![
        start(turn, Value::Null),
        message("user", "user.text"),
        receipt(json!({"type":"UserMessage","id":"user"})),
        message(
            "developer",
            if case == "unknown developer input" {
                "user.goal"
            } else {
                "tools.incremental_update"
            },
        ),
    ];
    for i in 0..17 {
        let wait = i < 13;
        let call = format!("call-{i}");
        rows.push(response(
            json!({"type":if wait {"function_call"} else {"custom_tool_call"},
            "namespace":"functions","name":if wait {"wait"} else {"exec"},"call_id":call}),
        ));
        if i < 9 {
            rows.push(receipt(json!({"type":"Reasoning","id":format!("r{i}")})));
        }
        if i < 5 {
            rows.push(receipt(json!({"type":"McpToolCall","tool":if case == "failed goal tool" && i==4 {"functions.update_goal"} else {"lookup"},
                "id":format!("m{i}"),"status":if i==4 {"failed"} else {"completed"}})));
        }
        rows.push(response(json!({"type":if wait {"function_call_output"} else {"custom_tool_call_output"},"call_id":call})));
    }
    let namespace = if case == "wrong result source" {
        "other"
    } else {
        "codex_tui"
    };
    rows.push(response(
        json!({"type":"function_call_output","namespace":namespace,"name":"send_message_to_thread",
        "id":if case == "wrong result ID" {Some("other")} else { None }}),
    ));
    if case != "missing result receipt" {
        rows.push(receipt(json!({"type":"FunctionCallOutput","id":"result","namespace":"codex_tui",
            "name":if case=="different result receipt" {"update_goal"} else {"send_message_to_thread"}})));
    }
    rows.push(message("assistant", "unknown"));
    rows.push(receipt(json!({"type":"AgentMessage","id":"msg"})));
    rows
}

#[tokio::test]
async fn consecutive_provider_failures_require_the_complete_current_proof() -> Result<()> {
    let node = Node::start().await?;
    for case in [
        "resume",
        "three failures",
        "older anchor",
        "stale latest",
        "no anchor",
        "duplicate id",
        "overlapping native turns",
        "completed foreground head",
        "completed intervening turn",
        "prior deliberate block",
        "already blocked at admission",
        "goal tool in anchor",
        "nested tool in latest",
        "user block between",
        "new goal",
        "rollback in anchor",
        "rollback between",
        "abort in latest",
        "abort after",
        "pending input",
        "goal changed on recheck",
        "older error changed on recheck",
        "queue on recheck",
        "turn changed on recheck",
        "new rollout receipt on recheck",
        "first API error",
        "latest API error",
        "first rollout error",
        "latest rollout error",
        "first rollout code",
        "latest rollout code",
        "wrong native start",
        "wrong terminal time",
        "unproven source",
        "foreign user receipt",
        "wrong result source",
        "missing result receipt",
        "different result receipt",
        "wrong result ID",
        "failed goal tool",
        "unknown developer input",
        "over turn limit",
    ] {
        let thread = Uuid::now_v7().to_string();
        let mut state = Read::new(&thread);
        let mut end = gent_daemon::store::now() - 5;
        if case == "stale latest" {
            end -= gent_protocol::wake::VERIFIED_BLOCKED_MAX_AGE_SECS + 1;
        }
        let updated = end - if case == "older anchor" { 7300 } else { 844 };
        state.goal["status"] = json!("blocked");
        state.goal["createdAt"] = json!(updated - 90);
        state.goal["updatedAt"] = json!(updated);
        let anchor = failure(&state, updated - 2, updated, "input[1].content[0].role");
        let latest = failure(&state, end - 2, end, "input[0].tools[0].tools[0].role");
        let block =
            event(json!({"type":"thread_goal_updated","threadId":thread,"goal":state.goal}));
        let tool = response(json!({"type":"function_call","name":"update_goal"}));
        let rollback = event(json!({"type":"thread_rolled_back","num_turns":1}));
        let abort = event(json!({"type":"turn_aborted","turn_id":latest["id"]}));
        let mut rows = vec![
            json!({"type":"session_meta","payload":{"id":thread}}),
            start(&anchor, json!("goal")),
        ];
        match case {
            "already blocked at admission" => {
                rows[1] = start(&anchor, json!("user"));
                rows.insert(1, block.clone());
            }
            "prior deliberate block" => rows.push(block.clone()),
            "goal tool in anchor" => rows.push(tool),
            "rollback in anchor" => rows.push(rollback.clone()),
            _ => {}
        }
        let mut finish = terminal(&anchor);
        match case {
            "first rollout error" => {
                finish["payload"]["error"]["message"] = latest["error"]["message"].clone()
            }
            "first rollout code" => {
                finish["payload"]["error"]["codex_error_info"] = json!("unauthorized")
            }
            _ => {}
        }
        rows.push(finish);
        match case {
            "user block between" => rows.push(block.clone()),
            "rollback between" => rows.push(rollback),
            _ => {}
        }
        state.older_turns = vec![anchor.clone()];
        let extra = match case {
            "three failures" => 1,
            "over turn limit" => 31,
            _ => 0,
        };
        for i in 0..extra {
            let turn = failure(
                &state,
                updated + 1 + i,
                updated + 1 + i,
                "input[4].content[1].role",
            );
            rows.extend(foreground(&thread, &turn, "resume"));
            rows.push(terminal(&turn));
            state.older_turns.insert(0, turn);
        }
        let mut body = foreground(&thread, &latest, case);
        match case {
            "wrong native start" => body[0]["payload"]["started_at"] = json!(end-1),
            "unproven source" => body[0]["payload"]["turn_attribution"] = Value::Null,
            "foreign user receipt" => body[2]["payload"]["turn_id"] = anchor["id"].clone(),
            "abort in latest" => body.push(abort.clone()),
            "nested tool in latest" => body.push(response(json!({"type":"custom_tool_call_output","call_id":"nested",
                "internal_chat_message_metadata_passthrough":{"executed_tool_calls":[{"name":"functions.update_goal"}]}}))),
            _=>{}
        }
        rows.extend(body);
        let mut finish = terminal(&latest);
        match case {
            "latest rollout error" => {
                finish["payload"]["error"]["message"] = anchor["error"]["message"].clone()
            }
            "latest rollout code" => {
                finish["payload"]["error"]["codex_error_info"] = json!("unauthorized")
            }
            "wrong terminal time" => finish["payload"]["completed_at"] = json!(end - 1),
            _ => {}
        }
        rows.push(finish);
        if case == "abort after" {
            rows.push(abort);
        }
        state.turn = latest;
        match case {
            "new goal" => state.goal["createdAt"]=json!(updated-1),
            "completed foreground head" => {state.turn["status"]=json!("completed"); state.turn["error"]=Value::Null;}
            "completed intervening turn" => state.older_turns.insert(0,json!({"id":Uuid::now_v7(),"status":"completed","error":null,"startedAt":updated+1,"completedAt":updated+2})),
            "no anchor" => state.older_turns.clear(),
            "duplicate id" => state.older_turns[0]["id"]=state.turn["id"].clone(),
            "overlapping native turns" => state.older_turns[0]["completedAt"]=json!(end),
            "first API error" => state.older_turns[0]["error"]["codexErrorInfo"]=json!("unauthorized"),
            "latest API error" => state.turn["error"]["codexErrorInfo"]=json!("unauthorized"),
            "pending input" => state.queue.push(json!({"id":"pending"})),
            _=>{}
        }
        let path = node
            .root
            .path()
            .join(format!("rollout-fixture-{thread}.jsonl"));
        let mut file = std::io::BufWriter::new(std::fs::File::create(&path)?);
        for row in rows {
            writeln!(file, "{row}")?;
        }
        file.flush()?;
        state.meta["path"] = json!(path);
        let mut after = state.clone();
        match case {
            "goal changed on recheck" => {
                after.goal["objective"] = json!("Replacement");
                after.append_on_queue_read = Some(event(
                    json!({"type":"thread_goal_updated","threadId":thread,"goal":after.goal}),
                ));
            }
            "older error changed on recheck" => {
                after.older_turns[0]["error"]["message"] = after.turn["error"]["message"].clone()
            }
            "queue on recheck" => after.queue.push(json!({"id":"pending"})),
            "turn changed on recheck" => after.turn["id"] = json!(Uuid::now_v7()),
            "new rollout receipt on recheck" => after.append_on_queue_read = Some(block),
            _ => {}
        }
        let result = exercise(&node, state, after, false, 2).await?;
        assert_eq!(
            result.resumes,
            usize::from(matches!(case, "resume" | "three failures" | "older anchor")),
            "{case}"
        );
        assert_eq!(result.notices, result.resumes, "{case}");
    }
    Ok(())
}

mod mixed;
