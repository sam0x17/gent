use super::*;
use std::io::Write;

struct History {
    state: Read,
    rows: Vec<Value>,
}

impl History {
    fn new(count: usize) -> Self {
        let thread = Uuid::now_v7().to_string();
        let mut state = Read::new(&thread);
        let end = gent_daemon::store::now() - 200;
        let start = end - 100;
        state.turn["startedAt"] = json!(start);
        state.turn["completedAt"] = json!(end);
        state.goal["status"] = json!("blocked");
        state.goal["createdAt"] = json!(start - 20);
        state.goal["updatedAt"] = json!(end);
        let failed = state.turn.clone();
        let mut rows = vec![json!({"type":"session_meta","payload":{"id":thread}})];
        rows.push(event(json!({"type":"task_started","turn_id":failed["id"],"started_at":start,"turn_attribution":{"turn_id":failed["id"],"turn_trigger":"queue"}})));
        rows.push(event(json!({"type":"task_complete","turn_id":failed["id"],"started_at":start,"completed_at":end,"error":{"message":failed["error"]["message"]}})));
        for i in 0..count as i64 {
            let id = Uuid::now_v7().to_string();
            let when = end + i;
            rows.push(event(json!({"type":"task_started","turn_id":id,"started_at":when,"turn_attribution":{"turn_id":id,"turn_trigger":"queue"}})));
            rows.push(json!({"type":"response_item","payload":{"type":"message","role":"user","internal_chat_message_metadata_passthrough":{"turn_id":id,"content_item_kinds":["user.text"]}}}));
            rows.push(event(json!({"type":"item_completed","thread_id":thread,"turn_id":id,"item":{"type":"UserMessage","id":Uuid::now_v7(),"client_id":Uuid::now_v7()}})));
            rows.push(event(json!({"type":"task_complete","turn_id":id,"started_at":when,"completed_at":when+1})));
            let completed = json!({"id":id,"startedAt":when,"completedAt":when+1,"status":"completed","error":null,"items":[],"itemsView":"notLoaded"});
            state
                .older_turns
                .insert(0, std::mem::replace(&mut state.turn, completed));
        }
        Self { state, rows }
    }

    fn write(&mut self, node: &Node) -> Result<()> {
        let thread = self.state.meta["id"].as_str().unwrap();
        let path = node
            .root
            .path()
            .join(format!("rollout-test-{thread}.jsonl"));
        self.state.meta["path"] = json!(path);
        let mut file = std::io::BufWriter::new(std::fs::File::create(path)?);
        for row in &self.rows {
            writeln!(file, "{row}")?;
        }
        file.flush()?;
        Ok(())
    }
}

fn event(payload: Value) -> Value {
    json!({"type":"event_msg","payload":payload})
}

fn with_tools(h: &mut History, index: usize, case: &str) {
    let turn = h.rows[index]["payload"]["turn_id"].clone();
    let start = h.rows[index]["payload"]["started_at"].as_i64().unwrap();
    let item = |details, ms| {
        event(
            json!({"type":"item_completed","thread_id":h.state.meta["id"],
        "turn_id":turn,"completed_at_ms":ms,"item":details}),
        )
    };
    let reasoning = item(json!({"type":"Reasoning","id":"r"}), (start + 1) * 1000);
    let call = json!({"type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"c",
        "internal_chat_message_metadata_passthrough":{"turn_id":turn}}});
    let mut meta = json!({"turn_id":turn});
    if case == "complete inventory" {
        meta["tool_calls_complete"] = json!(true);
        meta["executed_tool_calls"] = json!([{"name":"functions.get_goal"}]);
    } else if case == "async user tool" {
        meta["executed_tool_calls"] = json!([{"name":"functions.send_message_to_user_async"}]);
    }
    let output = json!({"type":"response_item","payload":{"type":"custom_tool_call_output",
        "call_id":"c","internal_chat_message_metadata_passthrough":meta}});
    let command = item(
        json!({"type":"CommandExecution", "id":"command", "source":"unified_exec_startup",
        "status":if case == "command declined" { "declined" } else { "completed" }}),
        (start + 1) * 1000,
    );
    let mcp = item(
        json!({"type":"McpToolCall","id":"mcp","server":"fixture", "tool":"lookup",
        "status":"completed"}),
        (start + 1) * 1000,
    );
    let mut work = if case == "complete inventory" {
        vec![call, output]
    } else {
        vec![call, command, mcp, output]
    };
    match case {
        "late anchor" => work.push(reasoning),
        "anchored opaque work" | "async user tool" => work.insert(0, reasoning),
        _ => {}
    }
    h.rows.splice(index + 3..index + 3, work);
}

#[tokio::test]
async fn queue_masked_provider_failures_require_the_entire_suffix() -> Result<()> {
    let node = Node::start().await?;
    for case in [
        "cross page",
        "new input",
        "steer",
        "second ordinary input",
        "anchored opaque work",
        "later turn opaque work",
        "unanchored opaque work",
        "late anchor",
        "complete inventory",
        "async user tool",
        "command declined",
        "unattributed",
        "foreign receipt",
        "duplicate client",
        "goal update",
        "nested goal tool",
        "interrupted",
        "unknown row",
        "manual user turn",
        "new goal on recheck",
        "queued again",
        "suffix changed",
        "same second preexisting block",
        "old failure",
        "long failure",
    ] {
        let mut h = History::new(37);
        let failed = h.state.older_turns.last_mut().unwrap();
        match case {
            "new input" => {
                let mut m = h.rows[4].clone();
                m["payload"]["internal_chat_message_metadata_passthrough"]["content_item_kinds"] = json!(["user.goal"]);
                h.rows.insert(5, m);
            }
            "second ordinary input" => h.rows.insert(6, h.rows[4].clone()),
            "steer" => h.rows.insert(6, h.rows[5].clone()),
            "later turn opaque work" | "command declined" => with_tools(&mut h, 7, case),
            "anchored opaque work" | "unanchored opaque work" | "late anchor" |
            "complete inventory" | "async user tool" => with_tools(&mut h, 3, case),
            "unattributed" => h.rows[3]["payload"]["turn_attribution"] = Value::Null,
            "foreign receipt" => h.rows[5]["payload"]["thread_id"] = json!(Uuid::now_v7()),
            "duplicate client" =>
                h.rows[9]["payload"]["item"]["client_id"] = h.rows[5]["payload"]["item"]["client_id"].clone(),
            "goal update" => h.rows.insert(6, event(json!({"type":"thread_goal_updated","threadId":h.state.meta["id"],"goal":h.state.goal}))),
            "nested goal tool" => h.rows.insert(6,json!({"type":"response_item","payload":{"type":"custom_tool_call_output","internal_chat_message_metadata_passthrough":{"executed_tool_calls":[{"name":"functions.update_goal"}]}}})),
            "interrupted" => h.state.older_turns[15]["status"] = json!("interrupted"),
            "unknown row" => h.rows.insert(10, event(json!({"type":"unknown"}))),
            "manual user turn" => h.rows[3]["payload"]["turn_attribution"]["turn_trigger"] = json!("user"),
            "same second preexisting block" => h.state.goal["updatedAt"] = failed["startedAt"].clone(),
            "old failure" => {
                let stale = json!(gent_daemon::store::now() - 7201);
                failed["startedAt"] = stale.clone();
                failed["completedAt"] = stale.clone();
                h.state.goal["createdAt"] = stale.clone();
                h.state.goal["updatedAt"] = stale;
            }
            "long failure" => {
                let start = gent_daemon::store::now() - 15000;
                failed["startedAt"] = json!(start);
                h.state.goal["createdAt"] = json!(start);
                h.state.goal["updatedAt"] = json!(start + 1);
                h.rows[1]["payload"]["started_at"] = json!(start);
                h.rows[2]["payload"]["started_at"] = json!(start);
            }
            _ => {}
        }
        h.write(&node)?;
        let mut after = h.state.clone();
        match case {
            "new goal on recheck" => after.goal["tokenBudget"] = json!(81),
            "queued again" => after.queue.push(json!({"id":"pending"})),
            "suffix changed" => {
                after.append_on_queue_read = Some(event(json!({"type":"thread_goal_cleared"})))
            }
            _ => {}
        }
        let result = exercise(&node, h.state, after, false, 2).await?;
        assert_eq!(
            result.resumes,
            usize::from(matches!(
                case,
                "cross page"
                    | "long failure"
                    | "later turn opaque work"
                    | "anchored opaque work"
                    | "complete inventory"
            )),
            "{case}"
        );
        assert_eq!(result.notices, result.resumes, "{case}");
    }
    Ok(())
}

#[tokio::test]
async fn healthy_and_conclusively_stale_heads_do_not_query_queue_or_older_pages() -> Result<()> {
    let node = Node::start().await?;
    for (status, expected_pages) in [("active", 1), ("complete", 0), ("blocked", 1)] {
        let mut h = History::new(37);
        h.state.goal["status"] = json!(status);
        if status == "blocked" {
            let old = gent_daemon::store::now() - 10000;
            h.state.goal["createdAt"] = json!(old);
            h.state.goal["updatedAt"] = json!(old);
            // The latest long completed turn started before the freshness cutoff.
            // A preceding failed turn must have finished before that start.
            h.state.turn["startedAt"] = json!(old + 100);
        }
        h.write(&node)?;
        let thread = h.state.meta["id"].as_str().unwrap().to_string();
        let host = host(&thread, h.state.clone(), h.state, false);
        let (_bindings, registry, _) = node.register(&host.path, &thread).await?;
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        let req = host.requests.lock().unwrap();
        assert_eq!(
            req.iter()
                .filter(|r| r["method"] == "thread/turns/list")
                .count(),
            expected_pages,
            "{status}"
        );
        assert!(
            !req.iter().any(|r| r["method"] == "thread/queue/list"),
            "{status}"
        );
    }
    Ok(())
}
