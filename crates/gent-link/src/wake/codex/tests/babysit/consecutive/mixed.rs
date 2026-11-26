use super::*;
use gent_protocol::wake::{DirectWake, WakeRecord, WakeState, WakeTarget};
use sha2::{Digest, Sha256};

const RELAY: &str = "Synthetic direct Gent input.";

fn tool_update(turn: &Value, deferred: bool) -> Vec<Value> {
    let message = |kind| {
        response(json!({"type":"message","role":"developer",
        "internal_chat_message_metadata_passthrough":{"turn_id":turn["id"],"content_item_kinds":[kind]}}))
    };
    let mut rows = vec![
        message("tools.incremental_update"),
        response(
            json!({"type":"additional_tools","role":"developer","id":"decl","tools":[{"type":"function"}]}),
        ),
    ];
    if deferred {
        rows.push(message("tools.deferred_namespaces"));
    }
    rows
}

fn admission(thread: &str, turn: &Value, trigger: Value, client: Uuid, input: &str) -> Vec<Value> {
    vec![
        start(turn, trigger),
        response(
            json!({"type":"message","role":"user","content":[{"type":"input_text","text":input}],
            "internal_chat_message_metadata_passthrough":{"turn_id":turn["id"],"content_item_kinds":["user.text"]}}),
        ),
        event(
            json!({"type":"item_completed","thread_id":thread,"turn_id":turn["id"],
            "item":{"type":"UserMessage","id":"msg","client_id":client,"content":[{"type":"text","text":input}]}}),
        ),
    ]
}

fn completed(started: i64, ended: i64) -> Value {
    json!({"id":Uuid::now_v7(),"startedAt":started,"completedAt":ended,"status":"completed","error":null})
}

fn success(turn: &Value) -> Value {
    event(
        json!({"type":"task_complete","turn_id":turn["id"],"started_at":turn["startedAt"],"completed_at":turn["completedAt"]}),
    )
}

fn journal(
    node: &Node,
    registered: &str,
    thread: &str,
    turn: &Value,
    attempt: Uuid,
    case: &str,
) -> Result<()> {
    let hash = Sha256::digest(if case == "wrong journal hash" {
        b"Other input"
    } else {
        RELAY.as_bytes()
    });
    let now = turn["completedAt"].as_i64().unwrap();
    let record = WakeRecord {
        direct: Some(DirectWake {
            reply_request_id: Uuid::new_v4().to_string(),
            input_hash: format!("{hash:x}"),
            turn_id: Some(turn["id"].as_str().unwrap().into()),
            finished: case != "unfinished",
            response_hash: None,
            response_message_id: None,
        }),
        message_id: Uuid::now_v7().to_string(),
        agent: registered.to_owned(),
        attempt_id: if case == "wrong client" {
            Uuid::new_v4()
        } else {
            attempt
        }
        .to_string(),
        target: WakeTarget::Codex {
            thread_id: if case == "wrong thread" {
                Uuid::now_v7().to_string()
            } else {
                thread.into()
            },
        },
        state: WakeState::Submitted,
        submission_id: Some(turn["id"].as_str().unwrap().into()),
        inbox_seen_at: Some(now),
        claimed_at: now - 10,
        updated_at: now,
    };
    let db = rusqlite::Connection::open(node.home.join("state.sqlite3"))?;
    db.execute("INSERT INTO wake_dispatches(message_id,agent,attempt_id,claimed_at,payload) VALUES(?1,?2,?3,?4,?5)",
        rusqlite::params![record.message_id,registered,record.attempt_id,record.claimed_at,serde_json::to_string(&record)?])?;
    Ok(())
}

#[tokio::test]
async fn newest_failed_queue_is_claimed_only_through_a_verified_mixed_suffix() -> Result<()> {
    let node = Node::start().await?;
    for case in [
        "resume",
        "human completion",
        "wrong journal hash",
        "wrong client",
        "wrong thread",
        "unfinished",
        "different native text",
        "two user inputs",
        "pending queue",
        "unknown delayed receipt",
        "future receipt",
        "wrong receipt thread",
        "rollback",
        "explicit block",
        "bad queue failure",
        "unpaired declaration",
        "unbound declaration",
        "changed journal on recheck",
        "latest failure too old",
    ] {
        let thread = Uuid::now_v7().to_string();
        let mut state = Read::new(&thread);
        let now = gent_daemon::store::now();
        let updated = now
            - if case == "latest failure too old" {
                94000
            } else {
                38000
            };
        state.goal["createdAt"] = json!(updated - 1000);
        state.goal["updatedAt"] = json!(updated);
        state.goal["status"] = json!("blocked");
        let first = failure(&state, updated - 70, updated, "input[1].content[0].role");
        let second = failure(
            &state,
            updated + 18,
            updated + 844,
            "input[0].tools[0].tools[0].role",
        );
        let queued = completed(updated + 4028, updated + 4193);
        let mut failed = failure(
            &state,
            updated + 7088,
            updated + 7103,
            "input[0].content[0].role",
        );
        failed["error"]["message"] = json!(
            json!({"error":{"type":"invalid_request_error","code":"invalid_request_error",
            "message":"Invalid request payload","param":"123"}})
            .to_string()
        );
        let relay = completed(updated + 21658, updated + 21719);
        let last_client = Uuid::new_v4();
        let mut rows = vec![
            json!({"type":"session_meta","payload":{"id":thread}}),
            start(&first, json!("goal")),
            terminal(&first),
        ];
        rows.extend(admission(
            &thread,
            &second,
            Value::Null,
            Uuid::new_v4(),
            "Failed foreground",
        ));
        rows.push(terminal(&second));
        let mut body = admission(
            &thread,
            &queued,
            json!("queue"),
            Uuid::new_v4(),
            "Queued input",
        );
        let mut update = tool_update(&queued, true);
        if case == "unpaired declaration" {
            update.remove(0);
        }
        if case == "unbound declaration" {
            update[0]["payload"]["internal_chat_message_metadata_passthrough"]["turn_id"] =
                relay["id"].clone();
        }
        body.splice(1..1, update);
        rows.extend(body);
        let owner = match case {
            "unknown delayed receipt" => json!(Uuid::new_v4()),
            "future receipt" => relay["id"].clone(),
            _ => first["id"].clone(),
        };
        let receipt_thread = if case == "wrong receipt thread" {
            Uuid::new_v4().to_string()
        } else {
            thread.clone()
        };
        rows.push(event(
            json!({"type":"item_completed","thread_id":receipt_thread,"turn_id":owner,
            "item":{"type":"CommandExecution","id":"late","status":"completed"}}),
        ));
        rows.push(success(&queued));
        rows.extend(admission(
            &thread,
            &failed,
            json!("queue"),
            Uuid::new_v4(),
            "Failed queue",
        ));
        let mut end = terminal(&failed);
        if case == "bad queue failure" {
            end["payload"]["error"]["codex_error_info"] = json!("unauthorized");
        }
        rows.push(end);
        if case == "rollback" {
            rows.push(event(json!({"type":"thread_rolled_back","num_turns":1})));
        }
        let mut body = admission(&thread, &relay, Value::Null, last_client, RELAY);
        if case == "different native text" {
            body[1]["payload"]["content"][0]["text"] = json!("Different input");
        }
        if case == "two user inputs" {
            body.extend_from_within(1..3);
        }
        body.splice(1..1, tool_update(&relay, false));
        rows.extend(body);
        if case == "explicit block" {
            rows.push(event(
                json!({"type":"thread_goal_updated","threadId":thread,"goal":state.goal}),
            ));
        }
        rows.push(success(&relay));
        state.turn = relay.clone();
        state.older_turns = vec![failed.clone(), queued, second, first];
        if case == "pending queue" {
            state.queue.push(json!({"id":"pending"}));
        }
        let path = node
            .root
            .path()
            .join(format!("rollout-mixed-{thread}.jsonl"));
        let mut file = std::io::BufWriter::new(std::fs::File::create(&path)?);
        for row in rows {
            writeln!(file, "{row}")?;
        }
        file.flush()?;
        state.meta["path"] = json!(path);
        let mut after = state.clone();
        if case == "changed journal on recheck" {
            after.retire_dispatch_on_queue_read =
                Some((node.home.join("state.sqlite3"), last_client));
        }
        let host = host(&thread, state, after, false);
        let (_binding, registry, registered) = node.register(&host.path, &thread).await?;
        if case != "human completion" {
            journal(&node, &registered, &thread, &relay, last_client, case)?;
        }
        sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        let allows = usize::from(case == "resume");
        assert_eq!(
            host.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r["method"] == "thread/goal/set")
                .count(),
            allows,
            "{case}"
        );
        assert_eq!(node.notices(&registered).await?, allows, "{case}");
        let db = rusqlite::Connection::open(node.home.join("state.sqlite3"))?;
        let count: i64 = db.query_row(
            "SELECT count(*) FROM babysitter_attempts WHERE agent=?1",
            [&registered],
            |r| r.get(0),
        )?;
        assert_eq!(
            count,
            i64::from(case == "resume" || case == "changed journal on recheck"),
            "{case}"
        );
        if case == "resume" {
            let (id,t,reason):(String,i64,String)=db.query_row("SELECT turn,failed_at,reason FROM babysitter_attempts WHERE agent=?1 AND submitted=1",[&registered],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            assert_eq!(failed["id"], id);
            assert_eq!(failed["completedAt"], t);
            assert_eq!(serde_json::from_str::<Value>(&reason)?, "request_payload");
        }
    }
    Ok(())
}

mod queue_steer;
mod queued_goal;
