//! A blocked goal is followed by two successful queue turns. One receives a
//! second input whose relay is explicitly answered before the queue drains.
use super::*;
use gent_protocol::{
    Effect, OwnerOp, Permission, Policy, RelayResponseKind, Rule, Selector, wake::WakeDelivery,
};

async fn relay_input(
    node: &Node,
    registered: &str,
    key: &str,
    thread: &str,
    turn: &Value,
    attempt: Uuid,
    case: &str,
) -> Result<String> {
    let sender = config::secret();
    agent(
        &node.home,
        &sender,
        AgentOp::Register {
            name: "intermediary".into(),
            provider: "generic".into(),
        },
    )
    .await?;
    crate::owner(
        &node.home,
        OwnerOp::SetPolicy {
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
        },
    )
    .await?;
    let sent = agent(
        &node.home,
        &sender,
        AgentOp::RequestReply {
            recipient: registered.into(),
            request_id: Uuid::now_v7().to_string(),
            text: "Synthetic relay request".into(),
            files: vec![],
            file_ids: vec![],
        },
    )
    .await?;
    let message = sent["message_id"].as_str().unwrap();
    let target = WakeTarget::Codex {
        thread_id: thread.into(),
    };
    let claimed = agent(
        &node.home,
        key,
        AgentOp::WakeDirectClaim {
            message_id: message.into(),
            attempt_id: attempt.to_string(),
            target: target.clone(),
        },
    )
    .await?;
    let delivery: WakeDelivery = serde_json::from_value(claimed["delivery"].clone())?;
    let native = turn["id"].as_str().unwrap();
    agent(
        &node.home,
        key,
        AgentOp::WakeSubmitted {
            message_id: message.into(),
            attempt_id: attempt.to_string(),
            submission_id: native.into(),
        },
    )
    .await?;
    agent(
        &node.home,
        key,
        AgentOp::WakeDirectObserve {
            message_id: message.into(),
            attempt_id: attempt.to_string(),
            target,
            turn_id: native.into(),
        },
    )
    .await?;
    if case == "cancelled" {
        agent(
            &node.home,
            &sender,
            AgentOp::RelayCancel {
                turn_id: message.into(),
                request_id: Uuid::now_v7().to_string(),
            },
        )
        .await?;
    }
    if case != "unanswered" {
        let outcome = match case {
            "cancelled" => RelayResponseKind::Cancelled,
            "progress" => RelayResponseKind::Progress,
            _ => RelayResponseKind::Complete,
        };
        agent(
            &node.home,
            key,
            AgentOp::RelayRespond {
                turn_id: message.into(),
                request_id: Uuid::now_v7().to_string(),
                text: "Synthetic reply".into(),
                files: vec![],
                file_ids: vec![],
                outcome,
            },
        )
        .await?;
    }
    let record = crate::owner(
        &node.home,
        OwnerOp::WakeShow {
            message_id: message.into(),
        },
    )
    .await?;
    assert_eq!(record["direct"]["finished"], false);
    Ok(delivery.prompt())
}

#[tokio::test]
async fn drained_steered_queue_requires_a_completed_matching_relay() -> Result<()> {
    for case in [
        "resume",
        "unanswered",
        "cancelled",
        "progress",
        "human steer",
        "wrong digest",
        "mismatched native pair",
        "wrong response source",
        "wrong provenance",
        "nonadjacent native pair",
        "third input",
        "reused item",
        "reused client",
        "out of order",
        "unknown wait",
        "untimed wait",
        "foreign wait",
        "pending input",
        "recheck removes journal",
        "goal decision",
        "later user boundary",
        "later user without boundary",
        "non-goal anchor",
        "failed queue",
    ] {
        let node = Node::start().await?;
        let thread = Uuid::now_v7().to_string();
        let second = gent_daemon::store::now() - 9000;
        let mut read = Read::new(&thread);
        read.goal["status"] = json!("blocked");
        read.goal["tokenBudget"] = Value::Null;
        read.goal["createdAt"] = json!(second - 2000);
        read.goal["updatedAt"] = json!(second);
        let mut goal = failure(&read, second - 964, second, "");
        let error = |param| {
            json!({"error":{"message":"Invalid request payload","type":"invalid_request_error","code":"invalid_request_error","param":param}}).to_string()
        };
        goal["error"]["message"] = json!(error("54604"));
        let queue = if case == "failed queue" {
            failure(&read, second, second + 351, "input[0].tools[1].type")
        } else {
            completed(second, second + 351)
        };
        let drained = completed(second + 634, second + 668);
        let mut later = failure(&read, second + 8689, second + 8830, "");
        later["error"]["message"] = json!(error("21846"));
        later["rootTurnId"] = later["id"].clone();
        read.older_turns = vec![queue.clone(), goal.clone()];
        read.turn = drained.clone();
        if case.starts_with("later user") {
            read.older_turns.insert(0, drained.clone());
            read.turn = later.clone();
        }
        let path = node
            .root
            .path()
            .join(format!("rollout-queue-{thread}.jsonl"));
        read.meta["path"] = json!(path);
        if case == "pending input" {
            read.queue.push(json!({"id":"pending"}));
        }
        let attempt = Uuid::new_v4();
        let mut after = read.clone();
        if case == "recheck removes journal" {
            after.retire_dispatch_on_queue_read = Some((node.home.join("state.sqlite3"), attempt));
        }
        let host = host(&thread, read, after, false);
        let (_binding, registry, registered) = node.register(&host.path, &thread).await?;
        let prompt = relay_input(
            &node,
            &registered,
            &registry.credential(&thread)?.unwrap(),
            &thread,
            &queue,
            attempt,
            case,
        )
        .await?;

        let mut rows = vec![
            json!({"type":"session_meta","payload":{"id":thread,"history_mode":"paginated"}}),
            start(
                &goal,
                json!(if case == "non-goal anchor" {
                    "user"
                } else {
                    "goal"
                }),
            ),
            terminal(&goal),
        ];
        let first = Uuid::new_v4();
        let mut initial = admission(
            &thread,
            &queue,
            json!("queue"),
            first,
            "Initial queued input",
        );
        initial[2]["payload"]["completed_at_ms"] = json!(second * 1000 + 48);
        rows.extend(initial);
        let receipt = |at: i64, item: Value| {
            event(
                json!({"type":"item_completed","thread_id":thread,"turn_id":queue["id"],
            "started_at_ms":at,"completed_at_ms":at,"item":item}),
            )
        };
        rows.push(receipt(
            (second + 10) * 1000,
            json!({"type":"Reasoning","id":"r"}),
        ));
        rows.push(receipt(
            (second + 158) * 1000,
            json!({"type":"McpToolCall","id":"w","status":"failed",
            "tool": if case=="unknown wait" {"gent_inbox"} else {"gent_wait"},
            "server": if case=="foreign wait" {"other"} else {"gent"}}),
        ));
        if case == "untimed wait" {
            rows.last_mut().unwrap()["payload"]["started_at_ms"] = Value::Null;
        }
        let client = match case {
            "reused client" => first,
            "human steer" => Uuid::new_v4(),
            _ => attempt,
        };
        let text = if case == "wrong digest" {
            "Different input"
        } else {
            &prompt
        };
        let mut steer = admission(&thread, &queue, json!("queue"), client, text);
        steer[1]["payload"]["id"] = json!("response-item");
        steer[1]["metadata"]["retained_source"]["id"] = json!({"message_id":if case == "wrong response source" {"foreign"} else {"response-item"}, "turn_id":queue["id"]});
        steer[1]["payload"]["internal_chat_message_metadata_passthrough"]["content_item_metadata"] =
            json!([{"provenance":{"type": if case == "wrong provenance" {"agent"} else {"user"}}}]);
        steer[2]["payload"]["completed_at_ms"] =
            json!(second * 1000 + if case == "out of order" { 47 } else { 233121 });
        if case != "reused item" {
            steer[2]["payload"]["item"]["id"] = json!("steer");
        }
        if case == "mismatched native pair" {
            steer[1]["payload"]["content"][0]["text"] = json!("Other text");
        }
        if case == "nonadjacent native pair" {
            steer.insert(2, event(json!({"type":"token_count"})));
        }
        rows.extend_from_slice(&steer[1..]);
        if case == "third input" {
            rows.extend_from_slice(&steer[1..]);
        }
        if case == "goal decision" {
            rows.push(event(
                json!({"type":"thread_goal_cleared","threadId":thread}),
            ));
        }
        rows.push(if case == "failed queue" {
            terminal(&queue)
        } else {
            success(&queue)
        });
        rows.extend(admission(
            &thread,
            &drained,
            json!("queue"),
            Uuid::new_v4(),
            "Second queue",
        ));
        rows.push(success(&drained));
        if case.starts_with("later user") {
            if case == "later user boundary" {
                rows.push(event(
                    json!({"type":"thread_settings_applied","thread_id":thread}),
                ));
            }
            let mut input = admission(
                &thread,
                &later,
                json!("user"),
                Uuid::new_v4(),
                "New foreground work",
            );
            input[0]["payload"]["turn_attribution"]["root_turn_id"] = later["id"].clone();
            rows.extend(input);
            rows.push(terminal(&later));
        }
        let mut file = std::io::BufWriter::new(std::fs::File::create(&path)?);
        for row in rows {
            writeln!(file, "{row}")?;
        }
        file.flush()?;
        for _ in 0..2 {
            sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        }
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
        let submitted: usize = db.query_row(
            "SELECT count(*) FROM babysitter_attempts WHERE agent=?1 AND submitted=1 AND turn=?2 AND failed_at=?3 AND reason=?4",
            rusqlite::params![registered, goal["id"].as_str(), second, "\"request_payload\""],
            |r| r.get(0),
        )?;
        assert_eq!(submitted, allows, "{case}");
    }
    Ok(())
}
