//! A goal provider failure and the first queued admission share a second.
//! The queue drains through another turn before the automatic goal sweep.
use super::*;

#[tokio::test]
async fn queue_drained_after_goal_failure_in_same_second() -> Result<()> {
    let node = Node::start().await?;
    for case in [
        "resume",
        "page boundary",
        "active",
        "pending",
        "operator block",
        "goal replaced",
        "foreign witness",
        "early witness",
        "command started after owner finished",
        "impossible file time",
        "early exec",
        "no exec start",
        "refused command",
        "interrupted file",
        "preceding human failure",
        "wrong API error",
        "missing primary",
        "unnamed duplicate",
        "duplicate item",
        "orphan supplement",
        "early supplement",
        "foreign supplement",
        "supplement has decision",
        "wrong exec",
        "skipped queue",
        "wrong extension",
        "wrong sleep id",
        "unpaired extension",
        "unpaired sleep",
        "unrecognized older failure",
        "goal changed on recheck",
        "queue on recheck",
        "newer operator turn",
    ] {
        let thread = Uuid::now_v7().to_string();
        let mut read = Read::new(&thread);
        let second = gent_daemon::store::now() - 60;
        read.goal["createdAt"] = json!(second - 80);
        read.goal["updatedAt"] = json!(second);
        read.goal["status"] = json!("blocked");
        let original = failure(&read, second - 20, second, "input[0].content[0].role");
        let queued = failure(&read, second, second + 6, "input[0].tools[1].type");
        let drained = completed(second + 6, second + 10);
        let mut rows = vec![
            json!({"type":"session_meta","payload":{"id":thread}}),
            start(
                &original,
                json!(if case == "preceding human failure" {
                    "user"
                } else {
                    "goal"
                }),
            ),
            terminal(&original),
        ];
        if case == "operator block" {
            rows.push(event(
                json!({"type":"thread_goal_updated","threadId":thread,"goal":read.goal}),
            ));
        }
        rows.extend(admission(
            &thread,
            &queued,
            json!("queue"),
            Uuid::new_v4(),
            "queued",
        ));
        let receipt = |turn: &Value, item: Value, ms: i64| {
            event(
                json!({"type":"item_completed","thread_id":thread,"turn_id":turn["id"],
                "started_at_ms":ms,"completed_at_ms":ms,"item":item}),
            )
        };
        let mut witness = receipt(
            &original,
            json!({"id":"command","type":"CommandExecution","status":"failed","source":"unified_exec_startup"}),
            (second + i64::from(case != "early witness")) * 1000,
        );
        witness["payload"]["started_at_ms"] =
            json!(if case == "command started after owner finished" {
                (second + 1) * 1000
            } else {
                (second - 1) * 1000
            });
        if case == "foreign witness" {
            witness["payload"]["turn_id"] = json!(Uuid::new_v4());
        }
        if case == "refused command" {
            witness["payload"]["item"]["status"] = json!("declined");
        }
        rows.push(witness);
        let mut meta = json!({"turn_id":queued["id"],"create_time":second + if case == "early exec" {0} else {2}});
        if case == "no exec start" {
            meta.as_object_mut().unwrap().remove("create_time");
        }
        let call = response(
            json!({"type":"custom_tool_call","name":if case == "wrong exec" {"wait"} else {"exec"},
            "id":"invoke","call_id":"exec-call","internal_chat_message_metadata_passthrough":meta}),
        );
        let primary = response(
            json!({"type":"custom_tool_call_output","id":"primary","call_id":"exec-call",
            "internal_chat_message_metadata_passthrough":meta}),
        );
        let supplement = |turn: &Value, id: &str| {
            response(json!({"type":"custom_tool_call_output","name":"exec",
            "id":id,"call_id":"exec-call","internal_chat_message_metadata_passthrough":{"turn_id":turn["id"]}}))
        };
        rows.push(call);
        rows.push(receipt(
            &queued,
            json!({"type":"FileChange","id":"file",
            "status":if case == "interrupted file" {"interrupted"} else {"completed"}}),
            (second
                + if case == "impossible file time" {
                    10
                } else {
                    2
                })
                * 1000,
        ));
        if case == "early supplement" {
            rows.push(supplement(&queued, "too-early"));
        }
        if case != "missing primary" {
            rows.push(primary.clone());
        }
        if case == "unnamed duplicate" {
            let mut extra = primary;
            extra["payload"]["id"] = json!("second-primary");
            rows.push(extra);
        }
        rows.push(supplement(&queued, "first-result"));
        rows.push(terminal(&queued));
        read.older_turns = vec![queued.clone(), original];
        if case == "skipped queue" {
            let intervening = completed(second + 6, second + 6);
            rows.extend(admission(
                &thread,
                &intervening,
                json!("queue"),
                Uuid::new_v4(),
                "intervening",
            ));
            rows.push(success(&intervening));
            read.older_turns.insert(0, intervening);
        }
        rows.extend(admission(
            &thread,
            &drained,
            json!("queue"),
            Uuid::new_v4(),
            "drained",
        ));
        let mut result = supplement(
            &drained,
            if case == "duplicate item" {
                "first-result"
            } else {
                "second-result"
            },
        );
        let p = &mut result["payload"];
        match case {
            "orphan supplement" => p["call_id"] = json!("orphan"),
            "foreign supplement" => {
                p["internal_chat_message_metadata_passthrough"]["turn_id"] = queued["id"].clone()
            }
            "supplement has decision" => {
                p["internal_chat_message_metadata_passthrough"]["executed_tool_calls"] =
                    json!([{"name":"functions.update_goal"}])
            }
            _ => {}
        }
        rows.push(result);
        let meta = json!({"turn_id":drained["id"]});
        if case != "unpaired extension" {
            rows.push(response(
                json!({"type":"function_call","name":"sleep","namespace":"clock","call_id":"sleep",
                "internal_chat_message_metadata_passthrough":meta}),
            ));
        }
        if case != "unpaired sleep" {
            rows.push(receipt(&drained, json!({"type":"Extension","kind":if case=="wrong extension" {"other"} else {"clock.sleep"},
                "id":if case=="wrong sleep id" {"other"} else {"sleep"}, "durationMs":3}), (second+7)*1000));
        }
        rows.push(response(
            json!({"type":"function_call_output","id":"sleep-result","call_id":"sleep",
            "internal_chat_message_metadata_passthrough":meta}),
        ));
        rows.push(success(&drained));
        read.turn = drained;
        if case == "page boundary" {
            for _ in 0..30 {
                let next = completed(second + 10, second + 10);
                rows.extend(admission(
                    &thread,
                    &next,
                    json!("queue"),
                    Uuid::new_v4(),
                    "later",
                ));
                rows.push(success(&next));
                read.older_turns
                    .insert(0, std::mem::replace(&mut read.turn, next));
            }
        }
        match case {
            "active" => read.meta["status"]["type"] = json!("active"),
            "pending" => read.queue.push(json!({"id":"waiting"})),
            "goal replaced" => read.goal["createdAt"] = json!(second),
            "wrong API error" => {
                read.older_turns[1]["error"]["message"] = queued["error"]["message"].clone()
            }
            "unrecognized older failure" => read.older_turns[1]["status"] = json!("interrupted"),
            _ => {}
        }
        let path = node
            .root
            .path()
            .join(format!("rollout-queued-goal-{thread}.jsonl"));
        let mut file = std::io::BufWriter::new(std::fs::File::create(&path)?);
        for row in rows {
            writeln!(file, "{row}")?;
        }
        file.flush()?;
        read.meta["path"] = json!(path);
        let mut after = read.clone();
        match case {
            "goal changed on recheck" => after.goal["status"] = json!("paused"),
            "queue on recheck" => after.queue.push(json!({"id":"waiting"})),
            "newer operator turn" => after.meta["status"]["type"] = json!("active"),
            _ => {}
        }
        let result = exercise(&node, read, after, false, 2).await?;
        assert_eq!(
            result.resumes,
            usize::from(matches!(case, "resume" | "page boundary")),
            "{case}"
        );
        assert_eq!(result.notices, result.resumes, "{case}");
    }
    Ok(())
}
