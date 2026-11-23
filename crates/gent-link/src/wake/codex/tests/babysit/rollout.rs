use super::*;
use std::io::{BufWriter, Write};

const PAYLOAD: &str = r#"{"error":{"type":"invalid_request_error","code":"invalid_request_error","message":"Invalid request payload","param":"12345"}}"#;

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
