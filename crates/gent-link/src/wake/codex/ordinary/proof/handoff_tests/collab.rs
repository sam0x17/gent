use super::*;

#[test]
fn repeated_thread_items_and_completed_nested_tools_identify_only_the_opener() -> Result<()> {
    let f = Fixture::new()?;
    let turn = f.failed.turn;
    let thread = &f.failed.thread;
    let scope = json!({"turn_id":turn});
    let execution = |kind: &str| {
        json!({"type":"response_item","payload":{"type":kind,"call_id":"call-a",
        "id":"wrapper","internal_chat_message_metadata_passthrough":scope}})
    };
    let nested = |item: Value| {
        json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":thread,"turn_id":turn,
        "started_at_ms":3000,"completed_at_ms":3100,"item":item}})
    };
    let later = format!("fco_{}", Uuid::new_v4());
    let mut rows = f.rows.clone();
    let terminal = rows.pop().unwrap();
    let mut call = execution("custom_tool_call");
    call["payload"]["name"] = json!("exec");
    call["payload"]["status"] = json!("completed");
    rows.push(call);
    rows.push(nested(json!({"type":"CollabAgentToolCall","id":format!("exec-{}",Uuid::new_v4()),
        "tool":"send_input","status":"completed","sender_thread_id":thread,"receiver_thread_ids":[Uuid::new_v4()]})));
    rows.push(nested(
        json!({"type":"McpToolCall","id":format!("exec-{}",Uuid::new_v4()),
        "server":"gent","tool":"gent_request_ids","status":"completed"}),
    ));
    rows.push(execution("custom_tool_call_output"));
    let mut message = f.rows[3].clone();
    let mut receipt = f.rows[4].clone();
    message["payload"]["id"] = json!(later);
    receipt["payload"]["item"]["id"] = json!(later);
    rows.extend([message, receipt, terminal]);
    assert_eq!(f.origin(&rows)?, f.origin(&f.rows)?);
    for (i, ptr, val) in [
        (5, "/payload/call_id", json!("different")),
        (5, "/payload/status", json!("in_progress")),
        (5, "/payload/name", json!("request_user_input")),
        (
            5,
            "/payload/internal_chat_message_metadata_passthrough/turn_id",
            json!(Uuid::new_v4()),
        ),
        (6, "/payload/thread_id", json!(Uuid::new_v4())),
        (6, "/payload/completed_at_ms", json!(2999)),
        (6, "/payload/item/sender_thread_id", json!(Uuid::new_v4())),
        (6, "/payload/item/receiver_thread_ids", json!([thread])),
        (6, "/payload/item/tool", json!("request_user_input")),
        (6, "/payload/item/id", json!("external")),
        (7, "/payload/item/server", json!("external")),
        (7, "/payload/item/tool", json!("gent_wait")),
        (7, "/payload/item/status", json!("failed")),
        (
            7,
            "/payload/item/id",
            rows[6]["payload"]["item"]["id"].clone(),
        ),
        (8, "/payload/call_id", Value::Null),
        (9, "/payload/name", json!("external")),
        (
            10,
            "/payload/item/id",
            rows[4]["payload"]["item"]["id"].clone(),
        ),
    ] {
        let mut bad = rows.clone();
        *bad[i].pointer_mut(ptr).unwrap() = val;
        assert_eq!(f.origin(&bad)?, None, "{i} {ptr}");
    }
    for extra in [
        json!({"type":"event_msg","payload":{"type":"turn_aborted"}}),
        json!({"type":"event_msg","payload":{"type":"thread_goal_updated"}}),
        json!({"type":"response_item","payload":{"type":"function_call","name":"request_user_input","call_id":"q"}}),
        json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"unmatched","name":"send_message_to_thread","namespace":"external"}}),
        nested(json!({"type":"RequestUserInput","questions":[]})),
        nested(json!({"type":"UserMessage","id":"external","client_id":Uuid::new_v4()})),
        json!({"type":"response_item","payload":{"type":"message","role":"user","id":"external"}}),
    ] {
        for at in [5, 7, 11] {
            let mut bad = rows.clone();
            bad.insert(at, extra.clone());
            assert_eq!(f.origin(&bad)?, None, "external input at {at}");
        }
    }
    let mut duplicate = rows.clone();
    duplicate.splice(11..11, rows[9..11].iter().cloned());
    assert_eq!(f.origin(&duplicate)?, None);
    let mut reused = rows.clone();
    let mut group = rows[5..9].to_vec();
    for row in &mut group[1..3] {
        row["payload"]["item"]["id"] = json!(format!("exec-{}", Uuid::new_v4()));
    }
    reused.splice(9..9, group);
    assert_eq!(f.origin(&reused)?, None);
    Ok(())
}
