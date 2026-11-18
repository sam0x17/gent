use super::*;

fn queued_bytes(pair: &Pair, id: &str) -> Vec<u8> {
    pair.stores[0]
        .db
        .query_row(
            "SELECT body FROM network_events WHERE json_extract(body,'$.event.message.id')=?1",
            [id],
            |r| r.get(0),
        )
        .unwrap()
}

fn queued(pair: &Pair, id: &str) -> Value {
    serde_json::from_slice(&queued_bytes(pair, id)).unwrap()
}

#[tokio::test]
async fn negotiated_codecs_preserve_old_queue_new_messages_files_and_restarts() {
    let mut pair = Pair::new().await;
    let old = pair.send(vec![]).unwrap();
    let old_id = old["message_id"].as_str().unwrap();
    assert_eq!(queued(&pair, old_id)["version"], 1);
    let old_bytes = queued_bytes(&pair, old_id);
    pair.reopen(0);
    pair.reopen(1);
    assert_eq!(queued_bytes(&pair, old_id), old_bytes);
    for store in &mut pair.stores {
        store.presence_tick().unwrap();
    }
    pair.pump();
    for store in &pair.stores {
        assert_eq!(
            store
                .db
                .query_row("SELECT version FROM wire_peers", [], |r| r.get::<_, u8>(0))
                .unwrap(),
            2
        );
    }
    let file = FilePart {
        name: "agent notes.txt".into(),
        media_type: "text/plain".into(),
        data_base64: "YWdlbnQ=".into(),
    };
    let new = pair.send(vec![file.clone()]).unwrap();
    let id = new["message_id"].as_str().unwrap();
    let wire = queued(&pair, id);
    assert_eq!(wire["version"], 2);
    assert_eq!(wire["event"]["sender_chat"]["chat_id"], pair.agents[0]);
    assert_eq!(
        wire["event"]["message"]["recipient_chat_id"],
        pair.agents[1]
    );
    assert!(wire["event"].get("sender").is_none());
    let new_bytes = queued_bytes(&pair, id);
    pair.reopen(0);
    pair.reopen(1);
    assert_eq!(queued_bytes(&pair, id), new_bytes);
    pair.pump();
    let inbox = pair.agent(1, AgentOp::Inbox).unwrap();
    assert!(inbox.as_array().unwrap().iter().any(|m| m["id"] == old_id));
    let received = inbox
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == id)
        .unwrap();
    assert_eq!(received["files"][0], json!(file));
}
