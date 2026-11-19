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
async fn connected_v4_peers_upgrade_without_old_envelopes_overwriting_capabilities() {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    for store in &pair.stores {
        store
            .db
            .execute("UPDATE wire_peers SET version=4", [])
            .unwrap();
        store
            .db
            .execute(
                "UPDATE node_presence SET challenge=NULL,issued_at=NULL,next_probe_at=0",
                [],
            )
            .unwrap();
    }
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
            crate::messages::wire::CURRENT
        );
    }
    let sent = pair.send(vec![]).unwrap();
    assert_eq!(
        queued(&pair, sent["message_id"].as_str().unwrap())["version"],
        crate::messages::wire::CURRENT
    );
    pair.pump();
    pair.reopen(0);
    pair.reopen(1);
    let sent = pair.send(vec![]).unwrap();
    assert_eq!(
        queued(&pair, sent["message_id"].as_str().unwrap())["version"],
        crate::messages::wire::CURRENT
    );
}

#[tokio::test]
async fn lower_wire_records_neither_replace_nor_refresh_a_fresh_higher_capability() {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    let store = &pair.stores[0];
    let peer = pair.stores[1].identity.node.id();
    let saved: i64 = store
        .db
        .query_row("SELECT confirmed_at FROM wire_peers", [], |r| r.get(0))
        .unwrap();
    for elapsed in [30, 60, 89, 91] {
        let tx = store.db.unchecked_transaction().unwrap();
        let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
        session.timestamp = saved + elapsed;
        session.confirm_wire_version(peer, 4).unwrap();
        let expected = if elapsed <= 90 {
            crate::messages::wire::CURRENT
        } else {
            4
        };
        assert_eq!(session.wire_version(peer).unwrap(), expected);
        let confirmed: i64 = tx
            .query_row("SELECT confirmed_at FROM wire_peers", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            confirmed,
            if elapsed <= 90 {
                saved
            } else {
                saved + elapsed
            }
        );
        tx.commit().unwrap();
    }
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
            crate::messages::wire::CURRENT
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
    assert_eq!(wire["version"], crate::messages::wire::CURRENT);
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
