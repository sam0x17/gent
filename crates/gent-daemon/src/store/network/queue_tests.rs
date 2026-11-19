use super::*;

#[tokio::test]
async fn directory_reconciliation_bypasses_unstarted_inventory_backlog() {
    let mut pair = Pair::new().await;
    for store in &mut pair.stores {
        store.presence_tick().unwrap();
    }
    pair.pump();
    for i in 0..24 {
        pair.stores[0]
            .execute(Request::Agent {
                credential: config::secret(),
                action: AgentOp::Register {
                    name: format!("backlog-{i}"),
                    provider: "test".into(),
                },
            })
            .unwrap();
    }
    assert!(pair.stores[0].directory_tick().unwrap());
    let selected = queue::next_id(&pair.stores[0].db, pair.stores[1].identity.node.id())
        .unwrap()
        .unwrap();
    let kind: String = pair.stores[0].db.query_row("SELECT json_extract(CAST(body AS TEXT),'$.event.kind') FROM network_events WHERE id=?1", [&selected], |r|r.get(0)).unwrap();
    assert_eq!(kind, "directory");
    pair.pump();
}

#[tokio::test]
async fn presence_bypasses_unstarted_directory_records() {
    let mut pair = Pair::new().await;
    for i in 0..24 {
        pair.stores[0]
            .execute(Request::Agent {
                credential: config::secret(),
                action: AgentOp::Register {
                    name: format!("backlog-{i}"),
                    provider: "test".into(),
                },
            })
            .unwrap();
    }
    pair.stores[0].presence_tick().unwrap();
    let peer = pair.stores[1].identity.node.id();
    let selected = queue::next_id(&pair.stores[0].db, peer).unwrap().unwrap();
    let kind: String = pair.stores[0].db.query_row(
        "SELECT json_extract(CAST(body AS TEXT),'$.event.kind') FROM network_events WHERE id=?1",
        [&selected], |r| r.get(0)).unwrap();
    assert_eq!(kind, "presence");
    pair.pump();
    assert_eq!(
        pair.stores[1]
            .db
            .query_row("SELECT COUNT(*) FROM agents", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        26
    );
}

#[tokio::test]
async fn presence_never_interleaves_a_fragmented_record_even_after_cursor_failure() {
    for fail_cursor in [false, true] {
        let mut pair = Pair::new().await;
        for store in &mut pair.stores {
            store.presence_tick().unwrap();
        }
        pair.pump();
        pair.send(vec![FilePart {
            name: "sample.png".into(),
            media_type: "image/png".into(),
            data_base64: STANDARD.encode(vec![5; FRAGMENT_BYTES * 2]),
        }])
        .unwrap();
        let peer = pair.stores[1].identity.node.id().to_owned();
        let selected = queue::next_id(&pair.stores[0].db, &peer).unwrap().unwrap();
        let group = pair.group();
        if fail_cursor {
            pair.stores[0].db.execute_batch("CREATE TRIGGER fail_offset BEFORE UPDATE OF offset ON network_events BEGIN SELECT RAISE(ABORT,'injected cursor failure'); END;").unwrap();
            assert!(pair.stores[0].data_prepare(&group).is_err());
            pair.stores[0]
                .db
                .execute_batch("DROP TRIGGER fail_offset")
                .unwrap();
        } else {
            pair.stores[0].data_prepare(&group).unwrap();
        }
        pair.reopen(0);
        pair.stores[0]
            .db
            .execute("UPDATE node_presence SET next_probe_at=0", [])
            .unwrap();
        pair.stores[0].presence_tick().unwrap();
        pair.stores[0].directory_tick().unwrap();
        assert_eq!(
            queue::next_id(&pair.stores[0].db, &peer)
                .unwrap()
                .as_deref(),
            Some(selected.as_str())
        );
        pair.pump();
        let inbox = pair.agent(1, AgentOp::Inbox).unwrap();
        assert_eq!(inbox.as_array().unwrap().len(), 1);
        assert_eq!(
            inbox[0]["files"][0]["data_base64"],
            STANDARD.encode(vec![5; FRAGMENT_BYTES * 2])
        );
        assert_eq!(
            pair.stores[1]
                .db
                .query_row("SELECT COUNT(*) FROM network_partial", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
}
