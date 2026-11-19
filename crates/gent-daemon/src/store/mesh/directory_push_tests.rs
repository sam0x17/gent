use super::*;

#[tokio::test]
async fn trusted_replica_repairs_a_third_nodes_chat_while_origin_is_offline() {
    let mut mesh = Mesh::new().await;
    for _ in 0..20 {
        mesh.round(true);
    }
    let registered = mesh.stores[0]
        .execute(Request::Agent {
            credential: config::secret(),
            action: AgentOp::Register {
                name: "coordinator".into(),
                provider: "test".into(),
            },
        })
        .unwrap();
    let chat = registered["agent"]["id"].as_str().unwrap();
    for _ in 0..20 {
        mesh.round(false);
    }
    for store in &mut mesh.stores {
        store.presence_tick().unwrap();
    }
    for _ in 0..20 {
        mesh.round(false);
    }
    assert!(
        mesh.stores[2]
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM agents WHERE id=?1)",
                [chat],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    for table in ["agent_activity", "network_origins"] {
        mesh.stores[2]
            .db
            .execute(&format!("DELETE FROM {table} WHERE agent=?1"), [chat])
            .unwrap();
    }
    mesh.stores[2]
        .db
        .execute("DELETE FROM agents WHERE id=?1", [chat])
        .unwrap();
    mesh.stores[2]
        .db
        .execute("UPDATE node_presence SET next_probe_at=0", [])
        .unwrap();
    mesh.stores[2].presence_tick().unwrap();
    // Only replicas 1 and 2 exchange ciphertext. Origin 0 supplies nothing.
    for _ in 0..10 {
        for (from, to) in [(2, 1), (1, 2)] {
            let group: Vec<u8> = mesh.stores[from]
                .db
                .query_row(
                    "SELECT outgoing FROM network_links WHERE peer=?1",
                    [mesh.stores[to].identity.node.id()],
                    |r| r.get(0),
                )
                .unwrap();
            mesh.stores[from].data_prepare(&group).unwrap();
            let next = mesh.stores[to].data_next(&group).unwrap();
            if let Some(packet) = mesh.stores[from].data_outgoing(&group, next).unwrap() {
                mesh.stores[to].data_receive(&packet).unwrap();
            }
        }
    }
    let restored: (String, String) = mesh.stores[2]
        .db
        .query_row("SELECT name,node_id FROM agents WHERE id=?1", [chat], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(
        restored,
        (
            "coordinator".into(),
            mesh.stores[0].identity.node.id().into()
        )
    );
    assert_eq!(mesh.count(2, "messages"), 0);
}
