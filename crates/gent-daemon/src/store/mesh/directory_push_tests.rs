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

#[tokio::test]
async fn third_node_learns_send_receive_and_native_dates_without_receiving_a_message() -> Result<()>
{
    use gent_protocol::{Effect, Permission, Rule, Selector};
    let mut mesh = Mesh::new().await;
    for _ in 0..20 {
        mesh.round(true);
    }
    let credentials = [config::secret(), config::secret(), config::secret()];
    let mut ids = Vec::new();
    for (i, credential) in credentials.iter().enumerate() {
        let value = mesh.stores[i].execute(Request::Agent {
            credential: credential.clone(),
            action: AgentOp::Register {
                name: format!("chat-{i}"),
                provider: "test".into(),
            },
        })?;
        ids.push(value["agent"]["id"].as_str().unwrap().to_owned());
    }
    let owner = config::read_private(&mesh.homes[0].path().join("owner.key"))?;
    let mut policy = mesh.stores[0].config.policy.clone();
    for permission in [Permission::Send, Permission::Receive] {
        policy.rules.push(Rule {
            actor: Selector::All,
            peer: Selector::All,
            permission,
            effect: Effect::Allow,
        });
    }
    mesh.stores[0].execute(Request::Owner {
        credential: owner,
        action: OwnerOp::SetPolicy { policy },
    })?;
    for _ in 0..20 {
        mesh.round(false);
    }
    let sent = mesh.stores[0].execute(Request::Agent {
        credential: credentials[0].clone(),
        action: AgentOp::Send {
            recipient: ids[1].clone(),
            request_id: uuid::Uuid::now_v7().to_string(),
            text: "fixture".into(),
            files: vec![],
            file_ids: vec![],
        },
    })?;
    let date: i64 = mesh.stores[0].db.query_row(
        "SELECT json_extract(payload,'$.created_at') FROM messages WHERE id=?1",
        [sent["message_id"].as_str().unwrap()],
        |r| r.get(0),
    )?;
    let inspect = config::read_private(&mesh.homes[2].path().join("owner.key"))?;
    mesh.stores[2].execute(Request::Owner {
        credential: inspect.clone(),
        action: OwnerOp::ObserveActivity {
            agent_id: ids[2].clone(),
            last_activity_at: date,
            last_native_message_at: Some(date - 10),
        },
    })?;
    for _ in 0..20 {
        mesh.round(false);
    }
    for store in &mut mesh.stores {
        store
            .db
            .execute("UPDATE node_presence SET next_probe_at=0", [])?;
        store.presence_tick()?;
    }
    for _ in 0..24 {
        mesh.round(false);
    }
    mesh.reopen(2);
    let directory = mesh.stores[2].execute(Request::Owner {
        credential: inspect,
        action: OwnerOp::Agents,
    })?;
    let row = |id: &str| {
        directory
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap()
    };
    let arrival = mesh.stores[1].db.query_row(
        "SELECT timestamp FROM chat_message_dates WHERE agent=?1 AND kind='gent'",
        [&ids[1]],
        |r| r.get::<_, i64>(0),
    )?;
    assert!(arrival >= date);
    for (id, expected) in [(&ids[0], date), (&ids[1], arrival)] {
        assert_eq!(row(id)["last_gent_message_at"], expected);
        assert_eq!(row(id)["has_gent_messages"], true);
    }
    assert!(row(&ids[2])["last_gent_message_at"].is_null());
    assert_eq!(row(&ids[2])["last_native_message_at"], date - 10);
    assert_eq!(mesh.count(2, "messages"), 0);
    assert_eq!(
        mesh.stores[0].db.query_row(
            "SELECT timestamp FROM chat_message_dates WHERE agent=?1 AND kind='native'",
            [&ids[2]],
            |r| r.get::<_, i64>(0)
        )?,
        date - 10
    );
    Ok(())
}
