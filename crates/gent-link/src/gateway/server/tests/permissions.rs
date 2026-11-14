use super::*;

#[tokio::test]
async fn permission_check_uses_each_calls_bound_agent_and_never_exports_policy() {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let server = f.start().await;
    let client = client();
    let mut ids = Vec::new();
    for chat in ["a", "b", "hidden"] {
        let registered = server
            .call(
                &client,
                &f.token,
                chat,
                "gent_register",
                json!({"name":chat,"provider":"synthetic-host"}),
            )
            .await;
        ids.push(registered["agent"]["id"].as_str().unwrap().to_owned());
    }
    let mut policy = Policy::default();
    policy
        .groups
        .insert("owner-only-group-name".into(), ids[..2].to_vec());
    policy.rules.push(Rule {
        actor: Selector::Group("owner-only-group-name".into()),
        peer: Selector::Group("owner-only-group-name".into()),
        permission: Permission::Enumerate,
        effect: Effect::Allow,
    });
    owner(
        &f.home,
        OwnerOp::SetPolicy {
            policy: policy.clone(),
        },
    )
    .await;
    let tools = server.rpc(&client, &f.token, "tools/list", json!({})).await;
    let names: Vec<_> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"gent_permission_check"));
    assert!(!names.contains(&"gent_permission_explain"));
    for (chat, actor, peer) in [("a", &ids[0], &ids[1]), ("b", &ids[1], &ids[0])] {
        let value = server
            .call(
                &client,
                &f.token,
                chat,
                "gent_permission_check",
                json!({"peer":peer}),
            )
            .await;
        assert_eq!(value["actor"], *actor);
        assert_eq!(value["peer"], *peer);
        assert_eq!(value["policy"]["reply_policy"]["allowed"], true);
        assert_eq!(value["policy"]["send_unsolicited"]["allowed"], false);
        let serialized = value.to_string();
        for private in [&ids[2], "owner-only-group-name", "matching_rules", "traces"] {
            assert!(!serialized.contains(private), "{serialized}");
        }
        assert!(value.get("authority").is_none());
        assert!(value.get("revision").is_none());
    }
    let mut unavailable = Vec::new();
    for peer in [ids[2].clone(), uuid::Uuid::new_v4().to_string()] {
        let response = server.rpc(&client, &f.token, "tools/call", json!({
            "name":"gent_permission_check","arguments":{"peer":peer},"_meta":{"test/conversation":"a"}
        })).await;
        assert_eq!(response["result"]["isError"], true);
        unavailable.push(response);
    }
    assert_eq!(unavailable[0], unavailable[1]);
    for params in [
        json!({"name":"gent_permission_check","arguments":{"peer":ids[1]}}),
        json!({"name":"gent_permission_check","arguments":{"peer":ids[1],"actor":ids[0]},"_meta":{"test/conversation":"hidden"}}),
        json!({"name":"gent_permission_check","arguments":{"peer":ids[1]},"_meta":{"test/conversation":"hidden"}}),
    ] {
        let response = server.rpc(&client, &f.token, "tools/call", params).await;
        assert_eq!(response["result"]["isError"], true, "{response}");
    }
    policy.rules.push(Rule {
        actor: Selector::All,
        peer: Selector::All,
        permission: Permission::Receive,
        effect: Effect::Deny,
    });
    owner(&f.home, OwnerOp::SetPolicy { policy }).await;
    let value = server
        .call(
            &client,
            &f.token,
            "a",
            "gent_permission_check",
            json!({"peer":ids[1]}),
        )
        .await;
    assert_eq!(value["policy"]["reply_policy"]["allowed"], false);
    owner(
        &f.home,
        OwnerOp::Revoke {
            agent_id: ids[1].clone(),
        },
    )
    .await;
    let revoked = server.rpc(&client, &f.token, "tools/call", json!({
        "name":"gent_permission_check","arguments":{"peer":ids[1]},"_meta":{"test/conversation":"a"}
    })).await;
    assert_eq!(revoked, unavailable[0]);
    server.close().await;
    daemon.close(&f.home).await;
}
