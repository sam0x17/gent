use super::*;

#[tokio::test]
async fn group_edits_bind_each_http_call_and_keep_members_and_results_scoped() {
    use gent_protocol::{ConfigurationEdit, administration::GroupAction};
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let server = f.start().await;
    let client = client();
    let mut ids = Vec::new();
    for chat in ["a", "b", "hidden"] {
        ids.push(
            server
                .call(
                    &client,
                    &f.token,
                    chat,
                    "gent_register",
                    json!({"name":chat,"provider":"test"}),
                )
                .await["agent"]["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let mut policy = Policy::default();
    policy.groups.insert("team".into(), vec![ids[2].clone()]);
    for (a, b) in [(0, 1), (1, 0)] {
        policy.rules.push(Rule {
            actor: Selector::Agent(ids[a].clone()),
            peer: Selector::Agent(ids[b].clone()),
            permission: Permission::Enumerate,
            effect: Effect::Allow,
        });
    }
    owner(&f.home, OwnerOp::SetPolicy { policy }).await;
    let grant = uuid::Uuid::new_v4().to_string();
    owner(
        &f.home,
        OwnerOp::Configure {
            request_id: grant.clone(),
            edit: ConfigurationEdit::GrantGroupAdmin {
                grant_id: grant.clone(),
                administrator: ids[0].clone(),
                group: "team".into(),
                members: Selector::All,
                actions: vec![GroupAction::Add, GroupAction::Remove],
                lifetime_seconds: 60,
            },
        },
    )
    .await;
    let scopes = server
        .call(&client, &f.token, "a", "gent_group_admin_scopes", json!({}))
        .await;
    assert_eq!(scopes["grants"].as_array().unwrap().len(), 1);
    assert!(!scopes.to_string().contains(&ids[2]));
    assert_eq!(
        server
            .call(&client, &f.token, "b", "gent_group_admin_scopes", json!({}))
            .await["grants"],
        json!([])
    );
    assert_eq!(
        server
            .call(
                &client,
                &f.token,
                "a",
                "gent_group_members",
                json!({"group":"team"})
            )
            .await["members"],
        json!([])
    );
    let args = json!({"request_id":request_id(),"changes":[{"grant_id":grant,"group":"team","member":ids[1],"action":"add"}]});
    for (arguments, meta) in [
        (args.clone(), json!({})),
        (args.clone(), json!({"test/conversation":"b"})),
        (
            {
                let mut forged = args.clone();
                forged["administrator"] = json!(ids[0]);
                forged
            },
            json!({"test/conversation":"b"}),
        ),
    ] {
        let result = server
            .rpc(
                &client,
                &f.token,
                "tools/call",
                json!({"name":"gent_group_apply","arguments":arguments,"_meta":meta}),
            )
            .await;
        assert_eq!(result["result"]["isError"], true, "{result}");
    }
    let preview = server
        .call(
            &client,
            &f.token,
            "a",
            "gent_group_preview",
            json!({"changes":args["changes"]}),
        )
        .await;
    assert!(!preview.to_string().contains(&ids[2]));
    let result = server
        .call(&client, &f.token, "a", "gent_group_apply", args.clone())
        .await;
    assert_eq!(result["state"], "applied");
    assert!(result.get("revision").is_none());
    assert!(result.get("config_saved").is_none());
    assert_eq!(
        server
            .call(
                &client,
                &f.token,
                "a",
                "gent_group_request",
                json!({"request_id":args["request_id"]})
            )
            .await,
        result
    );
    let denied=server.rpc(&client,&f.token,"tools/call",json!({"name":"gent_group_request","arguments":{"request_id":args["request_id"]},"_meta":{"test/conversation":"b"}})).await;
    assert_eq!(denied["result"]["isError"], true);
    owner(
        &f.home,
        OwnerOp::Configure {
            request_id: request_id(),
            edit: ConfigurationEdit::RevokeGroupAdmin { grant_id: grant },
        },
    )
    .await;
    assert_eq!(
        server
            .call(&client, &f.token, "a", "gent_group_apply", args)
            .await,
        result
    );
    server.close().await;
    daemon.close(&f.home).await;
}

#[tokio::test]
async fn delegated_edits_bind_each_http_call_and_keep_request_status_private() {
    delegated_edits(false).await;
}

#[tokio::test]
async fn selector_edits_bind_each_http_call_and_keep_request_status_private() {
    delegated_edits(true).await;
}

async fn delegated_edits(selector_rules: bool) {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let server = f.start().await;
    let client = client();
    let mut ids = Vec::new();
    for chat in ["a", "b"] {
        let v = server
            .call(
                &client,
                &f.token,
                chat,
                "gent_register",
                json!({"name":chat,"provider":"test"}),
            )
            .await;
        ids.push(v["agent"]["id"].as_str().unwrap().to_owned());
    }
    let policy = Policy {
        rules: vec![Rule {
            actor: Selector::All,
            peer: Selector::All,
            permission: Permission::Enumerate,
            effect: Effect::Allow,
        }],
        ..Default::default()
    };
    owner(&f.home, OwnerOp::SetPolicy { policy }).await;
    let grant = uuid::Uuid::new_v4().to_string();
    owner(
        &f.home,
        OwnerOp::Configure {
            request_id: grant.clone(),
            edit: gent_protocol::ConfigurationEdit::GrantPermissionAdmin {
                selector_rules,
                grant_id: grant.clone(),
                administrator: ids[0].clone(),
                actor: if selector_rules {
                    Selector::All
                } else {
                    Selector::Agent(ids[0].clone())
                },
                peer: if selector_rules {
                    Selector::SameNode
                } else {
                    Selector::Agent(ids[1].clone())
                },
                permissions: vec![Permission::Send],
                lifetime_seconds: 60,
            },
        },
    )
    .await;
    let apply_tool = if selector_rules {
        "gent_permission_rule_apply"
    } else {
        "gent_permission_apply"
    };
    let preview_tool = if selector_rules {
        "gent_permission_rule_preview"
    } else {
        "gent_permission_preview"
    };
    let scope_tool = if selector_rules {
        "gent_permission_rule_scopes"
    } else {
        "gent_permission_admin_check"
    };
    let scope_args = if selector_rules {
        json!({})
    } else {
        json!({"actor":ids[0],"peer":ids[1]})
    };
    let actor = if selector_rules {
        json!({"kind":"all"})
    } else {
        json!(ids[0])
    };
    let peer = if selector_rules {
        json!({"kind":"same_node"})
    } else {
        json!(ids[1])
    };
    let args = json!({"request_id":request_id(),"changes":[{"grant_id":grant,"actor":actor,"peer":peer,"permission":"send","decision":"allow"}]});
    for chat in ["a", "b"] {
        let scope = server
            .call(&client, &f.token, chat, scope_tool, scope_args.clone())
            .await;
        assert_eq!(
            scope["grants"].as_array().unwrap().len(),
            usize::from(chat == "a")
        );
    }
    for (name, arguments, meta) in [
        (apply_tool, args.clone(), json!({"test/conversation":"b"})),
        (apply_tool, args.clone(), json!({})),
        (
            apply_tool,
            {
                let mut forged = args.clone();
                forged["administrator"] = json!(ids[0]);
                forged
            },
            json!({"test/conversation":"b"}),
        ),
    ] {
        let r = server
            .rpc(
                &client,
                &f.token,
                "tools/call",
                json!({"name":name,"arguments":arguments,"_meta":meta}),
            )
            .await;
        assert_eq!(r["result"]["isError"], true, "{r}");
    }
    let preview = server
        .call(
            &client,
            &f.token,
            "a",
            preview_tool,
            json!({"changes":args["changes"]}),
        )
        .await;
    assert!(preview.get("revision").is_none());
    let result = server
        .call(&client, &f.token, "a", apply_tool, args.clone())
        .await;
    assert_eq!(result["state"], "applied");
    assert!(result.get("revision").is_none());
    assert!(result.get("config_saved").is_none());
    assert_eq!(
        server
            .call(
                &client,
                &f.token,
                "a",
                "gent_permission_request",
                json!({"request_id":args["request_id"]})
            )
            .await,
        result
    );
    let denied=server.rpc(&client,&f.token,"tools/call",json!({"name":"gent_permission_request","arguments":{"request_id":args["request_id"]},"_meta":{"test/conversation":"b"}})).await;
    assert_eq!(denied["result"]["isError"], true);
    owner(
        &f.home,
        OwnerOp::Configure {
            request_id: request_id(),
            edit: gent_protocol::ConfigurationEdit::RevokePermissionAdmin { grant_id: grant },
        },
    )
    .await;
    assert_eq!(
        server.call(&client, &f.token, "a", apply_tool, args).await,
        result
    );
    server.close().await;
    daemon.close(&f.home).await;
}

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
