use super::*;

async fn invoke(
    server: &Running,
    client: &reqwest::Client,
    token: &str,
    name: &str,
    arguments: Value,
) -> Value {
    let result = server
        .rpc(
            client,
            token,
            "tools/call",
            json!({"name":name,"arguments":arguments}),
        )
        .await;
    assert!(result.get("error").is_none(), "{result}");
    assert_ne!(result["result"]["isError"], true, "{result}");
    serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn explicit_http_chats_relay_without_metadata_and_recover_after_restart() {
    let f = Fixture::new();
    let out = f.home.join("phone.json");
    registry::add(&f.home, "phone", registry::conversations::KEY, &out, 24).unwrap();
    let exported: Value = serde_json::from_slice(&fs::read(out).unwrap()).unwrap();
    let token = exported["token"].as_str().unwrap();
    let daemon = Daemon::start(&f.home).await;
    let server = f.start().await;
    let client = client();
    let metadata_tools = server.rpc(&client, &f.token, "tools/list", json!({})).await;
    assert!(
        !metadata_tools
            .to_string()
            .contains("gent_conversation_open")
    );
    let tools = server.rpc(&client, token, "tools/list", json!({})).await;
    let tools = tools["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|t| t["name"] == "gent_conversation_open"));
    let register = tools.iter().find(|t| t["name"] == "gent_register").unwrap();
    assert!(
        register["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("conversation"))
    );
    let missing = server
        .rpc(
            &client,
            token,
            "tools/call",
            json!({"name":"gent_register","arguments":{"name":"missing","provider":"phone"}}),
        )
        .await;
    assert_eq!(missing["result"]["isError"], true);
    let a =
        invoke(&server, &client, token, "gent_conversation_open", json!({})).await["conversation"]
            .clone();
    let b =
        invoke(&server, &client, token, "gent_conversation_open", json!({})).await["conversation"]
            .clone();
    let agent = invoke(
        &server,
        &client,
        token,
        "gent_register",
        json!({"conversation":a,"name":"phone A","provider":"phone"}),
    )
    .await;
    let other = invoke(
        &server,
        &client,
        token,
        "gent_register",
        json!({"conversation":b,"name":"phone B","provider":"phone"}),
    )
    .await;
    assert_ne!(agent["agent"]["id"], other["agent"]["id"]);
    let target = server
        .call(
            &client,
            &f.token,
            "target",
            "gent_register",
            json!({"name":"target","provider":"native"}),
        )
        .await;
    let mut policy = Policy::default();
    for permission in [Permission::Enumerate, Permission::Send, Permission::Receive] {
        policy.rules.push(Rule {
            actor: Selector::All,
            peer: Selector::All,
            permission,
            effect: Effect::Allow,
        });
    }
    owner(&f.home, OwnerOp::SetPolicy { policy }).await;
    let attached = invoke(
        &server,
        &client,
        token,
        "gent_relay_attach",
        json!({"conversation":a,"target":target["agent"]["id"],"request_id":request_id()}),
    )
    .await;
    let args = json!({"conversation":a,"attachment_id":attached["attachment"]["id"],"request_id":request_id(),"text":"Hello from the phone"});
    let sent = invoke(&server, &client, token, "gent_relay_send", args.clone()).await;
    let duplicate = invoke(&server, &client, token, "gent_relay_send", args.clone()).await;
    assert_eq!(sent["turn_id"], duplicate["turn_id"]);
    let pending = invoke(
        &server,
        &client,
        token,
        "gent_relay_wait",
        json!({
            "conversation":a,"turn_id":sent["turn_id"],"wait_seconds":0
        }),
    )
    .await;
    assert_eq!(pending["state"], "pending");
    let unrelated = invoke(
        &server,
        &client,
        token,
        "gent_relay_status",
        json!({"conversation":b}),
    )
    .await;
    assert!(unrelated["attachment"].is_null());
    server.close().await;
    daemon.close(&f.home).await;
    let daemon = Daemon::start(&f.home).await;
    let server = f.start().await;
    let identity = invoke(
        &server,
        &client,
        token,
        "gent_identity",
        json!({"conversation":a}),
    )
    .await;
    assert_eq!(identity["agent"]["id"], agent["agent"]["id"]);
    let repeated = invoke(&server, &client, token, "gent_relay_send", args).await;
    assert_eq!(repeated["turn_id"], sent["turn_id"]);
    let turn = server
        .call(&client, &f.token, "target", "gent_relay_next", json!({}))
        .await;
    assert_eq!(turn["request"]["id"], sent["turn_id"]);
    assert_eq!(turn["request"]["text"], "Hello from the phone");
    let png = json!({"name":"preview.png","media_type":"image/png","data_base64":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aL1cAAAAASUVORK5CYII="});
    let response = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        server.call(&client, &f.token, "target", "gent_relay_respond", json!({"turn_id":sent["turn_id"],"request_id":request_id(),"text":"Here is the result.","outcome":"complete","files":[png.clone()]})).await
    };
    let args = json!({"conversation":a,"turn_id":sent["turn_id"],"wait_seconds":5});
    let waiting = invoke(&server, &client, token, "gent_relay_wait", args);
    let (result, _) = tokio::join!(waiting, response);
    assert_eq!(result["state"], "completed");
    assert_eq!(result["responses"].as_array().unwrap().len(), 1);
    assert_eq!(result["responses"][0]["text"], "Here is the result.");
    assert_eq!(
        result["responses"][0]["files"][0]["data_base64"],
        png["data_base64"]
    );
    let inaccessible = server.rpc(&client, token, "tools/call", json!({
        "name":"gent_relay_turn_status", "arguments":{"conversation":b,"turn_id":sent["turn_id"]}
    })).await;
    assert_eq!(inaccessible["result"]["isError"], true);
    let after = invoke(&server, &client, token, "gent_relay_wait", json!({
        "conversation":a,"turn_id":sent["turn_id"],"after_message_id":result["next_after"],"wait_seconds":1
    })).await;
    assert_eq!(after["state"], "completed");
    assert_eq!(after["responses"], json!([]));
    let second = invoke(&server, &client, token, "gent_relay_send", json!({
        "conversation":a,"attachment_id":attached["attachment"]["id"],"request_id":request_id(),"text":"Follow-up"
    })).await;
    let pending = invoke(
        &server,
        &client,
        token,
        "gent_relay_wait",
        json!({
            "conversation":a,"turn_id":second["turn_id"],"wait_seconds":1
        }),
    )
    .await;
    assert_eq!(pending["state"], "pending");
    let invalid = server.rpc(&client, token, "tools/call", json!({
        "name":"gent_relay_wait","arguments":{"conversation":a,"turn_id":second["turn_id"],"wait_seconds":21}
    })).await;
    assert_eq!(invalid["result"]["isError"], true);
    let waiting = server.rpc(&client, token, "tools/call", json!({
        "name":"gent_relay_wait","arguments":{"conversation":a,"turn_id":second["turn_id"],"wait_seconds":5}
    }));
    let revoke = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Registry::open(&f.home)
            .unwrap()
            .revoke(exported["client"].as_str().unwrap())
            .unwrap();
    };
    let (revoked, _) = tokio::join!(waiting, revoke);
    assert_eq!(revoked["result"]["isError"], true);
    let next = server
        .call(&client, &f.token, "target", "gent_relay_next", json!({}))
        .await;
    assert_eq!(next["request"]["id"], second["turn_id"]);
    server.close().await;
    daemon.close(&f.home).await;
}
