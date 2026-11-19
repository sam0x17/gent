use super::*;

#[tokio::test]
async fn mcp_send_waits_for_the_answer_and_non_blocking_send_returns_without_one() {
    let f = Fixture::new();
    let daemon = Daemon::start(&f.home).await;
    let server = f.start().await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let a = server
        .call(
            &client,
            &f.token,
            "caller",
            "gent_register",
            json!({"name":"caller","provider":"web"}),
        )
        .await;
    let b = server
        .call(
            &client,
            &f.token,
            "target",
            "gent_register",
            json!({"name":"target","provider":"native"}),
        )
        .await;
    let arguments = json!({"recipient":b["agent"]["id"],"request_id":request_id(),"text":"hello"});
    let sending = server.call(&client, &f.token, "caller", "gent_send", arguments.clone());
    let answering = async {
        let message = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let inbox = server
                    .call(&client, &f.token, "target", "gent_inbox", json!({}))
                    .await;
                if let Some(message) = inbox.as_array().unwrap().first() {
                    break message.clone();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(message["sender"], a["agent"]["id"]);
        assert_eq!(message["relay"]["kind"], "request");
        server
            .call(
                &client,
                &f.token,
                "target",
                "gent_ack",
                json!({"message_id":message["id"]}),
            )
            .await;
        // A receipt must not release the waiting call before the actual answer.
        tokio::time::sleep(Duration::from_millis(250)).await;
        server
            .call(
                &client,
                &f.token,
                "target",
                "gent_reply",
                json!({
                    "message_id":message["id"],"request_id":request_id(),"text":"Hello back",
                }),
            )
            .await
    };
    let started = std::time::Instant::now();
    let (response, answer) = tokio::join!(sending, answering);
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert_eq!(response["state"], "completed");
    assert_eq!(response["responses"][0]["text"], "Hello back");
    assert_eq!(response["final_message_id"], answer["message_id"]);
    let duplicate = server
        .call(&client, &f.token, "caller", "gent_send", arguments)
        .await;
    assert_eq!(duplicate["duplicate"], true);
    assert_eq!(duplicate["message_id"], response["message_id"]);
    let recovered = server
        .call(
            &client,
            &f.token,
            "caller",
            "gent_wait",
            json!({
                "message_id":response["message_id"],"wait_seconds":0,
            }),
        )
        .await;
    assert_eq!(recovered["state"], "completed");
    let sent = tokio::time::timeout(
        Duration::from_secs(5),
        server.call(
            &client,
            &f.token,
            "caller",
            "gent_send_non_blocking",
            json!({
                "recipient":b["agent"]["id"],"request_id":request_id(),"text":"FYI only",
            }),
        ),
    )
    .await
    .unwrap();
    assert!(sent["message_id"].is_string());
    let inbox = server
        .call(&client, &f.token, "target", "gent_inbox", json!({}))
        .await;
    assert!(
        inbox
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["text"] == "FYI only" && m["relay"].is_null())
    );
    // The host's bounded call duration is a continuation, not a lost request
    // or a demand for another user prompt. A later call retrieves this same ID.
    let pending = server
        .call(
            &client,
            &f.token,
            "caller",
            "gent_send",
            json!({
                "recipient":b["agent"]["id"],"request_id":request_id(),"text":"A slower question",
            }),
        )
        .await;
    assert_eq!(pending["state"], "pending");
    assert_eq!(pending["next_action"]["tool"], "gent_wait");
    assert_eq!(
        pending["next_action"]["arguments"]["message_id"],
        pending["message_id"]
    );
    let waiting = server.call(
        &client,
        &f.token,
        "caller",
        "gent_wait",
        pending["next_action"]["arguments"].clone(),
    );
    let answer = server.call(
        &client,
        &f.token,
        "target",
        "gent_reply",
        json!({
            "message_id":pending["message_id"],"request_id":request_id(),"text":"Later answer",
        }),
    );
    let (completed, _) = tokio::join!(waiting, answer);
    assert_eq!(completed["state"], "completed");
    assert_eq!(completed["responses"][0]["text"], "Later answer");
    server.close().await;
    daemon.close(&f.home).await;
}
