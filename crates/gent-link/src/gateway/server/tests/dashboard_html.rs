use super::*;

#[tokio::test]
async fn dashboard_attach_html_uses_bound_chat_file_and_revision() {
    let f = Fixture::new();
    gent_daemon::entitlements::grant_test(&f.home, &config::load(&f.home).unwrap());
    let daemon = Daemon::start(&f.home).await;
    let server = f.start().await;
    let client = client();
    let call = |chat, name, args| server.call(&client, &f.token, chat, name, args);
    let rejected = |chat: &str, revision: u64, file: &str| {
        server.rpc(&client, &f.token, "tools/call", json!({"name":"gent_dashboard_attach_html",
            "arguments":{"expected_revision":revision,"file_id":file},"_meta":{"test/conversation":chat}}))
    };
    let board = json!({"title":"Native","widgets":[{"id":"status","kind":"text","label":"Run","value":"Ready"}]});
    let mut publisher = None;
    for chat in ["a", "b"] {
        let registration = call(
            chat,
            "gent_register",
            json!({"name":chat, "provider":"fixture"}),
        )
        .await;
        if chat == "a" {
            publisher = registration["agent"]["id"].as_str().map(str::to_owned);
        }
        call(
            chat,
            "gent_dashboard_define",
            json!({"expected_revision":0,"board":board}),
        )
        .await;
    }
    let html = "<main>Résumé</main>";
    let file = import_file_for_chat_a(&f, html.as_bytes(), "card.html", "text/html").await;
    let id = file["id"].as_str().unwrap();
    let denied = rejected("b", 1, id).await;
    assert_eq!(denied["result"]["isError"], true);
    assert_eq!(
        denied["result"]["content"],
        rejected("b", 1, &uuid::Uuid::new_v4().to_string()).await["result"]["content"]
    );
    assert_eq!(rejected("a", 0, id).await["result"]["isError"], true);
    for (bytes, mime) in [
        (&b"plain"[..], "text/plain"),
        (&[0xff], "text/html"),
        (&[], "text/html"),
        (&vec![b'x'; 65_537], "text/html"),
    ] {
        let invalid = import_file_for_chat_a(&f, bytes, "invalid.html", mime).await;
        assert_eq!(
            rejected("a", 1, invalid["id"].as_str().unwrap()).await["result"]["isError"],
            true
        );
    }
    let attach = json!({"expected_revision":1,"file_id":id});
    for _ in 0..2 {
        assert_eq!(
            call("a", "gent_dashboard_attach_html", attach.clone()).await,
            json!({"revision":2})
        );
    }
    let read = call("a", "gent_dashboard_get", json!({})).await;
    assert_eq!(read, json!({"revision":2,"board":board}));
    let list = owner(&f.home, OwnerOp::Dashboards { after: None }).await;
    for row in list["rows"].as_array().unwrap() {
        let expected = if row["chat"] == "a" { Some(html) } else { None };
        assert_eq!(row["board"]["static_html"].as_str(), expected);
        assert_eq!(row["board"]["widgets"], board["widgets"]);
    }
    let mut forged = board.clone();
    forged["static_html"] = json!(html);
    let invalid = server
        .rpc(
            &client,
            &f.token,
            "tools/call",
            json!({"name":"gent_dashboard_define",
        "arguments":{"expected_revision":1,"board":forged}, "_meta":{"test/conversation":"b"}}),
        )
        .await;
    assert_eq!(invalid["result"]["isError"], true);
    owner(
        &f.home,
        OwnerOp::Revoke {
            agent_id: publisher.unwrap(),
        },
    )
    .await;
    let list = owner(&f.home, OwnerOp::Dashboards { after: None }).await;
    assert_eq!(list["rows"].as_array().unwrap().len(), 1);
    assert_eq!(list["rows"][0]["chat"], "b");
    assert_eq!(list["rows"][0]["board"], board);
    assert_eq!(rejected("a", 2, id).await["result"]["isError"], true);
    server.close().await;
    daemon.close(&f.home).await;
}
