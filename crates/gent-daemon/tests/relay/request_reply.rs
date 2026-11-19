use super::*;

#[test]
fn response_required_sends_preserve_selection_retry_and_answer_once() {
    let mut f = Fixture::new();
    let selected = ok(f.agent(
        0,
        AgentOp::RelayAttach {
            target: f.agents[1].clone(),
            request_id: Uuid::now_v7().to_string(),
        },
    ));
    let request_id = Uuid::now_v7().to_string();
    let send = AgentOp::RequestReply {
        recipient: f.agents[2].clone(),
        request_id: request_id.clone(),
        text: "A question requiring an answer".into(),
        files: vec![],
        file_ids: vec![],
    };
    let sent = ok(f.agent(0, send.clone()));
    assert_eq!(
        ok(f.agent(0, send.clone()))["message_id"],
        sent["message_id"]
    );
    let current = ok(f.agent(
        0,
        AgentOp::RelayStatus {
            attachment_id: None,
        },
    ));
    assert_eq!(current["attachment"]["id"], selected["attachment"]["id"]);
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM relay_attachments", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
    let id = sent["message_id"].as_str().unwrap().to_owned();
    let inbox = ok(f.agent(2, AgentOp::Inbox));
    assert_eq!(inbox[0]["id"], id);
    ok(f.agent(
        2,
        AgentOp::Ack {
            message_id: id.clone(),
        },
    ));
    let status = ok(f.agent(
        0,
        AgentOp::RelayTurnStatus {
            turn_id: id.clone(),
            after_message_id: None,
        },
    ));
    assert_eq!(status["state"], "pending");
    assert_eq!(status["received"], true);
    f.store = Store::open(f.home.path()).unwrap();
    let reply = AgentOp::Reply {
        message_id: id.clone(),
        request_id: Uuid::now_v7().to_string(),
        text: "The answer".into(),
        files: vec![],
        file_ids: vec![],
    };
    let answered = ok(f.agent(2, reply.clone()));
    assert_eq!(ok(f.agent(2, reply))["message_id"], answered["message_id"]);
    assert!(matches!(
        f.agent(
            2,
            AgentOp::Reply {
                message_id: id.clone(),
                request_id: Uuid::now_v7().to_string(),
                text: "Another answer".into(),
                files: vec![],
                file_ids: vec![]
            }
        ),
        Response::Error(_)
    ));
    assert_eq!(ok(f.agent(0, send))["duplicate"], true);
    let status = ok(f.agent(
        0,
        AgentOp::RelayTurnStatus {
            turn_id: id.clone(),
            after_message_id: None,
        },
    ));
    assert_eq!(status["state"], "completed");
    assert_eq!(status["responses"][0]["text"], "The answer");
    assert!(matches!(
        f.agent(
            1,
            AgentOp::RelayTurnStatus {
                turn_id: id,
                after_message_id: None
            }
        ),
        Response::Error(_)
    ));
    assert!(matches!(
        f.agent(
            0,
            AgentOp::Send {
                recipient: f.agents[2].clone(),
                request_id,
                text: "A question requiring an answer".into(),
                files: vec![],
                file_ids: vec![]
            }
        ),
        Response::Error(_)
    ));
}
