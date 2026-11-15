use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, DuplexStream};
use tokio_tungstenite::tungstenite::protocol::Role;

async fn fixture() -> (
    DuplexStream,
    BufReader<DuplexStream>,
    WebSocketStream<UnixStream>,
    tokio::task::JoinHandle<Result<()>>,
) {
    let (input, stdin) = tokio::io::duplex(1024);
    let (stdout, output) = tokio::io::duplex(1024);
    let (client, server) = UnixStream::pair().unwrap();
    let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    let server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
    let task = tokio::spawn(transport(BufReader::new(stdin), stdout, client));
    (input, BufReader::new(output), server, task)
}

#[tokio::test]
async fn frames_remain_exact_and_only_the_ide_answers_approval_requests() {
    let (mut input, mut output, mut host, task) = fixture().await;
    let init = r#"{ "id": "editor-1", "method":"initialize", "params":{"clientInfo":{"name":"codex_vscode"}} }"#;
    input.write_all(init.as_bytes()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(40), host.next())
            .await
            .is_err()
    );
    input.write_all(b"\n").await.unwrap();
    assert_eq!(
        host.next().await.unwrap().unwrap().into_text().unwrap(),
        init
    );
    let approval = r#"{"id":"approval-1","method":"item/commandExecution/requestApproval","params":{"command":"synthetic-only"}}"#;
    host.send(Message::Text(approval.into())).await.unwrap();
    let mut line = String::new();
    output.read_line(&mut line).await.unwrap();
    assert_eq!(line, format!("{approval}\n"));
    assert!(
        tokio::time::timeout(Duration::from_millis(40), host.next())
            .await
            .is_err()
    );
    let answer = r#"{"id":"approval-1", "result":{"decision":"decline"}}"#;
    input
        .write_all(format!("{answer}\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(
        host.next().await.unwrap().unwrap().into_text().unwrap(),
        answer
    );
    host.close(None).await.unwrap();
    // Server loss terminates even when the IDE still has stdin open.
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut tail = Vec::new();
    output.read_to_end(&mut tail).await.unwrap();
    assert!(tail.is_empty());
}

#[tokio::test]
async fn invalid_incomplete_and_oversized_input_fail_without_replay_or_content_errors() {
    for bytes in [
        b"{private-invalid}\n".to_vec(),
        b"{\"partial\":true}".to_vec(),
        vec![b'x'; LIMIT + 1],
    ] {
        let (mut input, _output, mut host, task) = fixture().await;
        let send = tokio::spawn(async move {
            let _ = input.write_all(&bytes).await;
            input.shutdown().await.ok();
        });
        let error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(!format!("{error:#}").contains("private-invalid"));
        assert!(!matches!(host.next().await, Some(Ok(Message::Text(_)))));
        send.await.unwrap();
    }
}

#[tokio::test]
async fn unexpected_server_frames_never_enter_stdio() {
    for frame in [
        Message::Binary(vec![1, 2].into()),
        Message::Text("{\n\"a\":1}".into()),
        Message::Text("invalid-private".into()),
    ] {
        let (_input, mut output, mut host, task) = fixture().await;
        host.send(frame).await.unwrap();
        let error = task.await.unwrap().unwrap_err();
        assert!(!format!("{error:#}").contains("invalid-private"));
        let mut data = Vec::new();
        output.read_to_end(&mut data).await.unwrap();
        assert!(data.is_empty());
    }
}
