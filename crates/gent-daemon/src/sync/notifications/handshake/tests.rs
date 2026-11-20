use super::{connect, wire};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::tungstenite::{Message, handshake::derive_accept_key, protocol::Role};
use tokio_tungstenite::{WebSocketStream, tungstenite::Error};

async fn read_upgrade(socket: &mut TcpStream) -> String {
    let mut reader = BufReader::new(socket);
    let mut request = String::new();
    loop {
        let start = request.len();
        assert!(reader.read_line(&mut request).await.unwrap() > 0);
        if &request[start..] == "\r\n" {
            return request;
        }
    }
}

#[tokio::test]
async fn old_relay_conflict_immediately_recovers_authenticated_v2_hints() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/watch", listener.local_addr().unwrap());
    let (relay, _) = crate::sync::test_http::server(vec![]).await;
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let offered = read_upgrade(&mut first).await.to_ascii_lowercase();
        assert!(offered.contains("x-gent-peer-session: 2\r\n"));
        assert!(offered.contains("x-gent-peer-handoff: 1\r\n"));
        first
            .write_all(b"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        drop(first);
        let (mut second, _) = listener.accept().await.unwrap();
        let request = read_upgrade(&mut second).await;
        let headers = request.to_ascii_lowercase();
        assert!(headers.contains("authorization: bearer test\r\n"));
        assert!(headers.contains("x-gent-watch: 2\r\n"));
        assert!(!headers.contains(wire::HEADER));
        assert!(!headers.contains(wire::HANDOFF));
        let key = request
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-key"))
            .unwrap()
            .1
            .trim();
        let accept = derive_accept_key(key.as_bytes());
        second.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await.unwrap();
        let mut socket = WebSocketStream::from_raw_socket(second, Role::Server, None).await;
        socket
            .send(Message::text(r#"{"version":2,"event":"ready"}"#))
            .await
            .unwrap();
    });
    let (mut socket, negotiated) =
        tokio::time::timeout(Duration::from_secs(3), connect(&relay, &url, true, true))
            .await
            .unwrap()
            .unwrap();
    assert!(!negotiated);
    let ready = socket.next().await.unwrap().unwrap().into_text().unwrap();
    assert_eq!(ready.as_str(), r#"{"version":2,"event":"ready"}"#);
    server.await.unwrap();
}

#[tokio::test]
async fn authorization_denial_does_not_retry_as_hint_only() {
    let (relay, requests) = crate::sync::test_http::server(vec![(401, vec![])]).await;
    let mut url = relay.origin.join("v1/watch").unwrap();
    url.set_scheme("ws").unwrap();
    let error = connect(&relay, url.as_str(), true, true).await.unwrap_err();
    assert!(
        matches!(error.downcast_ref::<Error>(), Some(Error::Http(r)) if r.status().as_u16() == 401)
    );
    assert_eq!(requests.await.unwrap().len(), 1);
}
