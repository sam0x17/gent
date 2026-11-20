//! Bounded HTTP fixture shared by transport tests. Status zero drops the response.
use super::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
type Requests = Vec<(String, Vec<u8>)>;
pub(super) async fn server(responses: Vec<(u16, Vec<u8>)>) -> (Relay, JoinHandle<Requests>) {
    server_with_headers(
        responses
            .into_iter()
            .map(|(status, body)| (status, body, ""))
            .collect(),
    )
    .await
}
pub(super) async fn server_with_headers(
    responses: Vec<(u16, Vec<u8>, &'static str)>,
) -> (Relay, JoinHandle<Requests>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, response, headers) in responses {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            let mut line = String::new();
            socket.read_line(&mut line).await.unwrap();
            let request = line.clone();
            let mut length = 0;
            loop {
                line.clear();
                socket.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse().unwrap();
                }
            }
            assert!(length <= gent_protocol::transport_exchange::MAX_BYTES);
            let mut body = vec![0; length];
            socket.read_exact(&mut body).await.unwrap();
            requests.push((request, body));
            // Simulate a committed upload whose HTTP response is lost.
            if status == 0 {
                continue;
            }
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 {status} Test\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                        response.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(&response).await.unwrap();
        }
        requests
    });
    (
        Relay {
            client: Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            origin: format!("http://{address}/").parse().unwrap(),
            authorization: header::HeaderValue::from_static("Bearer test"),
            batches: Arc::default(),
            states: Arc::default(),
            exchange: None,
            cluster: None,
        },
        task,
    )
}
