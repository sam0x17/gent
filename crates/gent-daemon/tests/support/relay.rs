use futures_util::{SinkExt, StreamExt};
use gent_daemon::config;
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::broadcast,
    task::JoinHandle,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, handshake::derive_accept_key, protocol::Role},
};
struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub type Mailboxes = Arc<Mutex<BTreeMap<String, Vec<Vec<u8>>>>>;
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum Notice {
    Changed,
    Close,
    Text(String),
}
pub struct RelayServer {
    pub endpoint: String,
    pub token: String,
    pub mode: Arc<AtomicUsize>,
    pub data: Mailboxes,
    #[allow(dead_code)]
    pub notices: broadcast::Sender<Notice>,
    #[allow(dead_code)]
    pub watching: Arc<AtomicUsize>,
    #[allow(dead_code)]
    pub requests: Arc<AtomicUsize>,
    _task: Task,
}
impl RelayServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let token = config::secret();
        let mode = Arc::new(AtomicUsize::new(0));
        let data = Mailboxes::default();
        let (notices, _) = broadcast::channel(128);
        let watching = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (n, w, r) = (notices.clone(), watching.clone(), requests.clone());
        let (t, m, d) = (token.clone(), mode.clone(), data.clone());
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (t, m, d) = (t.clone(), m.clone(), d.clone());
                let (n, w, r) = (n.clone(), w.clone(), r.clone());
                tokio::spawn(async move {
                    serve(socket, t, m, d, n, w, r).await;
                });
            }
        });
        Self {
            endpoint,
            token,
            mode,
            data,
            notices,
            watching,
            requests,
            _task: Task(task),
        }
    }
}
async fn serve(
    mut socket: TcpStream,
    token: String,
    mode: Arc<AtomicUsize>,
    data: Mailboxes,
    notices: broadcast::Sender<Notice>,
    watching: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
) {
    let mut reader = BufReader::new(&mut socket);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let request: Vec<_> = line.split_whitespace().map(str::to_owned).collect();
    let mut length = 0;
    let mut authorized = false;
    let mut websocket_key = None;
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        if name.eq_ignore_ascii_case("sec-websocket-key") {
            websocket_key = Some(value.trim().to_owned());
        }
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse().unwrap();
        }
        if name.eq_ignore_ascii_case("authorization") {
            authorized = value.trim() == format!("Bearer {token}");
        }
    }
    assert!(length <= 1024 * 1024);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await.unwrap();
    drop(reader);
    if request[1] == "/v1/watch" && authorized && ![1, 4].contains(&mode.load(Ordering::SeqCst)) {
        let key = websocket_key.unwrap();
        let accept = derive_accept_key(key.as_bytes());
        let mut receiver = notices.subscribe();
        socket.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await.unwrap();
        let mut socket = WebSocketStream::from_raw_socket(socket, Role::Server, None).await;
        struct Watching(Arc<AtomicUsize>);
        impl Drop for Watching {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        watching.fetch_add(1, Ordering::SeqCst);
        let _watching = Watching(watching);
        socket
            .send(Message::text(r#"{"version":1,"event":"ready"}"#))
            .await
            .unwrap();
        loop {
            let message = tokio::select! {
                notice = receiver.recv() => match notice {
                    Ok(Notice::Changed) => Message::text(r#"{"version":1,"event":"changed"}"#),
                    Ok(Notice::Text(text)) => Message::text(text),
                    _ => { let _ = socket.close(None).await; break; }
                },
                frame = socket.next() => match frame {
                    Some(Ok(Message::Text(text))) if text == "gent-ping-v1" && mode.load(Ordering::SeqCst) != 1 => Message::text("gent-pong-v1"),
                    _ => break,
                }
            };
            if socket.send(message).await.is_err() {
                break;
            }
        }
        return;
    }
    requests.fetch_add(1, Ordering::SeqCst);
    if request[1].starts_with("/v1/objects/") && mode.load(Ordering::SeqCst) == 6 {
        data.lock().unwrap().insert("blocked-object".into(), vec![]);
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    }
    let (status, response) = {
        let parts: Vec<_> = request[1].split('/').collect();
        let mut data = data.lock().unwrap();
        if !authorized {
            (401, vec![])
        } else if request[1] == "/v1/watch" || mode.load(Ordering::SeqCst) == 1 {
            (503, vec![])
        } else if parts.get(2) == Some(&"objects") {
            object(
                &mut data,
                &parts,
                &request[0],
                &body,
                mode.load(Ordering::SeqCst),
            )
        } else if parts.len() == 5 && matches!(parts[4], "checkpoint" | "retire") {
            checkpoint(&mut data, &parts, &request[0], &body)
        } else if parts.len() == 4 {
            let next = if mode.load(Ordering::SeqCst) == 3 {
                9999
            } else {
                data.get(parts[3]).map_or(0, Vec::len)
            };
            (200, serde_json::to_vec(&json!({"next":next})).unwrap())
        } else {
            let sequence: usize = parts[4].parse().unwrap();
            let queue = data.entry(parts[3].into()).or_default();
            if request[0] == "PUT" {
                if sequence == queue.len() {
                    queue.push(body.clone());
                }
                if queue.get(sequence) == Some(&body) {
                    (
                        200,
                        serde_json::to_vec(&json!({"stored":true,"sequence":sequence})).unwrap(),
                    )
                } else {
                    (409, vec![])
                }
            } else if let Some(packet) = queue.get(sequence).filter(|p| !p.is_empty()) {
                let mut bytes = packet.clone();
                if mode.load(Ordering::SeqCst) == 2 {
                    let end = bytes.len() - 1;
                    bytes[end] ^= 1;
                }
                (200, bytes)
            } else {
                (404, vec![])
            }
        }
    };
    if request[0] == "PUT" && status == 200 && mode.load(Ordering::SeqCst) != 5 {
        let _ = notices.send(Notice::Changed);
    }
    let header = format!(
        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    let _ = socket.write_all(header.as_bytes()).await;
    let _ = socket.write_all(&response).await;
}

fn checkpoint(
    data: &mut BTreeMap<String, Vec<Vec<u8>>>,
    parts: &[&str],
    method: &str,
    body: &[u8],
) -> (u16, Vec<u8>) {
    use gent_crypto::stream::Receipt;
    let key = format!("checkpoint/{}", parts[3]);
    if method == "GET" {
        return data
            .get(&key)
            .map_or((404, vec![]), |r| (200, r[0].clone()));
    }
    let receipt = Receipt::decode(body).unwrap();
    if parts[4] == "retire" {
        let queue = data.entry(parts[3].into()).or_default();
        let end = receipt.sequence() as usize + 1;
        if queue.len() < end {
            queue.resize(end, vec![]);
        }
        for packet in &mut queue[..end] {
            packet.clear();
        }
        return (204, vec![]);
    }
    if let Some(saved) = data.get(&key) {
        let old = Receipt::decode(&saved[0]).unwrap();
        if old.sequence() > receipt.sequence() || saved[0] == body {
            return (204, vec![]);
        }
        if old.sequence() == receipt.sequence() {
            return (409, vec![]);
        }
    }
    data.insert(key, vec![body.to_vec()]);
    (200, vec![])
}

// Development object transport for daemon scheduling tests. The Worker suite
// separately verifies service quotas, conditional writes, expiry, and cleanup.
fn object(
    data: &mut BTreeMap<String, Vec<Vec<u8>>>,
    parts: &[&str],
    method: &str,
    body: &[u8],
    mode: usize,
) -> (u16, Vec<u8>) {
    let key = format!("objects/{}", parts[3]);
    if parts.len() == 4 && method == "PUT" {
        if let Some(saved) = data.get(&key) {
            if saved[0] != body {
                return (409, vec![]);
            }
        } else {
            let manifest: gent_protocol::file_objects::Manifest =
                serde_json::from_slice(body).unwrap();
            let mut saved = vec![body.to_vec()];
            saved.resize(manifest.chunks.len() + 1, vec![]);
            data.insert(key.clone(), saved);
        }
    }
    let Some(saved) = data.get_mut(&key) else {
        return (404, vec![]);
    };
    let manifest: gent_protocol::file_objects::Manifest =
        serde_json::from_slice(&saved[0]).unwrap();
    if parts.len() == 4 {
        let uploaded: Vec<_> = saved[1..]
            .iter()
            .enumerate()
            .filter_map(|(i, b)| (!b.is_empty()).then_some(i))
            .collect();
        let complete = uploaded.len() == manifest.chunks.len();
        let upload_until = manifest
            .expires_at
            .min(gent_daemon::store::now() as u64 + 3600);
        return (200,serde_json::to_vec(&json!({"manifest":manifest,"uploaded":uploaded,"complete":complete,"upload_until":upload_until})).unwrap());
    }
    let index: usize = parts[4].parse().unwrap();
    if method == "PUT" {
        if !saved[index + 1].is_empty() && saved[index + 1] != body {
            return (409, vec![]);
        }
        saved[index + 1] = body.to_vec();
        (200,serde_json::to_vec(&json!({"stored":true,"index":index,"complete":saved[1..].iter().all(|b|!b.is_empty())})).unwrap())
    } else if saved[index + 1].is_empty() {
        (404, vec![])
    } else {
        let mut bytes = saved[index + 1].clone();
        if mode == 2 {
            bytes[0] ^= 1;
        }
        (200, bytes)
    }
}
