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
    task::JoinHandle,
};
struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub type Mailboxes = Arc<Mutex<BTreeMap<String, Vec<Vec<u8>>>>>;
pub struct RelayServer {
    pub endpoint: String,
    pub token: String,
    pub mode: Arc<AtomicUsize>,
    pub data: Mailboxes,
    _task: Task,
}
impl RelayServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let token = config::secret();
        let mode = Arc::new(AtomicUsize::new(0));
        let data = Mailboxes::default();
        let (t, m, d) = (token.clone(), mode.clone(), data.clone());
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (t, m, d) = (t.clone(), m.clone(), d.clone());
                tokio::spawn(async move {
                    serve(socket, t, m, d).await;
                });
            }
        });
        Self {
            endpoint,
            token,
            mode,
            data,
            _task: Task(task),
        }
    }
}
async fn serve(mut socket: TcpStream, token: String, mode: Arc<AtomicUsize>, data: Mailboxes) {
    let mut reader = BufReader::new(&mut socket);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let request: Vec<_> = line.split_whitespace().map(str::to_owned).collect();
    let mut length = 0;
    let mut authorized = false;
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
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
    let (status, response) = {
        let parts: Vec<_> = request[1].split('/').collect();
        let mut data = data.lock().unwrap();
        if !authorized {
            (401, vec![])
        } else if mode.load(Ordering::SeqCst) == 1 {
            (503, vec![])
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
            } else if let Some(packet) = queue.get(sequence) {
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
    let header = format!(
        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    let _ = socket.write_all(header.as_bytes()).await;
    let _ = socket.write_all(&response).await;
}
