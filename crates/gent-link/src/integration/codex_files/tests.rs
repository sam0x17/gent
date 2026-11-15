use super::*;
use futures_util::{SinkExt, StreamExt};
use gent_daemon::config;
use std::{
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::UnixListener, task::JoinHandle};
use tokio_tungstenite::tungstenite::Message;

fn source(thread: &str, key: &str) -> Source {
    Source::new("/tmp/private/host.sock".into(), thread.into(), key.into())
}

#[test]
fn selections_are_bound_to_conversation_credential_endpoint_and_kind() {
    let a = source("one", "first-key");
    let token = a
        .token(&Selection::Page {
            cursor: "native-anchor".into(),
        })
        .unwrap();
    assert!(a.selection(&token).is_ok());
    for b in [
        source("two", "first-key"),
        source("one", "second-key"),
        Source::new("/tmp/another.sock".into(), "one".into(), "first-key".into()),
    ] {
        assert!(b.selection(&token).is_err());
    }
    let mut bytes = token.into_bytes();
    bytes[10] = if bytes[10] == b'A' { b'B' } else { b'A' };
    assert!(a.selection(std::str::from_utf8(&bytes).unwrap()).is_err());
    for invalid in ["".into(), "a.b".into(), "x".repeat(MAX_TOKEN + 1)] {
        assert!(a.selection(&invalid).is_err());
    }
    let tools = tools();
    for tool in tools {
        let p = tool.input_schema["properties"].as_object().unwrap();
        for forbidden in ["threadId", "session_id", "path", "url", "credential"] {
            assert!(!p.contains_key(forbidden));
        }
    }
}

#[test]
fn only_bounded_embedded_user_image_bytes_are_read() {
    for v in [
        json!({"type":"localImage","path":"/etc/passwd"}),
        json!({"type":"image","url":"https://private.invalid/secret"}),
        json!({"type":"image","url":"file:///private"}),
        json!({"type":"image","fileId":"remote-id"}),
        json!({"type":"image","url":"data:text/plain;base64,c2VjcmV0"}),
        json!({"type":"text","url":"data:image/png;base64,c2VjcmV0"}),
    ] {
        assert!(image(&v).unwrap().is_none());
    }
    for text in [
        "data:image/png;base64,!!!",
        "data:image/png;base64,",
        &format!(
            "data:image/png;base64,{}",
            "A".repeat(MAX_FILE.div_ceil(3) * 4 + 1)
        ),
    ] {
        assert!(image(&json!({"type":"image","url":text})).is_err());
    }
    let input = json!({"type":"image","url":format!("data:image/png;base64,{}", STANDARD.encode(b"original\0bytes"))});
    assert_eq!(&*image(&input).unwrap().unwrap().1, b"original\0bytes");
    assert!(turns(&json!({"data":[{},{}]})).is_err());
    assert!(items(&json!({"items":[],"itemsView":"summary"})).is_err());
}

struct Fixture {
    root: tempfile::TempDir,
    native: JoinHandle<()>,
    daemon: JoinHandle<Result<()>>,
    pages: Arc<Mutex<Vec<Value>>>,
    calls: Arc<Mutex<Vec<Value>>>,
    source: Source,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.native.abort();
        self.daemon.abort();
    }
}
impl Fixture {
    async fn new(bytes: &[u8]) -> Self {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        config::private_dir(root.path()).unwrap();
        config::initialize(root.path(), "native-images").unwrap();
        let home = root.path().to_owned();
        let daemon = tokio::spawn(async move { gent_daemon::run(&home).await });
        for _ in 0..100 {
            if root.path().join("daemon.sock").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(root.path().join("daemon.sock").exists());
        let path = root.path().join("host.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let thread = uuid::Uuid::now_v7().to_string();
        let source = Source::new(path, thread.clone(), config::secret());
        let pages = Arc::new(Mutex::new(vec![
            json!({"id":"newer","items":[],"itemsView":"full"}),
            json!({"id":"original","itemsView":"full","items":[
                {"type":"agentMessage","id":"private-reply","text":"not returned"},
                {"type":"userMessage","id":"input","content":[
                    {"type":"text","text":"not returned"},
                    {"type":"image","url":format!("data:image/png;base64,{}", STANDARD.encode(bytes))},
                    {"type":"image","url":"https://do-not-fetch.invalid/private"}
                ]}
            ]}),
        ]));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = calls.clone();
        let data = pages.clone();
        let native = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = tokio_tungstenite::accept_async(stream).await.unwrap();
                while let Some(Ok(Message::Text(text))) = stream.next().await {
                    let v: Value = serde_json::from_str(&text).unwrap();
                    seen.lock().unwrap().push(v.clone());
                    let Some(id) = v.get("id") else {
                        assert_eq!(v["method"], "initialized");
                        continue;
                    };
                    let result = match v["method"].as_str().unwrap() {
                        "initialize" => json!({}),
                        "thread/turns/list" => {
                            assert_eq!(v["params"]["threadId"], thread);
                            assert_eq!(v["params"]["limit"], 1);
                            assert_eq!(v["params"]["itemsView"], "full");
                            let pages = data.lock().unwrap();
                            let position = match v["params"]["cursor"].as_str() {
                                None => {
                                    assert_eq!(v["params"]["sortDirection"], "desc");
                                    0
                                }
                                Some(c) => {
                                    let (kind, id) = c.split_once(':').unwrap();
                                    let at = pages.iter().position(|p| p["id"] == id).unwrap();
                                    if kind == "before" {
                                        assert_eq!(v["params"]["sortDirection"], "desc");
                                        at + 1
                                    } else {
                                        assert_eq!(kind, "at");
                                        assert_eq!(v["params"]["sortDirection"], "asc");
                                        at
                                    }
                                }
                            };
                            if let Some(page) = pages.get(position) {
                                json!({"data":[page],"backwardsCursor":format!("at:{}", page["id"].as_str().unwrap()),
                                    "nextCursor":if position+1 < pages.len() { json!(format!("before:{}",page["id"].as_str().unwrap())) } else { Value::Null }})
                            } else {
                                json!({"data":[],"nextCursor":null})
                            }
                        }
                        method => panic!("forbidden native method: {method}"),
                    };
                    if stream
                        .send(Message::Text(
                            json!({"id":id,"result":result}).to_string().into(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        });
        Self {
            root,
            daemon,
            native,
            pages,
            calls,
            source,
        }
    }
    async fn agent(&self, action: AgentOp) -> Result<Value> {
        gent_daemon::request(
            self.root.path(),
            Request::Agent {
                credential: self.source.credential.clone(),
                action,
            },
        )
        .await
    }
}

#[tokio::test]
async fn native_images_page_import_and_retry_without_exposing_other_content() {
    let bytes = (0..300_000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let mut f = Fixture::new(&bytes).await;
    let home = f.root.path().to_owned();
    assert!(f.source.list(&home, None).await.is_err());
    assert!(f.calls.lock().unwrap().is_empty());
    f.agent(AgentOp::Register {
        name: "images".into(),
        provider: "codex".into(),
    })
    .await
    .unwrap();
    let first = f.source.list(&home, None).await.unwrap();
    assert_eq!(first["attachments"], json!([]));
    let next = first["next_cursor"].as_str().unwrap();
    let second = f.source.list(&home, Some(next)).await.unwrap();
    assert_eq!(second["unavailable_images"], 1);
    assert_eq!(second["next_cursor"], Value::Null);
    assert!(!second.to_string().contains("not returned"));
    let token = second["attachments"][0]["attachment_id"].as_str().unwrap();
    assert_eq!(second["attachments"][0]["byte_length"], bytes.len());
    let count = f.calls.lock().unwrap().len();
    assert!(f.source.list(&home, Some(token)).await.is_err());
    assert!(
        f.source
            .import(&home, uuid::Uuid::now_v7().to_string(), next)
            .await
            .is_err()
    );
    assert_eq!(f.calls.lock().unwrap().len(), count);
    f.pages
        .lock()
        .unwrap()
        .insert(0, json!({"id":"another-new-turn","items":[]}));
    let id = uuid::Uuid::now_v7().to_string();
    let imported = f.source.import(&home, id.clone(), token).await.unwrap();
    assert_eq!(
        imported["file"]["sha256"],
        format!("{:x}", Sha256::digest(&bytes))
    );
    assert_eq!(imported["duplicate"], false);
    let viewed = f
        .agent(AgentOp::FileView {
            file_id: imported["file"]["id"].as_str().unwrap().into(),
        })
        .await
        .unwrap();
    assert_eq!(
        STANDARD
            .decode(viewed["data_base64"].as_str().unwrap())
            .unwrap(),
        bytes
    );
    // Changed source bytes cannot silently retarget a saved selection.
    f.pages.lock().unwrap()[2]["items"][1]["content"][1]["url"] =
        json!("data:image/png;base64,Y2hhbmdlZA==");
    assert!(
        f.source
            .import(&home, uuid::Uuid::now_v7().to_string(), token)
            .await
            .is_err()
    );
    // A committed result can be retried after native history disappears and
    // after a daemon restart, without reading or importing anything again.
    f.native.abort();
    f.daemon.abort();
    let _ = (&mut f.daemon).await;
    let restart_home = home.clone();
    f.daemon = tokio::spawn(async move { gent_daemon::run(&restart_home).await });
    for _ in 0..100 {
        if f.agent(AgentOp::Identity).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let resumed = Source::new(
        f.source.endpoint.clone(),
        f.source.thread.clone(),
        f.source.credential.clone(),
    );
    let retried = resumed.import(&home, id.clone(), token).await.unwrap();
    assert_eq!(retried["file"], imported["file"]);
    assert_eq!(retried["duplicate"], true);
    assert!(
        std::fs::read_dir(home.join("files"))
            .map(|mut d| d.next().is_none())
            .unwrap_or(true)
    );
    let agent = f.agent(AgentOp::Identity).await.unwrap();
    gent_daemon::request(
        &home,
        Request::Owner {
            credential: config::read_private(&home.join("owner.key")).unwrap(),
            action: gent_protocol::OwnerOp::Revoke {
                agent_id: agent["agent"]["id"].as_str().unwrap().into(),
            },
        },
    )
    .await
    .unwrap();
    assert!(resumed.list(&home, None).await.is_err());
    assert!(resumed.import(&home, id, token).await.is_err());
}

#[test]
fn native_files_require_matching_authenticated_binding_and_opted_in_socket() {
    use crate::integration::{Bindings, Host};
    let root = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    config::initialize(root.path(), "scope").unwrap();
    let thread = uuid::Uuid::now_v7().to_string();
    let meta = json!({"threadId":thread});
    let mut bindings = Bindings::new(root.path(), Host::Codex).unwrap();
    let key = bindings
        .credential("codex-mcp-client", &meta, "gent_register", &json!({}))
        .unwrap();
    assert!(!bindings.has_host_files());
    assert!(bindings.host_files(&meta, &key).is_err());
    bindings
        .enable_wake(root.path(), &root.path().join("native.sock"))
        .unwrap();
    assert!(bindings.host_files(&meta, &key).is_ok());
    assert!(bindings.host_files(&meta, "other-key").is_err());
    assert!(
        bindings
            .host_files(&json!({"threadId":uuid::Uuid::now_v7().to_string()}), &key)
            .is_err()
    );
    assert!(
        bindings
            .host_files(&json!({"sessionId":thread}), &key)
            .is_err()
    );
    assert!(
        bindings
            .credential("wrong-client", &meta, "gent_host_attachments", &json!({}))
            .is_err()
    );
    let claude = Bindings::new(root.path(), Host::ClaudeCode).unwrap();
    assert!(!claude.has_host_files());
    assert!(claude.host_files(&meta, &key).is_err());
}
