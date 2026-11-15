use super::*;
use std::os::unix::fs::PermissionsExt;
use tokio::net::UnixListener;

struct Fixture {
    _root: tempfile::TempDir,
    path: PathBuf,
    requests: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    fn new(thread: String, status: &str, direct: bool, response: Value) -> Self {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("host.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let status = status.to_owned();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(Message::Text(text))) = stream.next().await {
                let request: Value = serde_json::from_str(&text).unwrap();
                seen.lock().unwrap().push(request.clone());
                let Some(id) = request.get("id") else {
                    continue;
                };
                let result = match request["method"].as_str().unwrap() {
                    "initialize" => json!({}),
                    "thread/read" => {
                        json!({"thread":{"id":thread,"status":{"type":status},"canAcceptDirectInput":direct}})
                    }
                    "thread/queue/add" => response.clone(),
                    "thread/loaded/list" => response.clone(),
                    method => panic!("forbidden host operation: {method}"),
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
        });
        Self {
            _root: root,
            path,
            requests,
            task,
        }
    }
}

#[tokio::test]
async fn loaded_thread_pages_are_bounded_and_reject_substituted_cursors_and_ids() {
    let thread = uuid::Uuid::now_v7().to_string();
    for (data, next, cursor, valid) in [
        (json!([thread]), json!("page-2"), None, true),
        (json!([]), Value::Null, Some("page-2"), true),
        (json!([thread, thread]), Value::Null, None, false),
        (json!(["not-a-thread"]), Value::Null, None, false),
        (json!([]), json!("page-2"), Some("page-2"), false),
        (json!([]), json!("x".repeat(513)), None, false),
        (json!(vec![thread.clone(); 129]), Value::Null, None, false),
    ] {
        let f = Fixture::new(
            thread.clone(),
            "idle",
            true,
            json!({"data":data,"nextCursor":next}),
        );
        let mut host = Host::connect(&f.path).await.unwrap();
        let result = host.loaded(cursor).await;
        assert_eq!(result.is_ok(), valid);
        let requests = f.requests.lock().unwrap();
        assert_eq!(
            requests.last().unwrap()["params"],
            json!({"limit":128,"cursor":cursor})
        );
    }
}

#[tokio::test]
async fn only_exact_loaded_direct_input_threads_are_eligible() {
    let thread = uuid::Uuid::now_v7().to_string();
    for (status, direct, expected) in [
        ("active", true, true),
        ("idle", true, true),
        ("notLoaded", true, false),
        ("systemError", true, false),
        ("future-status", true, false),
        ("active", false, false),
    ] {
        let f = Fixture::new(thread.clone(), status, direct, json!({}));
        let mut host = Host::connect(&f.path).await.unwrap();
        assert_eq!(host.accepts(&thread).await.unwrap(), expected);
        assert!(
            f.requests
                .lock()
                .unwrap()
                .iter()
                .all(|r| r["method"] != "thread/queue/add")
        );
    }
    let f = Fixture::new(uuid::Uuid::now_v7().to_string(), "idle", true, json!({}));
    let mut host = Host::connect(&f.path).await.unwrap();
    assert!(host.accepts(&thread).await.is_err());
}

#[tokio::test]
async fn queue_submission_preserves_target_and_validates_host_response() {
    let thread = uuid::Uuid::now_v7().to_string();
    let attempt = uuid::Uuid::new_v4().to_string();
    let submission = uuid::Uuid::now_v7().to_string();
    for (client, id, valid) in [
        (attempt.clone(), submission.clone(), true),
        (uuid::Uuid::new_v4().to_string(), submission.clone(), false),
        (attempt.clone(), "not-an-id".into(), false),
        (attempt.clone(), uuid::Uuid::nil().to_string(), false),
    ] {
        let f = Fixture::new(
            thread.clone(),
            "active",
            true,
            json!({"queuedSubmission":{"clientUserMessageId":client,"id":id}}),
        );
        let mut host = Host::connect(&f.path).await.unwrap();
        let result = host.enqueue(&thread, &attempt).await;
        assert_eq!(result.is_ok(), valid);
        let requests = f.requests.lock().unwrap();
        let queued = requests
            .iter()
            .filter(|r| r["method"] == "thread/queue/add")
            .collect::<Vec<_>>();
        assert_eq!(queued.len(), 1);
        assert_eq!(
            queued[0]["params"],
            json!({"threadId":thread,"clientUserMessageId":attempt,
            "input":[{"type":"text","text":PROMPT}]})
        );
        assert!(requests.iter().all(|r| matches!(
            r["method"].as_str(),
            Some("initialize" | "initialized" | "thread/queue/add")
        )));
    }
}

#[tokio::test]
async fn socket_permissions_and_owner_directory_are_required_before_handshake() {
    let f = Fixture::new(uuid::Uuid::now_v7().to_string(), "idle", true, json!({}));
    std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(Host::connect(&f.path).await.is_err());
    std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(
        f.path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(Host::connect(&f.path).await.is_err());
    assert!(f.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn server_approval_requests_are_never_answered() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("host.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _ = stream.next().await;
        stream
            .send(Message::Text(
                json!({"id":1,"method":"item/commandExecution/requestApproval","params":{}})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        // The connection must close without approving or returning tool input.
        assert!(!matches!(stream.next().await, Some(Ok(Message::Text(_)))));
    });
    assert!(Host::connect(&path).await.is_err());
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}
