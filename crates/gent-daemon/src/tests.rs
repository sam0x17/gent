use super::*;
use gent_protocol::OwnerOp;

#[tokio::test]
async fn request_waits_for_restart_before_sending_and_status_remains_a_probe() {
    let root = tempfile::tempdir().unwrap();
    // Exercise both a missing socket and an old socket with no listener.
    for stale in [false, true] {
        let socket = root.path().join("daemon.sock");
        if stale {
            drop(UnixListener::bind(&socket).unwrap());
        }
        let probe = Request::Owner {
            credential: "test".into(),
            action: OwnerOp::Status,
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(100), request(root.path(), probe))
                .await
                .unwrap()
                .is_err()
        );
        let request = request(
            root.path(),
            Request::Owner {
                credential: "test".into(),
                action: OwnerOp::RenameNode {
                    name: "after-restart".into(),
                },
            },
        );
        let restart = async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            if stale {
                fs::remove_file(&socket).unwrap();
            }
            let listener = UnixListener::bind(&socket).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut frame = Vec::new();
            stream.read_until(b'\n', &mut frame).await.unwrap();
            let Request::Owner {
                action: OwnerOp::RenameNode { name },
                ..
            } = serde_json::from_slice(&frame).unwrap()
            else {
                panic!("unexpected request")
            };
            assert_eq!(name, "after-restart");
            let mut reply =
                serde_json::to_vec(&Response::Ok(serde_json::json!({"ok":true}))).unwrap();
            reply.push(b'\n');
            stream.get_mut().write_all(&reply).await.unwrap();
        };
        let (result, ()) = tokio::join!(request, restart);
        assert_eq!(result.unwrap(), serde_json::json!({"ok":true}));
        fs::remove_file(socket).unwrap();
    }
}

#[tokio::test]
async fn request_with_an_uncertain_outcome_is_not_replayed() {
    let root = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(root.path().join("daemon.sock")).unwrap();
    let request = request(
        root.path(),
        Request::Owner {
            credential: "test".into(),
            action: OwnerOp::RenameNode {
                name: "once".into(),
            },
        },
    );
    let lost_response = async {
        let (stream, _) = listener.accept().await.unwrap();
        let mut frame = Vec::new();
        BufReader::new(stream)
            .read_until(b'\n', &mut frame)
            .await
            .unwrap();
        assert!(!frame.is_empty());
    };
    let (result, ()) = tokio::join!(request, lost_response);
    assert!(result.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn storage_timeout_returns_a_protocol_error_and_does_not_rename_later() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    let original = config::initialize(&home, "cluster").unwrap();
    let credential = config::read_private(&home.join("owner.key")).unwrap();
    let store = Arc::new(Mutex::new(store::Store::open(&home).unwrap()));
    let held = store.clone();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let holder = tokio::task::spawn_blocking(move || {
        let _store = held.lock().unwrap();
        entered.send(()).unwrap();
        released.recv().unwrap();
    });
    ready.await.unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    let slots = Arc::new(Semaphore::new(1));
    let permit = slots.clone().acquire_owned().await.unwrap();
    let serving = tokio::spawn(serve(
        server,
        store.clone(),
        Arc::new(Semaphore::new(2)),
        permit,
        Arc::new(serde_json::Value::Null),
    ));
    let request = Request::Owner {
        credential,
        action: OwnerOp::RenameNode {
            name: "must-not-run".into(),
        },
    };
    let mut bytes = serde_json::to_vec(&request).unwrap();
    bytes.push(b'\n');
    client.write_all(&bytes).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(12),
        BufReader::new(client).read_until(b'\n', &mut response),
    )
    .await
    .unwrap()
    .unwrap();
    let Response::Error(message) = serde_json::from_slice(&response).unwrap() else {
        panic!("expected timeout response");
    };
    assert!(message.contains("timed out"));
    assert!(message.contains("same request ID"));
    serving.await.unwrap().unwrap();
    assert_eq!(slots.available_permits(), 0);
    release.send(()).unwrap();
    holder.await.unwrap();
    let _permit = tokio::time::timeout(Duration::from_secs(2), slots.acquire())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(config::load(&home).unwrap().node.name, original.node.name);
    // Subsequent requests can use the same daemon without a restart.
    assert!(
        access::run(store, "test recovery", |store| store.maintain())
            .await
            .is_ok()
    );
}
