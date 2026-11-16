use super::*;
use gent_protocol::OwnerOp;

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
