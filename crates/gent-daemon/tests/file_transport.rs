use gent_crypto::files::{FileGrant, MAX_FILE_BYTES, seal};
use gent_daemon::{
    config,
    file_objects::{self, Objects},
    file_transport::FileRelay,
};
use gent_protocol::file_objects::Manifest;
use rusqlite::{Connection, TransactionBehavior};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn database(path: &Path) -> Connection {
    let _file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .unwrap();
    let mut db = Connection::open(path).unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .unwrap();
    file_objects::initialize(&mut db).unwrap();
    db
}

async fn responder(response: Vec<u8>) -> (FileRelay, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    config::write_private(&home.path().join("relay.key"), &[b'0'; 64]).unwrap();
    let relay = FileRelay::open(
        &config::RelayConfig {
            endpoint: format!("http://{}", listener.local_addr().unwrap()),
            credential_file: "relay.key".into(),
        },
        home.path(),
    )
    .unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut part = [0; 4096];
            let n = stream.read(&mut part).await.unwrap();
            assert!(n > 0 && bytes.len() < 32768);
            bytes.extend_from_slice(&part[..n]);
        }
        let _ = stream.write_all(&response).await;
    });
    (relay, task)
}
fn ok(body: &[u8]) -> Vec<u8> {
    [
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
        body,
    ]
    .concat()
}

#[tokio::test]
async fn client_rejects_bad_progress_ciphertext_and_unbounded_bodies() {
    let sealed = seal("test.png", "image/png", b"secret image bytes").unwrap();
    let manifest = sealed.transport_manifest(now() + 600).unwrap();
    let id = &sealed.grant().descriptor().id;
    for body in [
        json!({"manifest":manifest,"uploaded":[0,0],"complete":true,"upload_until":now()+300}),
        json!({"manifest":manifest,"uploaded":[],"complete":true,"upload_until":now()+300}),
        json!({"manifest":manifest,"uploaded":[],"complete":false,"upload_until":now()+300,"key":"forbidden"}),
    ] {
        let (client, task) = responder(ok(&serde_json::to_vec(&body).unwrap())).await;
        assert!(client.status(id).await.is_err());
        task.await.unwrap();
    }
    let mut altered = sealed.chunks()[0].clone();
    altered[0] ^= 1;
    for response in [
        ok(&altered),
        ok(&vec![0; altered.len() + 1]),
        b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100\r\n"
            .iter()
            .copied()
            .chain(vec![0; 256])
            .chain(b"\r\n0\r\n\r\n".iter().copied())
            .collect(),
    ] {
        let (client, task) = responder(response).await;
        assert!(client.get(id, &manifest, 0).await.is_err());
        task.await.unwrap();
    }
    let changed = json!({"manifest":Manifest { expires_at: manifest.expires_at+1, ..manifest.clone() },
        "uploaded":[],"complete":false,"upload_until":now()+300});
    let (client, task) = responder(ok(&serde_json::to_vec(&changed).unwrap())).await;
    assert!(client.reserve(id, &manifest).await.is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn client_does_not_forward_credentials_through_redirects() {
    let trap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{}/stolen\r\nContent-Length: 0\r\n\r\n",
        trap.local_addr().unwrap()
    );
    let (client, task) = responder(response.into_bytes()).await;
    assert!(
        client
            .status(&uuid::Uuid::new_v4().to_string())
            .await
            .is_err()
    );
    task.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), trap.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires local Wrangler object storage and GENT_TEST_RELAY_TOKEN_FILE"]
async fn wrangler_transports_encrypted_file_objects_with_endpoint_restart() {
    let token_path = std::env::var("GENT_TEST_RELAY_TOKEN_FILE").unwrap();
    let token = config::read_private(Path::new(&token_path)).unwrap();
    let parent = std::env::var("GENT_FILE_PROOF_ROOT").ok();
    let temporary = if let Some(parent) = parent {
        tempfile::tempdir_in(parent).unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let home = temporary.path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
    config::write_private(&home.join("relay.key"), token.as_bytes()).unwrap();
    let settings = config::RelayConfig {
        endpoint: std::env::var("GENT_TEST_RELAY_URL").unwrap(),
        credential_file: "relay.key".into(),
    };
    let relay = FileRelay::open(&settings, home).unwrap();
    let private = uuid::Uuid::new_v4().to_string();
    let marker = format!("private Gent screenshot pixels {private}");
    let mut original: Vec<u8> = (0..MAX_FILE_BYTES).map(|n| (n % 251) as u8).collect();
    original[..marker.len()].copy_from_slice(marker.as_bytes());
    let sealed = seal(
        &format!("private-{private}.png"),
        &format!("application/x-gent-{private}"),
        &original,
    )
    .unwrap();
    let id = sealed.grant().descriptor().id.clone();
    let expiry = now() + 1800;
    let manifest = sealed.transport_manifest(expiry).unwrap();
    let source_path = home.join("sender.sqlite3");
    let receiver_path = home.join("receiver.sqlite3");
    let mut source = database(&source_path);
    {
        let tx = source
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        Objects::new(&tx, now())
            .unwrap()
            .stage(&sealed, expiry)
            .unwrap();
        tx.commit().unwrap();
    }
    drop(sealed);
    assert!(!relay.reserve(&id, &manifest).await.unwrap().complete);
    // Leave the first relay acknowledgment uncommitted locally, modeling a crash
    // after the remote write. The resumed sender must retry identical ciphertext.
    for index in [0, 127] {
        let tx = source
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let bytes = Objects::new(&tx, now())
            .unwrap()
            .upload_chunk(&id, index)
            .unwrap();
        tx.commit().unwrap();
        relay.put(&id, &manifest, index, &bytes).await.unwrap();
        if index != 0 {
            let tx = source
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            Objects::new(&tx, now())
                .unwrap()
                .acknowledge_upload(&id, index)
                .unwrap();
            tx.commit().unwrap();
        }
    }
    drop(source);
    drop(relay);
    let relay = FileRelay::open(&settings, home).unwrap();
    let mut source = database(&source_path);
    let pending = {
        let tx = source
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            Objects::new(&tx, now())
                .unwrap()
                .transport_manifest(&id)
                .unwrap(),
            manifest
        );
        Objects::new(&tx, now())
            .unwrap()
            .pending_uploads(&id)
            .unwrap()
    };
    assert_eq!(pending.len(), 127);
    for index in pending {
        let bytes = {
            let tx = source
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            Objects::new(&tx, now())
                .unwrap()
                .upload_chunk(&id, index)
                .unwrap()
        };
        relay.put(&id, &manifest, index, &bytes).await.unwrap();
        let tx = source
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        Objects::new(&tx, now())
            .unwrap()
            .acknowledge_upload(&id, index)
            .unwrap();
        tx.commit().unwrap();
    }
    let status = relay.status(&id).await.unwrap().unwrap();
    assert!(status.complete);
    assert_eq!(status.manifest, manifest);
    // Trusted fixture handoff only. Actual agent grants still need their MLS
    // message binding; this test never sends keys or private metadata to HTTP.
    let private_grant = {
        let tx = source
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        Objects::new(&tx, now())
            .unwrap()
            .grant(&id)
            .unwrap()
            .encode_private()
            .unwrap()
    };
    let grant = FileGrant::decode_private(&private_grant).unwrap();
    let mut receiver = database(&receiver_path);
    {
        let tx = receiver
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        Objects::new(&tx, now())
            .unwrap()
            .expect(&grant, expiry)
            .unwrap();
        tx.commit().unwrap();
    }
    for index in [127, 0] {
        let bytes = relay.get(&id, &manifest, index).await.unwrap().unwrap();
        let tx = receiver
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        Objects::new(&tx, now())
            .unwrap()
            .accept_chunk(&id, index, &bytes)
            .unwrap();
        tx.commit().unwrap();
    }
    drop(receiver);
    drop(relay);
    let relay = FileRelay::open(&settings, home).unwrap();
    let mut receiver = database(&receiver_path);
    let missing = {
        let tx = receiver
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let store = Objects::new(&tx, now()).unwrap();
        assert!(store.read(&id).is_err());
        store.missing_chunks(&id).unwrap()
    };
    assert_eq!(missing.len(), 126);
    for index in missing {
        let bytes = relay.get(&id, &manifest, index).await.unwrap().unwrap();
        let tx = receiver
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        Objects::new(&tx, now())
            .unwrap()
            .accept_chunk(&id, index, &bytes)
            .unwrap();
        tx.commit().unwrap();
    }
    {
        let tx = receiver
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let store = Objects::new(&tx, now()).unwrap();
        store.finish(&id).unwrap();
        assert_eq!(*store.read(&id).unwrap(), original);
        tx.commit().unwrap();
    }
    let empty = seal("empty", "application/octet-stream", b"").unwrap();
    let empty_id = &empty.grant().descriptor().id;
    let empty_manifest = empty.transport_manifest(expiry).unwrap();
    relay.reserve(empty_id, &empty_manifest).await.unwrap();
    relay
        .put(empty_id, &empty_manifest, 0, &empty.chunks()[0])
        .await
        .unwrap();
    let bytes = relay
        .get(empty_id, &empty_manifest, 0)
        .await
        .unwrap()
        .unwrap();
    assert!(empty.grant().open(&[bytes]).unwrap().is_empty());
    relay.delete(empty_id).await.unwrap();
    assert!(relay.status(empty_id).await.unwrap().is_none());
    let report = json!({"object_id":id,"bytes":MAX_FILE_BYTES,"chunks":128,"marker":marker,"manifest":manifest});
    config::write_private(
        &home.join("report.json"),
        &serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    if std::env::var_os("GENT_FILE_PROOF_ROOT").is_some() {
        println!(
            "File-object proof retained at {}",
            temporary.keep().display()
        );
    } else {
        relay.delete(&id).await.unwrap();
    }
}
