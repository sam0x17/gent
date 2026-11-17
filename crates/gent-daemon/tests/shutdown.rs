use gent_daemon::{DaemonLock, config, request, run_locked};
use gent_protocol::{AgentOp, OwnerOp, Request, Response};
use std::{os::unix::fs::PermissionsExt, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

#[tokio::test]
async fn shutdown_drains_accepted_frames_before_releasing_ownership() {
    let home = tempfile::Builder::new()
        .prefix("gent-drain-")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    config::private_dir(home.path()).unwrap();
    config::initialize(home.path(), "drain").unwrap();
    let owner_key = config::read_private(&home.path().join("owner.key")).unwrap();
    let lock = DaemonLock::acquire(home.path()).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let daemon = tokio::spawn(run_locked(lock, async {
        stopped.await.unwrap();
    }));
    let status = || Request::Owner {
        credential: owner_key.clone(),
        action: OwnerOp::Status,
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        while request(home.path(), status()).await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(DaemonLock::acquire(home.path()).is_err());
    let key = config::secret();
    let registration = Request::Agent {
        credential: key.clone(),
        action: AgentOp::Register {
            name: "accepted-before-update".into(),
            provider: "test".into(),
        },
    };
    let mut connection = UnixStream::connect(home.path().join("daemon.sock"))
        .await
        .unwrap();
    connection
        .write_all(&serde_json::to_vec(&registration).unwrap())
        .await
        .unwrap();
    // A later connection responds, so the earlier frame has been accepted.
    request(home.path(), status()).await.unwrap();
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while home.path().join("daemon.sock").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(DaemonLock::acquire(home.path()).is_err());
    connection.write_all(b"\n").await.unwrap();
    let mut response = String::new();
    BufReader::new(connection)
        .read_line(&mut response)
        .await
        .unwrap();
    let Response::Ok(registered) = serde_json::from_str(&response).unwrap() else {
        panic!("registration failed")
    };
    tokio::time::timeout(Duration::from_secs(5), daemon)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let _lock = DaemonLock::acquire(home.path()).unwrap();
    let mut store = gent_daemon::store::Store::open(home.path()).unwrap();
    let Response::Ok(identity) = store.handle(Request::Agent {
        credential: key,
        action: AgentOp::Identity,
    }) else {
        panic!("lost registration")
    };
    assert_eq!(registered["agent"]["id"], identity["agent"]["id"]);
}
