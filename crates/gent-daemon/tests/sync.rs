use gent_crypto::{NodeIdentity, OwnerKey};
use gent_daemon::{
    config::{self, RelayConfig},
    encrypted::ordered::OrderedEndpoint,
    store::{Store, now},
    sync,
};
use gent_protocol::{OwnerOp, Policy, Request, Response};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use uuid::Uuid;

struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn private_temp() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    home
}
fn ok(response: Response) -> Value {
    match response {
        Response::Ok(v) => v,
        Response::Error(e) => panic!("{e}"),
    }
}
struct Fixture {
    homes: [tempfile::TempDir; 2],
    stores: [Arc<Mutex<Store>>; 2],
    owner: String,
}
impl Fixture {
    fn new(endpoint: &str, token: &str) -> Self {
        let homes = [private_temp(), private_temp()];
        config::initialize(homes[0].path(), "sync").unwrap();
        drop(Store::open(homes[0].path()).unwrap());
        let cfg = config::load(homes[0].path()).unwrap();
        let keyfile = fs::read(homes[0].path().join("identity.key")).unwrap();
        let node =
            NodeIdentity::from_secret_bytes(&cfg.node.id, keyfile[8..40].try_into().unwrap())
                .unwrap();
        let owner_key = OwnerKey::from_secret_bytes(keyfile[40..72].try_into().unwrap());
        let peer = NodeIdentity::generate().unwrap();
        let mut source = OrderedEndpoint::open_runtime(homes[0].path(), &node).unwrap();
        let state = source.authority_state().unwrap();
        let timestamp = now() as u64;
        let request = peer
            .request_enrollment(state.anchor(), state.checkpoint(), "joined-peer", timestamp)
            .unwrap();
        source
            .apply_authority(&[state
                .enroll(
                    &owner_key,
                    &request,
                    request.fingerprint().unwrap(),
                    timestamp,
                )
                .unwrap()])
            .unwrap();
        let current = source.authority_state().unwrap();
        Store::install_joined(homes[1].path(), &peer, &current).unwrap();
        assert!(Store::install_joined(homes[1].path(), &peer, &current).is_err());
        let mut target = OrderedEndpoint::open_runtime(homes[1].path(), &peer).unwrap();
        let kp = target.key_package(Uuid::new_v4(), timestamp).unwrap();
        let invitation = source
            .create_configuration(&owner_key, Uuid::new_v4(), (peer.id(), &kp), timestamp)
            .unwrap();
        target.join_configuration(&invitation, timestamp).unwrap();
        let stored = fs::read(homes[1].path().join("identity.key")).unwrap();
        assert_eq!(&stored[..8], b"GENTKEY2");
        assert!(
            !stored
                .windows(32)
                .any(|window| window == owner_key.expose_secret().as_ref())
        );
        for home in &homes {
            let mut cfg = config::load(home.path()).unwrap();
            cfg.relay = Some(RelayConfig {
                endpoint: endpoint.into(),
                credential_file: "relay.key".into(),
            });
            config::write_private(&home.path().join("relay.key"), token.as_bytes()).unwrap();
            config::save(home.path(), &cfg).unwrap();
        }
        let stores =
            std::array::from_fn(|i| Arc::new(Mutex::new(Store::open(homes[i].path()).unwrap())));
        let owner = config::read_private(&homes[0].path().join("owner.key")).unwrap();
        let peer_owner = config::read_private(&homes[1].path().join("owner.key")).unwrap();
        assert!(matches!(
            stores[1].lock().unwrap().handle(Request::Owner {
                credential: peer_owner,
                action: OwnerOp::Renew
            }),
            Response::Error(_)
        ));
        Self {
            homes,
            stores,
            owner,
        }
    }
    fn start(&self, i: usize) -> Task {
        Task(sync::start(self.stores[i].clone()).unwrap().unwrap())
    }
    fn set(&self, policy: Policy) -> u64 {
        ok(self.stores[0].lock().unwrap().handle(Request::Owner {
            credential: self.owner.clone(),
            action: OwnerOp::SetPolicy { policy },
        }))["revision"]
            .as_u64()
            .unwrap()
    }
    async fn wait_revision(&self, revision: u64) {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if config::load(self.homes[1].path()).unwrap().applied_revision == Some(revision) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("configuration did not propagate automatically");
    }
}
fn policy(label: &str) -> Policy {
    Policy {
        groups: BTreeMap::from([(label.into(), vec![])]),
        ..Default::default()
    }
}

type Mailboxes = Arc<Mutex<BTreeMap<String, Vec<Vec<u8>>>>>;
struct RelayServer {
    endpoint: String,
    token: String,
    mode: Arc<AtomicUsize>,
    data: Mailboxes,
    _task: Task,
}
impl RelayServer {
    async fn start() -> Self {
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

#[tokio::test]
async fn automatic_sync_catches_up_after_outage_and_peer_restart() {
    let relay = RelayServer::start().await;
    let mut f = Fixture::new(&relay.endpoint, &relay.token);
    let source = f.start(0);
    let receiver = f.start(1);
    let revision = f.set(policy("first-private-marker"));
    f.wait_revision(revision).await;
    relay.mode.store(1, Ordering::SeqCst);
    let revision = f.set(policy("during-outage"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_ne!(
        config::load(f.homes[1].path()).unwrap().applied_revision,
        Some(revision)
    );
    drop(receiver);
    let newest = f.set(policy("newest-private-marker"));
    relay.mode.store(0, Ordering::SeqCst);
    f.stores[1] = Arc::new(Mutex::new(Store::open(f.homes[1].path()).unwrap()));
    let _receiver = f.start(1);
    f.wait_revision(newest).await;
    assert_eq!(
        config::load(f.homes[1].path()).unwrap().policy.groups,
        policy("newest-private-marker").groups
    );
    for bytes in relay.data.lock().unwrap().values().flatten() {
        assert!(!String::from_utf8_lossy(bytes).contains("private-marker"));
    }
    // The relay can lose all storage; the sender's retained outbox repairs it.
    drop(source);
    relay.data.lock().unwrap().clear();
    f.stores[0] = Arc::new(Mutex::new(Store::open(f.homes[0].path()).unwrap()));
    let _source = f.start(0);
    let revision = f.set(policy("after-relay-loss"));
    f.wait_revision(revision).await;
}

#[tokio::test]
async fn malicious_relay_positions_and_bytes_cannot_change_configuration() {
    let relay = RelayServer::start().await;
    let f = Fixture::new(&relay.endpoint, &relay.token);
    relay.mode.store(3, Ordering::SeqCst);
    let _source = f.start(0);
    let _receiver = f.start(1);
    let revision = f.set(policy("authenticated"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        config::load(f.homes[1].path()).unwrap().applied_revision,
        Some(1)
    );
    relay.mode.store(2, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        config::load(f.homes[1].path()).unwrap().applied_revision,
        Some(1)
    );
    relay.mode.store(0, Ordering::SeqCst);
    f.wait_revision(revision).await;
}

#[tokio::test]
async fn fragmented_configuration_sync_needs_no_agent_turn() {
    let relay = RelayServer::start().await;
    let f = Fixture::new(&relay.endpoint, &relay.token);
    let _source = f.start(0);
    let _receiver = f.start(1);
    let mut large = Policy::default();
    let members: Vec<_> = (0..4096).map(|_| Uuid::new_v4().to_string()).collect();
    for index in 0..4 {
        large
            .groups
            .insert(format!("private-group-{index}"), members.clone());
    }
    let revision = f.set(large.clone());
    f.wait_revision(revision).await;
    assert_eq!(
        config::load(f.homes[1].path()).unwrap().policy.groups,
        large.groups
    );
}

#[tokio::test]
async fn buffered_configuration_recovers_while_the_relay_is_offline() {
    let relay = RelayServer::start().await;
    let f = Fixture::new(&relay.endpoint, &relay.token);
    let _source = f.start(0);
    let revision = f.set(policy("buffered-before-restart"));
    let packet = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(bytes) = relay
                .data
                .lock()
                .unwrap()
                .values()
                .find_map(|q| q.get(1).cloned())
            {
                break gent_crypto::stream::Packet::decode(&bytes).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let keyfile = fs::read(f.homes[1].path().join("identity.key")).unwrap();
    let cfg = config::load(f.homes[1].path()).unwrap();
    let peer =
        NodeIdentity::from_secret_bytes(&cfg.node.id, keyfile[8..40].try_into().unwrap()).unwrap();
    OrderedEndpoint::open_runtime(f.homes[1].path(), &peer)
        .unwrap()
        .stage_configuration(&packet, now() as u64)
        .unwrap();
    assert_ne!(
        config::load(f.homes[1].path()).unwrap().applied_revision,
        Some(revision)
    );
    relay.mode.store(1, Ordering::SeqCst);
    let _receiver = f.start(1);
    f.wait_revision(revision).await;
}

#[test]
fn relay_configuration_requires_a_private_token_and_safe_origin() {
    for endpoint in [
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com/private",
        "https://example.com/?token=secret",
    ] {
        assert!(
            RelayConfig {
                endpoint: endpoint.into(),
                credential_file: "relay.key".into()
            }
            .validate()
            .is_err()
        );
    }
    let home = private_temp();
    config::initialize(home.path(), "test").unwrap();
    let mut cfg = config::load(home.path()).unwrap();
    cfg.relay = Some(RelayConfig {
        endpoint: "https://gent.link".into(),
        credential_file: "absent.key".into(),
    });
    config::save(home.path(), &cfg).unwrap();
    let store = Arc::new(Mutex::new(Store::open(home.path()).unwrap()));
    assert!(sync::start(store).is_err());
}

#[tokio::test]
#[ignore = "requires the local Wrangler relay and GENT_TEST_RELAY_TOKEN_FILE"]
async fn wrangler_transports_actual_encrypted_configuration() {
    let endpoint = std::env::var("GENT_TEST_RELAY_URL").unwrap();
    let token = config::read_private(std::path::Path::new(
        &std::env::var("GENT_TEST_RELAY_TOKEN_FILE").unwrap(),
    ))
    .unwrap();
    let f = Fixture::new(&endpoint, &token);
    let _source = f.start(0);
    let receiver = f.start(1);
    let first = f.set(policy("wrangler-private-policy"));
    f.wait_revision(first).await;
    drop(receiver);
    let latest = f.set(policy("wrangler-offline-catchup"));
    let _receiver = f.start(1);
    f.wait_revision(latest).await;
}
