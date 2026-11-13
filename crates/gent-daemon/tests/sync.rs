use gent_crypto::{NodeIdentity, OwnerKey};
use gent_daemon::{
    config::{self, RelayConfig},
    encrypted::ordered::OrderedEndpoint,
    store::{Store, now},
    sync,
};
use gent_protocol::{OwnerOp, Policy, Request, Response};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};
use tokio::task::JoinHandle;
#[path = "support/relay.rs"]
mod relay;
use relay::RelayServer;
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
async fn receiver_checkpoints_retire_only_verified_history_and_restore_lost_relay_storage() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use gent_crypto::stream::Packet;
    let relay = RelayServer::start().await;
    let mut f = Fixture::new(&relay.endpoint, &relay.token);
    let source = f.start(0);
    let revision = f.set(policy("checkpoint-private-history"));
    let packet = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(packet) = relay
                .data
                .lock()
                .unwrap()
                .values()
                .filter_map(|q| q.get(1))
                .find_map(|p| Packet::decode(p).ok())
            {
                break packet;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let key = format!("checkpoint/{}", URL_SAFE_NO_PAD.encode(packet.group()));
    let forged = NodeIdentity::generate()
        .unwrap()
        .sign_stream_receipt(packet.group(), packet.sequence(), packet.digest().unwrap())
        .unwrap();
    relay
        .data
        .lock()
        .unwrap()
        .insert(key.clone(), vec![forged.encode().unwrap()]);
    let before = relay.requests.load(Ordering::SeqCst);
    relay.notices.send(relay::Notice::Changed).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while relay.requests.load(Ordering::SeqCst) <= before + 1 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let db = rusqlite::Connection::open(f.homes[0].path().join("state.sqlite3")).unwrap();
    let count = || {
        db.query_row("SELECT COUNT(*) FROM stream_confirmed", [], |r| {
            r.get::<_, u64>(0)
        })
        .unwrap()
    };
    assert_eq!(count(), 0);
    assert!(
        db.query_row(
            "SELECT length(packet)>0 FROM stream_outbox WHERE group_id=?1 AND sequence=?2",
            rusqlite::params![packet.group(), packet.sequence()],
            |r| r.get::<_, bool>(0)
        )
        .unwrap()
    );
    relay.data.lock().unwrap().remove(&key);
    let receiver = f.start(1);
    f.wait_revision(revision).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !db
            .query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM stream_outbox WHERE group_id=?1 AND sequence=?2)",
                rusqlite::params![packet.group(), packet.sequence()],
                |r| r.get::<_, bool>(0),
            )
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert!(count() > 0);
    drop(receiver);
    drop(source);
    relay.data.lock().unwrap().clear();
    // Both daemons reopen their own committed state after relay loss.
    f.stores =
        std::array::from_fn(|i| Arc::new(Mutex::new(Store::open(f.homes[i].path()).unwrap())));
    let _source = f.start(0);
    let _receiver = f.start(1);
    let revision = f.set(policy("checkpoint-after-loss"));
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
    let token_path = home.path().join("transport.key");
    let token = format!("gent_t1.{}.{}", now(), "ab".repeat(32));
    config::write_private(&token_path, token.as_bytes()).unwrap();
    assert_eq!(config::read_relay_credential(&token_path).unwrap(), token);
    assert!(config::read_private(&token_path).is_err());
    config::write_private(&token_path, token.replace("gent_t1", "gent_s1").as_bytes()).unwrap();
    assert!(config::read_relay_credential(&token_path).is_err());
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
    let token = config::read_relay_credential(std::path::Path::new(
        &std::env::var("GENT_TEST_RELAY_TOKEN_FILE").unwrap(),
    ))
    .unwrap();
    let f = Fixture::new(&endpoint, &token);
    if let Ok(path) = std::env::var("GENT_TEST_RELAY_PEER_TOKEN_FILE") {
        let peer = config::read_relay_credential(std::path::Path::new(&path)).unwrap();
        assert!(
            peer != token,
            "per-node proof requires distinct credentials"
        );
        config::write_private(&f.homes[1].path().join("relay.key"), peer.as_bytes()).unwrap();
    }
    let _source = f.start(0);
    let receiver = f.start(1);
    let first = f.set(policy("wrangler-private-policy"));
    f.wait_revision(first).await;
    drop(receiver);
    let latest = f.set(policy("wrangler-offline-catchup"));
    let _receiver = f.start(1);
    f.wait_revision(latest).await;
}

async fn wait_watchers(relay: &RelayServer, expected: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while relay.watching.load(Ordering::SeqCst) != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("notification connections did not settle");
}

#[tokio::test]
async fn push_applies_newest_configuration_without_idle_mailbox_polling() {
    let relay = RelayServer::start().await;
    let f = Fixture::new(&relay.endpoint, &relay.token);
    let _source = f.start(0);
    let _receiver = f.start(1);
    wait_watchers(&relay, 2).await;
    let revision = f.set(policy("initial-push"));
    f.wait_revision(revision).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let requests = relay.requests.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        relay.requests.load(Ordering::SeqCst),
        requests,
        "idle push connection must not poll mailboxes every second"
    );
    f.set(policy("replaced"));
    let newest = f.set(policy("newest-push"));
    tokio::time::timeout(Duration::from_secs(2), f.wait_revision(newest))
        .await
        .expect("configuration waited for periodic reconciliation");
    assert_eq!(
        config::load(f.homes[1].path()).unwrap().policy.groups,
        policy("newest-push").groups
    );
    drop(_receiver);
    wait_watchers(&relay, 1).await;
    drop(_source);
    wait_watchers(&relay, 0).await;
}

#[tokio::test]
async fn reconnect_reconciles_packets_whose_notifications_were_lost() {
    let relay = RelayServer::start().await;
    let f = Fixture::new(&relay.endpoint, &relay.token);
    let _source = f.start(0);
    let _receiver = f.start(1);
    wait_watchers(&relay, 2).await;
    let initial = f.set(policy("before-lost-hint"));
    f.wait_revision(initial).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let count = relay
        .data
        .lock()
        .unwrap()
        .values()
        .map(Vec::len)
        .sum::<usize>();
    relay.mode.store(5, Ordering::SeqCst); // HTTP works; push hints are dropped.
    let next = f.set(policy("stored-without-hint"));
    tokio::time::timeout(Duration::from_secs(2), async {
        while relay
            .data
            .lock()
            .unwrap()
            .values()
            .map(Vec::len)
            .sum::<usize>()
            <= count
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        config::load(f.homes[1].path()).unwrap().applied_revision,
        Some(initial)
    );
    relay.notices.send(relay::Notice::Close).unwrap();
    relay.mode.store(0, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(5), f.wait_revision(next))
        .await
        .unwrap();
    wait_watchers(&relay, 2).await;
}

#[tokio::test]
async fn invalid_push_cannot_change_authority_and_polling_recovers_without_websockets() {
    let relay = RelayServer::start().await;
    let f = Fixture::new(&relay.endpoint, &relay.token);
    let _source = f.start(0);
    let _receiver = f.start(1);
    wait_watchers(&relay, 2).await;
    let initial = f.set(policy("verified-only"));
    f.wait_revision(initial).await;
    for invalid in [
        r#"{"version":1,"event":"changed","revision":99999}"#.to_owned(),
        "x".repeat(2048),
    ] {
        relay.mode.store(4, Ordering::SeqCst); // Disable replacement push channels.
        relay.notices.send(relay::Notice::Text(invalid)).unwrap();
        wait_watchers(&relay, 0).await;
        assert_eq!(
            config::load(f.homes[1].path()).unwrap().applied_revision,
            Some(initial)
        );
        relay.mode.store(0, Ordering::SeqCst);
        wait_watchers(&relay, 2).await;
    }
    relay.mode.store(4, Ordering::SeqCst);
    relay.notices.send(relay::Notice::Close).unwrap();
    wait_watchers(&relay, 0).await;
    let next = f.set(policy("fallback"));
    tokio::time::timeout(Duration::from_secs(5), f.wait_revision(next))
        .await
        .unwrap();
    drop(_source);
    drop(_receiver);
    wait_watchers(&relay, 0).await;
}
