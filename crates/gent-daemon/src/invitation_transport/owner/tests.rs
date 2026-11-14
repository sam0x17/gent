use super::super::{
    joining::Joining,
    tests::{Fixture, token},
};
use super::*;
use crate::{
    config,
    pairing::{self, Peer, ServiceRelay},
    store::{
        invitations::{Action, Invocation},
        now,
    },
};
use gent_crypto::{NodeIdentity, invitation::Invitation};
use gent_protocol::PairingOp;
use serde_json::{Value, json};
use std::{fs, path::Path};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use uuid::Uuid;
mod service;

type Key = (String, String, String, u64);
#[derive(Default)]
struct State {
    messages: BTreeMap<Key, Vec<u8>>,
    writes: BTreeMap<Key, usize>,
    drop_once: BTreeSet<(String, u64)>,
    hide_owner: Option<u64>,
    deny: bool,
    corrupt_once: Option<u64>,
    gets: usize,
}
struct Relay {
    origin: String,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Relay {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let shared = state.clone();
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let (socket, _) = incoming.unwrap(); let state = shared.clone();
                        children.spawn(async move { let _ = tokio::time::timeout(Duration::from_secs(10), serve(socket, state)).await; });
                    }
                    _ = children.join_next(), if !children.is_empty() => {}
                }
            }
        });
        Self {
            origin,
            state,
            task,
        }
    }
}
async fn serve(mut socket: tokio::net::TcpStream, state: Arc<Mutex<State>>) -> Result<()> {
    let mut bytes = Vec::new();
    let end = loop {
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        ensure!(bytes.len() < 16384, "test request header too large");
        let mut part = [0; 4096];
        let n = socket.read(&mut part).await?;
        ensure!(n > 0, "closed test request");
        bytes.extend_from_slice(&part[..n]);
    };
    let headers = String::from_utf8(bytes[..end].to_vec())?;
    let length = headers
        .lines()
        .find_map(|h| {
            h.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(str::parse::<usize>)
        })
        .transpose()?
        .unwrap_or(0);
    ensure!(
        length <= super::super::protocol::MAX_WIRE_BYTES,
        "test request body too large"
    );
    while bytes.len() < end + length {
        let mut part = [0; 8192];
        let n = socket.read(&mut part).await?;
        ensure!(n > 0, "closed test body");
        bytes.extend_from_slice(&part[..n]);
    }
    let first: Vec<_> = headers.lines().next().unwrap().split(' ').collect();
    let fields: Vec<_> = first[1].split('/').collect();
    let role = if headers.contains("Bearer gent_t1.") {
        "owner"
    } else if headers.contains("Bearer gent_j1.") {
        "join"
    } else {
        "invalid"
    };
    let response = {
        let mut state = state.lock().unwrap();
        if state.deny || role == "invalid" {
            Some((401, Vec::new()))
        } else if fields.len() == 5 && fields[4] == "attempts" && role == "owner" {
            let mut attempts = BTreeMap::<String, [u64; 2]>::new();
            for (id, attempt, side, index) in state.messages.keys() {
                if id == fields[3] {
                    attempts.entry(attempt.clone()).or_default()[usize::from(side == "owner")] =
                        index + 1;
                }
            }
            let attempts: BTreeMap<_, _> = attempts
                .into_iter()
                .map(|(id, next)| (id, json!({"next":next})))
                .collect();
            let expires = super::super::protocol::issued_at(fields[3]).unwrap() + 900;
            Some((
                200,
                serde_json::to_vec(&json!({"attempts":attempts,"expires_at":expires}))?,
            ))
        } else if fields.len() == 7 {
            let index: u64 = fields[6].parse()?;
            let key = (fields[3].into(), fields[4].into(), fields[5].into(), index);
            if (first[0] == "PUT") != (role == fields[5]) {
                Some((403, Vec::new()))
            } else if first[0] == "PUT" {
                let body = bytes[end..].to_vec();
                *state.writes.entry(key.clone()).or_default() += 1;
                if state.messages.get(&key).is_some_and(|old| *old != body) {
                    Some((409, Vec::new()))
                } else {
                    state.messages.insert(key, body);
                    if state.drop_once.remove(&(fields[5].into(), index)) {
                        None
                    } else {
                        Some((204, Vec::new()))
                    }
                }
            } else {
                state.gets += 1;
                if fields[5] == "owner" && state.hide_owner == Some(index) {
                    Some((404, Vec::new()))
                } else if let Some(mut body) = state.messages.get(&key).cloned() {
                    if fields[5] == "owner" && state.corrupt_once == Some(index) {
                        state.corrupt_once = None;
                        *body.last_mut().unwrap() ^= 1;
                    }
                    Some((200, body))
                } else {
                    Some((404, Vec::new()))
                }
            }
        } else {
            Some((400, Vec::new()))
        }
    };
    if let Some((status, body)) = response {
        let header = format!(
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(header.as_bytes()).await?;
        socket.write_all(&body).await?;
    }
    Ok(())
}

fn request(action: PairingOp) -> Invocation {
    Invocation {
        id: Uuid::new_v4().to_string(),
        action: Action::Pair { action },
    }
}
fn client(invitation: &Invitation, node: &NodeIdentity) -> Joining {
    let mut client = Joining::new(
        Invitation::decode(&invitation.encode().unwrap()).unwrap(),
        &token(Side::Join),
    )
    .unwrap();
    client.prepare_node(node, "joined").unwrap();
    client.short_wait();
    client
}
async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn lost_upload_acknowledgments_retry_identical_ciphertext_in_both_directions() {
    let relay = Relay::new().await;
    relay.state.lock().unwrap().drop_once.extend([
        ("join".into(), 0),
        ("owner".into(), 0),
        ("join".into(), 1),
        ("owner".into(), 1),
        ("join".into(), 2),
        ("owner".into(), 2),
    ]);
    let Fixture {
        _home,
        store,
        invitation,
    } = Fixture::new(&relay.origin);
    let store = Arc::new(Mutex::new(store));
    let worker = start(store);
    let node = NodeIdentity::generate().unwrap();
    let mut client = client(&invitation, &node);
    let value = client.invoke(&request(PairingOp::Snapshot)).await.unwrap();
    assert_eq!(
        value["anchor"]["cluster_id"],
        invitation.offer().offer.anchor.cluster_id
    );
    assert!(value["relay"].is_null());
    until(|| relay.state.lock().unwrap().writes.values().all(|n| *n >= 2)).await;
    {
        let state = relay.state.lock().unwrap();
        assert_eq!(
            state
                .messages
                .keys()
                .map(|(_, a, _, _)| a)
                .collect::<BTreeSet<_>>()
                .len(),
            1
        );
        assert_eq!(state.messages.len(), 6);
        assert!(state.writes.values().all(|n| *n >= 2));
    }
    worker.stop().await;
}

#[tokio::test]
async fn owner_restart_after_committed_enrollment_resumes_with_a_fresh_attempt() {
    let relay = Relay::new().await;
    let Fixture {
        _home,
        store,
        invitation,
    } = Fixture::new(&relay.origin);
    let store = Arc::new(Mutex::new(store));
    let worker = start(store.clone());
    let node = NodeIdentity::generate().unwrap();
    let mut client = client(&invitation, &node);
    let snapshot: pairing::Snapshot =
        serde_json::from_value(client.invoke(&request(PairingOp::Snapshot)).await.unwrap())
            .unwrap();
    let enrollment = node
        .request_enrollment(
            &snapshot.anchor,
            &snapshot.checkpoint,
            "joined",
            now() as u64,
        )
        .unwrap();
    use base64::Engine;
    let enroll = request(PairingOp::Enroll {
        request: base64::engine::general_purpose::STANDARD.encode(enrollment.encode().unwrap()),
    });
    relay.state.lock().unwrap().hide_owner = Some(3);
    let pending = tokio::spawn(async move {
        let result = client.invoke(&enroll).await;
        (client, result)
    });
    until(|| {
        relay
            .state
            .lock()
            .unwrap()
            .messages
            .keys()
            .any(|(_, _, s, i)| s == "owner" && *i == 3)
    })
    .await;
    let old_attempts: BTreeSet<_> = relay
        .state
        .lock()
        .unwrap()
        .messages
        .keys()
        .map(|(_, a, _, _)| a.clone())
        .collect();
    worker.stop().await;
    *store.lock().unwrap() = Store::open(_home.path()).unwrap();
    let worker = start(store.clone());
    // Keep the old receipt unavailable. The new attempt resends the exact
    // invocation at index 2 and recovers the already committed enrollment.
    let (mut client, result) = pending.await.unwrap();
    let enrolled = result.unwrap();
    assert!(enrolled["state"].is_string());
    relay.state.lock().unwrap().hide_owner = None;
    let snapshot: pairing::Snapshot =
        serde_json::from_value(client.invoke(&request(PairingOp::Snapshot)).await.unwrap())
            .unwrap();
    use base64::engine::general_purpose::STANDARD;
    let signed =
        gent_crypto::SignedState::decode(&STANDARD.decode(snapshot.state).unwrap()).unwrap();
    let state =
        gent_crypto::VerifiedState::restore(snapshot.anchor, snapshot.checkpoint, signed).unwrap();
    assert_eq!(state.state().nodes.len(), 2);
    assert_eq!(
        state.state().nodes[node.id()].signing_key,
        node.public_key()
    );
    let attempts: BTreeSet<_> = relay
        .state
        .lock()
        .unwrap()
        .messages
        .keys()
        .map(|(_, a, _, _)| a.clone())
        .collect();
    assert!(attempts.len() > old_attempts.len());
    for id in old_attempts {
        assert!(
            store
                .lock()
                .unwrap()
                .invitation_attempt_seen(&invitation.offer().offer.id, &id)
                .unwrap()
        );
    }
    worker.stop().await;
}

#[tokio::test]
async fn cancelled_joining_future_and_corrupt_ciphertext_never_rewind_a_live_channel() {
    let relay = Relay::new().await;
    let Fixture {
        _home,
        store,
        invitation,
    } = Fixture::new(&relay.origin);
    let worker = start(Arc::new(Mutex::new(store)));
    let node = NodeIdentity::generate().unwrap();
    let mut client = client(&invitation, &node);
    client.invoke(&request(PairingOp::Snapshot)).await.unwrap();
    let same = request(PairingOp::Snapshot);
    relay.state.lock().unwrap().hide_owner = Some(3);
    assert!(
        tokio::time::timeout(Duration::from_millis(800), client.invoke(&same))
            .await
            .is_err()
    );
    relay.state.lock().unwrap().hide_owner = None;
    client.invoke(&same).await.unwrap();
    relay.state.lock().unwrap().corrupt_once = Some(3);
    client.invoke(&request(PairingOp::Snapshot)).await.unwrap();
    let attempts: BTreeSet<_> = relay
        .state
        .lock()
        .unwrap()
        .messages
        .keys()
        .map(|(_, a, _, _)| a.clone())
        .collect();
    assert!(attempts.len() >= 3);
    worker.stop().await;
}

struct NativePeer {
    client: Joining,
    ids: BTreeMap<Vec<u8>, String>,
}
impl Peer for NativePeer {
    async fn prepare_node(&mut self, node: &NodeIdentity, name: &str) -> Result<()> {
        self.client.prepare_node(node, name)
    }
    async fn call(&mut self, action: PairingOp) -> Result<Value> {
        let id = self
            .ids
            .entry(serde_jcs::to_vec(&action)?)
            .or_insert_with(|| Uuid::new_v4().to_string())
            .clone();
        self.client
            .invoke(&Invocation {
                id,
                action: Action::Pair { action },
            })
            .await
    }
    async fn prepare_service(&mut self, service: &ServiceRelay) -> Result<()> {
        let offered = &self.client.offer().offer.service;
        ensure!(
            service.account.account_id == offered.account_id
                && service.account.origin.trim_end_matches('/') == offered.account_origin
                && service.relay_endpoint.trim_end_matches('/') == offered.relay_origin,
            "service changed"
        );
        Ok(())
    }
    // Account provisioning remains synthetic in this native HTTP fixture.
    async fn provision_service(
        &mut self,
        runtime: &Path,
        _home: &Path,
        service: &ServiceRelay,
    ) -> Result<()> {
        let mut cfg = config::load(runtime)?;
        cfg.cluster.local_only = false;
        cfg.service = Some(service.account.clone());
        cfg.relay = Some(config::RelayConfig {
            endpoint: service.relay_endpoint.clone(),
            credential_file: "relay.key".into(),
        });
        config::write_private(&runtime.join("relay.key"), token(Side::Owner).as_bytes())?;
        config::save(runtime, &cfg)
    }
}

#[tokio::test]
async fn staged_pairing_and_exact_finish_receipt_use_the_background_driver() {
    let relay = Relay::new().await;
    let Fixture {
        _home,
        store,
        invitation,
    } = Fixture::new(&relay.origin);
    let worker = start(Arc::new(Mutex::new(store)));
    let cluster = invitation.offer().offer.anchor.cluster_id.clone();
    let mut peer = NativePeer {
        client: Joining::new(invitation, &token(Side::Join)).unwrap(),
        ids: BTreeMap::new(),
    };
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("joined");
    let result = pairing::join(
        &home,
        pairing::Options {
            replace_node: None,
            cluster: &cluster,
            name: "joined",
            relay_endpoint: None,
        },
        &mut peer,
    )
    .await
    .unwrap();
    assert_eq!(result["joined"], true);
    assert_eq!(
        &fs::read(home.join("identity.key")).unwrap()[..8],
        b"GENTKEY2"
    );
    let finish = Invocation {
        id: Uuid::new_v4().to_string(),
        action: Action::Finish,
    };
    let receipt = peer.client.invoke(&finish).await.unwrap();
    assert_eq!(receipt["finished"], true);
    assert_eq!(peer.client.invoke(&finish).await.unwrap(), receipt);
    assert!(
        peer.client
            .invoke(&request(PairingOp::Snapshot))
            .await
            .is_err()
    );
    worker.stop().await;
}

#[tokio::test]
async fn native_revocation_closes_cached_responses_and_service_denial_stops_joining() {
    let relay = Relay::new().await;
    let Fixture {
        _home,
        store,
        invitation,
    } = Fixture::new(&relay.origin);
    let shared = Arc::new(Mutex::new(store));
    let node = NodeIdentity::generate().unwrap();
    let mut client = client(&invitation, &node);
    let worker = start(shared.clone());
    client.invoke(&request(PairingOp::Snapshot)).await.unwrap();
    let owner = config::read_private(&_home.path().join("owner.key")).unwrap();
    shared
        .lock()
        .unwrap()
        .revoke_invitation(&owner, &invitation.offer().offer.id)
        .unwrap();
    relay.state.lock().unwrap().deny = true;
    let before = Instant::now();
    assert!(client.invoke(&request(PairingOp::Snapshot)).await.is_err());
    assert!(before.elapsed() < Duration::from_secs(2));
    let mut scheduler = Scheduler::new();
    scheduler.tick(shared).await.unwrap();
    assert!(scheduler.owners.is_empty());
    worker.stop().await;
}

#[tokio::test]
async fn admission_has_global_and_per_invitation_limits_and_releases_expired_slots() {
    let relay = Relay::new().await;
    let Fixture {
        _home,
        mut store,
        invitation,
    } = Fixture::new(&relay.origin);
    let credential = config::read_private(&_home.path().join("owner.key")).unwrap();
    let mut invitations = vec![invitation];
    for _ in 0..4 {
        let invitation = Invitation::decode(
            &store
                .create_invitation(&credential, &Uuid::now_v7().to_string(), false, None)
                .unwrap(),
        )
        .unwrap();
        store
            .activate_invitation(&credential, &invitation.offer().offer.id)
            .unwrap();
        invitations.push(invitation);
    }
    for invitation in &invitations {
        let mailbox = Mailbox::new(invitation.offer(), Side::Join, &token(Side::Join)).unwrap();
        for _ in 0..3 {
            let (_, hello) =
                gent_crypto::invitation::channel::Initiator::start(invitation, now() as u64)
                    .unwrap();
            mailbox
                .put(
                    &hello.attempt,
                    0,
                    &Envelope::Handshake(hello.noise.try_into().unwrap()),
                )
                .await
                .unwrap();
        }
    }
    let shared = Arc::new(Mutex::new(store));
    let mut scheduler = Scheduler::new();
    for _ in 0..6 {
        scheduler.tick(shared.clone()).await.unwrap();
    }
    assert_eq!(scheduler.slots.available_permits(), 0);
    assert_eq!(
        scheduler
            .owners
            .values()
            .map(|o| o.live.len())
            .sum::<usize>(),
        MAX_SESSIONS
    );
    assert!(
        scheduler
            .owners
            .values()
            .all(|o| o.live.len() <= MAX_PER_INVITATION)
    );
    let mut expired = Vec::new();
    for (id, owner) in &mut scheduler.owners {
        for (attempt, live) in &mut owner.live {
            expired.push((id.clone(), attempt.clone()));
            live.last_input = Instant::now() - Duration::from_secs(IDLE_SECONDS + 1);
        }
        owner.retry_at = Instant::now();
    }
    scheduler.tick(shared.clone()).await.unwrap();
    for (id, attempt) in expired {
        assert!(!scheduler.owners[&id].live.contains_key(&attempt));
        assert!(
            shared
                .lock()
                .unwrap()
                .invitation_attempt_seen(&id, &attempt)
                .unwrap()
        );
    }
    assert!(
        scheduler
            .owners
            .values()
            .map(|o| o.live.len())
            .sum::<usize>()
            <= MAX_SESSIONS
    );
    for invitation in invitations {
        shared
            .lock()
            .unwrap()
            .revoke_invitation(&credential, &invitation.offer().offer.id)
            .unwrap();
    }
    scheduler.tick(shared).await.unwrap();
    assert!(scheduler.owners.is_empty());
    assert_eq!(scheduler.slots.available_permits(), MAX_SESSIONS);
}

#[tokio::test]
async fn local_revocation_prevents_a_cached_handshake_upload_without_service_revocation() {
    let relay = Relay::new().await;
    let Fixture {
        _home,
        store,
        invitation,
    } = Fixture::new(&relay.origin);
    let shared = Arc::new(Mutex::new(store));
    let (_, hello) =
        gent_crypto::invitation::channel::Initiator::start(&invitation, now() as u64).unwrap();
    let mailbox = Mailbox::new(invitation.offer(), Side::Join, &token(Side::Join)).unwrap();
    mailbox
        .put(
            &hello.attempt,
            0,
            &Envelope::Handshake(hello.noise.try_into().unwrap()),
        )
        .await
        .unwrap();
    let mut owner = Owner::new(invitation.offer().clone(), &token(Side::Owner)).unwrap();
    let slots = Arc::new(Semaphore::new(MAX_SESSIONS));
    owner.tick(shared.clone(), slots.clone()).await.unwrap();
    assert_eq!(owner.live.len(), 1);
    let credential = config::read_private(&_home.path().join("owner.key")).unwrap();
    shared
        .lock()
        .unwrap()
        .revoke_invitation(&credential, &invitation.offer().offer.id)
        .unwrap();
    assert!(owner.tick(shared, slots).await.is_err());
    assert!(
        relay
            .state
            .lock()
            .unwrap()
            .messages
            .keys()
            .all(|(_, _, side, _)| side == "join")
    );
}

#[tokio::test]
async fn malformed_hello_cannot_block_later_attempts_or_consume_native_admission() {
    let relay = Relay::new().await;
    let Fixture {
        _home,
        store,
        invitation,
    } = Fixture::new(&relay.origin);
    let shared = Arc::new(Mutex::new(store));
    let bad = "00000000-0000-4000-8000-000000000001";
    relay.state.lock().unwrap().messages.insert(
        (
            invitation.offer().offer.id.clone(),
            bad.into(),
            "join".into(),
            0,
        ),
        b"malformed".to_vec(),
    );
    let worker = start(shared.clone());
    let mut client = client(&invitation, &NodeIdentity::generate().unwrap());
    client.invoke(&request(PairingOp::Snapshot)).await.unwrap();
    assert!(
        !shared
            .lock()
            .unwrap()
            .invitation_attempt_seen(&invitation.offer().offer.id, bad)
            .unwrap()
    );
    assert!(
        !relay
            .state
            .lock()
            .unwrap()
            .messages
            .keys()
            .any(|(_, a, s, _)| a == bad && s == "owner")
    );
    worker.stop().await;
}
