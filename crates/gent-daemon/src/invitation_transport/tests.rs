use super::*;
use crate::{
    config,
    store::{
        Store,
        invitations::{Action, Invocation},
    },
};
use gent_crypto::{
    NodeIdentity,
    invitation::{
        Invitation,
        channel::{Initiator, MAX_MESSAGE_BYTES},
    },
};
use gent_protocol::{PairingOp, Response};
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use uuid::Uuid;

pub(super) struct Fixture {
    pub(super) _home: tempfile::TempDir,
    pub(super) store: Store,
    pub(super) invitation: Invitation,
}
impl Fixture {
    pub(super) fn new(origin: &str) -> Self {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut cfg = config::initialize(home.path(), "invitation-wire").unwrap();
        cfg.cluster.local_only = false;
        cfg.service = Some(config::ServiceConfig {
            origin: if origin.starts_with("https:") {
                "https://accounts.example/".into()
            } else {
                "http://127.0.0.1:1/".into()
            },
            account_id: Uuid::new_v4().to_string(),
        });
        cfg.relay = Some(config::RelayConfig {
            endpoint: origin.into(),
            credential_file: "relay.key".into(),
        });
        config::write_private(
            &home.path().join("relay.key"),
            token(Side::Owner).as_bytes(),
        )
        .unwrap();
        config::save(home.path(), &cfg).unwrap();
        let mut store = Store::open(home.path()).unwrap();
        let credential = config::read_private(&home.path().join("owner.key")).unwrap();
        let invitation = Invitation::decode(
            &store
                .create_invitation(&credential, &Uuid::now_v7().to_string(), true, None)
                .unwrap(),
        )
        .unwrap();
        store
            .activate_invitation(&credential, &invitation.offer().offer.id)
            .unwrap();
        Self {
            _home: home,
            store,
            invitation,
        }
    }
    fn mailbox(&self, side: Side) -> Mailbox {
        Mailbox::new(self.invitation.offer(), side, &token(side)).unwrap()
    }
}
pub(super) fn token(side: Side) -> String {
    format!(
        "{}.{}.{}",
        if side == Side::Owner {
            "gent_t1"
        } else {
            "gent_j1"
        },
        now(),
        "ab".repeat(32)
    )
}

#[test]
fn real_noise_records_fit_wire_limits_and_preserve_encrypted_snapshot_and_maximum_messages() {
    let mut fixture = Fixture::new("https://relay.example");
    let (init, hello) = Initiator::start(&fixture.invitation, now() as u64).unwrap();
    let packed = Envelope::Handshake(hello.noise.as_slice().try_into().unwrap())
        .encode()
        .unwrap();
    assert_eq!(packed.len(), 57);
    let Envelope::Handshake(noise) = Envelope::decode(&packed).unwrap() else {
        panic!()
    };
    let hello = gent_crypto::invitation::channel::Hello {
        attempt: hello.attempt,
        noise: noise.to_vec(),
    };
    let (pending, reply) = fixture
        .store
        .begin_invitation(&fixture.invitation.offer().offer.id, &hello)
        .unwrap();
    let node = NodeIdentity::generate().unwrap();
    let (mut channel, claim) = init.finish(&reply, &node, "joined", now() as u64).unwrap();
    let mut session = fixture.store.accept_invitation(pending, &claim).unwrap();
    let request = Invocation {
        id: Uuid::new_v4().to_string(),
        action: Action::Pair {
            action: PairingOp::Snapshot,
        },
    };
    let mut payloads = vec![request.encode().unwrap().to_vec()];
    for size in [0, 1, 65_509, 65_510, 65_511, MAX_MESSAGE_BYTES] {
        payloads.push(vec![b'x'; size]);
    }
    for (i, bytes) in payloads.iter().enumerate() {
        let sealed = channel.seal(bytes, now() as u64).unwrap();
        let envelope = Envelope::Frames(sealed);
        let wire = envelope.encode().unwrap();
        assert!(wire.len() <= protocol::MAX_WIRE_BYTES);
        assert!(Envelope::decode(&wire).unwrap() == envelope);
        let Envelope::Frames(frames) = Envelope::decode(&wire).unwrap() else {
            panic!()
        };
        let reply = fixture
            .store
            .invitation_call(&mut session, &frames)
            .unwrap();
        let wire = Envelope::Frames(reply).encode().unwrap();
        let Envelope::Frames(frames) = Envelope::decode(&wire).unwrap() else {
            panic!()
        };
        let response: Response =
            serde_json::from_slice(&channel.open(&frames, now() as u64).unwrap()).unwrap();
        if i == 0 {
            let Response::Ok(snapshot) = response else {
                panic!()
            };
            assert!(snapshot["relay"].is_null());
            assert_eq!(
                snapshot["anchor"]["cluster_id"],
                fixture.invitation.offer().offer.anchor.cluster_id
            );
        } else {
            assert!(matches!(response, Response::Error(_)));
        }
    }
}

#[test]
fn envelope_rejects_truncation_trailing_bytes_versions_counts_and_sizes() {
    let valid = [
        Envelope::Handshake([7; 48]),
        Envelope::Frames(vec![vec![8; 25], vec![9; 500]]),
    ];
    for value in valid {
        let wire = value.encode().unwrap();
        for end in 0..wire.len() {
            assert!(Envelope::decode(&wire[..end]).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(Envelope::decode(&trailing).is_err());
        for index in [0, 7, 8] {
            let mut changed = wire.clone();
            changed[index] = 255;
            assert!(Envelope::decode(&changed).is_err());
        }
    }
    for frames in [
        vec![],
        vec![vec![0; 24]],
        vec![vec![0; 65_536]],
        vec![vec![0; 25]; 98],
        vec![vec![0; 65_535]; 97],
    ] {
        assert!(Envelope::Frames(frames).encode().is_err());
    }
    let mut wire = Envelope::Frames(vec![vec![0; 25]]).encode().unwrap();
    for count in [0u16, 98, u16::MAX] {
        wire[9..11].copy_from_slice(&count.to_be_bytes());
        assert!(Envelope::decode(&wire).is_err());
    }
    assert!(Envelope::decode(&vec![0; protocol::MAX_WIRE_BYTES + 1]).is_err());
}

struct Captured {
    line: String,
    headers: String,
    body: Vec<u8>,
}
async fn responder(listener: TcpListener, responses: Vec<Option<Vec<u8>>>) -> Vec<Captured> {
    let mut captured = Vec::new();
    for response in responses {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let end = loop {
            if let Some(offset) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break offset + 4;
            }
            assert!(bytes.len() < 8192);
            let mut part = [0; 4096];
            let n = socket.read(&mut part).await.unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&part[..n]);
        };
        let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(|v| v.parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        assert!(length <= protocol::MAX_WIRE_BYTES);
        while bytes.len() < end + length {
            let mut part = [0; 8192];
            let n = socket.read(&mut part).await.unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&part[..n]);
        }
        captured.push(Captured {
            line: headers.lines().next().unwrap().into(),
            headers,
            body: bytes[end..].to_vec(),
        });
        if let Some(response) = response {
            let _ = socket.write_all(&response).await;
        }
    }
    captured
}
fn response(status: &str, body: &[u8]) -> Vec<u8> {
    [
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes(),
        body.to_vec(),
    ]
    .concat()
}
async fn setup(
    responses: Vec<Option<Vec<u8>>>,
) -> (Fixture, tokio::task::JoinHandle<Vec<Captured>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    (fixture, tokio::spawn(responder(listener, responses)))
}

#[tokio::test]
async fn http_retries_preserve_exact_bytes_and_constrain_credential_directions() {
    let envelope = Envelope::Frames(vec![vec![13; 300]]);
    let wire = envelope.encode().unwrap();
    let (fixture, task) = setup(vec![
        None,
        Some(response("204 No Content", b"")),
        Some(response("200 OK", &wire)),
        Some(response("404 Not Found", b"missing")),
    ])
    .await;
    let join = fixture.mailbox(Side::Join);
    let owner = fixture.mailbox(Side::Owner);
    let attempt = Uuid::new_v4().to_string();
    assert!(join.put(&attempt, 2, &envelope).await.is_err());
    join.put(&attempt, 2, &envelope).await.unwrap();
    assert!(owner.get(&attempt, 2).await.unwrap().unwrap() == envelope);
    assert!(join.get(&attempt, 3).await.unwrap().is_none());
    assert!(join.attempts().await.is_err());
    assert!(join.put("../escape", 0, &envelope).await.is_err());
    assert!(
        join.get(&attempt, protocol::MAX_MESSAGES_PER_SIDE)
            .await
            .is_err()
    );
    let requests = task.await.unwrap();
    assert_eq!(requests[0].body, requests[1].body);
    assert_eq!(requests[0].body, wire);
    assert!(
        requests[0]
            .line
            .ends_with(&format!("/{attempt}/join/2 HTTP/1.1"))
    );
    assert!(requests[2].line.starts_with("GET /v1/invitations/"));
    assert!(
        requests[2]
            .line
            .ends_with(&format!("/{attempt}/join/2 HTTP/1.1"))
    );
    assert!(
        requests[3]
            .line
            .ends_with(&format!("/{attempt}/owner/3 HTTP/1.1"))
    );
    assert!(
        requests[0]
            .headers
            .contains("authorization: Bearer gent_j1.")
    );
    assert!(
        requests[2]
            .headers
            .contains("authorization: Bearer gent_t1.")
    );
    for side in [Side::Owner, Side::Join] {
        assert!(
            Mailbox::new(
                fixture.invitation.offer(),
                side,
                &format!("gent_s1.{}.{}", now(), "ab".repeat(32))
            )
            .is_err()
        );
        let other = if side == Side::Owner {
            Side::Join
        } else {
            Side::Owner
        };
        assert!(Mailbox::new(fixture.invitation.offer(), side, &token(other)).is_err());
    }
}

#[tokio::test]
async fn client_rejects_redirects_unbounded_and_malformed_responses_without_reflecting_content() {
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let responses = vec![
        format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{}/stolen\r\nContent-Length: 0\r\n\r\n", sink.local_addr().unwrap()).into_bytes(),
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", protocol::MAX_WIRE_BYTES + 1).into_bytes(),
        response("200 OK", b"sensitive reflected response"),
        response("403 Forbidden", b"sensitive reflected response"),
        [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec(), format!("{:x}\r\n", protocol::MAX_WIRE_BYTES + 1).into_bytes(), vec![b'z'; protocol::MAX_WIRE_BYTES + 1], b"\r\n0\r\n\r\n".to_vec()].concat(),
    ];
    let count = responses.len();
    let (fixture, task) = setup(responses.into_iter().map(Some).collect()).await;
    let client = fixture.mailbox(Side::Join);
    let attempt = Uuid::new_v4().to_string();
    for _ in 0..count {
        let error = client.get(&attempt, 0).await.err().unwrap();
        let error = format!("{error:#}");
        assert!(
            !error.contains("sensitive")
                && !error.contains("gent_j1")
                && !error.contains("http://")
        );
    }
    task.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), sink.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn listing_validates_deadline_ids_counts_and_directional_totals() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    let deadline = fixture.invitation.offer().offer.expires_at;
    let id = Uuid::new_v4().to_string();
    let good = json!({"attempts":{&id:{"next":[2,1]}},"expires_at":deadline});
    let mut bodies = vec![good.clone()];
    let mut wrong = good.clone();
    wrong["expires_at"] = json!(deadline + 1);
    bodies.push(wrong);
    let mut wrong = good.clone();
    wrong["extra"] = json!(1);
    bodies.push(wrong);
    bodies.push(json!({"attempts":{"invalid":{"next":[1,0]}},"expires_at":deadline}));
    for next in [json!([0, 0]), json!([1, 4097]), json!([1]), json!([-1, 0])] {
        bodies.push(json!({"attempts":{&id:{"next":next}},"expires_at":deadline}));
    }
    bodies.push(json!({"attempts":{&id:{"next":[4096,0]},Uuid::new_v4().to_string():{"next":[1,0]}},"expires_at":deadline}));
    let many: BTreeMap<_, _> = (0..65)
        .map(|_| (Uuid::new_v4().to_string(), json!({"next":[1,0]})))
        .collect();
    bodies.push(json!({"attempts":many,"expires_at":deadline}));
    let count = bodies.len();
    let responses = bodies
        .iter()
        .map(|v| Some(response("200 OK", &serde_json::to_vec(v).unwrap())))
        .collect();
    let task = tokio::spawn(responder(listener, responses));
    let owner = fixture.mailbox(Side::Owner);
    assert_eq!(owner.attempts().await.unwrap()[&id].next, [2, 1]);
    for _ in 1..count {
        assert!(owner.attempts().await.is_err());
    }
    task.await.unwrap();
    owner.clock.store(deadline, Ordering::Relaxed);
    assert!(owner.attempts().await.is_err());
    assert!(owner.clone().get(&id, 0).await.is_err());
}
