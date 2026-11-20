use super::*;
use crate::sync::{schedule, test_http, transfer};
use gent_crypto::stream::Packet;
use gent_protocol::transport_batch::Batch;

#[tokio::test]
async fn cooldown_is_bounded_per_peer_and_scoped_to_the_connection() {
    let wss = Wss::default();
    let first = Connection::open(&wss);
    let old = wss.channel.lock().unwrap().clone().unwrap();
    let now = tokio::time::Instant::now();
    for id in 1..=MAX_PEERS as u128 + 1 {
        old.failed(Uuid::from_u128(id), now);
    }
    assert_eq!(old.failed.lock().unwrap().len(), MAX_PEERS);
    let peer = Uuid::from_u128(MAX_PEERS as u128 + 1);
    assert!(!old.available(peer, now));
    assert!(old.available(Uuid::from_u128(1000), now));
    drop(first);
    let _next = Connection::open(&wss);
    assert!(
        wss.channel
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .available(peer, now)
    );
    assert!(old.available(peer, now + COOLDOWN));
}

fn rewrite(bytes: &[u8], peer: Uuid) -> Vec<u8> {
    Frame {
        peer,
        ..Frame::decode(bytes).unwrap()
    }
    .encode()
    .unwrap()
}

fn attempt(
    route: &Wss,
    sender: &SharedStore,
    stream: &Stream,
) -> tokio::task::JoinHandle<(Prepared, Option<u64>)> {
    let route = route.clone();
    let sender = sender.clone();
    let stream = stream.clone();
    tokio::spawn(async move {
        let health = sender.lock().unwrap().sync_health.clone();
        let mut prepared = Prepared::new(Arc::default());
        let delivery = route
            .transfer(&sender, &stream, &health, &mut prepared)
            .await
            .map(|result| result.unwrap().expect("queued peer batch").last);
        (prepared, delivery)
    })
}

// Invoked by the paired-store fixture. No QUIC endpoint is created. The
// service-auth Worker proof separately exercises the relay's wire forwarding.
pub(crate) async fn exercise_peer_watch(stores: &[SharedStore; 2], stream: Stream) {
    let [sender, receiver] = stores;
    let group = &stream.group;
    let a = Uuid::parse_str(&receiver.lock().unwrap().session_peer(group, false).unwrap()).unwrap();
    let b = Uuid::parse_str(&sender.lock().unwrap().session_peer(group, true).unwrap()).unwrap();
    let confirmed = || {
        sender
            .lock()
            .unwrap()
            .transport_confirm(group, false, None)
            .unwrap()
            .unwrap()
    };
    let baseline = confirmed();
    let tx = Wss::default();
    let mut rx = Connection::open(&Wss::default());
    let mut socket = Connection::open(&tx);
    let delivery = attempt(&tx, sender, &stream);
    let push = socket.next_send().await.unwrap();
    let frame = Frame::decode(&push).unwrap();
    assert_eq!((frame.kind, frame.peer), (Kind::Push, b));
    rx.received(&rewrite(&push, a), receiver).unwrap();
    let lost = rx.next_send().await.unwrap();
    assert_eq!(Frame::decode(&lost).unwrap().kind, Kind::Receipt);
    drop(socket);
    assert!(delivery.await.unwrap().1.is_none());
    assert_eq!(baseline, confirmed());

    // Recipient is unavailable on reconnect. New work for this peer skips
    // WSS immediately, and mailbox storage still needs the original ciphertext.
    let mut socket = Connection::open(&tx);
    let retry = attempt(&tx, sender, &stream);
    let again = socket.next_send().await.unwrap();
    let again = Frame::decode(&again).unwrap();
    assert_eq!(again.payload, frame.payload);
    socket
        .received(
            &Frame {
                kind: Kind::Unavailable,
                payload: &[],
                ..again
            }
            .encode()
            .unwrap(),
            sender,
        )
        .unwrap();
    let (mut prepared, delivery) = retry.await.unwrap();
    assert!(delivery.is_none());
    assert!(
        tokio::time::timeout(Duration::from_secs(1), attempt(&tx, sender, &stream))
            .await
            .unwrap()
            .unwrap()
            .1
            .is_none()
    );
    drop(socket);

    let compact = Batch::decode(&frame.payload[7 + group.len()..]).unwrap();
    let canonical: Vec<_> = compact
        .packets()
        .iter()
        .map(|p| Packet::decode_compact(p).unwrap().encode().unwrap())
        .collect();
    let next = baseline.sequence() + 1;
    let last = next + canonical.len() as u64 - 1;
    let (relay, requests) = test_http::server(vec![
        (
            200,
            serde_json::to_vec(&serde_json::json!({"next":next, "checkpoint":null})).unwrap(),
        ),
        (204, vec![]),
        (
            200,
            serde_json::to_vec(
                &serde_json::json!({"stored":true, "next":last+1, "count":canonical.len()}),
            )
            .unwrap(),
        ),
    ])
    .await;
    assert_eq!(
        transfer::run(
            sender.clone(),
            relay,
            stream.clone(),
            Arc::default(),
            &mut prepared,
            &mut transfer::State::default()
        )
        .await
        .unwrap(),
        Some(last)
    );
    let requests = requests.await.unwrap();
    assert_eq!(Batch::decode(&requests[2].1).unwrap().packets(), canonical);
    assert_eq!(baseline, confirmed());

    // Deliver the retained batch again on a fresh watch. A receipt with the
    // right correlation from a third peer cannot complete the request.
    let mut socket = Connection::open(&tx);
    let streams = std::slice::from_ref(&stream);
    let work = sender.lock().unwrap().sync_pending_groups(streams).unwrap();
    assert!(!work.ready.contains(group));
    assert!(work.unconfirmed.contains(group));
    let hints = schedule::Hints::default();
    let mut schedule = schedule::Schedule::default();
    let retries = Default::default();
    schedule.select(streams, &hints, &work, &retries, true);
    assert!(
        schedule
            .select(streams, &hints, &work, &retries, true)
            .streams
            .is_empty()
    );
    hints.reconnected();
    let selected = schedule.select(streams, &hints, &work, &retries, true);
    let peer = selected
        .streams
        .iter()
        .find(|s| selected.peers.contains(&s.group))
        .unwrap();
    let delivery = attempt(&tx, sender, peer);
    let push = socket.next_send().await.unwrap();
    assert_eq!(Frame::decode(&push).unwrap().payload, frame.payload);
    rx.received(&rewrite(&push, a), receiver).unwrap();
    let response = rx.next_send().await.unwrap();
    let ack = Frame::decode(&response).unwrap();
    assert_eq!(ack.payload, Frame::decode(&lost).unwrap().payload);
    socket
        .received(&rewrite(&response, Uuid::new_v4()), sender)
        .unwrap();
    assert!(socket.pending.contains_key(&ack.id));
    socket.received(&rewrite(&response, b), sender).unwrap();
    assert_eq!(delivery.await.unwrap().1, Some(last));
    assert_eq!(confirmed().sequence(), last);
}
