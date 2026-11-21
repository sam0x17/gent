use super::*;
use crate::sync::test_http::server;

fn packet(sequence: u64) -> Packet {
    // HTTP framing tests do not establish trust. The transport integration
    // suite exercises real signatures, encryption, ordering and receipt checks.
    serde_json::from_value(serde_json::json!({
        "version":1, "group":"dGVzdA==", "sequence":sequence,
        "previous":if sequence == 0 { [0;32] } else { [1;32] },
        "ciphertext":"Ynl0ZXM=", "signature":STANDARD_SIGNATURE,
    }))
    .unwrap()
}
const STANDARD_SIGNATURE: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

#[tokio::test]
async fn a_lost_response_retries_identical_packets_and_fetch_validates_every_position() {
    let mut batch = Batch::default();
    for sequence in 0..16 {
        batch.push(packet(sequence).encode().unwrap()).unwrap();
    }
    let mut wrong = Batch::default();
    wrong.push(packet(1).encode().unwrap()).unwrap();
    let (relay, task) = server(vec![
        (0, vec![]),
        (200, br#"{"stored":true,"count":16,"next":16}"#.to_vec()),
        (200, batch.encode()),
        (200, wrong.encode()),
    ])
    .await;
    let health = health::Health::default();
    let observation = || health.peer_transport("peer", Some((&[], b"test")));
    assert!(
        relay
            .put_batch(b"test", 0, &batch, Some(&health))
            .await
            .is_err()
    );
    assert!(observation()["last"].is_null());
    assert_eq!(
        relay
            .put_batch(b"test", 0, &batch, Some(&health))
            .await
            .unwrap(),
        16
    );
    assert_eq!(observation()["last"]["sequence"], 15);
    assert!(observation()["last_signed_receipt"].is_null());
    assert_eq!(relay.get_batch(b"test", 0).await.unwrap().len(), 16);
    assert!(relay.get_batch(b"test", 0).await.is_err());
    let requests = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0], requests[1]);
    assert!(requests.iter().all(|(line, _)| line.contains("/batch/0 ")));
}

#[tokio::test]
async fn old_relays_fall_back_but_authorization_errors_do_not() {
    let mut batch = Batch::default();
    batch.push(packet(0).encode().unwrap()).unwrap();
    let (relay, task) = server(vec![
        (404, vec![]),
        (200, br#"{"stored":true,"sequence":0}"#.to_vec()),
        (200, packet(0).encode().unwrap()),
    ])
    .await;
    assert_eq!(relay.put_batch(b"test", 0, &batch, None).await.unwrap(), 1);
    assert_eq!(relay.get_batch(b"test", 0).await.unwrap().len(), 1);
    let requests = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert!(requests[0].0.contains("/batch/"));
    assert!(!requests[1].0.contains("/batch/"));
    assert!(!requests[2].0.contains("/batch/"));
    let (relay, task) = server(vec![(401, vec![])]).await;
    assert!(relay.put_batch(b"test", 0, &batch, None).await.is_err());
    assert!(relay.batches.enabled());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn interrupted_legacy_upload_records_only_the_acknowledged_prefix() {
    let health = health::Health::default();
    let mut batch = Batch::default();
    batch.push(packet(0).encode().unwrap()).unwrap();
    batch.push(packet(1).encode().unwrap()).unwrap();
    let (relay, requests) = server(vec![
        (404, vec![]),
        (200, br#"{"stored":true,"sequence":0}"#.to_vec()),
        (503, vec![]),
    ])
    .await;
    assert!(
        relay
            .put_batch(b"test", 0, &batch, Some(&health))
            .await
            .is_err()
    );
    requests.await.unwrap();
    let observed = health.peer_transport("peer", Some((&[], b"test")));
    assert_eq!(observed["last"]["evidence"], "mailbox_upload");
    assert_eq!(observed["last"]["sequence"], 0);
}
