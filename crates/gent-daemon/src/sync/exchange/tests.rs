use super::*;
use crate::sync::test_http::server;

fn put(sequence: u64) -> wire::Operation {
    wire::Operation {
        method: "PUT".into(),
        path: format!("/v1/mailboxes/test/{sequence}"),
        body: STANDARD.encode(format!("persisted ciphertext {sequence}")),
    }
}
fn response(statuses: &[u16]) -> Vec<u8> {
    serde_json::to_vec(&wire::Response {
        version: wire::VERSION,
        results: statuses
            .iter()
            .map(|status| wire::ResultItem {
                status: *status,
                body: STANDARD.encode("result"),
            })
            .collect(),
    })
    .unwrap()
}

#[tokio::test]
async fn concurrent_operations_share_http_and_keep_independent_outcomes() {
    let (relay, task) = server(vec![(200, response(&[200, 409, 200]))]).await;
    let exchange = Exchange::start(relay.client, relay.origin);
    let (a, b, c) = tokio::join!(
        exchange.request(put(0)),
        exchange.request(put(1)),
        exchange.request(put(2))
    );
    assert_eq!(a.unwrap().status, 200);
    assert_eq!(b.unwrap().status, 409);
    assert_eq!(c.unwrap().status, 200);
    let requests = task.await.unwrap();
    assert_eq!(requests.len(), 1);
    let decoded: wire::Request = serde_json::from_slice(&requests[0].1).unwrap();
    assert_eq!(
        decoded
            .operations
            .iter()
            .map(|op| op.path.as_str())
            .collect::<Vec<_>>(),
        [
            "/v1/mailboxes/test/0",
            "/v1/mailboxes/test/1",
            "/v1/mailboxes/test/2"
        ]
    );
    assert_eq!(exchange.snapshot()["http_requests"], 1);
    assert_eq!(exchange.snapshot()["mailbox_operations"], 3);
}

#[tokio::test]
async fn response_loss_retries_identical_operations_without_legacy_replay() {
    let (relay, task) = server(vec![(0, vec![]), (200, response(&[200]))]).await;
    let exchange = Exchange::start(relay.client, relay.origin);
    assert!(exchange.request(put(0)).await.is_err());
    assert_eq!(exchange.request(put(0)).await.unwrap().status, 200);
    let requests = task.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
}

#[tokio::test]
async fn legacy_fallback_preserves_mailbox_order_and_is_cached() {
    let (relay, task) = server(vec![
        (404, vec![]),
        (200, vec![]),
        (200, vec![]),
        (200, vec![]),
    ])
    .await;
    let exchange = Exchange::start(relay.client, relay.origin);
    let (a, b) = tokio::join!(exchange.request(put(0)), exchange.request(put(1)));
    assert_eq!(a.unwrap().status, 200);
    assert_eq!(b.unwrap().status, 200);
    assert_eq!(exchange.request(put(2)).await.unwrap().status, 200);
    let requests = task.await.unwrap();
    assert!(requests[0].0.contains("/v2/exchange"));
    for (i, (line, body)) in requests[1..].iter().enumerate() {
        assert!(line.contains(&format!("/v1/mailboxes/test/{i} ")));
        assert_eq!(*body, STANDARD.decode(put(i as u64).body).unwrap());
    }
}

#[tokio::test]
async fn unauthorized_and_malformed_responses_never_trigger_legacy_writes() {
    for (status, body) in [
        (401, vec![]),
        (503, vec![]),
        (200, response(&[])),
        (200, b"invalid".to_vec()),
    ] {
        let (relay, task) = server(vec![(status, body)]).await;
        let exchange = Exchange::start(relay.client, relay.origin);
        assert!(exchange.request(put(0)).await.is_err());
        assert_eq!(task.await.unwrap().len(), 1);
    }
}
