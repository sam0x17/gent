use super::*;
use crate::sync::test_http::server;

fn put(sequence: u64) -> binary::Operation {
    binary::Operation {
        method: "PUT".into(),
        path: format!("/v1/mailboxes/test/{sequence}"),
        compact: false,
        body: format!("persisted ciphertext {sequence}").into_bytes(),
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
        assert_eq!(*body, put(i as u64).body);
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

#[tokio::test]
async fn advertised_binary_preserves_receipts_and_downgrade_retries_canonical_bytes() {
    use crate::sync::test_http::server_with_headers;
    use gent_crypto::{NodeIdentity, stream::Receipt};
    const OFFER: &str = "x-gent-exchange: binary-v1\r\n";
    let signer = NodeIdentity::generate().unwrap();
    let receipt = signer.sign_stream_receipt(b"group", 1, [7; 32]).unwrap();
    let result = binary::encode_response(&[binary::Item {
        status: 200,
        compact: true,
        body: receipt.encode_compact().unwrap(),
    }])
    .unwrap();
    let (relay, task) = server_with_headers(vec![
        (200, response(&[200]), OFFER),
        (200, result, OFFER),
        (400, vec![], ""),
        (200, response(&[204]), ""),
    ])
    .await;
    let exchange = Exchange::start(relay.client, relay.origin);
    exchange.request(put(0)).await.unwrap();
    let mut op = binary::Operation {
        method: "GET".into(),
        path: "/v1/mailboxes/Z3JvdXA/checkpoint".into(),
        body: vec![],
        compact: false,
    };
    let reply = exchange.request(op.clone()).await.unwrap();
    assert_eq!(Receipt::decode(&reply.body).unwrap(), receipt);
    op.method = "PUT".into();
    op.body = receipt.encode().unwrap();
    assert!(exchange.request(op.clone()).await.is_err());
    assert_eq!(exchange.request(op).await.unwrap().status, 204);
    let requests = task.await.unwrap();
    assert!(serde_json::from_slice::<wire::Request>(&requests[0].1).is_ok());
    assert_eq!(
        binary::decode_request(&requests[1].1).unwrap()[0].method,
        "GET"
    );
    let attempted = binary::decode_request(&requests[2].1)
        .unwrap()
        .pop()
        .unwrap();
    assert!(attempted.compact);
    let json: wire::Request = serde_json::from_slice(&requests[3].1).unwrap();
    assert_eq!(
        Receipt::decode_compact(&attempted.body)
            .unwrap()
            .encode()
            .unwrap(),
        STANDARD.decode(&json.operations[0].body).unwrap()
    );
    assert_eq!(exchange.snapshot()["binary_http_requests"], 2);
}

#[tokio::test]
async fn lost_binary_response_retries_identical_signed_packet_without_downgrade() {
    use crate::sync::test_http::server_with_headers;
    const OFFER: &str = "x-gent-exchange: binary-v1\r\n";
    let ack = binary::encode_response(&[binary::Item {
        status: 200,
        compact: false,
        body: vec![],
    }])
    .unwrap();
    let (relay, task) = server_with_headers(vec![
        (200, response(&[200]), OFFER),
        (0, vec![], ""),
        (200, ack, OFFER),
    ])
    .await;
    let exchange = Exchange::start(relay.client, relay.origin);
    exchange.request(put(0)).await.unwrap();
    let signer = gent_crypto::NodeIdentity::generate().unwrap();
    let ciphertext = vec![0xa5; 65536];
    let packet = signer
        .sign_stream_packet(b"g", 0, [0; 32], &ciphertext)
        .unwrap();
    let op = binary::Operation {
        method: "PUT".into(),
        path: "/v1/mailboxes/Zw/0".into(),
        body: packet.encode().unwrap(),
        compact: false,
    };
    assert!(exchange.request(op.clone()).await.is_err());
    exchange.request(op).await.unwrap();
    let captured = task.await.unwrap();
    assert_eq!(captured[1], captured[2]);
    let wire = binary::decode_request(&captured[1].1)
        .unwrap()
        .pop()
        .unwrap();
    assert!(wire.compact);
    let recovered = gent_crypto::stream::Packet::decode_compact(&wire.body).unwrap();
    recovered.verify(&signer.public_key()).unwrap();
    assert_eq!(recovered.encode().unwrap(), packet.encode().unwrap());
}
