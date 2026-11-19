use super::*;
use crate::sync::direct::Direct;
use std::sync::Mutex;

#[tokio::test]
async fn bootstrap_can_stop_only_after_a_verified_receipt_for_the_current_link() {
    let pair = Pair::new().await;
    let peer = pair.stores[1].identity.node.id();
    let group = pair.group();
    assert!(!pair.stores[0].mesh_link_confirmed(peer).unwrap());
    assert!(!pair.stores[0].mesh_link_confirmed("absent").unwrap());
    let receipt = pair.stores[1].transport_receipt(&group, false).unwrap();
    assert!(receipt.sequence() > 0);
    pair.stores[0]
        .transport_confirm(&group, false, Some(&receipt))
        .unwrap();
    assert!(pair.stores[0].mesh_link_confirmed(peer).unwrap());
    // A corrupt saved receipt is never accepted as evidence for cancelling work.
    pair.stores[0]
        .db
        .execute(
            "UPDATE stream_confirmed SET receipt=x'00' WHERE group_id=?1",
            [&group],
        )
        .unwrap();
    assert!(pair.stores[0].mesh_link_confirmed(peer).is_err());
}

#[tokio::test]
async fn direct_delivers_with_signed_receipts_and_disabled_path_preserves_cloud_retry() {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    let health: Vec<_> = pair.stores.iter().map(|s| s.sync_health.clone()).collect();
    let keys = pair.keys.clone();
    let ids = pair.agents.clone();
    let [left, right] = pair.stores;
    let stores = [Arc::new(Mutex::new(left)), Arc::new(Mutex::new(right))];
    let a = Direct::start(stores[0].clone(), health[0].clone())
        .await
        .unwrap()
        .unwrap();
    let b = Direct::start(stores[1].clone(), health[1].clone())
        .await
        .unwrap()
        .unwrap();
    a.advertise(stores[0].clone()).await.unwrap();
    b.advertise(stores[1].clone()).await.unwrap();
    pump(&stores);
    let stream = stores[0]
        .lock()
        .unwrap()
        .data_streams()
        .unwrap()
        .into_iter()
        .find(|s| s.outgoing)
        .unwrap();
    let send = || {
        stores[0]
            .lock()
            .unwrap()
            .execute(Request::Agent {
                credential: keys[0].clone(),
                action: AgentOp::Send {
                    recipient: ids[1].clone(),
                    request_id: Uuid::now_v7().to_string(),
                    text: "direct proof".into(),
                    files: vec![],
                    file_ids: vec![],
                },
            })
            .unwrap()
    };
    let sent = send();
    let wakeup = stores[0].lock().unwrap().sync_wakeup.clone();
    assert!(
        a.transfer(stores[0].clone(), &stream, &health[0], wakeup.clone())
            .await
            .unwrap()
            .unwrap()
            .is_some()
    );
    let inbox = stores[1]
        .lock()
        .unwrap()
        .execute(Request::Agent {
            credential: keys[1].clone(),
            action: AgentOp::Inbox,
        })
        .unwrap();
    assert_eq!(inbox[0]["id"], sent["message_id"]);
    assert!(
        stores[0]
            .lock()
            .unwrap()
            .transport_confirm(&stream.group, false, None)
            .unwrap()
            .is_some()
    );
    // Cloud sees the same persisted history after direct confirmation, without
    // importing a second message. No re-encryption is needed for fallback.
    pump(&stores);
    // Commit a new packet but lose its receipt. The sender must retain its exact
    // ciphertext until a later direct query returns signed committed evidence.
    send();
    let (endpoint, next) = {
        let mut receiver = stores[1].lock().unwrap();
        let endpoint: String = receiver
            .db
            .query_row("SELECT endpoint FROM direct_peers", [], |r| r.get(0))
            .unwrap();
        (
            endpoint.parse::<iroh::EndpointId>().unwrap(),
            receiver.data_next(&stream.group).unwrap(),
        )
    };
    let packet = {
        let mut sender = stores[0].lock().unwrap();
        sender.data_prepare(&stream.group).unwrap();
        sender.data_outgoing(&stream.group, next).unwrap().unwrap()
    };
    {
        let mut receiver = stores[1].lock().unwrap();
        let stranger = iroh::SecretKey::generate().public();
        assert!(
            receiver
                .direct_receive(stranger, &stream.group, vec![packet.clone()])
                .is_err()
        );
        assert_eq!(receiver.data_next(&stream.group).unwrap(), next);
        let _lost_receipt = receiver
            .direct_receive(endpoint, &stream.group, vec![packet.clone()])
            .unwrap();
        // A replay after receipt loss is accepted without importing a new chat
        // message. It must produce the same committed receipt sequence.
        assert_eq!(
            receiver
                .direct_receive(endpoint, &stream.group, vec![packet.clone()])
                .unwrap()
                .sequence(),
            next
        );
    }
    assert_eq!(
        stores[0]
            .lock()
            .unwrap()
            .data_outgoing(&stream.group, next)
            .unwrap()
            .unwrap()
            .encode()
            .unwrap(),
        packet.encode().unwrap()
    );
    a.transfer(stores[0].clone(), &stream, &health[0], wakeup.clone())
        .await
        .unwrap()
        .unwrap();
    pump(&stores);
    config::edit_local(pair.homes[1].path(), |cfg| {
        cfg.extra.insert(
            "transport".into(),
            toml::Value::try_from(config::Transport {
                direct: config::Direct::Off,
                relays: vec![],
            })?,
        );
        Ok(())
    })
    .unwrap();
    send();
    assert!(
        a.transfer(stores[0].clone(), &stream, &health[0], wakeup)
            .await
            .is_none()
    );
    pump(&stores);
    let inbox = stores[1]
        .lock()
        .unwrap()
        .execute(Request::Agent {
            credential: keys[1].clone(),
            action: AgentOp::Inbox,
        })
        .unwrap();
    assert_eq!(inbox.as_array().unwrap().len(), 3);
    drop(a);
    drop(b);
}

fn pump(stores: &[Arc<Mutex<Store>>; 2]) {
    for _ in 0..100 {
        let mut progress = false;
        for i in 0..2 {
            let mut sender = stores[i].lock().unwrap();
            let mut receiver = stores[1 - i].lock().unwrap();
            for entry in sender
                .data_streams()
                .unwrap()
                .into_iter()
                .filter(|s| s.outgoing)
            {
                let next = receiver.data_next(&entry.group).unwrap();
                sender.data_prepare(&entry.group).unwrap();
                if let Some(packet) = sender.data_outgoing(&entry.group, next).unwrap() {
                    receiver.data_receive(&packet).unwrap();
                    progress = true;
                }
                let receipt = receiver.transport_receipt(&entry.group, false).unwrap();
                sender
                    .transport_confirm(&entry.group, false, Some(&receipt))
                    .unwrap();
            }
        }
        if !progress {
            return;
        }
    }
    panic!("direct proof history did not drain");
}
