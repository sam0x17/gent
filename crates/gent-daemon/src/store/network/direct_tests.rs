use super::*;
use crate::sync::direct::{
    Direct,
    session::{self, Prepared},
};
use std::sync::Mutex;

#[tokio::test]
async fn direct_file_download_resumes_missing_chunks_and_obeys_current_access() {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    let bytes = vec![0xe7; gent_crypto::files::CHUNK_BYTES + 13];
    let sent = send_attachment(&mut pair, &bytes);
    let id: String = pair.stores[0]
        .db
        .query_row(
            "SELECT object_id FROM agent_files WHERE message=?1",
            [sent["message_id"].as_str().unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    let first = pair.stores[0].file_upload(&id, 0).unwrap();
    pair.stores[0].file_uploaded(&id, &[0, 1]).unwrap();
    pair.pump();
    pair.stores[1].file_received(&id, 0, &first).unwrap();
    let job = pair.stores[1].file_transfer(&id).unwrap().unwrap();
    assert_eq!(job.missing, vec![1]);

    let health = pair.stores.each_ref().map(|s| s.sync_health.clone());
    let stores = pair.stores.map(|s| Arc::new(Mutex::new(s)));
    let sender = Direct::start(stores[0].clone(), health[0].clone())
        .await
        .unwrap()
        .unwrap();
    let receiver = Direct::start(stores[1].clone(), health[1].clone())
        .await
        .unwrap()
        .unwrap();
    sender.advertise(stores[0].clone()).await.unwrap();
    receiver.advertise(stores[1].clone()).await.unwrap();
    pump(&stores);
    let other = iroh::SecretKey::generate().public();
    assert!(
        stores[0]
            .lock()
            .unwrap()
            .peer_file_chunk(other, &id, 1)
            .is_err()
    );
    let chunk = receiver
        .file_chunk(stores[1].clone(), &job.peer, &id, &job.manifest, 1)
        .await
        .unwrap();
    assert_eq!(
        chunk,
        stores[0].lock().unwrap().file_upload(&id, 1).unwrap()
    );
    stores[1]
        .lock()
        .unwrap()
        .file_received(&id, 1, &chunk)
        .unwrap();
    assert!(
        stores[1]
            .lock()
            .unwrap()
            .file_transfer(&id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        health[1].snapshot()["direct_traffic"]["received_file_chunk_bytes"],
        chunk.len()
    );

    config::edit_local(pair.homes[0].path(), |cfg| {
        cfg.extra.insert(
            "transport".into(),
            toml::Value::try_from(config::Transport {
                direct: config::Direct::Off,
                ..Default::default()
            })?,
        );
        Ok(())
    })
    .unwrap();
    assert!(
        receiver
            .file_chunk(stores[1].clone(), &job.peer, &id, &job.manifest, 0)
            .await
            .is_none()
    );
}

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
    // Even intact signed bytes cannot authorize a different persisted floor.
    pair.stores[0]
        .db
        .execute(
            "UPDATE stream_confirmed SET sequence=sequence+1 WHERE group_id=?1",
            [&group],
        )
        .unwrap();
    assert!(pair.stores[0].mesh_link_confirmed(peer).is_err());
    pair.stores[0]
        .db
        .execute(
            "UPDATE stream_confirmed SET sequence=sequence-1, receipt=x'00' WHERE group_id=?1",
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
        a.transfer(
            stores[0].clone(),
            &stream,
            &health[0],
            &mut Prepared::new(wakeup.clone())
        )
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
    // ciphertext until the retried batch returns signed committed evidence.
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
    // The accepting endpoint has a presence challenge to push while the
    // original initiator is retrying. Both use the already open connection.
    let (reverse, reverse_wakeup) = {
        let mut receiver = stores[1].lock().unwrap();
        receiver
            .db
            .execute("UPDATE node_presence SET next_probe_at=0", [])
            .unwrap();
        receiver.presence_tick().unwrap();
        let reverse = receiver
            .data_streams()
            .unwrap()
            .into_iter()
            .find(|s| s.outgoing)
            .unwrap();
        (reverse, receiver.sync_wakeup.clone())
    };
    let mut forward_batch = Prepared::new(wakeup.clone());
    let mut reverse_batch = Prepared::new(reverse_wakeup);
    let (forward, backward) = tokio::join!(
        a.transfer(stores[0].clone(), &stream, &health[0], &mut forward_batch),
        b.transfer(stores[1].clone(), &reverse, &health[1], &mut reverse_batch),
    );
    assert!(forward.unwrap().unwrap().is_some());
    assert!(backward.unwrap().unwrap().is_some());
    for side in &health {
        let direct = &side.snapshot()["direct_traffic"];
        assert_eq!(direct["connections_opened"], 1);
        assert_eq!(direct["binary_send_streams_opened"], 1);
        assert!(direct["connections_reused"].as_u64().unwrap() > 0);
    }
    pump(&stores);
    let before = health[0].snapshot()["direct_traffic"].clone();
    assert!(
        a.transfer(
            stores[0].clone(),
            &stream,
            &health[0],
            &mut Prepared::new(wakeup.clone())
        )
        .await
        .unwrap()
        .unwrap()
        .is_none()
    );
    assert_eq!(health[0].snapshot()["direct_traffic"], before);
    config::edit_local(pair.homes[1].path(), |cfg| {
        cfg.extra.insert(
            "transport".into(),
            toml::Value::try_from(config::Transport {
                direct: config::Direct::Off,
                ..Default::default()
            })?,
        );
        Ok(())
    })
    .unwrap();
    send();
    assert!(
        a.transfer(
            stores[0].clone(),
            &stream,
            &health[0],
            &mut Prepared::new(wakeup)
        )
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

#[tokio::test]
async fn session_restart_retries_the_exact_batch_until_the_reader_signs_its_history() {
    let mut pair = Pair::new().await;
    let group = pair.group();
    let base = pair.stores[1].transport_receipt(&group, false).unwrap();
    pair.stores[0]
        .transport_confirm(&group, false, Some(&base))
        .unwrap();
    let message = pair.send(vec![]).unwrap();
    let sender_id = pair.stores[0].identity.node.id().to_owned();
    let [sender, receiver] = pair.stores.map(|s| Arc::new(Mutex::new(s)));
    let wake = sender.lock().unwrap().sync_wakeup.clone();
    let mut sent_bytes = Vec::new();
    let mut signed = None;
    let receiver_store = receiver.clone();
    let peer = sender_id.clone();
    let lost = session::push(sender.clone(), &group, &mut Prepared::new(wake), |bytes| {
        sent_bytes = bytes.clone();
        let saved = &mut signed;
        async move {
            assert!(
                session::accept(
                    receiver_store.clone(),
                    session::Peer::Node("wrong".into()),
                    &bytes
                )
                .await
                .is_err()
            );
            *saved =
                Some(session::accept(receiver_store, session::Peer::Node(peer), &bytes).await?);
            anyhow::bail!("lost response")
        }
    })
    .await;
    assert!(lost.is_err());
    drop(sender);
    let sender = Arc::new(Mutex::new(Store::open(pair.homes[0].path()).unwrap()));
    let wake = sender.lock().unwrap().sync_wakeup.clone();
    let signed = gent_crypto::stream::Receipt::decode_compact(&signed.unwrap()).unwrap();
    let wrong_signer = gent_crypto::NodeIdentity::generate()
        .unwrap()
        .sign_stream_receipt(&group, signed.sequence(), signed.digest())
        .unwrap();
    let wrong_history = receiver
        .lock()
        .unwrap()
        .identity
        .node
        .sign_stream_receipt(&group, signed.sequence(), [7; 32])
        .unwrap();
    let wrong_group = receiver
        .lock()
        .unwrap()
        .identity
        .node
        .sign_stream_receipt(b"other", signed.sequence(), signed.digest())
        .unwrap();

    for invalid in [base.clone(), wrong_signer, wrong_history, wrong_group] {
        let result = session::push(
            sender.clone(),
            &group,
            &mut Prepared::new(wake.clone()),
            |bytes| {
                assert_eq!(bytes, sent_bytes);
                std::future::ready(invalid.encode_compact())
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            sender
                .lock()
                .unwrap()
                .transport_confirm(&group, false, None)
                .unwrap(),
            Some(base.clone())
        );
    }

    let accepted = session::push(
        sender.clone(),
        &group,
        &mut Prepared::new(wake.clone()),
        |bytes| {
            assert_eq!(bytes, sent_bytes);
            let receiver = receiver.clone();
            async move { session::accept(receiver, session::Peer::Node(sender_id), &bytes).await }
        },
    )
    .await
    .unwrap();
    assert_eq!(accepted.unwrap().last, signed.sequence());
    assert_eq!(
        sender
            .lock()
            .unwrap()
            .transport_confirm(&group, false, None)
            .unwrap(),
        Some(signed)
    );
    assert!(
        session::push(sender, &group, &mut Prepared::new(wake), |_| {
            std::future::ready(Err(anyhow::anyhow!("unexpected empty probe")))
        })
        .await
        .unwrap()
        .is_none()
    );
    let inbox = receiver
        .lock()
        .unwrap()
        .execute(Request::Agent {
            credential: pair.keys[1].clone(),
            action: AgentOp::Inbox,
        })
        .unwrap();
    assert_eq!(inbox.as_array().unwrap().len(), 1);
    assert_eq!(inbox[0]["id"], message["message_id"]);
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
