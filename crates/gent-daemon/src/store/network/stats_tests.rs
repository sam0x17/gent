use super::*;
use gent_protocol::stats::Stats;
use std::time::Instant;

fn read(pair: &mut Pair, node: usize) -> Result<Stats> {
    Ok(serde_json::from_value(pair.owner(node, OwnerOp::Stats)?)?)
}

#[derive(Debug, Default)]
struct Traffic {
    frames: usize,
    wire_bytes: usize,
    pages: usize,
    rows: usize,
}

fn drain(pair: &mut Pair) -> Result<Traffic> {
    use gent_protocol::transport_wss::{Frame, Kind};
    let mut measured = Traffic::default();
    for _ in 0..1000 {
        let mut progress = false;
        for from in 0..2 {
            let Some(sent) = pair.stores[from].next_stats_send()? else {
                continue;
            };
            let src = Uuid::parse_str(pair.stores[from].identity.node.id())?;
            let group: Vec<u8> = pair.stores[1 - from].db.query_row(
                "SELECT incoming FROM network_links",
                [],
                |r| r.get(0),
            )?;
            let content = encrypted::stats::open(&pair.stores[1 - from].db, &group, &sent.wire)?;
            let req: Value = serde_json::from_slice(&content)?;
            if req["exchange"]["op"] == "page" {
                measured.pages += 1;
                measured.rows += req["exchange"]["rows"].as_array().unwrap().len();
            }
            let push = Frame {
                kind: Kind::Push,
                peer: src,
                id: Uuid::new_v4(),
                payload: &sent.wire,
            }
            .encode()?;
            let frame = Frame::decode(&push)?;
            let ack = pair.stores[1 - from].accept_stats_send(frame.peer, frame.payload)?;
            let response = Frame {
                kind: Kind::Receipt,
                peer: sent.peer,
                id: frame.id,
                payload: &ack,
            }
            .encode()?;
            pair.stores[from].finish_stats_send(&sent, Some(Frame::decode(&response)?.payload))?;
            measured.frames += 2;
            measured.wire_bytes += push.len() + response.len();
            progress = true;
        }
        if !progress {
            return Ok(measured);
        }
    }
    anyhow::bail!("stats fixture did not converge")
}

#[tokio::test]
async fn physical_carriers_merge_before_ranking_and_only_send_changed_rows() -> Result<()> {
    let mut pair = Pair::new().await;
    let missing = read(&mut pair, 1)?;
    assert_eq!(
        (
            missing.coverage.expected_nodes,
            missing.coverage.reporting_nodes
        ),
        (2, 1)
    );
    assert!(
        missing
            .nodes
            .iter()
            .any(|n| n.outbound.is_none() && n.as_of.is_none())
    );
    // This chat would miss both carriers' local top ten. It must win after
    // merging the original sends accepted on the two sides of its host move.
    let moved = Uuid::from_u128(1).to_string();
    for (i, store) in pair.stores.iter_mut().enumerate() {
        let tx = store.db.transaction()?;
        tx.execute(
            "INSERT INTO usage_senders VALUES(?1,'moved',9,9,0)",
            [&moved],
        )?;
        for n in 0..1024 {
            let id = Uuid::from_u128(100 + (i as u128) * 1024 + n).to_string();
            tx.execute(
                "INSERT INTO usage_senders VALUES(?1,'counter fixture',10,30,2)",
                [id],
            )?;
        }
        tx.commit()?;
    }
    let begin = Instant::now();
    super::directory_push_tests::negotiate(&mut pair);
    let bootstrap = drain(&mut pair)?;
    eprintln!("bootstrap {bootstrap:?} in {:?}", begin.elapsed());
    assert_eq!(bootstrap.rows, 2050);
    let snapshot = read(&mut pair, 1)?;
    assert!(snapshot.coverage.complete);
    assert_eq!(snapshot.top_senders[0].chat_id, moved);
    assert_eq!(snapshot.top_senders[0].traffic.messages, 18);
    assert_eq!(snapshot.outbound.messages, 20498);

    pair.reopen(0);
    pair.reopen(1);
    let tx = pair.stores[0].db.transaction()?;
    for _ in 0..1100 {
        tx.execute(
            "UPDATE usage_senders SET messages=messages+1,text_bytes=text_bytes+3 WHERE chat_id=?1",
            [&moved],
        )?;
    }
    tx.commit()?;
    let begin = Instant::now();
    for store in &pair.stores {
        store.db.execute(
            "UPDATE stats_peers SET last_ad=last_ad-46,last_read=last_read-46",
            [],
        )?;
    }
    let sparse = drain(&mut pair)?;
    eprintln!("sparse {sparse:?} in {:?}", begin.elapsed());
    assert_eq!((sparse.pages, sparse.rows), (1, 1));
    let after = read(&mut pair, 1)?;
    assert_eq!(after.top_senders[0].traffic.messages, 1118);
    assert_eq!(after.outbound.messages, 21598);

    let begin = Instant::now();
    for _ in 0..10 {
        let _ = read(&mut pair, 1)?;
        pair.stores[1].presence_tick()?;
    }
    let steady = drain(&mut pair)?;
    eprintln!(
        "10 steady reads + ticks {steady:?} in {:?}",
        begin.elapsed()
    );
    assert_eq!((steady.frames, steady.wire_bytes), (0, 0));
    for store in &pair.stores {
        store
            .db
            .execute("UPDATE stats_peers SET last_ad=last_ad-301", [])?;
    }
    let begin = Instant::now();
    let heartbeat = drain(&mut pair)?;
    eprintln!("idle interval {heartbeat:?} in {:?}", begin.elapsed());
    assert_eq!((heartbeat.rows, heartbeat.pages), (0, 0));
    assert!((2..=4).contains(&heartbeat.frames));
    pair.stores[1]
        .db
        .execute("UPDATE request_clock SET floor=floor+601", [])?;
    let stale = read(&mut pair, 1)?;
    assert!(!stale.coverage.complete);
    assert_eq!(
        (stale.coverage.reporting_nodes, stale.coverage.fresh_nodes),
        (2, 1)
    );
    assert_eq!(stale.outbound, after.outbound);
    Ok(())
}
