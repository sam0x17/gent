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
    // Changes immediately following a successful advertisement coalesce.
    for store in &pair.stores {
        store
            .db
            .execute("UPDATE stats_peers SET last_ad=?1", [now()])?;
    }
    assert_eq!(drain(&mut pair)?.frames, 0);
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
            .execute("UPDATE stats_peers SET last_ad=?1", [now() - 3500])?;
    }
    assert_eq!(drain(&mut pair)?.frames, 0);
    for store in &pair.stores {
        store
            .db
            .execute("UPDATE stats_peers SET last_ad=?1", [now() - 3601])?;
    }
    let begin = Instant::now();
    let heartbeat = drain(&mut pair)?;
    eprintln!("idle interval {heartbeat:?} in {:?}", begin.elapsed());
    assert_eq!((heartbeat.rows, heartbeat.pages), (0, 0));
    assert!((2..=4).contains(&heartbeat.frames));
    pair.stores[1]
        .db
        .execute("UPDATE request_clock SET floor=floor+7205", [])?;
    let stale = read(&mut pair, 1)?;
    assert!(!stale.coverage.complete);
    assert_eq!(
        (stale.coverage.reporting_nodes, stale.coverage.fresh_nodes),
        (2, 1)
    );
    assert_eq!(stale.outbound, after.outbound);
    Ok(())
}

#[tokio::test]
async fn refresh_counts_live_proofs_separately_from_cache_age_and_staged_pages() -> Result<()> {
    use tokio::time::{Duration, Instant as Clock};
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    drain(&mut pair)?;
    let owner = config::read_private(&pair.homes[0].path().join("owner.key"))?;
    let [local, remote] = &mut pair.stores;
    assert!(local.begin_stats_refresh("invalid").is_err());
    assert!(local.stats_poll.is_none());
    tokio::time::pause();
    let deadline = || Clock::now() + Duration::from_secs(12);
    let started = Clock::now();
    let id = local.begin_stats_refresh(&owner)?.wait(deadline()).await;
    let cached = local.stats_snapshot(Some(id))?;
    assert_eq!(Clock::now(), started);
    assert_eq!(cached["coverage"]["fresh_nodes"], 2);
    assert_eq!(
        cached["refresh"],
        json!({"confirmed_nodes":1,"expected_nodes":2})
    );
    assert!(local.next_stats_send()?.is_none());

    local.sync_health.stats.routes.send_replace(1);
    tokio::time::advance(Duration::from_secs(6)).await;
    let remote_id = Uuid::parse_str(remote.local_node_id())?;
    let local_id = Uuid::parse_str(local.local_node_id())?;
    let tx = remote.db.transaction()?;
    for i in 1..=300 {
        tx.execute(
            "INSERT INTO usage_senders VALUES(?1,'sample',1,1,0)",
            [Uuid::from_u128(i).to_string()],
        )?;
    }
    tx.execute("UPDATE stats_peers SET last_read=last_read-6", [])?;
    tx.commit()?;
    let wait = local.begin_stats_refresh(&owner)?;
    // Challenge and Read both have authentic replies but neither installs totals.
    for _ in 0..2 {
        let send = local.next_stats_send()?.unwrap();
        let ack = remote.accept_stats_send(local_id, &send.wire)?;
        local.finish_stats_send(&send, Some(&ack))?;
    }
    let first = remote.next_stats_send()?.unwrap();
    let ack = local.accept_stats_send(remote_id, &first.wire)?;
    remote.finish_stats_send(&first, Some(&ack))?;
    let last = remote.next_stats_send()?.unwrap();
    let before = Clock::now();
    let id = wait.wait(deadline()).await;
    assert!(
        (Duration::from_secs(8)..=Duration::from_millis(8010)).contains(&(Clock::now() - before))
    );
    let partial = local.stats_snapshot(Some(id))?;
    assert_eq!(partial["outbound"], cached["outbound"]);
    assert_eq!(partial["refresh"], cached["refresh"]);
    let ack = local.accept_stats_send(remote_id, &last.wire)?;
    remote.finish_stats_send(&last, Some(&ack))?;
    let after = local.stats_snapshot(Some(id))?;
    assert_eq!(after["outbound"]["messages"], 300);
    assert_eq!(
        after["refresh"], partial["refresh"],
        "late pages cannot retroactively complete the poll"
    );
    tokio::time::advance(Duration::from_secs(6)).await;
    let wait = local.begin_stats_refresh(&owner)?;
    let probe = local.next_stats_send()?.unwrap();
    let ack = remote.accept_stats_send(local_id, &probe.wire)?;
    local.finish_stats_send(&probe, Some(&ack))?;
    let id = wait.wait(deadline()).await;
    assert_eq!(
        local.stats_snapshot(Some(id))?["refresh"]["confirmed_nodes"],
        2
    );
    assert!(local.next_stats_send()?.is_none());

    // Immutable peers that decline the initial side request keep their hourly
    // backoff, even when the operator opens Stats or refreshes repeatedly.
    local.db.execute(
        "UPDATE stats_peers SET supported=0,attempt_at=?1,failed_at=?2",
        params![now() + 3600, now()],
    )?;
    tokio::time::advance(Duration::from_secs(6)).await;
    let before = Clock::now();
    let id = local.begin_stats_refresh(&owner)?.wait(deadline()).await;
    assert_eq!(Clock::now(), before);
    assert_eq!(
        local.stats_snapshot(Some(id))?["refresh"],
        cached["refresh"]
    );
    assert!(local.next_stats_send()?.is_none());
    Ok(())
}

#[tokio::test]
async fn stats_refresh_socket_waiters_share_the_wss_round_and_leave_chat_capacity() -> Result<()> {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    drain(&mut pair)?;
    let owner = config::read_private(&pair.homes[0].path().join("owner.key"))?;
    let remote = &mut pair.stores[1];
    let tx = remote.db.transaction()?;
    tx.execute("UPDATE stats_peers SET last_read=?1", [now()])?;
    for i in 1..=600 {
        tx.execute(
            "INSERT INTO usage_senders VALUES(?1,'sample',1,2,0)",
            [Uuid::from_u128(i).to_string()],
        )?;
    }
    tx.commit()?;
    let stores = pair
        .stores
        .map(|store| Arc::new(std::sync::Mutex::new(store)));
    crate::sync::exercise_stats_refresh(stores, owner, pair.keys[0].clone()).await
}
