use super::*;

#[tokio::test]
async fn wire_capabilities_require_fresh_matching_proofs() {
    let mut pair = Pair::new().await;
    pair.stores[0].presence_tick().unwrap();
    let first = challenge(&pair, 0);
    reply(&pair, 0, wire::acknowledgement(Uuid::new_v4(), 2)).unwrap();
    assert_eq!(count(&pair, 0, "wire_peers"), 0);
    reply(&pair, 0, wire::acknowledgement(first, 3)).unwrap();
    assert_eq!(count(&pair, 0, "wire_peers"), 0);
    advance(&pair, 0, 31);
    reply(&pair, 0, wire::acknowledgement(first, 2)).unwrap();
    assert_eq!(count(&pair, 0, "wire_peers"), 0);
    pair.stores[0].presence_tick().unwrap();
    let second = challenge(&pair, 0);
    reply(&pair, 0, wire::acknowledgement(second, 2)).unwrap();
    assert_eq!(count(&pair, 0, "wire_peers"), 1);
    assert_eq!(remote(&mut pair, 0)["wire_version"], 2);
    advance(&pair, 0, 91);
    assert_eq!(remote(&mut pair, 0)["wire_version"], 1);
    reply(&pair, 0, wire::acknowledgement(second, 2)).unwrap();
    assert_eq!(remote(&mut pair, 0)["wire_version"], 1);
}

#[tokio::test]
async fn legacy_presence_reply_does_not_enable_activity_and_unmatched_proof_is_ignored() {
    let mut pair = Pair::new().await;
    pair.stores[0].presence_tick().unwrap();
    let first = challenge(&pair, 0);
    reply(&pair, 0, first).unwrap();
    assert_eq!(count(&pair, 0, "activity_peers"), 0);
    advance(&pair, 0, 31);
    pair.stores[0].presence_tick().unwrap();
    let second = challenge(&pair, 0);
    reply(&pair, 0, activity::acknowledgement(first)).unwrap();
    assert_eq!(count(&pair, 0, "activity_peers"), 0);
    reply(&pair, 0, activity::acknowledgement(second)).unwrap();
    assert_eq!(count(&pair, 0, "activity_peers"), 1);
    assert_eq!(remote(&mut pair, 0)["status"], "connected");
}

fn owner(pair: &mut Pair, index: usize, action: OwnerOp) -> Result<Value> {
    let credential = config::read_private(&pair.homes[index].path().join("owner.key"))?;
    pair.stores[index].execute(Request::Owner { credential, action })
}

fn remote(pair: &mut Pair, index: usize) -> Value {
    let peer = pair.stores[1 - index].identity.node.id().to_owned();
    owner(pair, index, OwnerOp::Nodes)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["id"] == peer)
        .unwrap()
        .clone()
}

fn advance(pair: &Pair, index: usize, seconds: i64) {
    pair.stores[index]
        .db
        .execute("UPDATE request_clock SET floor=floor+?1", [seconds])
        .unwrap();
}

fn count(pair: &Pair, index: usize, table: &str) -> u64 {
    pair.stores[index]
        .db
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

fn challenge(pair: &Pair, index: usize) -> Uuid {
    let value: String = pair.stores[index]
        .db
        .query_row("SELECT challenge FROM node_presence", [], |r| r.get(0))
        .unwrap();
    Uuid::parse_str(&value).unwrap()
}

fn deliver_one_way(pair: &mut Pair, from: usize) -> Result<()> {
    let group: Vec<u8> =
        pair.stores[from]
            .db
            .query_row("SELECT outgoing FROM network_links", [], |r| r.get(0))?;
    pair.stores[from].data_prepare(&group)?;
    let next = pair.stores[1 - from].data_next(&group)?;
    let packet = pair.stores[from]
        .data_outgoing(&group, next)?
        .context("expected one packet")?;
    pair.stores[1 - from].data_receive(&packet)
}

fn reply(pair: &Pair, index: usize, nonce: Uuid) -> Result<()> {
    let peer = pair.stores[1 - index].identity.node.id();
    let store = &pair.stores[index];
    let tx = store.db.unchecked_transaction()?;
    store
        .network_session(&tx, store.identity.state(&tx)?)
        .import_event(
            peer,
            Event::Presence {
                challenge: nonce,
                reply: true,
            },
        )?;
    tx.commit()?;
    Ok(())
}

#[tokio::test]
async fn node_inventory_distinguishes_owner_from_default_and_revoked_admin_rights() {
    let mut pair = Pair::new().await;
    let signing_owner = pair.stores[0].identity.node.id().to_owned();
    let joined = pair.stores[1].identity.node.id().to_owned();
    for allowed in [true, false] {
        if !allowed {
            owner(
                &mut pair,
                0,
                OwnerOp::DelegateConfiguration {
                    node_id: joined.clone(),
                    allow: false,
                },
            )
            .unwrap();
            pair.pump();
        }
        for index in 0..2 {
            pair.reopen(index);
            let nodes = owner(&mut pair, index, OwnerOp::Nodes).unwrap();
            let nodes = nodes.as_array().unwrap();
            let writer = nodes
                .iter()
                .find(|node| node["id"] == signing_owner)
                .unwrap();
            // Older owner memberships omit the delegation flag entirely.
            assert_eq!(writer["can_configure"], false);
            assert_eq!(writer["is_owner"], true);
            let peer = nodes.iter().find(|node| node["id"] == joined).unwrap();
            assert_eq!(peer["can_configure"], allowed);
            assert_eq!(peer["is_owner"], false);
        }
    }
    // Missing owner-routing evidence must not make the inventory unavailable.
    pair.stores[1]
        .db
        .execute("DELETE FROM configuration_streams", [])
        .unwrap();
    assert_eq!(remote(&mut pair, 1)["is_owner"], Value::Null);
}

#[tokio::test]
async fn pairing_and_one_way_traffic_do_not_establish_presence_or_touch_agents() {
    let mut pair = Pair::new().await;
    let agent_times: Vec<i64> = (0..2)
        .map(|i| {
            pair.stores[i]
                .db
                .query_row(
                    "SELECT last_seen FROM agents WHERE id=?1",
                    [&pair.agents[i]],
                    |r| r.get(0),
                )
                .unwrap()
        })
        .collect();
    assert_eq!(remote(&mut pair, 0)["status"], "unknown");
    assert_eq!(remote(&mut pair, 1)["status"], "unknown");
    assert!(pair.stores[0].presence_tick().unwrap());
    deliver_one_way(&mut pair, 0).unwrap();
    assert_eq!(remote(&mut pair, 0)["status"], "unknown");
    assert_eq!(remote(&mut pair, 1)["status"], "unknown");
    deliver_one_way(&mut pair, 1).unwrap();
    assert_eq!(remote(&mut pair, 0)["status"], "connected");
    assert_eq!(remote(&mut pair, 1)["status"], "unknown");
    assert!(pair.stores[1].presence_tick().unwrap());
    pair.pump();
    assert_eq!(remote(&mut pair, 1)["status"], "connected");
    for (i, expected) in agent_times.iter().enumerate() {
        for table in ["messages", "exchanges", "wake_dispatches"] {
            assert_eq!(count(&pair, i, table), 0, "{table}");
        }
        let observed: i64 = pair.stores[i]
            .db
            .query_row(
                "SELECT last_seen FROM agents WHERE id=?1",
                [&pair.agents[i]],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(*expected, observed);
        let before = remote(&mut pair, i);
        assert!(!before.to_string().contains(&pair.agents[0]));
        pair.reopen(i);
        assert_eq!(remote(&mut pair, i)["last_seen"], before["last_seen"]);
        assert!(!pair.stores[i].presence_tick().unwrap());
    }
}

#[tokio::test]
async fn late_and_replayed_replies_cannot_supply_freshness() {
    let mut pair = Pair::new().await;
    pair.stores[0].presence_tick().unwrap();
    let first = challenge(&pair, 0);
    reply(&pair, 0, Uuid::new_v4()).unwrap();
    assert_eq!(challenge(&pair, 0), first);
    deliver_one_way(&mut pair, 0).unwrap();
    advance(&pair, 0, 31);
    deliver_one_way(&mut pair, 1).unwrap();
    assert_eq!(remote(&mut pair, 0)["last_seen"], Value::Null);
    assert!(pair.stores[0].presence_tick().unwrap());
    let fresh = challenge(&pair, 0);
    assert_ne!(fresh, first);
    reply(&pair, 0, first).unwrap();
    assert_eq!(challenge(&pair, 0), fresh);
    pair.pump();
    let observed = remote(&mut pair, 0);
    assert_eq!(observed["status"], "connected");
    advance(&pair, 0, 5);
    reply(&pair, 0, fresh).unwrap();
    assert_eq!(remote(&mut pair, 0)["last_seen"], observed["last_seen"]);
    assert!(reply(&pair, 0, Uuid::nil()).is_err());
    assert!(reply(&pair, 0, Uuid::now_v7()).is_err());
    advance(&pair, 0, 25);
    assert!(pair.stores[0].presence_tick().unwrap());
    deliver_one_way(&mut pair, 0).unwrap();
    advance(&pair, 0, 31);
    deliver_one_way(&mut pair, 1).unwrap();
    // Clearing a late probe must not turn a degraded connection back into a
    // connected one merely because an older success is still within 90s.
    assert_eq!(remote(&mut pair, 0)["status"], "degraded");
    assert_eq!(remote(&mut pair, 0)["last_seen"], observed["last_seen"]);
    pair.reopen(0);
    assert_eq!(remote(&mut pair, 0)["status"], "degraded");
    pair.stores[0].presence_tick().unwrap();
    pair.pump();
    assert_eq!(remote(&mut pair, 0)["status"], "connected");
    assert_eq!(
        remote(&mut pair, 0)["presence"]["last_timeout_at"],
        Value::Null
    );
    advance(&pair, 0, 91);
    assert_eq!(remote(&mut pair, 0)["status"], "disconnected");
}

#[tokio::test]
async fn the_exact_response_deadline_is_accepted_without_extending_replays() {
    let mut pair = Pair::new().await;
    pair.stores[0].presence_tick().unwrap();
    let nonce = challenge(&pair, 0);
    deliver_one_way(&mut pair, 0).unwrap();
    advance(&pair, 0, 30);
    deliver_one_way(&mut pair, 1).unwrap();
    let observed = remote(&mut pair, 0);
    assert_eq!(observed["status"], "connected");
    advance(&pair, 0, 90);
    reply(&pair, 0, nonce).unwrap();
    assert_eq!(remote(&mut pair, 0)["last_seen"], observed["last_seen"]);
    advance(&pair, 0, 1);
    assert_eq!(remote(&mut pair, 0)["status"], "disconnected");
}

#[tokio::test]
async fn an_offline_peer_keeps_one_probe_across_time_and_restart_then_recovers() {
    let mut pair = Pair::new().await;
    assert!(pair.stores[0].presence_tick().unwrap());
    let first = challenge(&pair, 0);
    assert_eq!(count(&pair, 0, "network_events"), 1);
    for _ in 0..5 {
        advance(&pair, 0, 600);
        pair.reopen(0);
        assert!(!pair.stores[0].presence_tick().unwrap());
        assert_eq!(count(&pair, 0, "network_events"), 1);
        assert_eq!(challenge(&pair, 0), first);
    }
    assert_eq!(remote(&mut pair, 0)["status"], "disconnected");
    pair.pump();
    assert_eq!(remote(&mut pair, 0)["last_seen"], Value::Null);
    assert!(pair.stores[0].presence_tick().unwrap());
    pair.pump();
    assert_eq!(remote(&mut pair, 0)["status"], "connected");
    assert_eq!(count(&pair, 0, "node_presence"), 1);
}

#[tokio::test]
async fn failed_probe_and_reply_commits_preserve_atomic_retry_state() {
    let mut pair = Pair::new().await;
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_presence BEFORE INSERT ON node_presence BEGIN SELECT RAISE(ABORT,'fixture probe failure'); END;").unwrap();
    assert!(
        pair.stores[0]
            .presence_tick()
            .unwrap_err()
            .to_string()
            .contains("fixture probe")
    );
    assert_eq!(count(&pair, 0, "network_events"), 0);
    assert_eq!(count(&pair, 0, "node_presence"), 0);
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_presence")
        .unwrap();
    pair.stores[0].presence_tick().unwrap();
    let nonce = challenge(&pair, 0);
    deliver_one_way(&mut pair, 0).unwrap();
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_presence BEFORE UPDATE ON node_presence BEGIN SELECT RAISE(ABORT,'fixture response failure'); END;").unwrap();
    assert!(
        deliver_one_way(&mut pair, 1)
            .unwrap_err()
            .to_string()
            .contains("fixture response")
    );
    assert_eq!(challenge(&pair, 0), nonce);
    assert_eq!(remote(&mut pair, 0)["last_seen"], Value::Null);
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_presence")
        .unwrap();
    pair.pump();
    assert_eq!(remote(&mut pair, 0)["status"], "connected");
    assert_eq!(count(&pair, 0, "network_events"), 0);
}

#[tokio::test]
async fn presence_requires_current_membership_and_never_overrides_agent_policy() {
    let mut pair = Pair::new().await;
    pair.policy(false);
    pair.pump();
    for store in &mut pair.stores {
        store.presence_tick().unwrap();
    }
    pair.pump();
    assert_eq!(remote(&mut pair, 0)["status"], "connected");
    assert!(pair.send(vec![]).is_err());
    advance(&pair, 0, 30);
    pair.stores[0].presence_tick().unwrap();
    advance(&pair, 0, 31);
    assert_eq!(remote(&mut pair, 0)["status"], "degraded");
    advance(&pair, 0, 30);
    assert_eq!(remote(&mut pair, 0)["status"], "disconnected");
    advance(&pair, 0, 86400);
    assert!(!pair.stores[0].presence_tick().unwrap());
    assert_eq!(
        remote(&mut pair, 0)["presence"]["reason"],
        "stale_authority"
    );
    owner(&mut pair, 0, OwnerOp::Renew).unwrap();
    let peer = pair.stores[1].identity.node.id().to_owned();
    owner(&mut pair, 0, OwnerOp::RemoveNode { node_id: peer }).unwrap();
    assert!(!pair.stores[0].presence_tick().unwrap());
    assert_eq!(count(&pair, 0, "node_presence"), 0);
    assert_eq!(
        owner(&mut pair, 0, OwnerOp::Nodes)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn probe_storage_failure_does_not_consume_message_capacity() {
    let mut pair = Pair::new().await;
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_presence BEFORE INSERT ON network_events WHEN json_extract(NEW.body,'$.event.kind')='presence' BEGIN SELECT RAISE(ABORT,'fixture presence queue failure'); END;").unwrap();
    assert!(pair.stores[0].presence_tick().is_err());
    let sent = pair.send(vec![]).unwrap();
    pair.pump();
    assert_eq!(
        pair.agent(1, AgentOp::Inbox).unwrap()[0]["id"],
        sent["message_id"]
    );
    assert_eq!(count(&pair, 0, "node_presence"), 0);
}

#[tokio::test]
async fn probe_admission_is_batched_and_retry_metadata_has_a_short_deadline() {
    let mut pair = Pair::new().await;
    // These additional links test queue admission only. Signed enrollment is
    // real; their synthetic stream IDs are never used to encrypt or deliver.
    let store = &pair.stores[0];
    for _ in 0..34 {
        let node = gent_crypto::NodeIdentity::generate().unwrap();
        let state = store.identity.state(&store.db).unwrap();
        let request = node
            .request_enrollment(state.anchor(), state.checkpoint(), "batch", now() as u64)
            .unwrap();
        let update = state
            .enroll(
                &store.identity.signing_owner(&store.db).unwrap(),
                &request,
                request.fingerprint().unwrap(),
                now() as u64,
            )
            .unwrap();
        store.identity.apply(&store.db, update).unwrap();
        store
            .db
            .execute(
                "INSERT INTO network_links VALUES(?1,?2,?3,?4)",
                params![
                    node.id(),
                    node.public_key(),
                    Uuid::new_v4().as_bytes(),
                    Uuid::new_v4().as_bytes()
                ],
            )
            .unwrap();
    }
    assert!(pair.stores[0].presence_tick().unwrap());
    assert_eq!(count(&pair, 0, "node_presence"), 32);
    assert!(pair.stores[0].presence_tick().unwrap());
    assert_eq!(count(&pair, 0, "node_presence"), 35);
    assert!(!pair.stores[0].presence_tick().unwrap());
    let (shortest, longest): (i64, i64) = pair.stores[0]
        .db
        .query_row(
            "SELECT MIN(e.retire_after-p.issued_at),MAX(e.retire_after-p.issued_at)
         FROM network_events e JOIN node_presence p ON p.peer=e.peer
         WHERE json_extract(e.body,'$.event.kind')='presence'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((shortest, longest), (120, 120));
}
