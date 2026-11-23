//! A logical web node uses only its parent's existing encrypted native link.
use super::*;

#[tokio::test]
async fn dashboard_congestion_retries_after_drain_and_refreshes_a_replaced_key() -> Result<()> {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    let recipient = pair.stores[1].identity.node.id().to_owned();
    let key = pair.stores[1].identity.node.public_key();
    let agent = pair.agents[0].clone();
    let version = crate::messages::wire::DASHBOARD_VERSION;
    let board = serde_json::from_value(json!({"title":"Queued","widgets":[
        {"id":"status","kind":"text","label":"State","value":"old"}]}))?;
    pair.stores[0].db.execute_batch("WITH RECURSIVE slots(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM slots WHERE i<16384)
        INSERT INTO network_events(id,peer,body,traffic) SELECT 'filler-'||i,'capacity-test',X'7b7d','control' FROM slots;")?;
    assert_eq!(
        pair.agent(
            0,
            AgentOp::DashboardDefine {
                expected_revision: 0,
                board
            }
        )?["revision"],
        1
    );
    assert_eq!(
        pair.agent(
            0,
            AgentOp::DashboardUpdate {
                expected_revision: 1,
                values: BTreeMap::from([("status".into(), json!("new"))])
            }
        )?["revision"],
        2
    );
    let s = &pair.stores[0];
    let confirmed = |s: &Store| -> Result<()> {
        let tx = s.db.unchecked_transaction()?;
        s.network_session(&tx, s.identity.state(&tx)?)
            .confirm_wire_version(&recipient, version)?;
        tx.commit()?;
        Ok(())
    };
    s.db.execute("DELETE FROM wire_peers WHERE peer=?1", [&recipient])?;
    confirmed(s)?;
    assert_eq!(
        s.db.query_row(
            "SELECT version FROM wire_peers WHERE peer=?1",
            [&recipient],
            |r| r.get::<_, u8>(0)
        )?,
        version
    );
    assert_eq!(
        s.db.query_row("SELECT count(*) FROM dashboard_sent", [], |r| r
            .get::<_, u32>(0))?,
        0
    );
    assert_eq!(
        s.db.query_row(
            "SELECT count(*) FROM presence_requests WHERE peer=?1",
            [&recipient],
            |r| r.get::<_, u32>(0)
        )?,
        1
    );
    s.db.execute("DELETE FROM network_events WHERE peer='capacity-test'", [])?;
    pair.reopen(0);
    pair.stores[0]
        .db
        .execute("UPDATE node_presence SET next_probe_at=?1", [now() - 1])?;
    pair.stores[0].presence_tick()?;
    pair.pump();
    let body: String = pair.stores[1].db.query_row(
        "SELECT body FROM dashboards WHERE agent=?1 AND revision=2",
        [&agent],
        |r| r.get(0),
    )?;
    assert_eq!(
        serde_json::from_str::<Value>(&body)?["widgets"][0]["value"],
        "new"
    );
    let sent = |s: &Store| -> Result<String> {
        Ok(s.db.query_row(
            "SELECT event FROM dashboard_sent WHERE agent=?1",
            [&agent],
            |r| r.get(0),
        )?)
    };
    let s = &pair.stores[0];
    let old = sent(s)?;
    s.db.execute("UPDATE dashboard_sent SET peer_key=zeroblob(32)", [])?;
    s.db.execute("DELETE FROM wire_peers WHERE peer=?1", [&recipient])?;
    s.db.execute(
        "UPDATE network_links SET peer_key=zeroblob(32) WHERE peer=?1",
        [&recipient],
    )?;
    confirmed(s)?;
    assert_eq!(sent(s)?, old);
    assert!(
        !s.db
            .prepare("SELECT 1 FROM wire_peers WHERE peer=?1")?
            .exists([&recipient])?
    );
    s.db.execute(
        "UPDATE network_links SET peer_key=?2 WHERE peer=?1",
        params![recipient, key],
    )?;
    confirmed(s)?;
    let replacement = sent(s)?;
    assert_ne!(replacement, old);
    assert_eq!(
        s.db.query_row(
            "SELECT peer_key FROM dashboard_sent WHERE agent=?1",
            [&agent],
            |r| r.get::<_, Vec<u8>>(0)
        )?,
        key
    );
    confirmed(s)?;
    assert_eq!(sent(s)?, replacement);
    // While the returning peer's replay is in flight, intermediate
    // revisions coalesce. Even deletion must survive that interval.
    pair.agent(
        0,
        AgentOp::DashboardUpdate {
            expected_revision: 2,
            values: BTreeMap::from([("status".into(), json!("superseded"))]),
        },
    )?;
    pair.agent(
        0,
        AgentOp::DashboardDelete {
            expected_revision: 3,
        },
    )?;
    assert_eq!(sent(&pair.stores[0])?, replacement);
    pair.pump();
    pair.stores[0]
        .db
        .execute("UPDATE node_presence SET next_probe_at=?1", [now() - 1])?;
    pair.stores[0].presence_tick()?;
    pair.pump();
    assert!(
        pair.stores[1]
            .db
            .prepare("SELECT 1 FROM dashboards WHERE agent=?1 AND revision=4 AND body IS NULL")?
            .exists([&agent])?
    );
    Ok(())
}

#[tokio::test]
async fn unchanged_dashboard_survives_cleanup_and_restart_until_peer_returns() -> Result<()> {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    let board = serde_json::from_value(json!({"title":"Offline","widgets":[
        {"id":"s","label":"State","kind":"text","value":"pending"}]}))?;
    pair.agent(
        0,
        AgentOp::DashboardDefine {
            expected_revision: 0,
            board,
        },
    )?;
    let s = &pair.stores[0];
    let queued = |s: &Store| -> Result<(String, Option<i64>, bool)> {
        Ok(s.db.query_row(
            "SELECT e.id,e.retire_after,e.announcement FROM network_events e
             JOIN dashboard_sent d ON d.event=e.id",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?)
    };
    let (id, expiry, watermarked) = queued(s)?;
    assert_eq!((expiry, watermarked), (None, true));
    // Recreate the prior on-disk cursor and retention deadline with an
    // undelivered dashboard. Startup must migrate both in one transaction.
    s.db.execute("ALTER TABLE dashboard_sent DROP COLUMN peer_key", [])?;
    let old_deadline = now() + 86400 + history::RETENTION;
    s.db.execute(
        "UPDATE network_events SET announcement=0,retire_after=?2 WHERE id=?1",
        params![id, old_deadline],
    )?;
    pair.reopen(0);
    assert_eq!(queued(&pair.stores[0])?, (id.clone(), None, true));
    super::super::retention::clean(&pair.stores[0].db, old_deadline + 1, false)?;
    pair.reopen(0);
    assert!(
        pair.stores[0]
            .db
            .prepare("SELECT 1 FROM network_events WHERE id=?1")?
            .exists([&id])?
    );
    pair.pump();
    assert!(
        !pair.stores[0]
            .db
            .prepare("SELECT 1 FROM network_sent WHERE id=?1")?
            .exists([id])?
    );
    let revision: u64 = pair.stores[1].db.query_row(
        "SELECT revision FROM dashboards WHERE agent=?1",
        [&pair.agents[0]],
        |r| r.get(0),
    )?;
    assert_eq!(revision, 1);
    Ok(())
}

fn owner(store: &mut Store, home: &Path, action: OwnerOp) -> Value {
    store
        .execute(Request::Owner {
            credential: config::read_private(&home.join("owner.key")).unwrap(),
            action,
        })
        .unwrap()
}

#[tokio::test]
async fn hosted_chat_uses_parent_directory_and_native_transport_with_original_identity() {
    let mut pair = Pair::new().await;
    let parent = pair.stores[0].identity.node.id().to_owned();
    let remote = pair.stores[1].identity.node.id().to_owned();
    let policy = Policy {
        rules: [Permission::Enumerate, Permission::Send, Permission::Receive]
            .map(|permission| Rule {
                actor: Selector::All,
                peer: Selector::All,
                permission,
                effect: Effect::Allow,
            })
            .into(),
        ..Default::default()
    };
    owner(
        &mut pair.stores[0],
        pair.homes[0].path(),
        OwnerOp::SetPolicy { policy },
    );
    let child_home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(child_home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let child = gent_crypto::NodeIdentity::generate().unwrap();
    {
        let store = &pair.stores[0];
        let tx = store.db.unchecked_transaction().unwrap();
        let state = store.identity.state(&tx).unwrap();
        let enrollment = child
            .request_enrollment(state.anchor(), state.checkpoint(), "web", now() as u64)
            .unwrap();
        let signed = state
            .enroll(
                &*store.identity.signing_owner(&tx).unwrap(),
                &enrollment,
                enrollment.fingerprint().unwrap(),
                now() as u64,
            )
            .unwrap();
        let state = store.identity.apply(&tx, signed).unwrap();
        tx.commit().unwrap();
        Store::install_joined(child_home.path(), &child, &state).unwrap();
    }
    let key = config::secret();
    let mut child_store = Store::open(child_home.path()).unwrap();
    let original = child_store
        .execute(Request::Agent {
            credential: key.clone(),
            action: AgentOp::Register {
                name: "walking-web".into(),
                provider: "claude.ai".into(),
            },
        })
        .unwrap()["agent"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    drop(child_store);
    owner(
        &mut pair.stores[0],
        pair.homes[0].path(),
        OwnerOp::PrepareHostedNode {
            node_id: child.id().into(),
            home: child_home.path().into(),
        },
    );
    owner(
        &mut pair.stores[0],
        pair.homes[0].path(),
        OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit: ConfigurationEdit::HostNode {
                node_id: child.id().into(),
                parent: parent.clone(),
            },
        },
    );
    pair.stores[0].reconcile_hosted_routes().unwrap();
    pair.pump();
    // Resolve the logical child's last transport from the carrier's pinned
    // stream. The evidence remains diagnostic even without fresh presence.
    let group = pair.group();
    pair.stores[1].sync_health.record_transport(
        &group,
        crate::sync::health::TransportPath::ClusterHelper {
            helper_id: "helper".into(),
        },
        crate::sync::health::TransportEvidence::ReceivedPacket,
        1,
    );
    let nodes = owner(&mut pair.stores[1], pair.homes[1].path(), OwnerOp::Nodes);
    let rows = nodes.as_array().unwrap();
    let carrier = &rows.iter().find(|n| n["id"] == parent).unwrap()["transport"];
    let hosted = &rows.iter().find(|n| n["id"] == child.id()).unwrap()["transport"];
    assert_eq!(hosted, carrier);
    assert_eq!(hosted["carrier_id"], parent);
    assert_eq!(hosted["last"]["helper_id"], "helper");
    assert_eq!(
        pair.stores[1].synchronization_status().unwrap()["peer_transports"][0]["last"],
        hosted["last"]
    );
    // The native parent's Merkle directory also repairs a lost web chat.
    for store in &mut pair.stores {
        store.presence_tick().unwrap();
    }
    pair.pump();
    pair.stores[1]
        .db
        .execute("DELETE FROM network_origins WHERE agent=?1", [&original])
        .unwrap();
    pair.stores[1]
        .db
        .execute("DELETE FROM agents WHERE id=?1", [&original])
        .unwrap();
    // V4 reconciles on ordinary traffic, including the periodic heartbeat.
    pair.stores[1]
        .db
        .execute("UPDATE node_presence SET next_probe_at=0", [])
        .unwrap();
    pair.stores[1].presence_tick().unwrap();
    pair.pump();
    assert_eq!(
        pair.stores[1].synchronization_status().unwrap()["directory"]["peers"][0]["state"],
        "matched"
    );
    let gateway = config::read_private(&child_home.path().join("owner.key")).unwrap();
    let call = |store: &mut Store, action| {
        store.execute(Request::HostedAgent {
            epoch: None,
            node_id: child.id().into(),
            gateway_credential: gateway.clone(),
            credential: key.clone(),
            action,
        })
    };
    let identity = call(&mut pair.stores[0], AgentOp::Identity).unwrap();
    assert_eq!(identity["agent"]["id"], original);
    assert_eq!(identity["agent"]["node_id"], child.id());
    assert_eq!(identity["transport_node"], parent);
    let directory = call(&mut pair.stores[0], AgentOp::Agents).unwrap();
    assert_eq!(directory.as_array().unwrap().len(), 3);
    let remote_directory = pair.agent(1, AgentOp::Agents).unwrap();
    assert!(
        remote_directory
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["id"] == original && a["node_id"] == child.id())
    );
    assert!(
        !pair.stores[0]
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM network_links WHERE peer=?1)",
                [child.id()],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    let send = AgentOp::Send {
        recipient: pair.agents[1].clone(),
        request_id: Uuid::now_v7().to_string(),
        text: "remote through native host".into(),
        files: vec![FilePart {
            name: "sample.txt".into(),
            media_type: "text/plain".into(),
            data_base64: STANDARD.encode(b"file bytes"),
        }],
        file_ids: vec![],
    };
    let message = call(&mut pair.stores[0], send.clone()).unwrap();
    assert_eq!(
        call(&mut pair.stores[0], send.clone()).unwrap()["message_id"],
        message["message_id"]
    );
    pair.pump();
    let inbox = pair.agent(1, AgentOp::Inbox).unwrap();
    assert_eq!(inbox[0]["sender"], original);
    assert_eq!(
        inbox[0]["files"][0]["data_base64"],
        STANDARD.encode(b"file bytes")
    );
    let message_id = message["message_id"].as_str().unwrap().to_owned();
    pair.agent(
        1,
        AgentOp::Ack {
            message_id: message_id.clone(),
        },
    )
    .unwrap();
    pair.agent(
        1,
        AgentOp::Reply {
            message_id: message_id.clone(),
            request_id: Uuid::now_v7().to_string(),
            text: "reply through parent".into(),
            files: vec![],
            file_ids: vec![],
        },
    )
    .unwrap();
    pair.pump();
    assert_eq!(
        call(&mut pair.stores[0], AgentOp::Inbox).unwrap()[0]["text"],
        "reply through parent"
    );
    assert_eq!(
        call(&mut pair.stores[0], AgentOp::MessageStatus { message_id }).unwrap()["state"],
        "delivered"
    );
    pair.reopen(0);
    assert_eq!(
        call(&mut pair.stores[0], send).unwrap()["message_id"],
        message["message_id"]
    );
    assert!(Store::open(child_home.path()).is_err());
    // The authenticated native peer cannot impersonate the hosted origin, nor
    // can the child's old independent transport authenticate after delegation.
    let state = pair.stores[1].identity.state(&pair.stores[1].db).unwrap();
    let source = pair.stores[0].network_session(
        &pair.stores[0].db,
        pair.stores[0].identity.state(&pair.stores[0].db).unwrap(),
    );
    let registration = source.registration(&original).unwrap();
    let destination = pair.stores[1].network_session(&pair.stores[1].db, state);
    assert!(
        destination
            .import_registration(&remote, &registration)
            .is_err()
    );
    assert!(
        destination
            .import_registration(child.id(), &registration)
            .is_err()
    );
    // A new pending turn survives a carrier change while its native target has
    // already answered but the original carrier has not received that answer.
    owner(
        &mut pair.stores[0],
        pair.homes[0].path(),
        OwnerOp::WebLease {
            node_id: child.id().into(),
            seconds: 20,
        },
    );
    let pending = AgentOp::RequestReply {
        recipient: pair.agents[1].clone(),
        request_id: Uuid::now_v7().to_string(),
        text: "reply during takeover".into(),
        files: vec![],
        file_ids: vec![],
    };
    let turn = call(&mut pair.stores[0], pending.clone()).unwrap()["message_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let checkpoint =
        crate::store::hosted::snapshot::export(pair.homes[0].path(), child.id()).unwrap();
    owner(
        &mut pair.stores[0],
        pair.homes[0].path(),
        OwnerOp::WebCommit {
            epoch: None,
            node_id: child.id().into(),
            revision: checkpoint.revision,
        },
    );
    let committed_identity = call(&mut pair.stores[0], AgentOp::Identity).unwrap();
    call(
        &mut pair.stores[0],
        AgentOp::Rename {
            name: "unpublished-before-carrier-loss".into(),
            expected_generation: committed_identity["registration_generation"]
                .as_u64()
                .unwrap(),
        },
    )
    .unwrap();
    pair.pump();
    let reply = pair
        .agent(
            1,
            AgentOp::Reply {
                message_id: turn.clone(),
                request_id: Uuid::now_v7().to_string(),
                text: "answer retained on the new carrier".into(),
                files: vec![],
                file_ids: vec![],
            },
        )
        .unwrap();
    let new_home = tempfile::tempdir().unwrap();
    let demand = OwnerOp::WebDeliveryDemand {
        node_id: child.id().into(),
    };
    let current = owner(&mut pair.stores[1], pair.homes[1].path(), demand.clone());
    assert_eq!(current["message_id"], reply["message_id"]);
    // A late status response for an earlier send must leave this reply pending.
    let late = OwnerOp::WebDeliveryChecked {
        node_id: child.id().into(),
        message_id: turn.clone(),
    };
    assert_eq!(
        owner(&mut pair.stores[1], pair.homes[1].path(), late)["cleared"],
        false
    );
    assert_eq!(
        owner(&mut pair.stores[1], pair.homes[1].path(), demand)["message_id"],
        reply["message_id"]
    );
    std::fs::set_permissions(new_home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut cfg = config::load_for_runtime(child_home.path()).unwrap();
    cfg.set_hosted_parent(config::HostedParent {
        home: pair.homes[1].path().into(),
        node_id: remote.clone(),
    })
    .unwrap();
    config::save(new_home.path(), &cfg).unwrap();
    let new_gateway = config::secret();
    config::write_private(&new_home.path().join("owner.key"), new_gateway.as_bytes()).unwrap();
    {
        let anchor = pair.stores[1]
            .identity
            .state(&pair.stores[1].db)
            .unwrap()
            .anchor()
            .clone();
        let tx = pair.stores[1].db.transaction().unwrap();
        crate::store::hosted::snapshot::restore(&tx, &checkpoint, &anchor, child.id()).unwrap();
        tx.execute(
            "INSERT INTO hosted_nodes VALUES(?1,?2,?3)",
            params![
                child.id(),
                new_home.path().to_str().unwrap(),
                hash(&new_gateway)
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO hosted_checkpoints VALUES(?1,?2,?2,?3)",
            params![child.id(), checkpoint.revision, now() + 20],
        )
        .unwrap();
        tx.commit().unwrap();
    }
    owner(
        &mut pair.stores[0],
        pair.homes[0].path(),
        OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit: ConfigurationEdit::HostNode {
                node_id: child.id().into(),
                parent: remote.clone(),
            },
        },
    );
    pair.pump();
    pair.stores[1].reconcile_hosted_routes().unwrap();
    pair.pump();
    let state = pair.stores[0].identity.state(&pair.stores[0].db).unwrap();
    let old = pair.stores[0].network_session(&pair.stores[0].db, state);
    assert_eq!(
        old.stored_registration(&original).unwrap().name,
        committed_identity["agent"]["name"]
    );
    let next = |store: &mut Store, action| {
        store.execute(Request::HostedAgent {
            epoch: None,
            node_id: child.id().into(),
            gateway_credential: new_gateway.clone(),
            credential: key.clone(),
            action,
        })
    };
    assert_eq!(
        next(&mut pair.stores[1], AgentOp::Identity).unwrap()["agent"]["id"],
        original
    );
    assert!(call(&mut pair.stores[0], AgentOp::Identity).is_err());
    assert_eq!(
        owner(
            &mut pair.stores[0],
            pair.homes[0].path(),
            OwnerOp::WebCheckpoint {
                node_id: child.id().into(),
            }
        )["hosting_here"],
        false
    );
    let result = next(
        &mut pair.stores[1],
        AgentOp::RelayTurnStatus {
            turn_id: turn.clone(),
            after_message_id: None,
        },
    )
    .unwrap();
    assert_eq!(result["state"], "completed", "{result}");
    assert_eq!(result["responses"][0]["id"], reply["message_id"]);
    assert_eq!(
        next(&mut pair.stores[1], pending).unwrap()["message_id"],
        turn
    );
}
