use super::test_support::Pair;
use super::*;

fn owner(pair: &mut Pair, action: OwnerOp) -> Value {
    try_owner(pair, action).unwrap()
}
fn try_owner(pair: &mut Pair, action: OwnerOp) -> Result<Value> {
    pair.parent.execute(Request::Owner {
        credential: config::read_private(&pair.homes[0].path().join("owner.key"))?,
        action,
    })
}
fn call(pair: &mut Pair, index: usize, action: AgentOp) -> Result<Value> {
    pair.parent.execute(if index == 0 {
        Request::Agent {
            credential: pair.keys[index].clone(),
            action,
        }
    } else {
        Request::HostedAgent {
            epoch: None,
            node_id: pair.child.identity.node.id().into(),
            gateway_credential: config::read_private(&pair.homes[1].path().join("owner.key"))?,
            credential: pair.keys[index].clone(),
            action,
        }
    })
}
fn fixture() -> Pair {
    let mut pair = Pair::new();
    let node = pair.child.identity.node.id().to_owned();
    let home = pair.homes[1].path().to_owned();
    let parent = pair.parent.identity.node.id().to_owned();
    owner(
        &mut pair,
        OwnerOp::PrepareHostedNode {
            node_id: node.clone(),
            home,
        },
    );
    owner(
        &mut pair,
        OwnerOp::Configure {
            request_id: uuid::Uuid::new_v4().to_string(),
            edit: ConfigurationEdit::HostNode {
                node_id: node.clone(),
                parent,
            },
        },
    );
    owner(
        &mut pair,
        OwnerOp::WebLease {
            node_id: node,
            seconds: 20,
        },
    );
    pair
}
fn sent(pair: &mut Pair) -> String {
    let target = pair.agents[0].clone();
    call(
        pair,
        1,
        AgentOp::RequestReply {
            recipient: target,
            request_id: uuid::Uuid::now_v7().to_string(),
            text: "portable request".into(),
            files: vec![],
            file_ids: vec![],
        },
    )
    .unwrap()["turn_id"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn dashboard_restore_rewinds_only_hosted_boards_and_their_replication_cursors() -> Result<()> {
    let mut pair = fixture();
    let web = pair.child.identity.node.id().to_owned();
    let define = |title: &str| AgentOp::DashboardDefine {
        expected_revision: 0,
        board: serde_json::from_value(json!({"title":title, "widgets":[
            {"id":"status","kind":"link","label":"Status","value":"https://example.org/status"},
            {"id":"data","kind":"scatter","label":"Data","value":[[1,2]],"unit":"kg","x_unit":"s"}
        ]}))
        .unwrap(),
    };
    call(&mut pair, 0, define("native"))?;
    let initial = snapshot::export(pair.homes[0].path(), &web)?;
    assert!(
        serde_json::to_value(&initial)?["tables"]
            .get("dashboards")
            .is_none()
    );
    let mutation = define("hosted");
    call(&mut pair, 1, mutation.clone())?;
    let published = snapshot::export(pair.homes[0].path(), &web)?;
    // V9/V10 restore the raw checkpoint cell and validate its ordinary Text
    // widget. A replacement carrier can export those same fields again.
    let tables = serde_json::to_value(&published)?;
    let cell = tables["tables"]["dashboards"]["rows"][0][2]["value"]
        .as_str()
        .unwrap();
    let stored = serde_json::from_str::<Value>(cell)?;
    assert_eq!(stored["widgets"][1]["kind"], "events");
    assert!(stored["widgets"][1].get("x_unit").is_none());
    assert_eq!(stored["widgets"][0]["kind"], "text");
    assert_eq!(stored["widgets"][0]["unit"], "↗ web link");
    assert_eq!(stored["widgets"][0]["value"], "https://example.org/status");
    call(&mut pair, 1, mutation.clone())?;
    assert_eq!(
        snapshot::export(pair.homes[0].path(), &web)?.revision,
        published.revision
    );
    assert_eq!(
        owner(&mut pair, OwnerOp::Dashboards { after: None })["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    owner(
        &mut pair,
        OwnerOp::WebCommit {
            epoch: None,
            node_id: web.clone(),
            revision: published.revision,
        },
    );
    assert_eq!(
        owner(&mut pair, OwnerOp::Dashboards { after: None })["rows"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    call(
        &mut pair,
        1,
        AgentOp::DashboardDelete {
            expected_revision: 1,
        },
    )?;
    let tombstone = snapshot::export(pair.homes[0].path(), &web)?;
    let restore = |pair: &mut Pair, snap: &snapshot::Snapshot| -> Result<()> {
        let tx = pair.parent.db.transaction()?;
        snapshot::restore(&tx, snap, pair.state.anchor(), &web)?;
        tx.commit()?;
        Ok(())
    };
    for id in &pair.agents[..2] {
        pair.parent.db.execute(
            "INSERT INTO dashboard_sent(peer,agent,revision,event) VALUES('test',?1,2,'queued')",
            [id],
        )?;
    }
    restore(&mut pair, &published)?;
    let restored = call(&mut pair, 1, AgentOp::DashboardGet)?;
    assert_eq!(restored["board"]["title"], "hosted");
    assert_eq!(restored["board"]["widgets"][0]["kind"], "link");
    assert_eq!(
        restored["board"]["widgets"][1],
        json!({
            "id":"data","kind":"scatter","label":"Data","value":[[1,2]],"unit":"kg","x_unit":"s"
        })
    );
    assert_eq!(call(&mut pair, 1, mutation)?["revision"], 1);
    let retained: String =
        pair.parent
            .db
            .query_row("SELECT agent FROM dashboard_sent", [], |r| r.get(0))?;
    assert_eq!(retained, pair.agents[0]);
    restore(&mut pair, &tombstone)?;
    assert_eq!(
        call(&mut pair, 1, AgentOp::DashboardGet)?,
        json!({"revision":2,"board":null})
    );
    let mut foreign = serde_json::to_value(&published)?;
    foreign["tables"]["dashboards"]["rows"][0][0]["value"] = json!(pair.agents[0]);
    assert!(restore(&mut pair, &serde_json::from_value(foreign)?).is_err());
    let mut malformed = serde_json::to_value(&published)?;
    malformed["tables"]["dashboards"]["rows"][0][2]["value"] =
        json!(r#"{"title":"bad","widgets":[]}"#);
    assert!(restore(&mut pair, &serde_json::from_value(malformed)?).is_err());
    assert_eq!(call(&mut pair, 1, AgentOp::DashboardGet)?["revision"], 2);
    // An original V1 checkpoint has no dashboards entry; restore treats it
    // as an empty set for this logical web node.
    restore(&mut pair, &initial)?;
    assert_eq!(
        call(&mut pair, 1, AgentOp::DashboardGet)?,
        json!({"revision":0,"board":null})
    );
    assert_eq!(
        call(&mut pair, 0, AgentOp::DashboardGet)?["board"]["title"],
        "native"
    );
    Ok(())
}

#[test]
fn native_message_after_idle_marks_web_checkpoint_once() {
    let mut pair = fixture();
    let node = pair.child.identity.node.id().to_owned();
    let checkpoint = OwnerOp::WebCheckpoint {
        node_id: node.clone(),
    };
    let before = owner(&mut pair, checkpoint.clone())["revision"]
        .as_u64()
        .unwrap();
    pair.parent
        .db
        .execute(
            "UPDATE hosted_checkpoints SET lease_until=0 WHERE node=?1",
            [&node],
        )
        .unwrap();
    let send = AgentOp::Send {
        recipient: pair.agents[1].clone(),
        request_id: uuid::Uuid::now_v7().to_string(),
        text: "arrived while web carrier idle".into(),
        files: vec![],
        file_ids: vec![],
    };
    let first = call(&mut pair, 0, send.clone()).unwrap();
    assert_eq!(
        call(&mut pair, 0, send).unwrap()["message_id"],
        first["message_id"]
    );
    let state = owner(&mut pair, checkpoint);
    assert_eq!(state["revision"], before + 1);
    assert_eq!(state["lease_until"], 0);
    assert!(call(&mut pair, 1, AgentOp::Inbox).is_err());
}

#[test]
fn checkpoint_withholds_local_delivery_until_committed_and_preserves_native_credentials() {
    let mut pair = fixture();
    let node = pair.child.identity.node.id().to_owned();
    let message = sent(&mut pair);
    assert!(
        call(&mut pair, 0, AgentOp::Inbox)
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty()
    );
    let snapshot = snapshot::export(pair.homes[0].path(), &node).unwrap();
    let encoded = serde_json::to_string(&snapshot).unwrap();
    assert!(!encoded.contains(&hash(&pair.keys[0])));
    assert!(encoded.contains(&hash(&pair.keys[1])));
    owner(
        &mut pair,
        OwnerOp::WebCommit {
            epoch: None,
            node_id: node,
            revision: snapshot.revision,
        },
    );
    let inbox = call(&mut pair, 0, AgentOp::Inbox).unwrap();
    assert_eq!(inbox.as_array().unwrap().len(), 1);
    assert_eq!(inbox[0]["id"], message);
    let tx = pair.parent.db.transaction().unwrap();
    snapshot::restore(&tx, &snapshot, pair.state.anchor(), &snapshot.node).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        call(&mut pair, 0, AgentOp::Identity).unwrap()["agent"]["id"],
        pair.agents[0]
    );
}

#[test]
fn takeover_restores_committed_request_and_discards_unpublished_send() {
    let mut pair = fixture();
    let node = pair.child.identity.node.id().to_owned();
    let committed = sent(&mut pair);
    let snapshot = snapshot::export(pair.homes[0].path(), &node).unwrap();
    owner(
        &mut pair,
        OwnerOp::WebCommit {
            epoch: None,
            node_id: node.clone(),
            revision: snapshot.revision,
        },
    );
    let unpublished = sent(&mut pair);
    let tx = pair.parent.db.transaction().unwrap();
    snapshot::restore(&tx, &snapshot, pair.state.anchor(), &snapshot.node).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        pair.parent
            .db
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE id=?1",
                [unpublished],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        pair.parent
            .db
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE id=?1",
                [committed],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        1
    );
}

#[test]
fn expired_local_lease_rejects_web_mutations_without_affecting_native_chats() {
    let mut pair = fixture();
    let node = pair.child.identity.node.id().to_owned();
    owner(
        &mut pair,
        OwnerOp::WebLease {
            node_id: node.clone(),
            seconds: 0,
        },
    );
    assert!(call(&mut pair, 1, AgentOp::Identity).is_err());
    assert!(call(&mut pair, 0, AgentOp::Identity).is_ok());
    assert!(snapshot::export(pair.homes[0].path(), &node).is_err());
}

#[test]
fn replacing_a_grant_fences_queued_requests_restore_and_checkpoint_completion() {
    let mut pair = fixture();
    let node = pair.child.identity.node.id().to_owned();
    let home = pair.homes[1].path().to_owned();
    let grant = |epoch, expires_at| OwnerOp::WebGrant {
        node_id: node.clone(),
        epoch,
        expires_at,
    };
    let deadline = || (now() + 20) as u64;
    owner(&mut pair, grant(7, deadline()));
    let snapshot = snapshot::export_for_epoch(pair.homes[0].path(), &node, 7).unwrap();
    let checkpoint = home.join("epoch-test.json");
    config::write_private(&checkpoint, &serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let restore = |epoch| OwnerOp::RestoreWebNode {
        node_id: node.clone(),
        home: home.clone(),
        checkpoint: checkpoint.clone(),
        epoch,
    };
    let commit = |epoch| OwnerOp::WebCommit {
        node_id: node.clone(),
        revision: snapshot.revision,
        epoch,
    };
    let credential = pair.keys[1].clone();
    let gateway = config::read_private(&home.join("owner.key")).unwrap();
    let request = |epoch, action| Request::HostedAgent {
        node_id: node.clone(),
        gateway_credential: gateway.clone(),
        credential: credential.clone(),
        epoch,
        action,
    };
    let successor_deadline = deadline();
    owner(&mut pair, grant(8, successor_deadline));
    assert!(try_owner(&mut pair, grant(7, deadline())).is_err());
    assert!(try_owner(&mut pair, grant(7, 0)).is_err());
    assert!(
        try_owner(
            &mut pair,
            OwnerOp::WebLease {
                node_id: node.clone(),
                seconds: 25
            }
        )
        .is_err()
    );
    for stale in [None, Some(7)] {
        assert!(
            pair.parent
                .execute(request(stale, AgentOp::Identity))
                .is_err()
        );
        assert!(try_owner(&mut pair, commit(stale)).is_err());
        assert!(try_owner(&mut pair, restore(stale)).is_err());
    }
    assert!(snapshot::export_for_epoch(pair.homes[0].path(), &node, 7).is_err());
    assert!(snapshot::export(pair.homes[0].path(), &node).is_err());
    owner(&mut pair, restore(Some(8)));
    assert!(try_owner(&mut pair, restore(Some(8))).is_err());
    assert_eq!(
        owner(&mut pair, commit(Some(8)))["lease_until"],
        successor_deadline
    );
    pair.parent
        .execute(request(Some(8), AgentOp::Identity))
        .unwrap();
    owner(&mut pair, grant(8, 0));
    assert!(try_owner(&mut pair, grant(8, deadline())).is_err());
    assert!(
        pair.parent
            .execute(request(Some(8), AgentOp::Inbox))
            .is_err()
    );
    assert!(call(&mut pair, 0, AgentOp::Inbox).is_ok());
}

#[test]
fn expired_grant_rpc_and_restart_cannot_reopen_a_closed_epoch() {
    let mut pair = fixture();
    let node = pair.child.identity.node.id().to_owned();
    let grant = |epoch, expires_at| OwnerOp::WebGrant {
        node_id: node.clone(),
        epoch,
        expires_at,
    };
    let unix = now() as u64;
    assert!(try_owner(&mut pair, grant(4, unix)).is_err());
    assert!(try_owner(&mut pair, grant(4, unix + 60)).is_err());
    let lease = owner(&mut pair, grant(4, unix + 20));
    assert_eq!(lease["lease_until"], unix + 20);
    // The passive socket can obtain fresh authority for this same epoch after
    // natural expiry. Explicit release and daemon restart close it permanently.
    pair.parent
        .db
        .execute(
            "UPDATE hosted_checkpoints SET lease_until=?1 WHERE node=?2",
            params![unix - 1, node],
        )
        .unwrap();
    assert!(snapshot::export_for_epoch(pair.homes[0].path(), &node, 4).is_err());
    owner(&mut pair, grant(4, unix + 20));
    pair.parent = Store::open(pair.homes[0].path()).unwrap();
    assert!(try_owner(&mut pair, grant(4, unix + 20)).is_err());
    assert!(snapshot::export_for_epoch(pair.homes[0].path(), &node, 4).is_err());
    owner(&mut pair, grant(5, unix + 20));
    snapshot::export_for_epoch(pair.homes[0].path(), &node, 5).unwrap();
}

#[test]
fn rejected_message_receipt_does_not_require_a_message_row() {
    let pair = fixture();
    let state = pair.parent.identity.state(&pair.parent.db).unwrap();
    let session = pair.parent.network_session(&pair.parent.db, state);
    session
        .gate_web_event(
            &uuid::Uuid::new_v4().to_string(),
            &crate::messages::Event::Receipt {
                message_id: uuid::Uuid::new_v4().to_string(),
                delivered: false,
            },
        )
        .unwrap();
}

#[test]
fn file_checkpoint_waits_for_upload_and_retains_grant_without_native_bytes() {
    use gent_protocol::file_objects::IncomingFile;
    let mut pair = fixture();
    let node = pair.child.identity.node.id().to_owned();
    let bytes = b"synthetic portable file".to_vec();
    let result = call(
        &mut pair,
        1,
        AgentOp::FileReceiveData {
            file: IncomingFile {
                request_id: uuid::Uuid::now_v7().to_string(),
                name: "proof.txt".into(),
                media_type: "text/plain".into(),
                source_id: "a".repeat(64),
            },
            bytes: zeroize::Zeroizing::new(bytes),
        },
    )
    .unwrap();
    let id = result["file"]["id"].as_str().unwrap();
    assert!(snapshot::export(pair.homes[0].path(), &node).is_err());
    pair.parent
        .db
        .execute("UPDATE file_chunks SET uploaded=1 WHERE object_id=?1", [id])
        .unwrap();
    pair.parent
        .db
        .execute(
            "UPDATE file_objects SET incomplete_until=?2 WHERE id=?1",
            params![id, now() - 1],
        )
        .unwrap();
    let checkpoint = snapshot::export(pair.homes[0].path(), &node).unwrap();
    let encoded = serde_json::to_string(&checkpoint).unwrap();
    assert!(!encoded.contains("synthetic portable file"));
    assert!(encoded.contains(id));
    let tx = pair.parent.db.transaction().unwrap();
    snapshot::restore(&tx, &checkpoint, pair.state.anchor(), &node).unwrap();
    tx.commit().unwrap();
    assert!(pair.parent.db.query_row("SELECT incomplete_until>?2 AND incomplete_until<=expires_at FROM file_objects WHERE id=?1",
        params![id,now()], |r|r.get::<_,bool>(0)).unwrap());
    assert_eq!(
        pair.parent
            .db
            .query_row(
                "SELECT COUNT(*) FROM agent_files WHERE object_id=?1 AND agent=?2",
                params![id, pair.agents[1]],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        1
    );
}

#[test]
fn directory_publishes_only_committed_generations_and_restore_removes_orphans() {
    let mut pair = fixture();
    let node = pair.child.identity.node.id().to_owned();
    let snapshot = snapshot::export(pair.homes[0].path(), &node).unwrap();
    owner(
        &mut pair,
        OwnerOp::WebCommit {
            epoch: None,
            node_id: node.clone(),
            revision: snapshot.revision,
        },
    );
    let tree = |pair: &Pair| {
        let state = pair.parent.identity.state(&pair.parent.db).unwrap();
        pair.parent
            .network_session(&pair.parent.db, state)
            .directory_snapshot()
            .unwrap()
    };
    let committed_tree = tree(&pair);
    let old = call(&mut pair, 1, AgentOp::Identity).unwrap();
    call(
        &mut pair,
        1,
        AgentOp::Rename {
            name: "uncommitted-name".into(),
            expected_generation: 1,
        },
    )
    .unwrap();
    let published = {
        let state = pair.parent.identity.state(&pair.parent.db).unwrap();
        let session = pair.parent.network_session(&pair.parent.db, state);
        session
            .published_registration(&pair.agents[1], &node)
            .unwrap()
            .unwrap()
    };
    assert_eq!(published.generation, 1);
    assert_eq!(published.name, old["agent"]["name"]);
    assert_eq!(tree(&pair), committed_tree);
    let credential = config::secret();
    let extra = pair
        .parent
        .execute(Request::HostedAgent {
            epoch: None,
            node_id: node.clone(),
            gateway_credential: config::read_private(&pair.homes[1].path().join("owner.key"))
                .unwrap(),
            credential,
            action: AgentOp::Register {
                name: "uncommitted-chat".into(),
                provider: "test".into(),
            },
        })
        .unwrap()["agent"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let state = pair.parent.identity.state(&pair.parent.db).unwrap();
    assert!(
        pair.parent
            .network_session(&pair.parent.db, state)
            .published_registration(&extra, &node)
            .unwrap()
            .is_none()
    );
    assert_eq!(tree(&pair), committed_tree);
    let tx = pair.parent.db.transaction().unwrap();
    snapshot::restore(&tx, &snapshot, pair.state.anchor(), &node).unwrap();
    tx.commit().unwrap();
    assert_eq!(tree(&pair), committed_tree);
    assert_eq!(
        pair.parent
            .db
            .query_row("SELECT COUNT(*) FROM agents WHERE id=?1", [extra], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        call(&mut pair, 1, AgentOp::Identity).unwrap()["agent"]["name"],
        old["agent"]["name"]
    );
}
