use super::test_support::Pair;
use super::*;

fn owner(pair: &mut Pair, action: OwnerOp) -> Value {
    pair.parent
        .execute(Request::Owner {
            credential: config::read_private(&pair.homes[0].path().join("owner.key")).unwrap(),
            action,
        })
        .unwrap()
}
fn call(pair: &mut Pair, index: usize, action: AgentOp) -> Result<Value> {
    pair.parent.execute(if index == 0 {
        Request::Agent {
            credential: pair.keys[index].clone(),
            action,
        }
    } else {
        Request::HostedAgent {
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
    let checkpoint = snapshot::export(pair.homes[0].path(), &node).unwrap();
    let encoded = serde_json::to_string(&checkpoint).unwrap();
    assert!(!encoded.contains("synthetic portable file"));
    assert!(encoded.contains(id));
    let tx = pair.parent.db.transaction().unwrap();
    snapshot::restore(&tx, &checkpoint, pair.state.anchor(), &node).unwrap();
    tx.commit().unwrap();
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
            node_id: node.clone(),
            revision: snapshot.revision,
        },
    );
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
    let credential = config::secret();
    let extra = pair
        .parent
        .execute(Request::HostedAgent {
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
    let tx = pair.parent.db.transaction().unwrap();
    snapshot::restore(&tx, &snapshot, pair.state.anchor(), &node).unwrap();
    tx.commit().unwrap();
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
