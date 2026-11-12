use gent_daemon::{config, store::Store};
use gent_protocol::*;
use serde_json::{Value, json};

fn ok(response: Response) -> Value {
    match response {
        Response::Ok(value) => value,
        Response::Error(error) => panic!("unexpected error: {error}"),
    }
}
fn call(store: &mut Store, key: &str, action: AgentOp) -> Response {
    store.handle(Request::Agent {
        credential: key.into(),
        action,
    })
}
fn register(store: &mut Store, key: &str, name: &str) -> String {
    ok(call(
        store,
        key,
        AgentOp::Register {
            name: name.into(),
            provider: "previously-unknown-host".into(),
        },
    ))["agent"]["id"]
        .as_str()
        .unwrap()
        .into()
}
fn open_policy(a: &str, b: &str) -> Policy {
    let mut policy = Policy::default();
    for (actor, peer, permission) in [
        (a, b, Permission::Enumerate),
        (b, a, Permission::Enumerate),
        (a, b, Permission::Send),
        (b, a, Permission::Receive),
    ] {
        policy.rules.push(Rule {
            actor: Selector::Agent(actor.into()),
            peer: Selector::Agent(peer.into()),
            permission,
            effect: Effect::Allow,
        });
    }
    policy
}
fn policy(store: &mut Store, owner: &str, policy: Policy) {
    ok(store.handle(Request::Owner {
        credential: owner.into(),
        action: OwnerOp::SetPolicy { policy },
    }));
}
fn send(recipient: &str, request_id: &str) -> AgentOp {
    AgentOp::Send {recipient:recipient.into(),request_id:request_id.into(),text:"review this image".into(),files:vec![FilePart {name:"pixel.png".into(),media_type:"image/png".into(),data_base64:"iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAABLbSncAAAAEUlEQVR4nGP4z/AfK2IYWhIA0ad/gXfwoGMAAAAASUVORK5CYII=".into()}]}
}

#[test]
fn registered_identity_permissions_and_restart_delivery() {
    let temp = private_tempdir();
    config::initialize(temp.path(), "trial").unwrap();
    let owner = config::read_private(&temp.path().join("owner.key")).unwrap();
    let (ka, kb, kc) = (config::secret(), config::secret(), config::secret());
    let mut store = Store::open(temp.path()).unwrap();
    let a = register(&mut store, &ka, "a");
    let b = register(&mut store, &kb, "b");
    let c = register(&mut store, &kc, "c");
    assert_eq!(register(&mut store, &ka, "different label"), a);
    assert_eq!(ok(call(&mut store, &ka, AgentOp::Agents)), json!([]));
    let request_id = uuid::Uuid::new_v4().to_string();
    assert!(matches!(
        call(&mut store, &ka, send(&b, &request_id)),
        Response::Error(_)
    ));
    assert!(matches!(
        store.handle(Request::Owner {
            credential: ka.clone(),
            action: OwnerOp::Agents
        }),
        Response::Error(_)
    ));
    policy(&mut store, &owner, open_policy(&a, &b));
    let peers = ok(call(&mut store, &ka, AgentOp::Agents));
    assert_eq!(peers.as_array().unwrap().len(), 1);
    assert_eq!(peers[0]["id"], b);
    assert!(!peers.to_string().contains(&c));
    let sent = ok(call(&mut store, &ka, send(&b, &request_id)));
    let message_id = sent["message_id"].as_str().unwrap().to_string();
    assert_eq!(
        ok(call(&mut store, &ka, send(&b, &request_id)))["duplicate"],
        true
    );
    let mut changed = send(&b, &request_id);
    if let AgentOp::Send { text, .. } = &mut changed {
        *text = "different".into();
    }
    assert!(matches!(call(&mut store, &ka, changed), Response::Error(_)));
    assert!(matches!(
        call(
            &mut store,
            &kc,
            AgentOp::Ack {
                message_id: message_id.clone()
            }
        ),
        Response::Error(_)
    ));
    drop(store);
    let mut store = Store::open(temp.path()).unwrap();
    assert_eq!(register(&mut store, &ka, "a"), a);
    let inbox = ok(call(&mut store, &kb, AgentOp::Inbox));
    assert_eq!(inbox.as_array().unwrap().len(), 1);
    assert_eq!(inbox[0]["id"], message_id);
    assert_eq!(inbox[0]["files"][0]["name"], "pixel.png");
    assert_eq!(ok(call(&mut store, &kb, AgentOp::Inbox)), inbox);
    ok(call(
        &mut store,
        &kb,
        AgentOp::Ack {
            message_id: message_id.clone(),
        },
    ));
    assert_eq!(ok(call(&mut store, &kb, AgentOp::Inbox)), json!([]));
    assert_eq!(
        ok(call(
            &mut store,
            &ka,
            AgentOp::MessageStatus {
                message_id: message_id.clone()
            }
        ))["state"],
        "delivered"
    );
    let reply = ok(call(
        &mut store,
        &kb,
        AgentOp::Reply {
            message_id,
            request_id: uuid::Uuid::new_v4().to_string(),
            text: "make it blue".into(),
            files: vec![],
        },
    ));
    assert_eq!(
        ok(call(&mut store, &ka, AgentOp::Inbox))[0]["id"],
        reply["message_id"]
    );
    assert!(matches!(
        call(&mut store, &kb, send(&a, &uuid::Uuid::new_v4().to_string())),
        Response::Error(_)
    ));
}

#[test]
fn queued_work_is_rechecked_and_revoked_credentials_cannot_reregister() {
    let temp = private_tempdir();
    config::initialize(temp.path(), "trial").unwrap();
    let owner = config::read_private(&temp.path().join("owner.key")).unwrap();
    let (ka, kb) = (config::secret(), config::secret());
    let mut store = Store::open(temp.path()).unwrap();
    let a = register(&mut store, &ka, "a");
    let b = register(&mut store, &kb, "b");
    let mut p = open_policy(&a, &b);
    policy(&mut store, &owner, p.clone());
    let sent = ok(call(
        &mut store,
        &ka,
        send(&b, &uuid::Uuid::new_v4().to_string()),
    ));
    p.rules.push(Rule {
        actor: Selector::Agent(b.clone()),
        peer: Selector::Agent(a.clone()),
        permission: Permission::Receive,
        effect: Effect::Deny,
    });
    policy(&mut store, &owner, p);
    assert_eq!(ok(call(&mut store, &kb, AgentOp::Inbox)), json!([]));
    let message_id = sent["message_id"].as_str().unwrap().to_string();
    assert_eq!(
        ok(call(
            &mut store,
            &ka,
            AgentOp::MessageStatus {
                message_id: message_id.clone()
            }
        ))["state"],
        "revoked"
    );
    assert!(matches!(
        call(
            &mut store,
            &kb,
            AgentOp::Reply {
                message_id,
                request_id: uuid::Uuid::new_v4().to_string(),
                text: "no".into(),
                files: vec![]
            }
        ),
        Response::Error(_)
    ));
    ok(store.handle(Request::Owner {
        credential: owner,
        action: OwnerOp::Revoke { agent_id: b },
    }));
    assert!(matches!(
        call(
            &mut store,
            &kb,
            AgentOp::Register {
                name: "new".into(),
                provider: "new".into()
            }
        ),
        Response::Error(_)
    ));
}

#[test]
fn exchange_limits_and_expiry_are_enforced() {
    let temp = private_tempdir();
    config::initialize(temp.path(), "trial").unwrap();
    let owner = config::read_private(&temp.path().join("owner.key")).unwrap();
    let (ka, kb) = (config::secret(), config::secret());
    let mut store = Store::open(temp.path()).unwrap();
    let a = register(&mut store, &ka, "a");
    let b = register(&mut store, &kb, "b");
    policy(&mut store, &owner, open_policy(&a, &b));
    let sent = ok(call(
        &mut store,
        &ka,
        send(&b, &uuid::Uuid::new_v4().to_string()),
    ));
    let mut parent = sent["message_id"].as_str().unwrap().to_string();
    for index in 1..MAX_EXCHANGE_MESSAGES {
        let key = if index % 2 == 1 { &kb } else { &ka };
        parent = ok(call(
            &mut store,
            key,
            AgentOp::Reply {
                message_id: parent,
                request_id: uuid::Uuid::new_v4().to_string(),
                text: "reply".into(),
                files: vec![],
            },
        ))["message_id"]
            .as_str()
            .unwrap()
            .into();
    }
    assert!(matches!(
        call(
            &mut store,
            &ka,
            AgentOp::Reply {
                message_id: parent,
                request_id: uuid::Uuid::new_v4().to_string(),
                text: "extra".into(),
                files: vec![]
            }
        ),
        Response::Error(_)
    ));
    let next = ok(call(
        &mut store,
        &ka,
        send(&b, &uuid::Uuid::new_v4().to_string()),
    ));
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    db.execute(
        "UPDATE exchanges SET expires_at=0 WHERE id=?1",
        [next["exchange_id"].as_str().unwrap()],
    )
    .unwrap();
    assert!(matches!(
        call(
            &mut store,
            &kb,
            AgentOp::Reply {
                message_id: next["message_id"].as_str().unwrap().into(),
                request_id: uuid::Uuid::new_v4().to_string(),
                text: "late".into(),
                files: vec![]
            }
        ),
        Response::Error(_)
    ));
}

#[test]
fn unknown_identity_fields_are_rejected_at_the_protocol_boundary() {
    let forged = json!({"role":"agent","credential":"a".repeat(64),"action":{"op":"register","name":"x","provider":"x","agent_id":"victim","node_id":"another-node"}});
    assert!(serde_json::from_value::<Request>(forged).is_err());
}

fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
