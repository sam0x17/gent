use gent_crypto::{NodeIdentity, OwnerKey};
use gent_daemon::{
    config,
    encrypted::ordered::OrderedEndpoint,
    store::{Store, now},
};
use gent_protocol::*;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
use uuid::Uuid;

struct Fixture {
    home: tempfile::TempDir,
    owner_rpc: String,
    keys: [String; 2],
    agents: [String; 2],
    store: Store,
}
fn temp() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn ok(response: Response) -> Value {
    match response {
        Response::Ok(v) => v,
        Response::Error(e) => panic!("{e}"),
    }
}
fn agent(store: &mut Store, key: &str, action: AgentOp) -> Response {
    store.handle(Request::Agent {
        credential: key.into(),
        action,
    })
}
fn owner(store: &mut Store, key: &str, action: OwnerOp) -> Response {
    store.handle(Request::Owner {
        credential: key.into(),
        action,
    })
}
fn permit() -> Policy {
    Policy {
        rules: [Permission::Enumerate, Permission::Send, Permission::Receive]
            .map(|permission| Rule {
                actor: Selector::All,
                peer: Selector::All,
                permission,
                effect: Effect::Allow,
            })
            .into(),
        ..Default::default()
    }
}
impl Fixture {
    fn new() -> Self {
        let home = temp();
        config::initialize(home.path(), "runtime").unwrap();
        let owner_rpc = config::read_private(&home.path().join("owner.key")).unwrap();
        let mut store = Store::open(home.path()).unwrap();
        let keys = std::array::from_fn(|_| config::secret());
        let agents = std::array::from_fn(|i| {
            ok(agent(
                &mut store,
                &keys[i],
                AgentOp::Register {
                    name: format!("agent-{i}"),
                    provider: "generic-host".into(),
                },
            ))["agent"]["id"]
                .as_str()
                .unwrap()
                .into()
        });
        Self {
            home,
            owner_rpc,
            keys,
            agents,
            store,
        }
    }
    fn db(&self) -> Connection {
        Connection::open(self.home.path().join("state.sqlite3")).unwrap()
    }
    fn set(&mut self, policy: Policy) -> Value {
        ok(owner(
            &mut self.store,
            &self.owner_rpc,
            OwnerOp::SetPolicy { policy },
        ))
    }
    fn signing(&self) -> (NodeIdentity, OwnerKey) {
        let bytes = fs::read(self.home.path().join("identity.key")).unwrap();
        let cfg = config::load(self.home.path()).unwrap();
        (
            NodeIdentity::from_secret_bytes(&cfg.node.id, bytes[8..40].try_into().unwrap())
                .unwrap(),
            OwnerKey::from_secret_bytes(bytes[40..72].try_into().unwrap()),
        )
    }
    fn send(&mut self) -> Value {
        ok(agent(
            &mut self.store,
            &self.keys[0],
            AgentOp::Send {
                file_ids: vec![],
                recipient: self.agents[1].clone(),
                request_id: Uuid::now_v7().to_string(),
                text: "queued under signed policy".into(),
                files: vec![],
            },
        ))
    }
}

#[test]
fn latest_committed_policy_controls_existing_handles_and_restart() {
    let mut f = Fixture::new();
    let mut other = Store::open(f.home.path()).unwrap();
    assert_eq!(f.set(permit())["revision"], 1);
    f.send();
    // The handle opened before the change sees the new policy in its transaction.
    assert_eq!(
        ok(agent(&mut other, &f.keys[1], AgentOp::Inbox))
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        ok(owner(
            &mut other,
            &f.owner_rpc,
            OwnerOp::SetPolicy {
                policy: Policy::default()
            }
        ))["revision"],
        2
    );
    assert_eq!(
        ok(agent(&mut f.store, &f.keys[1], AgentOp::Inbox)),
        json!([])
    );
    // A later authorized edit replaces the whole policy, even from an old handle.
    assert_eq!(f.set(permit())["revision"], 3);
    assert_eq!(
        ok(agent(&mut other, &f.keys[1], AgentOp::Inbox))
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let mut disk = config::load(f.home.path()).unwrap();
    disk.policy = Policy::default();
    config::save(f.home.path(), &disk).unwrap();
    let mut reopened = Store::open(f.home.path()).unwrap();
    // Unsigned TOML edits are proposals until the owner applies them.
    assert_eq!(
        ok(agent(&mut reopened, &f.keys[1], AgentOp::Inbox))
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        ok(owner(
            &mut reopened,
            &f.owner_rpc,
            OwnerOp::SetPolicy {
                policy: disk.policy
            }
        ))["revision"],
        4
    );
    assert_eq!(
        ok(agent(&mut f.store, &f.keys[1], AgentOp::Inbox)),
        json!([])
    );
    assert_eq!(
        config::load(f.home.path()).unwrap().applied_revision,
        Some(4)
    );
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM authority_history", [], |r| r
                .get::<_, usize>(0))
            .unwrap(),
        5
    );
}

#[test]
fn failed_policy_commit_changes_neither_authority_nor_toml() {
    let mut f = Fixture::new();
    let bytes = fs::read(config::path(f.home.path())).unwrap();
    f.db().execute_batch("CREATE TRIGGER fail_policy BEFORE UPDATE ON authority BEGIN SELECT RAISE(ABORT,'injected authority failure'); END;").unwrap();
    assert!(matches!(
        owner(
            &mut f.store,
            &f.owner_rpc,
            OwnerOp::SetPolicy { policy: permit() }
        ),
        Response::Error(_)
    ));
    assert_eq!(fs::read(config::path(f.home.path())).unwrap(), bytes);
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM authority_history", [], |r| r
                .get::<_, usize>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        ok(agent(&mut f.store, &f.keys[0], AgentOp::Agents)),
        json!([])
    );
    f.db().execute_batch("DROP TRIGGER fail_policy;").unwrap();
    assert_eq!(f.set(permit())["revision"], 1);
}

#[test]
fn failed_toml_projection_recovers_the_newest_revision_and_local_settings() {
    let mut f = Fixture::new();
    let mut disk = config::load(f.home.path()).unwrap();
    disk.extra.insert(
        "local_preference".into(),
        toml::Value::String("keep".into()),
    );
    config::save(f.home.path(), &disk).unwrap();
    let saved = f.home.path().join("staged.toml");
    fs::rename(config::path(f.home.path()), &saved).unwrap();
    fs::create_dir(config::path(f.home.path())).unwrap();
    for name in ["older-name", "newest-name"] {
        let result = ok(owner(
            &mut f.store,
            &f.owner_rpc,
            OwnerOp::RenameNode { name: name.into() },
        ));
        assert_eq!(result["applied"], true);
        assert_eq!(result["config_saved"], false);
    }
    fs::remove_dir(config::path(f.home.path())).unwrap();
    fs::rename(saved, config::path(f.home.path())).unwrap();
    let mut reopened = Store::open(f.home.path()).unwrap();
    let disk = config::load(f.home.path()).unwrap();
    assert_eq!(disk.node.name, "newest-name");
    assert_eq!(disk.applied_revision, Some(2));
    assert_eq!(disk.extra["local_preference"].as_str(), Some("keep"));
    assert_eq!(
        ok(owner(&mut reopened, &f.owner_rpc, OwnerOp::Status))["node"]["name"],
        "newest-name"
    );
}

#[test]
fn failed_message_commit_rolls_back_exchange_and_registration_activity() {
    let mut f = Fixture::new();
    f.set(permit());
    f.db().execute("UPDATE agents SET last_seen=7", []).unwrap();
    f.db().execute_batch("CREATE TRIGGER fail_message BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT,'injected queue failure'); END;").unwrap();
    let request_id = Uuid::now_v7().to_string();
    let action = AgentOp::Send {
        file_ids: vec![],
        recipient: f.agents[1].clone(),
        request_id,
        text: "atomic".into(),
        files: vec![],
    };
    assert!(matches!(
        agent(&mut f.store, &f.keys[0], action.clone()),
        Response::Error(_)
    ));
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM exchanges", [], |r| r
                .get::<_, usize>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        f.db()
            .query_row(
                "SELECT last_seen FROM agents WHERE id=?1",
                [&f.agents[0]],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        7
    );
    f.db().execute_batch("DROP TRIGGER fail_message;").unwrap();
    ok(agent(&mut f.store, &f.keys[0], action));
    assert_eq!(
        f.db()
            .query_row("SELECT count FROM exchanges", [], |r| r.get::<_, usize>(0))
            .unwrap(),
        1
    );
}

#[test]
fn encrypted_configuration_reception_changes_live_rpc_policy() {
    let mut f = Fixture::new();
    let (node, signer) = f.signing();
    let mut local = OrderedEndpoint::open_runtime(f.home.path(), &node).unwrap();
    let peer = NodeIdentity::generate().unwrap();
    let remote_home = temp();
    let mut remote = OrderedEndpoint::open(remote_home.path(), &peer).unwrap();
    let timestamp = now() as u64;
    let state = local.authority_state().unwrap();
    let request = peer
        .request_enrollment(state.anchor(), state.checkpoint(), "peer", timestamp)
        .unwrap();
    local
        .apply_authority(&[state
            .enroll(&signer, &request, request.fingerprint().unwrap(), timestamp)
            .unwrap()])
        .unwrap();
    remote
        .initialize(&local.authority_state().unwrap(), timestamp)
        .unwrap();
    let kp = remote.key_package(Uuid::new_v4(), timestamp).unwrap();
    let outgoing = local
        .create_configuration(&signer, Uuid::new_v4(), (peer.id(), &kp), timestamp)
        .unwrap();
    remote.join_configuration(&outgoing, timestamp).unwrap();
    let kp = local.key_package(Uuid::new_v4(), timestamp).unwrap();
    let incoming = remote
        .create_configuration(&signer, Uuid::new_v4(), (node.id(), &kp), timestamp)
        .unwrap();
    local.join_configuration(&incoming, timestamp).unwrap();
    f.set(permit());
    f.send();
    while let Some(packet) = local
        .next_configuration(outgoing.packet.group(), Uuid::new_v4(), now() as u64)
        .unwrap()
    {
        remote.stage_configuration(&packet, now() as u64).unwrap();
        remote
            .drain_configuration(packet.group(), 128, now() as u64)
            .unwrap();
    }
    assert_eq!(
        remote.authority_state().unwrap().checkpoint(),
        local.authority_state().unwrap().checkpoint()
    );
    let update = remote
        .authority_state()
        .unwrap()
        .set_policy(&signer, Policy::default(), now() as u64)
        .unwrap();
    remote.apply_authority(&[update]).unwrap();
    // A local uncommitted TOML edit must not win over the newer accepted revision.
    let mut disk = config::load(f.home.path()).unwrap();
    disk.extra.insert(
        "local_preference".into(),
        toml::Value::String("keep".into()),
    );
    disk.policy.rules.push(Rule {
        actor: Selector::Group("undefined-local-edit".into()),
        peer: Selector::All,
        permission: Permission::Enumerate,
        effect: Effect::Allow,
    });
    // Simulate hand editing syntactically valid TOML with invalid shared policy.
    config::write_private(
        &config::path(f.home.path()),
        toml::to_string_pretty(&disk).unwrap().as_bytes(),
    )
    .unwrap();
    assert!(config::load(f.home.path()).is_err());
    let mut reopened = Store::open(f.home.path()).unwrap();
    assert_eq!(
        ok(agent(&mut reopened, &f.keys[1], AgentOp::Inbox))
            .as_array()
            .unwrap()
            .len(),
        1
    );
    while let Some(packet) = remote
        .next_configuration(incoming.packet.group(), Uuid::new_v4(), now() as u64)
        .unwrap()
    {
        local.stage_configuration(&packet, now() as u64).unwrap();
        local
            .drain_configuration(packet.group(), 128, now() as u64)
            .unwrap();
    }
    assert_eq!(
        ok(agent(&mut f.store, &f.keys[1], AgentOp::Inbox)),
        json!([])
    );
    assert_eq!(
        ok(agent(&mut f.store, &f.keys[0], AgentOp::Agents)),
        json!([])
    );
    let disk = config::load(f.home.path()).unwrap();
    assert!(disk.policy.rules.is_empty());
    assert_eq!(disk.applied_revision, Some(3));
    assert_eq!(disk.extra["local_preference"].as_str(), Some("keep"));
}

#[test]
fn missing_swapped_or_shared_signing_keys_fail_closed() {
    let f = Fixture::new();
    let path = f.home.path().join("identity.key");
    let bytes = fs::read(&path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
    assert_eq!(
        fs::metadata(f.home.path().join("state.sqlite3"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Store::open(f.home.path()).is_err());
    fs::remove_file(&path).unwrap();
    assert!(Store::open(f.home.path()).is_err());
    let other = Fixture::new();
    symlink(other.home.path().join("identity.key"), &path).unwrap();
    assert!(Store::open(f.home.path()).is_err());
    fs::remove_file(&path).unwrap();
    config::write_private(
        &path,
        &fs::read(other.home.path().join("identity.key")).unwrap(),
    )
    .unwrap();
    assert!(Store::open(f.home.path()).is_err());
    config::write_private(&path, &bytes).unwrap();
    Store::open(f.home.path()).unwrap();
    // Altering the database's trust anchor cannot replace the separate key-file pin.
    let anchor: Vec<u8> = other
        .db()
        .query_row("SELECT anchor FROM authority", [], |r| r.get(0))
        .unwrap();
    f.db()
        .execute("UPDATE authority SET anchor=?1", [anchor])
        .unwrap();
    assert!(Store::open(f.home.path()).is_err());
}

#[test]
fn interrupted_bootstrap_reuses_keys_and_genesis() {
    let home = temp();
    config::initialize(home.path(), "bootstrap").unwrap();
    let path = home.path().join("state.sqlite3");
    config::write_private(&path, &[]).unwrap();
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TRIGGER fail_bootstrap BEFORE INSERT ON metadata WHEN NEW.key='signed_authority' BEGIN SELECT RAISE(ABORT,'injected bootstrap failure'); END;").unwrap();
    assert!(Store::open(home.path()).is_err());
    let keys = fs::read(home.path().join("identity.key")).unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM authority", [], |r| r
            .get::<_, usize>(0))
            .unwrap(),
        0
    );
    db.execute_batch("DROP TRIGGER fail_bootstrap;").unwrap();
    Store::open(home.path()).unwrap();
    assert_eq!(fs::read(home.path().join("identity.key")).unwrap(), keys);
    assert_eq!(config::load(home.path()).unwrap().applied_revision, Some(0));
}

#[test]
fn expired_runtime_blocks_agents_until_owner_renewal_commits() {
    let home = temp();
    let cfg = config::initialize(home.path(), "expired").unwrap();
    let generated = NodeIdentity::generate().unwrap();
    let node = NodeIdentity::from_secret_bytes(&cfg.node.id, &generated.expose_secret()).unwrap();
    let signer = OwnerKey::generate().unwrap();
    let old = signer
        .create_cluster_with_id(
            (&cfg.cluster.id, &cfg.cluster.name),
            &node,
            &cfg.node.name,
            Policy::default(),
            now() as u64 - 2 * gent_crypto::MAX_STATE_LIFETIME,
        )
        .unwrap();
    // An interrupted initial bootstrap can be resumed after its lease expired.
    config::write_private(&home.path().join("state.sqlite3"), &[]).unwrap();
    let mut bytes = b"GENTKEY1".to_vec();
    bytes.extend_from_slice(node.expose_secret().as_ref());
    bytes.extend_from_slice(signer.expose_secret().as_ref());
    bytes.extend_from_slice(
        &serde_json::to_vec(
            &json!({"node":node.id(),"anchor":old.anchor(),"genesis":old.signed()}),
        )
        .unwrap(),
    );
    config::write_private(&home.path().join("identity.key"), &bytes).unwrap();
    let mut store = Store::open(home.path()).unwrap();
    let key = config::secret();
    let registration = AgentOp::Register {
        name: "expired".into(),
        provider: "host".into(),
    };
    assert!(matches!(
        agent(&mut store, &key, registration.clone()),
        Response::Error(_)
    ));
    let owner_rpc = config::read_private(&home.path().join("owner.key")).unwrap();
    assert_eq!(
        ok(owner(&mut store, &owner_rpc, OwnerOp::Status))["authority"]["fresh"],
        false
    );
    let db = Connection::open(home.path().join("state.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_renewal BEFORE UPDATE ON authority BEGIN SELECT RAISE(ABORT,'injected renewal failure'); END;").unwrap();
    assert!(store.maintain().is_err());
    assert!(matches!(
        agent(&mut store, &key, registration.clone()),
        Response::Error(_)
    ));
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM authority_history", [], |r| r
            .get::<_, usize>(0))
            .unwrap(),
        1
    );
    db.execute_batch("DROP TRIGGER fail_renewal;").unwrap();
    store.maintain().unwrap();
    store.maintain().unwrap();
    ok(agent(&mut store, &key, registration));
    let status = ok(owner(&mut store, &owner_rpc, OwnerOp::Status));
    assert_eq!(status["authority"]["fresh"], true);
    assert_eq!(status["authority"]["revision"], 1);
    assert_eq!(config::load(home.path()).unwrap().applied_revision, Some(1));
}

#[test]
fn legacy_local_database_preserves_agents_messages_and_identities() {
    let home = temp();
    let mut cfg = config::initialize(home.path(), "legacy").unwrap();
    cfg.policy = permit();
    config::save(home.path(), &cfg).unwrap();
    let key = config::secret();
    let a = Uuid::new_v4().to_string();
    let b = Uuid::new_v4().to_string();
    let msg = Message {
        attachments: vec![],
        relay: None,
        id: Uuid::new_v4().to_string(),
        exchange_id: Uuid::new_v4().to_string(),
        sender: a.clone(),
        recipient: b.clone(),
        text: "preserve me".into(),
        files: vec![],
        reply_to: None,
        created_at: now(),
        expires_at: now() + 1000,
        acknowledged: false,
    };
    let path = home.path().join("state.sqlite3");
    config::write_private(&path, &[]).unwrap();
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE agents(id TEXT PRIMARY KEY,credential_hash TEXT UNIQUE NOT NULL,node_id TEXT NOT NULL,name TEXT NOT NULL,provider TEXT NOT NULL,last_seen INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE exchanges(id TEXT PRIMARY KEY,a TEXT NOT NULL,b TEXT NOT NULL,expires_at INTEGER NOT NULL,count INTEGER NOT NULL);
        CREATE TABLE messages(id TEXT PRIMARY KEY,sender TEXT NOT NULL,recipient TEXT NOT NULL,request_id TEXT NOT NULL,fingerprint TEXT NOT NULL,payload TEXT NOT NULL,acknowledged INTEGER NOT NULL DEFAULT 0,UNIQUE(sender,request_id));
        CREATE INDEX inbox ON messages(recipient,acknowledged);
        CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);").unwrap();
    use sha2::{Digest, Sha256};
    for (id, credential) in [(&a, config::secret()), (&b, key.clone())] {
        db.execute(
            "INSERT INTO agents VALUES(?1,?2,?3,'legacy','host',0,0)",
            params![
                id,
                format!("{:x}", Sha256::digest(credential.as_bytes())),
                cfg.node.id
            ],
        )
        .unwrap();
    }
    db.execute(
        "INSERT INTO metadata VALUES('cluster',?1),('node',?2)",
        params![cfg.cluster.id, cfg.node.id],
    )
    .unwrap();
    db.execute(
        "INSERT INTO exchanges VALUES(?1,?2,?3,?4,1)",
        params![msg.exchange_id, a, b, msg.expires_at],
    )
    .unwrap();
    db.execute(
        "INSERT INTO messages VALUES(?1,?2,?3,?4,'legacy',?5,0)",
        params![
            msg.id,
            a,
            b,
            Uuid::new_v4().to_string(),
            serde_json::to_string(&msg).unwrap()
        ],
    )
    .unwrap();
    let mut store = Store::open(home.path()).unwrap();
    assert_eq!(ok(agent(&mut store, &key, AgentOp::Inbox))[0]["id"], msg.id);
    assert_eq!(config::load(home.path()).unwrap().node.id, cfg.node.id);
    assert_eq!(
        config::load(home.path()).unwrap().cluster.id,
        cfg.cluster.id
    );
}
