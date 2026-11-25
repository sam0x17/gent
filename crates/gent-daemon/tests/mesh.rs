#[path = "support/relay.rs"]
mod relay;
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gent_daemon::{
    config,
    pairing::{self, Peer},
    store::Store,
    sync,
};
use gent_protocol::{
    AgentOp, Effect, FilePart, OwnerOp, PairingOp, Permission, Policy, Request, Response, Rule,
    Selector,
};
use rusqlite::Connection;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::task::JoinHandle;
use uuid::Uuid;

struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn ok(response: Response) -> Value {
    match response {
        Response::Ok(value) => value,
        Response::Error(error) => panic!("{error}"),
    }
}
struct OwnerPeer {
    store: Arc<Mutex<Store>>,
    key: String,
    cluster: String,
}
impl Peer for OwnerPeer {
    async fn call(&mut self, action: PairingOp) -> Result<Value> {
        match self.store.lock().unwrap().handle(Request::Owner {
            credential: self.key.clone(),
            action: OwnerOp::Pair {
                cluster_id: self.cluster.clone(),
                action,
            },
        }) {
            Response::Ok(value) => Ok(value),
            Response::Error(error) => anyhow::bail!(error),
        }
    }
}
struct Node {
    home: tempfile::TempDir,
    store: Arc<Mutex<Store>>,
    owner: String,
    key: String,
    agent: String,
    task: Option<Task>,
}
impl Node {
    fn new(home: tempfile::TempDir) -> Self {
        let owner = config::read_private(&home.path().join("owner.key")).unwrap();
        gent_daemon::entitlements::grant_test(home.path(), &config::load(home.path()).unwrap());
        let mut store = Store::open(home.path()).unwrap();
        let key = config::secret();
        let agent = ok(store.handle(Request::Agent {
            credential: key.clone(),
            action: AgentOp::Register {
                name: "mesh-agent".into(),
                provider: "generic-host".into(),
            },
        }))["agent"]["id"]
            .as_str()
            .unwrap()
            .into();
        Self {
            home,
            store: Arc::new(Mutex::new(store)),
            owner,
            key,
            agent,
            task: None,
        }
    }
    fn start(&mut self) {
        self.task = Some(Task(sync::start(self.store.clone()).unwrap().unwrap()));
    }
    fn restart(&mut self) {
        self.task.take();
        self.store = Arc::new(Mutex::new(Store::open(self.home.path()).unwrap()));
        self.start();
    }
    fn owner(&self, action: OwnerOp) -> Value {
        ok(self.store.lock().unwrap().handle(Request::Owner {
            credential: self.owner.clone(),
            action,
        }))
    }
    fn agent(&self, action: AgentOp) -> Response {
        self.store.lock().unwrap().handle(Request::Agent {
            credential: self.key.clone(),
            action,
        })
    }
    fn db(&self) -> Connection {
        let db = Connection::open(self.home.path().join("state.sqlite3")).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db
    }
    fn count(&self, table: &str) -> usize {
        self.db()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
}
fn home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    home
}
async fn wait(mut check: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("mesh operation timed out");
}
async fn cluster(relay: &relay::RelayServer) -> Vec<Node> {
    let home = home();
    let mut cfg = config::initialize(home.path(), "mesh").unwrap();
    cfg.relay = Some(config::RelayConfig {
        endpoint: relay.endpoint.clone(),
        credential_file: "relay.key".into(),
    });
    config::write_private(&home.path().join("relay.key"), relay.token.as_bytes()).unwrap();
    config::save(home.path(), &cfg).unwrap();
    let mut nodes = vec![Node::new(home)];
    for _ in 0..2 {
        let next = join(&nodes[0]).await;
        nodes.push(next);
    }
    nodes
}
async fn join(owner: &Node) -> Node {
    let home = home();
    let cluster = config::load(owner.home.path()).unwrap().cluster.id;
    let mut peer = OwnerPeer {
        store: owner.store.clone(),
        key: owner.owner.clone(),
        cluster: cluster.clone(),
    };
    pairing::join(
        home.path(),
        pairing::Options {
            replace_node: None,
            cluster: &cluster,
            name: "peer",
            relay_endpoint: None,
        },
        &mut peer,
    )
    .await
    .unwrap();
    Node::new(home)
}
fn linked(nodes: &[Node]) -> bool {
    nodes.iter().all(|n| {
        n.count("network_links") == nodes.len() - 1
            && n.owner(OwnerOp::Agents).as_array().unwrap().len() == nodes.len()
    })
}
async fn restrict_initiation(nodes: &[Node]) {
    let mut policy = Policy::cluster_default();
    policy.rules.push(Rule {
        actor: Selector::Agent(nodes[2].agent.clone()),
        peer: Selector::Agent(nodes[1].agent.clone()),
        permission: Permission::Send,
        effect: Effect::Deny,
    });
    let revision = nodes[0].owner(OwnerOp::SetPolicy { policy })["revision"]
        .as_u64()
        .unwrap();
    wait(|| {
        nodes
            .iter()
            .all(|n| config::load(n.home.path()).unwrap().applied_revision == Some(revision))
    })
    .await;
}

#[tokio::test]
async fn peers_automatically_connect_and_exchange_files_without_the_owner_online() {
    let relay = relay::RelayServer::start().await;
    let mut nodes = cluster(&relay).await;
    for node in &mut nodes {
        node.start();
    }
    wait(|| linked(&nodes)).await;
    for node in &nodes {
        let visible = ok(node.agent(AgentOp::Agents));
        assert_eq!(visible.as_array().unwrap().len(), nodes.len());
        for peer in &nodes {
            assert!(
                visible
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a["id"] == peer.agent)
            );
        }
    }
    restrict_initiation(&nodes).await;
    nodes[0].task.take();
    relay.mode.store(1, std::sync::atomic::Ordering::SeqCst);
    let bytes = vec![0x6d; 1024 * 1024];
    let sent = ok(nodes[1].agent(AgentOp::Send {
        file_ids: vec![],
        recipient: nodes[2].agent.clone(),
        request_id: Uuid::now_v7().to_string(),
        text: "private-peer-image".into(),
        files: vec![FilePart {
            name: "image.png".into(),
            media_type: "image/png".into(),
            data_base64: STANDARD.encode(&bytes),
        }],
    }));
    nodes[1].restart();
    assert!(
        ok(nodes[2].agent(AgentOp::Inbox))
            .as_array()
            .unwrap()
            .is_empty()
    );
    relay.mode.store(0, std::sync::atomic::Ordering::SeqCst);
    let _ = relay.notices.send(relay::Notice::Changed);
    wait(|| {
        !ok(nodes[2].agent(AgentOp::Inbox))
            .as_array()
            .unwrap()
            .is_empty()
    })
    .await;
    let inbox = ok(nodes[2].agent(AgentOp::Inbox));
    assert_eq!(
        STANDARD
            .decode(inbox[0]["files"][0]["data_base64"].as_str().unwrap())
            .unwrap(),
        bytes
    );
    assert_eq!(nodes[0].count("messages"), 0);
    let id = sent["message_id"].as_str().unwrap().to_owned();
    ok(nodes[2].agent(AgentOp::Ack {
        message_id: id.clone(),
    }));
    wait(|| {
        ok(nodes[1].agent(AgentOp::MessageStatus {
            message_id: id.clone(),
        }))["state"]
            == "delivered"
    })
    .await;
    nodes[1].task.take();
    ok(nodes[2].agent(AgentOp::Reply {
        file_ids: vec![],
        message_id: id,
        request_id: Uuid::now_v7().to_string(),
        text: "offline direct feedback".into(),
        files: vec![],
    }));
    nodes[1].restart();
    nodes[2].restart();
    wait(|| {
        !ok(nodes[1].agent(AgentOp::Inbox))
            .as_array()
            .unwrap()
            .is_empty()
    })
    .await;
    assert_eq!(
        ok(nodes[1].agent(AgentOp::Inbox))[0]["text"],
        "offline direct feedback"
    );
    assert!(matches!(
        nodes[2].agent(AgentOp::Send {
            file_ids: vec![],
            recipient: nodes[1].agent.clone(),
            request_id: Uuid::now_v7().to_string(),
            text: "unsolicited".into(),
            files: vec![]
        }),
        Response::Error(_)
    ));
    for packet in relay.data.lock().unwrap().values().flatten() {
        assert!(!String::from_utf8_lossy(packet).contains("private-peer-image"));
    }
    assert_eq!(nodes[0].count("messages"), 0);
    nodes[0].restart();
    let mut late = join(&nodes[0]).await;
    late.start();
    nodes.push(late);
    wait(|| linked(&nodes)).await;
    assert!(
        nodes[1]
            .owner(OwnerOp::Nodes)
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["data_link"] == true)
            .count()
            == 3
    );
    assert_eq!(nodes[0].count("messages"), 0);
}

#[tokio::test]
async fn mesh_jobs_retry_storage_failures_and_restart_without_duplicate_streams() {
    let relay = relay::RelayServer::start().await;
    let mut nodes = cluster(&relay).await;
    // Fail after cryptographic group creation but before the job and outgoing
    // response commit. Ratchet/Welcome retries must reuse those durable groups.
    nodes[1].db().execute_batch("CREATE TRIGGER fail_mesh_result BEFORE UPDATE OF done ON mesh_jobs WHEN NEW.done=1 BEGIN SELECT RAISE(ABORT,'injected mesh result failure'); END;").unwrap();
    for node in &mut nodes {
        node.start();
    }
    wait(||nodes[1].db().query_row("SELECT EXISTS(SELECT 1 FROM mesh_jobs WHERE error LIKE '%injected mesh result failure%')",[],|r|r.get::<_,bool>(0)).unwrap()).await;
    assert_eq!(nodes[1].count("network_links"), 1);
    let created: Vec<Vec<u8>> = nodes[1]
        .db()
        .prepare("SELECT group_id FROM streams")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    nodes[1].task.take();
    nodes[1]
        .db()
        .execute_batch("DROP TRIGGER fail_mesh_result; UPDATE mesh_jobs SET retry_at=0;")
        .unwrap();
    nodes[1].restart();
    wait(|| linked(&nodes)).await;
    assert_eq!(nodes[1].count("streams"), 5);
    for group in created {
        assert!(
            nodes[1]
                .db()
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM streams WHERE group_id=?1)",
                    [group],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap()
        );
    }
    let counts: Vec<_> = nodes.iter().map(|n| n.count("streams")).collect();
    for node in &mut nodes {
        node.restart();
    }
    wait(|| linked(&nodes)).await;
    assert_eq!(
        nodes.iter().map(|n| n.count("streams")).collect::<Vec<_>>(),
        counts
    );
}

#[tokio::test]
async fn a_new_node_drains_directory_backlog_and_reports_transport_progress() {
    let relay = relay::RelayServer::start().await;
    let mut nodes = cluster(&relay).await;
    let mut expected: BTreeSet<_> = nodes.iter().map(|node| node.agent.clone()).collect();
    for i in 0..40 {
        let registration = ok(nodes[0].store.lock().unwrap().handle(Request::Agent {
            credential: config::secret(),
            action: AgentOp::Register {
                name: format!("history-{i}"),
                provider: "test".into(),
            },
        }));
        assert!(expected.insert(registration["agent"]["id"].as_str().unwrap().to_owned()));
    }
    for node in &mut nodes {
        node.start();
    }
    let agents = |node: &Node| -> BTreeSet<String> {
        node.owner(OwnerOp::Agents)
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_owned())
            .collect()
    };
    wait(|| nodes.iter().all(|node| agents(node) == expected)).await;
    // A directory push can deliver multiple registrations in one packet.
    wait(|| {
        nodes[1].owner(OwnerOp::Status)["sync"]["packets_received"]
            .as_u64()
            .is_some_and(|count| count > 0)
    })
    .await;
    let status = nodes[1].owner(OwnerOp::Status);
    assert!(status["sync"]["last_progress_at"].as_i64().is_some());
    assert!(
        status["sync"]["scope"]
            .as_str()
            .unwrap()
            .contains("not a complete cluster directory")
    );
    nodes[1].restart();
    assert_eq!(agents(&nodes[1]), expected);
}

#[tokio::test]
async fn release_channel_edit_reaches_connected_and_returning_nodes() {
    use gent_daemon::release_channel::{ReleaseChannel, current};
    use gent_protocol::ConfigurationEdit;

    let relay = relay::RelayServer::start().await;
    let mut nodes = cluster(&relay).await;
    let reader_id = config::load(nodes[2].home.path()).unwrap().node.id;
    nodes[0].owner(OwnerOp::DelegateConfiguration {
        node_id: reader_id,
        allow: false,
    });
    for node in &mut nodes {
        node.start();
    }
    wait(|| linked(&nodes) && nodes[2].owner(OwnerOp::Status)["can_set_release_channel"] == false)
        .await;
    let set = |channel| OwnerOp::Configure {
        request_id: Uuid::new_v4().to_string(),
        edit: ConfigurationEdit::SetReleaseChannel { channel },
    };
    let beta = set(ReleaseChannel::Beta);
    let select = |node: &Node, op: OwnerOp| {
        node.store.lock().unwrap().handle(Request::Owner {
            credential: node.owner.clone(),
            action: op,
        })
    };
    assert!(matches!(
        select(&nodes[2], beta.clone()),
        Response::Error(_)
    ));
    assert_eq!(
        nodes[1].owner(OwnerOp::Status)["can_set_release_channel"],
        true
    );
    nodes[2].task.take();
    for node in &nodes {
        assert_eq!(current(node.home.path()).unwrap(), ReleaseChannel::Stable);
    }

    // Queue from an enrolled administrator while the signing owner is offline.
    nodes[0].task.take();
    let queued = nodes[1].owner(beta.clone());
    assert_eq!(queued["state"], "queued");
    assert_eq!(queued["channel"], "beta");
    nodes[1].restart();
    assert_eq!(nodes[1].owner(beta.clone())["state"], "queued");
    assert_eq!(
        current(nodes[1].home.path()).unwrap(),
        ReleaseChannel::Stable
    );
    nodes[0].restart();
    wait(|| nodes[1].owner(beta.clone())["state"] == "applied").await;
    let applied = nodes[1].owner(beta.clone());
    let reused = OwnerOp::Configure {
        request_id: applied["request_id"].as_str().unwrap().into(),
        edit: ConfigurationEdit::SetReleaseChannel {
            channel: ReleaseChannel::Stable,
        },
    };
    assert!(matches!(select(&nodes[1], reused), Response::Error(_)));
    assert_eq!(current(nodes[0].home.path()).unwrap(), ReleaseChannel::Beta);
    assert_eq!(
        current(nodes[2].home.path()).unwrap(),
        ReleaseChannel::Stable
    );
    nodes[2].restart();
    wait(|| current(nodes[2].home.path()).unwrap() == ReleaseChannel::Beta).await;
    assert_eq!(nodes[2].owner(OwnerOp::Status)["release_channel"], "beta");
    let late = join(&nodes[0]).await;
    assert_eq!(current(late.home.path()).unwrap(), ReleaseChannel::Beta);

    // Returning to stable supersedes the edit on every active node. Retrying
    // the older request still returns its original revision and cannot undo it.
    nodes[0].owner(set(ReleaseChannel::Stable));
    wait(|| {
        nodes
            .iter()
            .all(|n| current(n.home.path()).unwrap() == ReleaseChannel::Stable)
    })
    .await;
    assert_eq!(nodes[1].owner(beta)["revision"], applied["revision"]);
    assert_eq!(
        current(nodes[1].home.path()).unwrap(),
        ReleaseChannel::Stable
    );
}
