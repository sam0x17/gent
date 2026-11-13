use gent_daemon::{config, store::Store};
use gent_protocol::*;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};
use uuid::Uuid;
#[path = "attachments/retention.rs"]
mod retention;

fn ok(response: Response) -> Value {
    match response {
        Response::Ok(value) => value,
        Response::Error(error) => panic!("{error}"),
    }
}
fn error(response: Response) -> String {
    match response {
        Response::Error(error) => error,
        Response::Ok(_) => panic!("unexpected success"),
    }
}
struct Fixture {
    home: tempfile::TempDir,
    store: Store,
    keys: [String; 3],
    agents: [String; 3],
}
impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        config::initialize(home.path(), "attachments").unwrap();
        let mut store = Store::open(home.path()).unwrap();
        let keys = std::array::from_fn(|_| config::secret());
        let agents = std::array::from_fn(|i| {
            ok(store.handle(Request::Agent {
                credential: keys[i].clone(),
                action: AgentOp::Register {
                    name: format!("agent-{i}"),
                    provider: "generic".into(),
                },
            }))["agent"]["id"]
                .as_str()
                .unwrap()
                .into()
        });
        let mut fixture = Self {
            home,
            store,
            keys,
            agents,
        };
        fixture.policy(Policy {
            rules: [Permission::Enumerate, Permission::Send, Permission::Receive]
                .map(|permission| Rule {
                    actor: Selector::All,
                    peer: Selector::All,
                    permission,
                    effect: Effect::Allow,
                })
                .into(),
            ..Default::default()
        });
        fixture
    }
    fn call(&mut self, i: usize, action: AgentOp) -> Response {
        self.store.handle(Request::Agent {
            credential: self.keys[i].clone(),
            action,
        })
    }
    fn owner(&mut self, action: OwnerOp) -> Value {
        ok(self.store.handle(Request::Owner {
            credential: config::read_private(&self.home.path().join("owner.key")).unwrap(),
            action,
        }))
    }
    fn policy(&mut self, policy: Policy) {
        self.owner(OwnerOp::SetPolicy { policy });
    }
    fn db(&self) -> Connection {
        Connection::open(self.home.path().join("state.sqlite3")).unwrap()
    }
    fn source(&mut self, i: usize, name: &str, bytes: &[u8]) -> AgentOp {
        let paths = ok(self.call(i, AgentOp::FilePaths));
        fs::write(
            PathBuf::from(paths["import_directory"].as_str().unwrap()).join(name),
            bytes,
        )
        .unwrap();
        AgentOp::FileImport {
            request_id: Uuid::new_v4().to_string(),
            name: name.into(),
            media_type: "application/octet-stream".into(),
        }
    }
    fn send(&self, recipient: usize, ids: Vec<String>) -> AgentOp {
        AgentOp::Send {
            recipient: self.agents[recipient].clone(),
            request_id: Uuid::new_v4().to_string(),
            text: String::new(),
            files: vec![],
            file_ids: ids,
        }
    }
    fn inbox(&mut self, i: usize) -> Vec<Message> {
        serde_json::from_value(ok(self.call(i, AgentOp::Inbox))).unwrap()
    }
    fn export(&mut self, i: usize, id: &str) -> Vec<u8> {
        let value = ok(self.call(i, AgentOp::FileExport { file_id: id.into() }));
        fs::read(value["path"].as_str().unwrap()).unwrap()
    }
}
#[test]
fn actual_bytes_retry_restart_forwarding_and_no_public_keys() {
    let mut f = Fixture::new();
    let bytes: Vec<_> = (0..2 * 1024 * 1024 + 19).map(|i| (i * 17) as u8).collect();
    let import = f.source(0, "render.bin", &bytes);
    let imported = ok(f.call(0, import.clone()));
    let id = imported["file"]["id"].as_str().unwrap().to_owned();
    assert_eq!(ok(f.call(0, import))["file"], imported["file"]);
    assert_eq!(
        error(f.call(
            1,
            AgentOp::FileStatus {
                file_id: id.clone()
            }
        )),
        "file unavailable"
    );
    let send = f.send(1, vec![id.clone()]);
    let sent = ok(f.call(0, send.clone()));
    let first = f.inbox(1).remove(0);
    assert!(first.files.is_empty());
    assert_ne!(first.attachments[0].id, id);
    assert_eq!(first.attachments[0].byte_length, bytes.len() as u64);
    let payload = serde_json::to_string(&first).unwrap();
    assert!(
        !payload.contains("grant") && !payload.contains("key") && !payload.contains("data_base64")
    );
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(
        ok(f.call(0, send.clone()))["message_id"],
        sent["message_id"]
    );
    assert_eq!(f.export(1, &first.attachments[0].id), bytes);
    assert_eq!(f.export(1, &first.attachments[0].id), bytes);
    assert_eq!(
        error(f.call(
            2,
            AgentOp::FileExport {
                file_id: first.attachments[0].id.clone()
            }
        )),
        "file unavailable"
    );
    let forward = f.send(2, vec![first.attachments[0].id.clone()]);
    ok(f.call(1, forward));
    let forwarded = f.inbox(2).remove(0);
    assert_ne!(forwarded.attachments[0].id, first.attachments[0].id);
    assert_eq!(f.export(2, &forwarded.attachments[0].id), bytes);
    let grants: Vec<Vec<u8>> = f
        .db()
        .prepare("SELECT grant FROM file_objects")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let mut keys = std::collections::BTreeSet::new();
    for grant in grants {
        let wire: Value = serde_json::from_slice(&grant).unwrap();
        assert!(keys.insert(wire["key"].to_string()));
    }
    let mut changed = send;
    if let AgentOp::Send { file_ids, .. } = &mut changed {
        *file_ids = vec![first.attachments[0].id.clone()];
    }
    assert!(error(f.call(0, changed)).contains("different content"));
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM file_objects", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        3
    );
}
#[test]
fn revoked_permissions_and_expiry_block_retrieval_and_forwarding() {
    let mut f = Fixture::new();
    let import = f.source(0, "empty.bin", b"");
    let id = ok(f.call(0, import))["file"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let send = f.send(1, vec![id.clone()]);
    ok(f.call(0, send));
    let incoming = f.inbox(1).remove(0).attachments.remove(0).id;
    assert!(f.export(1, &incoming).is_empty());
    let mut policy = config::load(f.home.path()).unwrap().policy;
    policy.rules.push(Rule {
        actor: Selector::Agent(f.agents[1].clone()),
        peer: Selector::Agent(f.agents[0].clone()),
        permission: Permission::Receive,
        effect: Effect::Deny,
    });
    f.policy(policy);
    for op in [
        AgentOp::FileStatus {
            file_id: incoming.clone(),
        },
        AgentOp::FileExport {
            file_id: incoming.clone(),
        },
    ] {
        assert_eq!(error(f.call(1, op)), "file unavailable");
    }
    let forward = f.send(2, vec![incoming]);
    assert_eq!(error(f.call(1, forward)), "file unavailable");
    // A staged source belongs only to its importer, independent of conversation grants.
    assert!(f.export(0, &id).is_empty());
    f.db()
        .execute("UPDATE file_objects SET expires_at=1", [])
        .unwrap();
    assert_eq!(
        error(f.call(0, AgentOp::FileStatus { file_id: id })),
        "file unavailable"
    );
    f.store.maintain().unwrap();
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM file_objects", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM agent_files", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        0
    );
}
#[test]
fn imports_and_exports_reject_paths_links_and_overwrites() {
    let mut f = Fixture::new();
    let import = f.source(0, "image.bin", b"original");
    let first = ok(f.call(0, import.clone()));
    let id = first["file"]["id"].as_str().unwrap().to_owned();
    let folders = ok(f.call(0, AgentOp::FilePaths));
    let path = PathBuf::from(folders["import_directory"].as_str().unwrap()).join("image.bin");
    fs::write(&path, b"changed").unwrap();
    assert!(error(f.call(0, import.clone())).contains("different content"));
    fs::remove_file(&path).unwrap();
    symlink(f.home.path().join("owner.key"), &path).unwrap();
    assert!(matches!(f.call(0, import.clone()), Response::Error(_)));
    fs::remove_file(&path).unwrap();
    fs::hard_link(f.home.path().join("owner.key"), &path).unwrap();
    assert!(error(f.call(0, import.clone())).contains("regular"));
    let mut traversal = import;
    if let AgentOp::FileImport { name, .. } = &mut traversal {
        *name = "../owner.key".into();
    }
    assert!(error(f.call(0, traversal)).contains("basename"));
    let export = ok(f.call(
        0,
        AgentOp::FileExport {
            file_id: id.clone(),
        },
    ));
    let out = PathBuf::from(export["path"].as_str().unwrap());
    fs::write(&out, b"user edits").unwrap();
    assert!(
        error(f.call(
            0,
            AgentOp::FileExport {
                file_id: id.clone()
            }
        ))
        .contains("different bytes")
    );
    assert_eq!(fs::read(&out).unwrap(), b"user edits");
    fs::remove_file(&out).unwrap();
    symlink(f.home.path().join("owner.key"), &out).unwrap();
    assert!(matches!(
        f.call(0, AgentOp::FileExport { file_id: id }),
        Response::Error(_)
    ));
    // A symlinked handoff directory must not make a daemon file browser.
    let other = f.home.path().join("elsewhere");
    fs::create_dir(&other).unwrap();
    let outbox = path.parent().unwrap();
    fs::remove_file(&path).unwrap();
    fs::remove_dir(outbox).unwrap();
    symlink(&other, outbox).unwrap();
    assert!(matches!(f.call(0, AgentOp::FilePaths), Response::Error(_)));
}
#[test]
fn message_failure_rolls_back_new_objects_bindings_and_exchange() {
    let mut f = Fixture::new();
    let import = f.source(0, "draft.bin", b"rollback proof");
    let id = ok(f.call(0, import))["file"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    f.db().execute_batch("CREATE TRIGGER fail_file_binding BEFORE INSERT ON agent_files WHEN NEW.message IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    let send = f.send(1, vec![id]);
    assert!(error(f.call(0, send.clone())).contains("injected"));
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM file_objects", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM exchanges", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        0
    );
    f.db()
        .execute_batch("DROP TRIGGER fail_file_binding")
        .unwrap();
    ok(f.call(0, send));
    assert_eq!(f.inbox(1).len(), 1);
}
#[test]
fn relay_turn_files_obey_grant_revocation_and_scoped_replies() {
    let mut f = Fixture::new();
    let grant = Uuid::new_v4().to_string();
    f.owner(OwnerOp::Configure {
        request_id: Uuid::new_v4().to_string(),
        edit: ConfigurationEdit::GrantRelay {
            grant_id: grant.clone(),
            intermediary: f.agents[0].clone(),
            target: f.agents[1].clone(),
            lifetime_seconds: 3600,
        },
    });
    let attached = ok(f.call(
        0,
        AgentOp::RelayAttach {
            target: f.agents[1].clone(),
            request_id: Uuid::new_v4().to_string(),
        },
    ));
    let import = f.source(0, "turn.bin", b"turn attachment");
    let id = ok(f.call(0, import))["file"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let sent = ok(f.call(
        0,
        AgentOp::RelaySend {
            attachment_id: attached["attachment"]["id"].as_str().unwrap().into(),
            request_id: Uuid::new_v4().to_string(),
            text: String::new(),
            files: vec![],
            file_ids: vec![id],
        },
    ));
    let turn = sent["turn_id"].as_str().unwrap().to_owned();
    let request = ok(f.call(1, AgentOp::RelayNext));
    let incoming = request["request"]["attachments"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(f.call(
        1,
        AgentOp::RelayRespond {
            turn_id: turn.clone(),
            request_id: Uuid::new_v4().to_string(),
            text: String::new(),
            files: vec![],
            file_ids: vec![incoming.clone()],
            outcome: RelayResponseKind::Complete,
        },
    ));
    let status = ok(f.call(
        0,
        AgentOp::RelayTurnStatus {
            turn_id: turn,
            after_message_id: None,
        },
    ));
    assert_eq!(status["state"], "completed");
    let outgoing = f.inbox(0).remove(0).attachments.remove(0).id;
    assert_ne!(incoming, outgoing);
    assert_eq!(f.export(0, &outgoing), b"turn attachment");
    f.owner(OwnerOp::Configure {
        request_id: Uuid::new_v4().to_string(),
        edit: ConfigurationEdit::RevokeRelay { grant_id: grant },
    });
    assert_eq!(
        error(f.call(1, AgentOp::FileStatus { file_id: incoming })),
        "file unavailable"
    );
    assert_eq!(
        error(f.call(0, AgentOp::FileStatus { file_id: outgoing })),
        "file unavailable"
    );
    // Public responses contain descriptors only.
    assert!(!json!(status).to_string().contains("\"key\""));
}
