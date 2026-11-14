use base64::{Engine as _, engine::general_purpose::STANDARD};
use gent_daemon::{config, store::Store};
use gent_protocol::*;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};
use uuid::Uuid;

fn ok(value: Response) -> Value {
    match value {
        Response::Ok(v) => v,
        Response::Error(e) => panic!("{e}"),
    }
}
fn error(value: Response) -> String {
    match value {
        Response::Error(e) => e,
        Response::Ok(v) => panic!("unexpected success: {v}"),
    }
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn jsonl(path: &Path, values: &[Value]) -> Value {
    let bytes = values
        .iter()
        .map(|v| format!("{v}\n"))
        .collect::<String>()
        .into_bytes();
    config::write_private(path, &bytes).unwrap();
    json!({"path":path.file_name().unwrap().to_str().unwrap(),"records":values.len(),"bytes":bytes.len(),"sha256":sha(&bytes)})
}
struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    directory: PathBuf,
    store: Store,
    owner: String,
    keys: [String; 2],
    agents: [String; 2],
    source: String,
    pin: String,
    message: String,
    binary: Vec<u8>,
    image: Vec<u8>,
    object: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        config::private_dir(temp.path()).unwrap();
        let home = temp.path().join("node");
        config::initialize(&home, "recovered").unwrap();
        let mut store = Store::open(&home).unwrap();
        let owner = config::read_private(&home.join("owner.key")).unwrap();
        let keys = [config::secret(), config::secret()];
        let agents = std::array::from_fn(|i| {
            ok(store.handle(Request::Agent {
                credential: keys[i].clone(),
                action: AgentOp::Register {
                    name: format!("current-{i}"),
                    provider: "test".into(),
                },
            }))["agent"]["id"]
                .as_str()
                .unwrap()
                .to_string()
        });
        let directory = temp.path().join("history");
        config::private_dir(&directory.join("files")).unwrap();
        config::write_private(
            &directory.join("recovery-required.json"),
            b"offline history",
        )
        .unwrap();
        let old_agents: [Agent; 4] = std::array::from_fn(|i| Agent {
            id: Uuid::new_v4().to_string(),
            node_id: Uuid::new_v4().to_string(),
            name: if i < 2 {
                format!("old-{i}")
            } else {
                format!("unrelated-secret-{i}")
            },
            provider: "old-test".into(),
            last_seen: 10,
            revoked: false,
        });
        let source = old_agents[0].id.clone();
        let image = b"historical image bytes".to_vec();
        let binary = vec![0x5a; file_objects::CHUNK_BYTES + 17];
        let object = Uuid::new_v4().to_string();
        let descriptor = FileDescriptor {
            id: object.clone(),
            name: "visual.bin".into(),
            media_type: "application/octet-stream".into(),
            byte_length: binary.len() as u64,
            sha256: sha(&binary),
        };
        let mut messages = Vec::new();
        let mut first = String::new();
        for index in 0..24 {
            let private = index == 23;
            let a = if private { 2 } else { 0 };
            let b = if private { 3 } else { 1 };
            let id = Uuid::new_v4().to_string();
            if index == 0 {
                first = id.clone();
            }
            let message = Message {
                id: id.clone(),
                exchange_id: Uuid::new_v4().to_string(),
                sender: old_agents[a].id.clone(),
                recipient: old_agents[b].id.clone(),
                text: if private {
                    "UNRELATED PRIVATE EXCHANGE".into()
                } else {
                    format!("historical message {index}")
                },
                files: if index == 0 {
                    vec![FilePart {
                        name: "pixel.png".into(),
                        media_type: "image/png".into(),
                        data_base64: STANDARD.encode(&image),
                    }]
                } else {
                    vec![]
                },
                attachments: if index == 0 {
                    vec![descriptor.clone()]
                } else {
                    vec![]
                },
                reply_to: None,
                created_at: 10,
                expires_at: 20,
                acknowledged: true,
                relay: None,
            };
            let assets = if index == 0 {
                json!([
                    {"source":"inline","index":0,"status":"exported","path":format!("files/{id}-inline-0"),"name":"pixel.png","media_type":"image/png","byte_length":image.len(),"sha256":sha(&image)},
                    {"source":"attachment","status":"exported","path":format!("files/{object}"),"file":descriptor}
                ])
            } else {
                json!([])
            };
            messages.push(json!({"message":message,"assets":assets}));
        }
        config::write_private(&directory.join(format!("files/{first}-inline-0")), &image).unwrap();
        config::write_private(&directory.join(format!("files/{object}")), &binary).unwrap();
        let agent_summary = jsonl(
            &directory.join("agents.jsonl"),
            &old_agents.iter().map(|a| json!(a)).collect::<Vec<_>>(),
        );
        let message_summary = jsonl(&directory.join("messages.jsonl"), &messages);
        let manifest = json!({"version":1,"kind":"gent_offline_history","archive_id":Uuid::new_v4(),"cluster_id":Uuid::new_v4(),"node_id":Uuid::new_v4(),"captured_at":10,"database_sha256":"11".repeat(32),"agents":agent_summary,"messages":message_summary,"files":{"exported":2,"missing":0,"incomplete":0},"content_bytes":agent_summary["bytes"].as_u64().unwrap()+message_summary["bytes"].as_u64().unwrap()+image.len() as u64+binary.len() as u64,"scope":"historical","provenance":"test fixture","activation":"unsupported"});
        let bytes = serde_json::to_vec(&manifest).unwrap();
        config::write_private(&directory.join("history.json"), &bytes).unwrap();
        Self {
            _temp: temp,
            home,
            directory,
            store,
            owner,
            keys,
            agents,
            source,
            pin: sha(&bytes),
            message: first,
            binary,
            image,
            object,
        }
    }
    fn action(&self, restore: Option<u64>) -> OwnerOp {
        OwnerOp::HistoryImport {
            directory: self.directory.to_str().unwrap().into(),
            manifest_sha256: self.pin.clone(),
            source_agent: self.source.clone(),
            target_agent: self.agents[0].clone(),
            restore_revision: restore,
        }
    }
    fn import(&mut self, restore: Option<u64>) -> Response {
        self.owner(self.action(restore))
    }
    fn owner(&mut self, action: OwnerOp) -> Response {
        self.store.handle(Request::Owner {
            credential: self.owner.clone(),
            action,
        })
    }
    fn agent(&mut self, index: usize, action: AgentOp) -> Response {
        self.store.handle(Request::Agent {
            credential: self.keys[index].clone(),
            action,
        })
    }
    fn counts(&self) -> (u64, u64, u64, u64) {
        let db = Connection::open(self.home.join("state.sqlite3")).unwrap();
        db.query_row("SELECT (SELECT COUNT(*) FROM messages),(SELECT COUNT(*) FROM exchanges),(SELECT COUNT(*) FROM network_events),(SELECT COUNT(*) FROM file_objects)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap()
    }
    fn rows(&self) -> (u64, u64, u64) {
        let db = Connection::open(self.home.join("state.sqlite3")).unwrap();
        db.query_row("SELECT (SELECT COUNT(*) FROM recovered_sources),(SELECT COUNT(*) FROM recovered_messages),(SELECT COUNT(*) FROM recovered_chunks)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap()
    }
}

#[test]
fn assigned_history_is_private_paginated_persistent_and_inert() {
    let mut f = Fixture::new();
    let before = f.counts();
    let result = ok(f.import(None));
    let id = result["import_id"].as_str().unwrap().to_string();
    assert_eq!(result["messages"], 23);
    assert_eq!(f.counts(), before);
    assert_eq!(ok(f.agent(0, AgentOp::Inbox)), json!([]));
    assert_eq!(ok(f.agent(0, AgentOp::Agents)), json!([]));
    let imports = ok(f.agent(0, AgentOp::HistoryImports));
    assert_eq!(imports["historical_imports"].as_array().unwrap().len(), 1);
    assert_eq!(
        ok(f.agent(1, AgentOp::HistoryImports))["historical_imports"],
        json!([])
    );
    let hidden = error(f.agent(
        1,
        AgentOp::HistoryMessages {
            import_id: id.clone(),
            after: 0,
        },
    ));
    assert_eq!(
        hidden,
        error(f.agent(
            1,
            AgentOp::HistoryMessages {
                import_id: Uuid::new_v4().to_string(),
                after: 0
            }
        ))
    );
    let page = ok(f.agent(
        0,
        AgentOp::HistoryMessages {
            import_id: id.clone(),
            after: 0,
        },
    ));
    assert_eq!(page["messages"].as_array().unwrap().len(), 20);
    assert_eq!(page["has_more"], true);
    assert!(
        !page.to_string().contains("UNRELATED") && !page.to_string().contains("unrelated-secret")
    );
    assert_eq!(page["messages"][0]["message"]["files"], json!([]));
    let last = ok(f.agent(
        0,
        AgentOp::HistoryMessages {
            import_id: id.clone(),
            after: page["next_after"].as_u64().unwrap(),
        },
    ));
    assert_eq!(last["messages"].as_array().unwrap().len(), 3);
    assert_eq!(last["has_more"], false);
    let mut recovered = Vec::new();
    for index in 0..2 {
        let value = ok(f.agent(
            0,
            AgentOp::HistoryFileRead {
                import_id: id.clone(),
                message_id: f.message.clone(),
                file_index: 1,
                chunk_index: index,
            },
        ));
        recovered.extend_from_slice(
            &STANDARD
                .decode(value["data_base64"].as_str().unwrap())
                .unwrap(),
        );
    }
    assert_eq!(recovered, f.binary);
    let viewed = ok(f.agent(
        0,
        AgentOp::HistoryFileView {
            import_id: id.clone(),
            message_id: f.message.clone(),
            file_index: 0,
        },
    ));
    assert_eq!(
        STANDARD
            .decode(viewed["data_base64"].as_str().unwrap())
            .unwrap(),
        f.image
    );
    error(f.agent(
        0,
        AgentOp::FileRead {
            file_id: f.object.clone(),
            chunk_index: 0,
        },
    ));
    error(f.agent(
        0,
        AgentOp::Reply {
            message_id: f.message.clone(),
            request_id: Uuid::now_v7().to_string(),
            text: "must not send".into(),
            files: vec![],
            file_ids: vec![],
        },
    ));
    assert_eq!(f.counts(), before);
    f.store = Store::open(&f.home).unwrap();
    assert_eq!(
        ok(f.agent(
            0,
            AgentOp::HistoryMessages {
                import_id: id.clone(),
                after: 20
            }
        ))["messages"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let counts = f.rows();
    fs::rename(&f.directory, f.directory.with_extension("gone")).unwrap();
    assert_eq!(ok(f.import(None))["duplicate"], true);
    assert_eq!(counts, f.rows());
}

#[test]
fn remove_restore_retries_and_agent_revocation_cannot_resurrect_old_access() {
    let mut f = Fixture::new();
    let id = ok(f.import(None))["import_id"]
        .as_str()
        .unwrap()
        .to_string();
    let removed = ok(f.owner(OwnerOp::HistoryRemove {
        import_id: id.clone(),
        expected_revision: 1,
    }));
    assert_eq!(removed["revision"], 2);
    assert_eq!(f.rows(), (1, 0, 0));
    error(f.import(None));
    error(f.import(Some(1)));
    error(f.agent(
        0,
        AgentOp::HistoryFileView {
            import_id: id.clone(),
            message_id: f.message.clone(),
            file_index: 0,
        },
    ));
    assert_eq!(
        ok(f.owner(OwnerOp::HistoryRemove {
            import_id: id.clone(),
            expected_revision: 1
        }))["duplicate"],
        true
    );
    assert_eq!(ok(f.import(Some(2)))["revision"], 3);
    assert_eq!(ok(f.import(Some(2)))["duplicate"], true);
    error(f.owner(OwnerOp::HistoryRemove {
        import_id: id.clone(),
        expected_revision: 1,
    }));
    ok(f.owner(OwnerOp::HistoryRemove {
        import_id: id.clone(),
        expected_revision: 3,
    }));
    error(f.import(Some(2)));
    assert_eq!(ok(f.import(Some(4)))["revision"], 5);
    ok(f.owner(OwnerOp::Revoke {
        agent_id: f.agents[0].clone(),
    }));
    error(f.agent(0, AgentOp::HistoryImports));
    error(f.import(None));
}

#[test]
fn failed_imports_roll_back_content_grants_and_quota() {
    for failure in 0..7 {
        let mut f = Fixture::new();
        let before = f.counts();
        match failure {
            0 => f.pin = "00".repeat(32),
            1 => {
                fs::write(
                    f.directory.join(format!("files/{}", f.object)),
                    vec![0; f.binary.len()],
                )
                .unwrap();
            }
            2 => {
                let path = f.directory.join(format!("files/{}", f.object));
                fs::remove_file(&path).unwrap();
                symlink("/etc/passwd", path).unwrap();
            }
            3 => {
                let path = f.directory.join("messages.jsonl");
                let mut bytes = fs::read(&path).unwrap();
                let last = bytes.len() - 2;
                bytes[last] = b' ';
                fs::write(path, bytes).unwrap();
            }
            4 => f.source = Uuid::new_v4().to_string(),
            5 => {
                Connection::open(f.home.join("state.sqlite3")).unwrap().execute_batch("CREATE TRIGGER stop_history BEFORE INSERT ON recovered_chunks WHEN NEW.position=1 BEGIN SELECT RAISE(ABORT,'injected history storage failure'); END;").unwrap();
            }
            6 => {
                let mut manifest: Value =
                    serde_json::from_slice(&fs::read(f.directory.join("history.json")).unwrap())
                        .unwrap();
                manifest["version"] = json!(2);
                let bytes = serde_json::to_vec(&manifest).unwrap();
                config::write_private(&f.directory.join("history.json"), &bytes).unwrap();
                f.pin = sha(&bytes);
            }
            _ => unreachable!(),
        }
        error(f.import(None));
        assert_eq!(f.rows(), (0, 0, 0), "case {failure}");
        assert_eq!(f.counts(), before);
    }
}

#[test]
fn receipt_and_byte_quotas_and_changed_chunks_fail_closed() {
    let mut f = Fixture::new();
    let db = Connection::open(f.home.join("state.sqlite3")).unwrap();
    for _ in 0..256 {
        db.execute(
            "INSERT INTO recovered_sources VALUES(?1,?2,?3,?4,'{}',2,1,0)",
            params![Uuid::new_v4().to_string(), f.agents[0], f.source, f.pin],
        )
        .unwrap();
    }
    assert!(error(f.import(None)).contains("receipt limit"));
    db.execute("DELETE FROM recovered_sources", []).unwrap();
    let quota_id = Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO recovered_sources VALUES(?1,?2,?3,?4,'{}',1,0,268435455)",
        params![quota_id, f.agents[0], f.source, f.pin],
    )
    .unwrap();
    assert!(error(f.import(None)).contains("quota"));
    assert_eq!(f.rows(), (1, 0, 0));
    db.execute("DELETE FROM recovered_sources", []).unwrap();
    let id = ok(f.import(None))["import_id"]
        .as_str()
        .unwrap()
        .to_string();
    db.execute(
        "UPDATE recovered_chunks SET bytes=zeroblob(length(bytes)) WHERE source=?1 AND slot=0",
        [&id],
    )
    .unwrap();
    assert!(
        error(f.agent(
            0,
            AgentOp::HistoryFileRead {
                import_id: id.clone(),
                message_id: f.message.clone(),
                file_index: 0,
                chunk_index: 0
            }
        ))
        .contains("integrity")
    );
    error(f.agent(
        0,
        AgentOp::HistoryFileView {
            import_id: id,
            message_id: f.message.clone(),
            file_index: 0,
        },
    ));
    db.execute("UPDATE recovered_schema SET version=2", [])
        .unwrap();
    assert!(Store::open(&f.home).is_err());
}

#[test]
fn lineage_is_preserved_and_invalid_or_excessive_provenance_rolls_back() {
    for case in 0..7 {
        let mut f = Fixture::new();
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(f.directory.join("history.json")).unwrap()).unwrap();
        let hop = json!({"archive":{"archive_id":Uuid::new_v4(),"cluster_id":Uuid::new_v4(),"node_id":Uuid::new_v4(),"captured_at":10,"database_sha256":"22".repeat(32)},
            "import_id":Uuid::new_v4(),"manifest_sha256":"33".repeat(32),"source_agent":f.source,"target_agent":Uuid::new_v4(),"target_revoked":false,"imported_at":11,"revision":1});
        manifest["version"] = json!(2);
        manifest["lineage"] = json!([hop.clone()]);
        match case {
            0 => (),
            1 => manifest["lineage"][0]["source_agent"] = json!(Uuid::new_v4()),
            2 => manifest["lineage"] = json!(vec![hop; 65]),
            3 => manifest["lineage"][0]["revision"] = json!(0),
            4 => manifest["version"] = json!(1),
            5 => manifest["lineage"][0]["archive"]["database_sha256"] = json!("untrusted"),
            6 => manifest["lineage"][0]["secret"] = json!("must-not-echo"),
            _ => unreachable!(),
        }
        let bytes = serde_json::to_vec(&manifest).unwrap();
        config::write_private(&f.directory.join("history.json"), &bytes).unwrap();
        f.pin = sha(&bytes);
        let before = f.counts();
        if case == 0 {
            assert_eq!(ok(f.import(None))["origin"]["lineage"], manifest["lineage"]);
            f.store = Store::open(&f.home).unwrap();
            assert_eq!(
                ok(f.agent(0, AgentOp::HistoryImports))["historical_imports"][0]["origin"]["lineage"],
                manifest["lineage"]
            );
        } else {
            assert!(!error(f.import(None)).contains("must-not-echo"));
            assert_eq!(f.rows(), (0, 0, 0));
        }
        assert_eq!(f.counts(), before);
    }
}

#[test]
fn aggregate_provenance_quota_preserves_readable_import_lists() {
    let mut f = Fixture::new();
    let db = Connection::open(f.home.join("state.sqlite3")).unwrap();
    db.execute(
        "INSERT INTO recovered_sources VALUES(?1,?2,?3,?4,?5,2,1,0)",
        params![
            Uuid::new_v4().to_string(),
            f.agents[0],
            f.source,
            f.pin,
            "x".repeat(2 * 1024 * 1024)
        ],
    )
    .unwrap();
    assert!(error(f.import(None)).contains("metadata quota"));
    assert_eq!(f.rows(), (1, 0, 0));
    let status = ok(f.owner(OwnerOp::HistoryStatus));
    assert_eq!(status["recovered"]["metadata_bytes"], 2 * 1024 * 1024);
    db.execute("DELETE FROM recovered_sources", []).unwrap();
    assert_eq!(ok(f.import(None))["messages"], 23);
}
