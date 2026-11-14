use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gent_crypto::files::seal;
use gent_protocol::{AgentOp, OwnerOp, Request, Response};
use gent_protocol::{FilePart, Message};
use rusqlite::{Connection, params};
use uuid::Uuid;

fn response(response: Response) -> Value {
    match response {
        Response::Ok(value) => value,
        Response::Error(error) => panic!("{error}"),
    }
}

struct Recovered {
    fixture: Fixture,
    agent: String,
    import: String,
}

impl Recovered {
    fn new(directory: &Path, source: &str) -> Self {
        let fixture = Fixture::new();
        let mut store = Store::open(&fixture.home).unwrap();
        let agent = response(store.handle(Request::Agent {
            credential: config::secret(),
            action: AgentOp::Register {
                name: "replacement".into(),
                provider: "generic".into(),
            },
        }))["agent"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let pin = format!(
            "{:x}",
            Sha256::digest(fs::read(directory.join("history.json")).unwrap())
        );
        let result = response(store.handle(Request::Owner {
            credential: config::read_private(&fixture.home.join("owner.key")).unwrap(),
            action: OwnerOp::HistoryImport {
                directory: directory.to_str().unwrap().into(),
                manifest_sha256: pin,
                source_agent: source.into(),
                target_agent: agent.clone(),
                restore_revision: None,
            },
        }));
        Self {
            fixture,
            agent,
            import: result["import_id"].as_str().unwrap().into(),
        }
    }
    fn mutate(&self, sql: &str) {
        Connection::open(self.fixture.home.join("state.sqlite3"))
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
    fn export(&self) -> Result<Value> {
        self.fixture.create();
        history::export_import(
            &self.fixture.archive,
            &self.fixture.key,
            &self.fixture.output,
            &self.import,
        )
    }
    fn owner(&self, action: OwnerOp) {
        let mut store = Store::open(&self.fixture.home).unwrap();
        response(store.handle(Request::Owner {
            credential: config::read_private(&self.fixture.home.join("owner.key")).unwrap(),
            action,
        }));
    }
}

#[test]
fn imported_history_survives_two_more_archives_with_original_provenance_and_bytes() {
    let h = History::new();
    h.export().unwrap();
    let original: Value =
        serde_json::from_slice(&fs::read(h.fixture.output.join("history.json")).unwrap()).unwrap();
    let recovered = Recovered::new(&h.fixture.output, &h.message.sender);
    // Both saved imports contain the same original message ID. Selecting one
    // must retain its source scope without merging the other assignment.
    {
        let mut store = Store::open(&recovered.fixture.home).unwrap();
        let another = response(store.handle(Request::Agent {
            credential: config::secret(),
            action: AgentOp::Register {
                name: "other-recipient".into(),
                provider: "generic".into(),
            },
        }))["agent"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        response(store.handle(Request::Owner {
            credential: config::read_private(&recovered.fixture.home.join("owner.key")).unwrap(),
            action: OwnerOp::HistoryImport {
                directory: h.fixture.output.to_str().unwrap().into(),
                manifest_sha256: format!(
                    "{:x}",
                    Sha256::digest(fs::read(h.fixture.output.join("history.json")).unwrap())
                ),
                source_agent: h.message.recipient.clone(),
                target_agent: another,
                restore_revision: None,
            },
        }));
    }
    recovered.owner(OwnerOp::Revoke {
        agent_id: recovered.agent.clone(),
    });
    fs::remove_file(&h.fixture.archive).unwrap();
    fs::remove_file(&h.fixture.key).unwrap();
    fs::remove_dir_all(&h.fixture.output).unwrap();
    let before = fs::read(recovered.fixture.home.join("state.sqlite3")).unwrap();
    let report = recovered.export().unwrap();
    assert_eq!(report["messages"], 1);
    assert_eq!(report["files"]["exported"], 2);
    assert_eq!(
        before,
        fs::read(recovered.fixture.home.join("state.sqlite3")).unwrap()
    );
    let listed = history::list(&recovered.fixture.archive, &recovered.fixture.key).unwrap();
    assert_eq!(listed["live_messages"], 0);
    assert_eq!(listed["historical_imports"].as_array().unwrap().len(), 2);
    let selected = listed["historical_imports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["import_id"] == recovered.import)
        .unwrap();
    assert_eq!(selected["target_revoked"], true);
    let manifest: Value =
        serde_json::from_slice(&fs::read(recovered.fixture.output.join("history.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["version"], 2);
    assert_eq!(
        manifest["lineage"][0]["archive"]["archive_id"],
        original["archive_id"]
    );
    assert_eq!(
        manifest["lineage"][0]["archive"]["database_sha256"],
        original["database_sha256"]
    );
    assert_eq!(manifest["lineage"][0]["target_agent"], recovered.agent);
    assert_eq!(manifest["lineage"][0]["target_revoked"], true);
    assert_eq!(manifest["lineage"][0]["revision"], 1);
    let next = Recovered::new(&recovered.fixture.output, &h.message.sender);
    next.export().unwrap();
    let next_manifest: Value =
        serde_json::from_slice(&fs::read(next.fixture.output.join("history.json")).unwrap())
            .unwrap();
    assert_eq!(next_manifest["lineage"].as_array().unwrap().len(), 2);
    assert_eq!(next_manifest["lineage"][0], manifest["lineage"][0]);
    assert_eq!(
        next_manifest["lineage"][1]["archive"]["archive_id"],
        manifest["archive_id"]
    );
    for fixture in [&recovered.fixture, &next.fixture] {
        let record: Value = serde_json::from_str(
            fs::read_to_string(fixture.output.join("messages.jsonl"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        assert_eq!(record["message"]["id"], h.message.id);
        assert_eq!(record["message"]["acknowledged"], true);
        assert_eq!(record["message"]["expires_at"], 20);
        assert_eq!(
            fs::read(
                fixture
                    .output
                    .join(record["assets"][0]["path"].as_str().unwrap())
            )
            .unwrap(),
            b"inline bytes"
        );
        assert_eq!(
            fs::read(
                fixture
                    .output
                    .join(record["assets"][1]["path"].as_str().unwrap())
            )
            .unwrap(),
            h.bytes
        );
        for (name, bytes) in tree(&fixture.output) {
            assert_eq!(
                fs::metadata(fixture.output.join(name)).unwrap().mode() & 0o777,
                0o600
            );
            assert!(
                !bytes
                    .windows(h.private_grant.len())
                    .any(|b| b == h.private_grant)
            );
        }
        assert!(Store::open(&fixture.output).is_err());
    }
}

#[test]
fn removed_imports_stay_receipts_and_missing_history_files_stay_missing() {
    for state in ["missing", "incomplete", "removed"] {
        let h = History::new();
        match state {
            "missing" => h.mutate(
                "DELETE FROM file_chunks; DELETE FROM agent_files; DELETE FROM file_objects",
            ),
            "incomplete" => h.mutate(
                "UPDATE file_objects SET complete=0; DELETE FROM file_chunks WHERE position=1",
            ),
            _ => (),
        }
        h.export().unwrap();
        let recovered = Recovered::new(&h.fixture.output, &h.message.sender);
        if state == "removed" {
            recovered.owner(OwnerOp::HistoryRemove {
                import_id: recovered.import.clone(),
                expected_revision: 1,
            });
            assert!(recovered.export().is_err());
            assert!(!recovered.fixture.output.exists());
            let listed = history::list(&recovered.fixture.archive, &recovered.fixture.key).unwrap();
            assert_eq!(listed["historical_imports"][0]["retired"], true);
            assert_eq!(listed["historical_imports"][0]["revision"], 2);
        } else {
            let report = recovered.export().unwrap();
            assert_eq!(report["files"][state], 1);
            let again = Recovered::new(&recovered.fixture.output, &h.message.sender);
            assert_eq!(again.export().unwrap()["files"][state], 1);
        }
    }
}

#[test]
fn recovered_export_rejects_corruption_unsupported_storage_and_wrong_provenance() {
    let h = History::new();
    h.export().unwrap();
    for sql in [
        "UPDATE recovered_chunks SET bytes=zeroblob(length(bytes)) WHERE slot=1 AND position=0",
        "DELETE FROM recovered_chunks WHERE slot=1 AND position=1",
        "UPDATE recovered_chunks SET digest=printf('%.*c',1048576,'x')",
        "UPDATE recovered_files SET descriptor=json_set(descriptor,'$.name','another.bin') WHERE slot=1",
        "UPDATE recovered_sources SET summary=json_set(summary,'$.source_agent.id','11111111-1111-4111-8111-111111111111')",
        "UPDATE recovered_sources SET bytes=bytes+1",
        "UPDATE recovered_messages SET payload=json_set(payload,'$.message.sender','11111111-1111-4111-8111-111111111111')",
        "UPDATE recovered_messages SET ordinal=2",
        "UPDATE recovered_messages SET payload=json_set(payload,'$.secret','must-not-echo')",
        "UPDATE recovered_schema SET version=2",
        "DROP TABLE recovered_chunks",
        "ALTER TABLE recovered_files RENAME TO saved_recovered_files; CREATE VIEW recovered_files AS SELECT * FROM saved_recovered_files",
    ] {
        let recovered = Recovered::new(&h.fixture.output, &h.message.sender);
        recovered.mutate(sql);
        let error = recovered.export().unwrap_err().to_string();
        assert!(!error.contains("must-not-echo"));
        assert!(!recovered.fixture.output.exists(), "{sql}");
        assert!(
            !fs::read_dir(recovered.fixture._directory.path())
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".gent-history-"))
        );
    }
}

#[test]
fn history_listing_accepts_archives_before_recovered_storage_and_authenticates_all_bytes() {
    let h = History::new();
    h.mutate("DROP TABLE recovered_chunks; DROP TABLE recovered_files; DROP TABLE recovered_messages; DROP TABLE recovered_sources; DROP TABLE recovered_schema;");
    h.fixture.create();
    assert_eq!(
        history::list(&h.fixture.archive, &h.fixture.key).unwrap()["historical_imports"],
        json!([])
    );
    let mut bytes = fs::read(&h.fixture.archive).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&h.fixture.archive, bytes).unwrap();
    assert!(history::list(&h.fixture.archive, &h.fixture.key).is_err());
}

struct History {
    fixture: Fixture,
    message: Message,
    bytes: Vec<u8>,
    private_grant: Vec<u8>,
}

impl History {
    fn new() -> Self {
        let fixture = Fixture::new();
        let cfg = config::load(&fixture.home).unwrap();
        let bytes = vec![0x73; 256 * 1024 + 17];
        let sealed = seal("visual.bin", "application/octet-stream", &bytes).unwrap();
        let private_grant = sealed.grant().encode_private().unwrap().to_vec();
        let a = Uuid::new_v4().to_string();
        let b = Uuid::new_v4().to_string();
        let message = Message {
            id: Uuid::new_v4().to_string(),
            exchange_id: Uuid::new_v4().to_string(),
            sender: a.clone(),
            recipient: b.clone(),
            text: "archived visual review".into(),
            files: vec![FilePart {
                name: "pixel.png".into(),
                media_type: "image/png".into(),
                data_base64: STANDARD.encode(b"inline bytes"),
            }],
            attachments: vec![sealed.grant().descriptor().clone()],
            reply_to: None,
            created_at: 10,
            expires_at: 20,
            acknowledged: false,
            relay: None,
        };
        let mut db = Connection::open(fixture.home.join("state.sqlite3")).unwrap();
        db.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        for (agent, secret) in [
            (&a, "must-not-export-credential-one"),
            (&b, "must-not-export-credential-two"),
        ] {
            db.execute(
                "INSERT INTO agents VALUES(?1,?2,?3,'archived','generic',10,0)",
                params![agent, secret, cfg.node.id],
            )
            .unwrap();
        }
        db.execute(
            "INSERT INTO exchanges VALUES(?1,?2,?3,20,1)",
            params![message.exchange_id, a, b],
        )
        .unwrap();
        db.execute(
            "INSERT INTO messages VALUES(?1,?2,?3,?4,'private-fingerprint',?5,1)",
            params![
                message.id,
                a,
                b,
                Uuid::new_v4().to_string(),
                serde_json::to_string(&message).unwrap()
            ],
        )
        .unwrap();
        let tx = db.transaction().unwrap();
        let objects = gent_daemon::file_objects::Objects::new(&tx, 10).unwrap();
        objects.stage(&sealed, 20).unwrap();
        tx.execute(
            "INSERT INTO agent_files VALUES(?1,NULL,?2,?3)",
            params![
                sealed.grant().descriptor().id,
                message.id,
                serde_json::to_string(&sealed.transport_manifest(20).unwrap()).unwrap()
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        Self {
            fixture,
            message,
            bytes,
            private_grant,
        }
    }
    fn mutate(&self, sql: &str) {
        Connection::open(self.fixture.home.join("state.sqlite3"))
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
    fn export(&self) -> Result<Value> {
        self.fixture.create();
        history::export(
            &self.fixture.archive,
            &self.fixture.key,
            &self.fixture.output,
        )
    }
    fn no_staging(&self) {
        assert!(
            !fs::read_dir(self.fixture._directory.path())
                .unwrap()
                .any(|e| e
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".gent-history-"))
        );
    }
}

#[test]
fn history_recovers_expired_bytes_and_acknowledgments_without_runtime_or_keys() {
    let h = History::new();
    let f = &h.fixture;
    let state_before = fs::read(f.home.join("state.sqlite3")).unwrap();
    let status = h.export().unwrap();
    assert_eq!(status["state"], "exported_history");
    assert_eq!(status["files"]["exported"], 2);
    assert_eq!(
        fs::read(f.home.join("state.sqlite3")).unwrap(),
        state_before
    );
    let report: Value =
        serde_json::from_slice(&fs::read(f.output.join("history.json")).unwrap()).unwrap();
    let archived = f.verify().unwrap();
    assert_eq!(report["archive_id"], archived.archive_id);
    assert_eq!(
        report["database_sha256"],
        archived
            .entries
            .iter()
            .find(|e| e.path == "state.sqlite3")
            .unwrap()
            .sha256
            .as_ref()
            .unwrap()
            .as_str()
    );
    for name in ["agents", "messages"] {
        let bytes = fs::read(f.output.join(report[name]["path"].as_str().unwrap())).unwrap();
        assert_eq!(report[name]["bytes"], bytes.len());
        assert_eq!(
            report[name]["sha256"],
            format!("{:x}", Sha256::digest(&bytes))
        );
    }
    let records = fs::read_to_string(f.output.join("messages.jsonl")).unwrap();
    let record: Value = serde_json::from_str(records.trim()).unwrap();
    assert_eq!(record["message"]["id"], h.message.id);
    assert_eq!(record["message"]["expires_at"], 20);
    assert_eq!(record["message"]["acknowledged"], true);
    assert_eq!(
        fs::read(f.output.join(record["assets"][0]["path"].as_str().unwrap())).unwrap(),
        b"inline bytes"
    );
    assert_eq!(
        fs::read(f.output.join(record["assets"][1]["path"].as_str().unwrap())).unwrap(),
        h.bytes
    );
    let before = tree(&f.output);
    for (path, bytes) in &before {
        assert_eq!(
            fs::metadata(f.output.join(path)).unwrap().mode() & 0o777,
            0o600
        );
        for secret in [
            b"must-not-export-credential".as_slice(),
            b"private-fingerprint",
            h.private_grant.as_slice(),
            fs::read(f.home.join("identity.key")).unwrap().as_slice(),
            fs::read(f.home.join("owner.key")).unwrap().as_slice(),
        ] {
            assert!(!bytes.windows(secret.len()).any(|part| part == secret));
        }
    }
    assert!(!f.output.join("state.sqlite3").exists() && !f.output.join("identity.key").exists());
    assert!(Store::open(&f.output).is_err());
    assert!(history::export(&f.archive, &f.key, &f.output).is_err());
    assert_eq!(tree(&f.output), before);
    h.no_staging();
}

#[test]
fn history_reports_missing_and_incomplete_files_without_partial_plaintext() {
    for (sql, expected) in [
        (
            "DELETE FROM file_chunks; DELETE FROM agent_files; DELETE FROM file_objects",
            "missing",
        ),
        (
            "UPDATE file_objects SET complete=0; DELETE FROM file_chunks WHERE position=1",
            "incomplete",
        ),
    ] {
        let h = History::new();
        h.mutate(sql);
        let status = h.export().unwrap();
        assert_eq!(status["files"][expected], 1);
        let record: Value = serde_json::from_str(
            fs::read_to_string(h.fixture.output.join("messages.jsonl"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        assert_eq!(record["assets"][1]["status"], expected);
        assert!(record["assets"][1].get("path").is_none());
        assert_eq!(
            fs::read_dir(h.fixture.output.join("files"))
                .unwrap()
                .count(),
            1
        );
        h.no_staging();
    }
}

#[test]
fn history_refuses_corrupt_content_identity_schema_and_payloads_atomically() {
    for sql in [
        "UPDATE file_chunks SET ciphertext=zeroblob(length(ciphertext)) WHERE position=0",
        "DELETE FROM file_chunks WHERE position=1",
        "UPDATE file_objects SET grant=zeroblob(2049)",
        "UPDATE file_object_schema SET version=2",
        "UPDATE agent_files SET message=NULL,agent=(SELECT id FROM agents LIMIT 1)",
        "PRAGMA foreign_keys=OFF; UPDATE agent_files SET message=printf('%.*c',1048576,'x')",
        "UPDATE metadata SET value='11111111-1111-4111-8111-111111111111' WHERE key='node'",
        "UPDATE messages SET payload=json_set(payload,'$.id','../../escape')",
        "UPDATE messages SET payload=json_set(payload,'$.credential','must-not-leak')",
        "UPDATE messages SET payload=json_set(payload,'$.attachments[0].name','../../escape')",
        "UPDATE messages SET payload=json_set(payload,'$.text',printf('%.*c',6291457,'x'))",
        "ALTER TABLE agents RENAME TO saved_agents; CREATE VIEW agents AS SELECT * FROM saved_agents",
    ] {
        let h = History::new();
        h.mutate(sql);
        let error = h.export().unwrap_err().to_string();
        assert!(!error.contains("must-not-leak"), "{error}");
        assert!(!h.fixture.output.exists(), "{sql}");
        h.no_staging();
    }
}

#[test]
fn history_authenticates_omitted_payloads_and_extracts_only_the_database() {
    let h = History::new();
    let f = &h.fixture;
    config::write_private(&f.home.join("zzz-private"), b"private trailing file").unwrap();
    f.create();
    let selected = f._directory.path().join("selected");
    config::private_dir(&selected).unwrap();
    config::write_private(&selected.join(recovery::MARKER), b"offline").unwrap();
    format::read_database(&f.archive, &read_key(&f.key).unwrap(), &selected).unwrap();
    let names: BTreeMap<_, _> = tree(&selected);
    assert_eq!(names.len(), 2);
    assert!(
        names.contains_key(Path::new("state.sqlite3"))
            && names.contains_key(Path::new(recovery::MARKER))
    );
    let mut bytes = fs::read(&f.archive).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&f.archive, bytes).unwrap();
    assert!(history::export(&f.archive, &f.key, &f.output).is_err());
    assert!(!f.output.exists());
    h.no_staging();
}
