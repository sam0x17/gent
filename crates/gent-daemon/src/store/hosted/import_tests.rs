use super::*;
use crate::store::now;
use gent_crypto::NodeIdentity;
use gent_protocol::{AgentOp, Request};
use serde_json::Value as Json;

use crate::store::hosted::test_support::Pair;

impl Pair {
    fn child_call(&mut self, index: usize, action: AgentOp) -> Json {
        self.child
            .execute(Request::Agent {
                credential: self.keys[index].clone(),
                action,
            })
            .unwrap()
    }

    fn import(&mut self) -> Result<()> {
        let _lock = crate::DaemonLock::acquire(self.homes[1].path())?;
        let tx = self.parent.db.transaction()?;
        import(
            &tx,
            self.homes[1].path(),
            &self.state,
            self.child.identity.node.id(),
            self.parent.identity.node.id(),
        )?;
        tx.commit()?;
        Ok(())
    }

    fn populate(&mut self) -> String {
        // Real encrypted object bytes and an agent-owned import retry. No
        // plaintext exports or filesystem handoffs are needed by a web client.
        let sealed =
            gent_crypto::files::seal("fixture.txt", "text/plain", b"isolated migration fixture")
                .unwrap();
        let expiry = now() as u64 + 3600;
        let object = sealed.grant().descriptor().id.clone();
        let tx = self.child.db.transaction().unwrap();
        crate::file_objects::Objects::new(&tx, now() as u64)
            .unwrap()
            .stage(&sealed, expiry)
            .unwrap();
        tx.execute(
            "INSERT INTO agent_files VALUES(?1,?2,NULL,?3)",
            params![
                object,
                self.agents[1],
                serde_json::to_string(&sealed.transport_manifest(expiry).unwrap()).unwrap()
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO file_imports VALUES(?1,?2,'retained-import',?3,?4)",
            params![
                self.agents[1],
                uuid::Uuid::now_v7().to_string(),
                object,
                expiry
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        let attachment = self.child_call(
            1,
            AgentOp::RelayAttach {
                target: self.agents[2].clone(),
                request_id: uuid::Uuid::now_v7().to_string(),
            },
        );
        let sent = self.child_call(
            1,
            AgentOp::RelaySend {
                attachment_id: attachment["attachment"]["id"].as_str().unwrap().into(),
                request_id: uuid::Uuid::now_v7().to_string(),
                text: "fixture relay turn".into(),
                files: vec![],
                file_ids: vec![object],
            },
        );
        let message = sent["turn_id"].as_str().unwrap().to_owned();
        self.child_call(
            2,
            AgentOp::WakeClaim {
                message_id: message.clone(),
                attempt_id: uuid::Uuid::new_v4().to_string(),
                target: gent_protocol::wake::WakeTarget::Codex {
                    thread_id: uuid::Uuid::new_v4().to_string(),
                },
            },
        );
        self.child_call(
            2,
            AgentOp::WorkBegin {
                message_id: message.clone(),
                expect_revision: 0,
                description: "fixture execution report".into(),
            },
        );
        self.child_call(
            2,
            AgentOp::Ack {
                message_id: message.clone(),
            },
        );
        self.child
            .db
            .execute("INSERT INTO network_rejections VALUES(?1)", [&message])
            .unwrap();
        self.child
            .db
            .execute(
                "INSERT INTO directory_cleared VALUES(?1)",
                [&self.agents[2]],
            )
            .unwrap();
        // Assigned history has its own IDs, composite keys and ciphertext.
        self.child.db.execute("INSERT INTO recovered_sources VALUES('history',?1,'original','digest','{}',1,0,16)", [&self.agents[1]]).unwrap();
        self.child
            .db
            .execute_batch(
                "INSERT INTO recovered_messages VALUES('history','old-message',0,'{}');
            INSERT INTO recovered_files VALUES('history','old-message',0,'{}');
            INSERT INTO recovered_chunks VALUES('history','old-message',0,0,zeroblob(16),'digest');
            INSERT INTO network_sent VALUES('transport-only','data',9999999999);
            UPDATE request_clock SET floor=floor+10000,legacy_until=legacy_until+20000;",
            )
            .unwrap();
        message
    }
}

fn placeholder(source: &Connection, target: &Connection, id: &str) {
    let mut agent = source
        .query_row("SELECT * FROM agents WHERE id=?1", [id], row)
        .unwrap();
    agent[1] = Value::Text(format!("remote:{id}"));
    target
        .execute(
            "INSERT INTO agents VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params_from_iter(&agent),
        )
        .unwrap();
    let origin = source
        .query_row("SELECT * FROM network_origins WHERE agent=?1", [id], row)
        .unwrap();
    target
        .execute(
            "INSERT INTO network_origins VALUES(?1,?2,?3,?4)",
            params_from_iter(&origin),
        )
        .unwrap();
}

fn rows(db: &Connection, table: &str) -> Vec<Vec<Value>> {
    db.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
        .unwrap()
        .query_map([], row)
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn application(db: &Connection) -> Vec<Vec<Vec<Value>>> {
    ["agents", "network_origins"]
        .into_iter()
        .chain(TABLES.split_whitespace())
        .map(|table| rows(db, table))
        .collect()
}

#[test]
fn preserves_application_state_credentials_journals_files_and_retries_idempotently() {
    let mut pair = Pair::new();
    let message = pair.populate();
    placeholder(&pair.child.db, &pair.parent.db, &pair.agents[1]);
    placeholder(&pair.parent.db, &pair.child.db, &pair.agents[0]);
    // A newer parent registration must not be downgraded by its stale remote
    // directory copy in the child.
    pair.parent
        .db
        .execute(
            "UPDATE agents SET name='new parent label' WHERE id=?1",
            [&pair.agents[0]],
        )
        .unwrap();
    pair.parent
        .db
        .execute(
            "UPDATE network_origins SET generation=2 WHERE agent=?1",
            [&pair.agents[0]],
        )
        .unwrap();
    let before = application(&pair.child.db);
    let authority = rows(&pair.parent.db, "authority");
    let parent_credential = pair
        .parent
        .db
        .query_row(
            "SELECT credential_hash FROM agents WHERE id=?1",
            [&pair.agents[0]],
            |r| r.get::<_, String>(0),
        )
        .unwrap();
    let registry = pair.homes[1].path().join("registry-fixture");
    fs::write(&registry, "unchanged registry").unwrap();
    pair.import().unwrap();
    assert_eq!(before, application(&pair.child.db));
    assert_eq!(authority, rows(&pair.parent.db, "authority"));
    assert_eq!(fs::read_to_string(registry).unwrap(), "unchanged registry");
    for table in TABLES
        .split_whitespace()
        .filter(|t| !["agent_activity", "directory_nodes"].contains(t))
    {
        assert_eq!(
            rows(&pair.parent.db, table),
            rows(&pair.child.db, table),
            "{table}"
        );
    }
    assert_eq!(
        pair.parent
            .db
            .query_row(
                "SELECT credential_hash,name FROM agents WHERE id=?1",
                [&pair.agents[0]],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            )
            .unwrap(),
        (parent_credential, "new parent label".into())
    );
    for id in &pair.agents[1..] {
        assert_eq!(
            pair.parent
                .db
                .query_row(
                    "SELECT credential_hash FROM agents WHERE id=?1",
                    [id],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            pair.child
                .db
                .query_row(
                    "SELECT credential_hash FROM agents WHERE id=?1",
                    [id],
                    |r| r.get::<_, String>(0)
                )
                .unwrap()
        );
    }
    assert!(rows(&pair.parent.db, "network_sent").is_empty());
    assert_eq!(
        pair.parent
            .db
            .query_row(
                "SELECT acknowledged FROM messages WHERE id=?1",
                [&message],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    let once = application(&pair.parent.db);
    pair.import().unwrap();
    assert_eq!(once, application(&pair.parent.db));
}

#[test]
fn late_failure_rolls_back_promotions_and_every_earlier_table() {
    let mut pair = Pair::new();
    pair.populate();
    placeholder(&pair.child.db, &pair.parent.db, &pair.agents[1]);
    let before = application(&pair.parent.db);
    pair.parent.db.execute_batch("CREATE TRIGGER migration_failure BEFORE INSERT ON file_chunks BEGIN SELECT RAISE(ABORT,'fixture failure'); END").unwrap();
    let _lock = crate::DaemonLock::acquire(pair.homes[1].path()).unwrap();
    let tx = pair.parent.db.transaction().unwrap();
    tx.execute(
        "INSERT INTO metadata VALUES('caller-write','preserved')",
        [],
    )
    .unwrap();
    assert!(
        import(
            &tx,
            pair.homes[1].path(),
            &pair.state,
            pair.child.identity.node.id(),
            pair.parent.identity.node.id()
        )
        .is_err()
    );
    assert_eq!(before, application(&tx));
    metadata(&tx, "caller-write", "preserved").unwrap();
    tx.commit().unwrap();
    assert_eq!(before, application(&pair.parent.db));
}

#[test]
fn rejects_unrelated_credentials_bindings_and_retired_generation_regressions() {
    for case in ["credential", "nonce", "revocation"] {
        let mut pair = Pair::new();
        placeholder(&pair.child.db, &pair.parent.db, &pair.agents[1]);
        match case {
            "credential" => {
                pair.parent
                    .db
                    .execute(
                        "UPDATE agents SET credential_hash=?2 WHERE id=?1",
                        params![pair.agents[1], "a".repeat(64)],
                    )
                    .unwrap();
            }
            "nonce" => {
                pair.parent
                    .db
                    .execute(
                        "UPDATE network_origins SET nonce=?2 WHERE agent=?1",
                        params![pair.agents[1], uuid::Uuid::new_v4().to_string()],
                    )
                    .unwrap();
            }
            _ => {
                pair.parent
                    .db
                    .execute("UPDATE agents SET revoked=1 WHERE id=?1", [&pair.agents[1]])
                    .unwrap();
            }
        }
        let before = application(&pair.parent.db);
        assert!(pair.import().is_err(), "{case}");
        assert_eq!(before, application(&pair.parent.db), "{case}");
    }
}

#[test]
fn preserves_revoked_child_generation_and_rejects_unbound_legacy_state() {
    let mut pair = Pair::new();
    placeholder(&pair.child.db, &pair.parent.db, &pair.agents[1]);
    pair.child
        .db
        .execute("UPDATE agents SET revoked=1 WHERE id=?1", [&pair.agents[1]])
        .unwrap();
    pair.child
        .db
        .execute(
            "UPDATE network_origins SET generation=3 WHERE agent=?1",
            [&pair.agents[1]],
        )
        .unwrap();
    pair.import().unwrap();
    assert_eq!(pair.parent.db.query_row("SELECT revoked,generation FROM agents JOIN network_origins ON agent=id WHERE id=?1", [&pair.agents[1]], |r| Ok((r.get::<_, i64>(0)?,r.get::<_, i64>(1)?))).unwrap(), (1,3));
    pair.child
        .db
        .execute(
            "DELETE FROM network_origins WHERE agent=?1",
            [&pair.agents[2]],
        )
        .unwrap();
    assert!(format!("{:#}", pair.import().unwrap_err()).contains("unbound legacy"));
}

#[test]
fn validates_existing_source_metadata_config_and_immutable_key() {
    for case in ["node", "cluster", "config", "key", "missing"] {
        let mut pair = Pair::new();
        match case {
            "node" | "cluster" => {
                pair.child
                    .db
                    .execute("UPDATE metadata SET value='wrong' WHERE key=?1", [case])
                    .unwrap();
            }
            "config" => {
                let mut cfg = config::load_for_runtime(pair.homes[1].path()).unwrap();
                cfg.node.id = uuid::Uuid::new_v4().to_string();
                config::save(pair.homes[1].path(), &cfg).unwrap();
            }
            "key" => {
                fs::copy(
                    pair.homes[0].path().join(runtime::KEY_FILE),
                    pair.homes[1].path().join(runtime::KEY_FILE),
                )
                .unwrap();
            }
            _ => {
                fs::rename(
                    pair.homes[1].path().join("state.sqlite3"),
                    pair.homes[1].path().join("saved.sqlite3"),
                )
                .unwrap();
            }
        }
        let before = application(&pair.parent.db);
        assert!(pair.import().is_err(), "{case}");
        assert_eq!(before, application(&pair.parent.db));
        if case == "missing" {
            assert!(!pair.homes[1].path().join("state.sqlite3").exists());
        }
    }
}

#[test]
fn rejects_plaintext_handoffs_without_discarding_them() {
    let mut pair = Pair::new();
    pair.child.db.execute("INSERT INTO file_exports(id,agent,object_id,name,digest,bytes,expires_at) VALUES('export',?1,'object','file','digest',1,9999999999)", [&pair.agents[1]]).unwrap();
    let saved = rows(&pair.child.db, "file_exports");
    let before = application(&pair.parent.db);
    assert!(format!("{:#}", pair.import().unwrap_err()).contains("nonempty file_exports"));
    assert_eq!(saved, rows(&pair.child.db, "file_exports"));
    assert_eq!(before, application(&pair.parent.db));
}

#[test]
fn accepts_stale_source_before_and_after_signed_activation_but_not_another_host() {
    let mut pair = Pair::new();
    let authority = rows(&pair.child.db, "authority");
    let signer = pair.parent.identity.signing_owner(&pair.parent.db).unwrap();
    let update = pair
        .state
        .host_node(
            &*signer,
            pair.child.identity.node.id(),
            pair.parent.identity.node.id(),
            now() as u64,
        )
        .unwrap();
    pair.state.advance_history(&[update]).unwrap();
    drop(signer);
    pair.import().unwrap();
    assert_eq!(authority, rows(&pair.child.db, "authority"));

    let mut pair = Pair::new();
    let another = NodeIdentity::generate().unwrap();
    let signer = pair.parent.identity.signing_owner(&pair.parent.db).unwrap();
    let request = another
        .request_enrollment(
            pair.state.anchor(),
            pair.state.checkpoint(),
            "other-host",
            now() as u64,
        )
        .unwrap();
    let update = pair
        .state
        .enroll(
            &*signer,
            &request,
            request.fingerprint().unwrap(),
            now() as u64,
        )
        .unwrap();
    pair.state.advance_history(&[update]).unwrap();
    let update = pair
        .state
        .host_node(
            &*signer,
            pair.child.identity.node.id(),
            another.id(),
            now() as u64,
        )
        .unwrap();
    pair.state.advance_history(&[update]).unwrap();
    drop(signer);
    assert!(
        pair.import()
            .unwrap_err()
            .to_string()
            .contains("another hosting parent")
    );
}

#[test]
fn refuses_an_old_key_after_signed_rotation_and_an_autocommit_parent() {
    let mut pair = Pair::new();
    assert!(
        import(
            &pair.parent.db,
            pair.homes[1].path(),
            &pair.state,
            pair.child.identity.node.id(),
            pair.parent.identity.node.id()
        )
        .unwrap_err()
        .to_string()
        .contains("parent transaction")
    );
    let generated = NodeIdentity::generate().unwrap();
    let replacement =
        NodeIdentity::from_secret_bytes(pair.child.identity.node.id(), &generated.expose_secret())
            .unwrap();
    let signer = pair.parent.identity.signing_owner(&pair.parent.db).unwrap();
    let request = replacement
        .request_enrollment(
            pair.state.anchor(),
            pair.state.checkpoint(),
            "web",
            now() as u64,
        )
        .unwrap();
    let update = pair
        .state
        .rotate_node_key(
            &*signer,
            &request,
            request.fingerprint().unwrap(),
            now() as u64,
        )
        .unwrap();
    pair.state.advance_history(&[update]).unwrap();
    drop(signer);
    assert!(
        pair.import()
            .unwrap_err()
            .to_string()
            .contains("key does not match enrolled child")
    );
}

#[test]
fn row_merge_preserves_both_acknowledgments_and_sender_retry_fingerprints() {
    let mut pair = Pair::new();
    pair.populate();
    pair.import().unwrap();
    // Simulate an existing received copy whose transport fingerprint omits the
    // sender's local file IDs. The authoritative child fingerprint must win.
    let payload: String = pair
        .parent
        .db
        .query_row("SELECT payload FROM messages", [], |r| r.get(0))
        .unwrap();
    let message: gent_protocol::Message = serde_json::from_str(&payload).unwrap();
    let remote = crate::store::message_fingerprint(
        &message.recipient,
        &message.text,
        &message.files,
        &message.reply_to,
        &message.relay,
        &[],
    )
    .unwrap();
    pair.parent
        .db
        .execute(
            "UPDATE messages SET fingerprint=?1,acknowledged=0",
            [remote],
        )
        .unwrap();
    pair.import().unwrap();
    assert_eq!(
        rows(&pair.parent.db, "messages"),
        rows(&pair.child.db, "messages")
    );
    pair.child
        .db
        .execute("UPDATE messages SET acknowledged=0", [])
        .unwrap();
    pair.import().unwrap();
    assert_eq!(
        pair.parent
            .db
            .query_row("SELECT acknowledged FROM messages", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn dashboard_import_merges_child_retry_state_and_skips_unrelated_cached_boards() -> Result<()> {
    let mut pair = Pair::new();
    let local = pair.agents[0].clone();
    let web = pair.agents[1].clone();
    placeholder(&pair.parent.db, &pair.child.db, &local);
    placeholder(&pair.child.db, &pair.parent.db, &web);
    let board =
        r#"{"title":"Child","widgets":[{"id":"x","label":"X","kind":"text","value":"yes"}]}"#;
    let fingerprint = "a".repeat(64);
    pair.parent.db.execute(
        "INSERT INTO dashboards VALUES(?1,2,?2,NULL)",
        params![web, board],
    )?;
    pair.parent
        .db
        .execute("INSERT INTO dashboards VALUES(?1,1,NULL,NULL)", [&local])?;
    pair.child.db.execute(
        "INSERT INTO dashboards VALUES(?1,2,?2,?3)",
        params![web, board, fingerprint],
    )?;
    pair.child.db.execute(
        "INSERT INTO dashboards VALUES(?1,7,?2,NULL)",
        params![local, board],
    )?;
    pair.import()?;
    pair.import()?;
    assert_eq!(
        pair.parent.db.query_row(
            "SELECT mutation FROM dashboards WHERE agent=?1",
            [&web],
            |r| r.get::<_, String>(0)
        )?,
        fingerprint
    );
    assert_eq!(
        pair.parent.db.query_row(
            "SELECT revision FROM dashboards WHERE agent=?1",
            [&local],
            |r| r.get::<_, u64>(0)
        )?,
        1
    );
    pair.child.db.execute(
        "UPDATE dashboards SET revision=3,body=NULL WHERE agent=?1",
        [&web],
    )?;
    pair.import()?;
    let before = rows(&pair.parent.db, "dashboards");
    pair.child.db.execute(
        "UPDATE dashboards SET body=?2 WHERE agent=?1",
        params![web, board],
    )?;
    assert!(pair.import().is_err());
    assert_eq!(rows(&pair.parent.db, "dashboards"), before);
    // Older native children have no such table at all.
    pair.child.db.execute_batch("DROP TABLE dashboards")?;
    pair.import()?;
    assert_eq!(rows(&pair.parent.db, "dashboards"), before);
    Ok(())
}

#[test]
fn row_copy_rejects_secondary_unique_and_immutable_conflicts() {
    let parent = Connection::open_in_memory().unwrap();
    let source = Connection::open_in_memory().unwrap();
    for db in [&parent, &source] {
        db.execute_batch("CREATE TABLE messages(id TEXT PRIMARY KEY,sender TEXT,recipient TEXT,request_id TEXT,fingerprint TEXT,payload TEXT,acknowledged INTEGER,UNIQUE(sender,request_id));
            INSERT INTO messages VALUES('message','sender','recipient','request','fingerprint','{}',0)").unwrap();
    }
    for mutation in [
        "UPDATE messages SET id='another-id'",
        "UPDATE messages SET id='message',payload='{\"changed\":true}'",
    ] {
        source.execute(mutation, []).unwrap();
        let before = rows(&parent, "messages");
        assert!(copy(&parent, &source, "messages", "child").is_err());
        assert_eq!(before, rows(&parent, "messages"));
    }
}

#[test]
fn combined_capacity_failure_preserves_source_and_rolls_back_all_imports() {
    for (table, fill) in [
        (
            "agents",
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<16383) INSERT INTO agents SELECT 'quota-'||i,'quota-credential-'||i,'fixture','quota','test',0,0 FROM n",
        ),
        (
            "file_objects",
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<128) INSERT INTO file_objects SELECT 'quota-'||i,X'00',16,9999999999,9999999999,1 FROM n",
        ),
        (
            "file_objects",
            "INSERT INTO file_objects VALUES('quota',X'00',268435456,9999999999,9999999999,1)",
        ),
        (
            "work_entries",
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<4096) INSERT INTO work_entries SELECT 'quota-'||i,(SELECT id FROM agents LIMIT 1),'{}' FROM n",
        ),
        (
            "wake_dispatches",
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<16384) INSERT INTO wake_dispatches SELECT 'quota-'||i,(SELECT id FROM agents LIMIT 1),'attempt-'||i,0,'{}' FROM n",
        ),
        (
            "messages",
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<8192) INSERT INTO messages SELECT 'quota-'||i,(SELECT id FROM agents LIMIT 1),(SELECT id FROM agents LIMIT 1),'request-'||i,'fingerprint','{}',0 FROM n",
        ),
        (
            "file_imports",
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<16384) INSERT INTO file_imports SELECT (SELECT id FROM agents LIMIT 1),'quota-'||i,'fingerprint','retired-object',0 FROM n",
        ),
    ] {
        let mut pair = Pair::new();
        pair.populate();
        pair.parent.db.execute_batch(fill).unwrap();
        let parent = application(&pair.parent.db);
        let source = application(&pair.child.db);
        let error = format!("{:#}", pair.import().unwrap_err());
        assert!(
            error.contains(&format!("exceeds {table} capacity")),
            "{error}"
        );
        assert_eq!(parent, application(&pair.parent.db));
        assert_eq!(source, application(&pair.child.db));
    }
}

#[test]
fn refuses_chat_configuration_retries_instead_of_losing_their_old_origin() {
    let mut pair = Pair::new();
    pair.child
        .db
        .execute(
            "INSERT INTO configuration_edits(origin,id,writer,fingerprint,edit,result,compact)
        VALUES(?1,'retained-config','writer','fingerprint',?2,NULL,1)",
            params![
                pair.child.identity.node.id(),
                br#"{"op":"agent_permissions"}"#.as_slice()
            ],
        )
        .unwrap();
    let before = application(&pair.parent.db);
    let saved = rows(&pair.child.db, "configuration_edits");
    assert!(
        pair.import()
            .unwrap_err()
            .to_string()
            .contains("retained child administration retries")
    );
    assert_eq!(before, application(&pair.parent.db));
    assert_eq!(saved, rows(&pair.child.db, "configuration_edits"));
}
