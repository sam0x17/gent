//! Offline preparation only. The caller owns the child lock, verifies its home,
//! journals this import in the parent transaction, and activates hosting later.
use crate::{config, encrypted, runtime};
use anyhow::{Context, Result, ensure};
use gent_crypto::VerifiedState;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter, types::Value};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

// Dependency order matters. Transport queues, MLS keys, configuration, presence,
// and filesystem handoff paths intentionally never enter the parent database.
const TABLES: &str = "exchanges messages relay_attachments relay_turns request_clock
    work_entries work_events wake_dispatches file_objects file_chunks agent_files
    file_imports message_file_proofs network_rejections agent_activity directory_cleared
    directory_nodes recovered_sources recovered_messages recovered_files recovered_chunks";

pub(super) fn import(
    parent_tx: &Connection,
    child_home: &Path,
    parent_state: &VerifiedState,
    child_id: &str,
    parent_id: &str,
) -> Result<()> {
    ensure!(
        !parent_tx.is_autocommit(),
        "hosted import requires a parent transaction"
    );
    ensure!(
        parent_tx.pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))?,
        "hosted import requires foreign keys"
    );
    ensure!(
        child_id != parent_id,
        "hosting child must differ from parent"
    );
    let member = parent_state
        .state()
        .nodes
        .get(child_id)
        .context("hosting child is not enrolled")?;
    ensure!(
        member
            .hosted_by
            .as_deref()
            .is_none_or(|host| host == parent_id),
        "child has another hosting parent"
    );
    ensure!(
        parent_state.transport_host(parent_id)? == parent_id,
        "hosting parent must be native"
    );
    metadata(parent_tx, "cluster", &parent_state.anchor().cluster_id)?;
    metadata(parent_tx, "node", parent_id)?;
    // open_database may create a missing file; never let migration bootstrap a
    // replacement for lost child state or keys. The owner validated ancestors.
    for name in ["state.sqlite3", runtime::KEY_FILE] {
        let stat = fs::symlink_metadata(child_home.join(name))
            .context("hosted migration source is missing")?;
        ensure!(
            stat.is_file()
                && !stat.file_type().is_symlink()
                && stat.permissions().mode() & 0o077 == 0,
            "hosted migration source must be a private regular file"
        );
    }
    let config = config::load_for_runtime(child_home)?;
    ensure!(
        config.node.id == child_id && config.cluster.id == parent_state.anchor().cluster_id,
        "hosted source configuration belongs to another node or cluster"
    );
    let mut source = encrypted::open_database(child_home, "state.sqlite3")?;
    source.execute_batch("PRAGMA query_only=ON; PRAGMA foreign_keys=ON;")?;
    let snapshot = source.transaction()?;
    metadata(&snapshot, "cluster", &parent_state.anchor().cluster_id)?;
    metadata(&snapshot, "node", child_id)?;
    metadata(&snapshot, "signed_authority", "1")?;
    ensure!(
        snapshot.query_row("SELECT COUNT(*) FROM authority", [], |r| r.get::<_, u64>(0))? == 1,
        "hosted source authority is missing"
    );
    let identity = runtime::Identity::load_or_create(
        child_home,
        &config,
        &snapshot,
        crate::store::now() as u64,
    )?;
    ensure!(
        identity.node.public_key() == member.signing_key
            && identity.state(&snapshot)?.anchor() == parent_state.anchor(),
        "hosted source key does not match enrolled child"
    );
    for db in [&snapshot as &Connection, parent_tx] {
        metadata(db, "work_journal_version", "1")?;
        metadata(db, "wake_journal_version", "1")?;
        for table in ["file_object_schema", "recovered_schema"] {
            ensure!(
                db.query_row(
                    &format!("SELECT version FROM {table} WHERE id=1"),
                    [],
                    |r| r.get::<_, u64>(0)
                )? == 1,
                "unsupported hosted migration schema: {table}"
            );
        }
    }
    for table in ["file_exports", "file_handoffs", "legacy_agent_bindings"] {
        ensure!(
            !snapshot.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table})"), [], |r| {
                r.get::<_, bool>(0)
            })?,
            "hosted migration does not support nonempty {table}; source data was preserved"
        );
    }
    // These retries are keyed by the old physical configuration origin. Moving
    // them would require rewriting signed/audited provenance, which is excluded.
    ensure!(
        !snapshot.query_row(
            "SELECT EXISTS(SELECT 1 FROM configuration_edits WHERE origin=?1
        AND CASE WHEN json_valid(edit) THEN json_extract(edit,'$.op') IN
        ('agent_permissions','agent_permission_rules','agent_groups') ELSE 1 END)",
            [child_id],
            |r| r.get::<_, bool>(0)
        )?,
        "hosted migration does not support retained child administration retries; source data was preserved"
    );
    parent_tx.execute_batch("SAVEPOINT hosted_state_import")?;
    let result = (|| {
        agents(parent_tx, &snapshot, child_id, parent_state.anchor())?;
        for table in TABLES.split_whitespace() {
            copy(parent_tx, &snapshot, table, child_id)
                .with_context(|| format!("hosted migration table {table}"))?;
        }
        if snapshot.table_exists(None, "dashboards")? {
            dashboards(parent_tx, &snapshot, child_id)?;
        }
        // Counts may differ on each peer. Count the union without decreasing
        // either retained count, which may include already retired messages.
        let mut exchanges = snapshot.prepare("SELECT id FROM exchanges")?;
        for id in exchanges.query_map([], |r| r.get::<_, String>(0))? {
            parent_tx.execute("UPDATE exchanges SET count=MAX(count,(SELECT COUNT(*) FROM messages WHERE json_extract(payload,'$.exchange_id')=exchanges.id)) WHERE id=?1", [id?])?;
        }
        capacity(parent_tx)?;
        ensure!(
            !parent_tx.prepare("PRAGMA foreign_key_check")?.exists([])?,
            "hosted import violates foreign keys"
        );
        Ok(())
    })();
    if result.is_err() && !parent_tx.is_autocommit() {
        parent_tx.execute_batch("ROLLBACK TO hosted_state_import; RELEASE hosted_state_import")?;
    } else if result.is_ok() {
        parent_tx.execute_batch("RELEASE hosted_state_import")?;
    }
    result
}

fn metadata(db: &Connection, key: &str, expected: &str) -> Result<()> {
    let value: String = db.query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
        r.get(0)
    })?;
    ensure!(
        value == expected,
        "hosted migration metadata mismatch: {key}"
    );
    Ok(())
}

pub(super) fn capacity(db: &Connection) -> Result<()> {
    // The union must fit the same durable limits as normal admission. Pending
    // work reserves future events, so counting only current rows is unsafe.
    let full: Option<String> = db.query_row(
        "SELECT 'agents' WHERE (SELECT COUNT(*) FROM agents)>16384
        UNION ALL SELECT 'file_objects' WHERE (SELECT COUNT(*) FROM file_objects)>?1
            OR (SELECT COALESCE(SUM(reserved_bytes),0) FROM file_objects)>?2
        UNION ALL SELECT 'work_entries' WHERE (SELECT COUNT(*) FROM work_entries)>4096
            OR (SELECT COUNT(*) FROM work_events)+(SELECT COALESCE(SUM(CASE json_extract(payload,'$.state')
                WHEN 'started' THEN 1 WHEN 'retry_approved' THEN 2 ELSE 0 END),0) FROM work_entries)>65536
            OR (SELECT COUNT(*)*8192+COALESCE(SUM(CASE json_extract(payload,'$.state')
                WHEN 'started' THEN 16384 WHEN 'retry_approved' THEN 32768 ELSE 0 END),0) FROM work_entries)
                +(SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM work_events)>134217728
        UNION ALL SELECT 'wake_dispatches' WHERE (SELECT COUNT(*) FROM wake_dispatches)>16384
        UNION ALL SELECT 'messages' WHERE (SELECT COUNT(*) FROM messages)>8192
            OR (SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM messages)>268435456
        UNION ALL SELECT 'file_imports' WHERE (SELECT COUNT(*) FROM file_imports)>16384
        UNION ALL SELECT 'recovered_sources' WHERE (SELECT COUNT(*) FROM recovered_sources)>256
            OR (SELECT COALESCE(SUM(bytes),0) FROM recovered_sources)>268435456
            OR (SELECT COALESCE(SUM(length(CAST(summary AS BLOB))),0) FROM recovered_sources)>2097152
        UNION ALL SELECT 'recovered_messages' WHERE (SELECT COUNT(*) FROM recovered_messages)>8192",
        params![crate::file_objects::MAX_OBJECTS, crate::file_objects::MAX_RESERVED_BYTES],
        |r| r.get(0),
    ).optional()?;
    if let Some(table) = full {
        anyhow::bail!("hosted migration exceeds {table} capacity; source data was preserved");
    }
    Ok(())
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Vec<Value>> {
    (0..r.as_ref().column_count()).map(|i| r.get(i)).collect()
}

fn text(value: &Value) -> Result<&str> {
    Ok(rusqlite::types::ValueRef::from(value).as_str()?)
}

fn integer(value: &Value) -> Result<i64> {
    Ok(rusqlite::types::ValueRef::from(value).as_i64()?)
}

fn origin(db: &Connection, id: &Value) -> Result<Vec<Value>> {
    let values = db
        .query_row(
            "SELECT nonce,legacy,generation FROM network_origins WHERE agent=?1",
            [id],
            row,
        )
        .context(
            "hosted migration requires an existing chat origin; unbound legacy chat is unsupported",
        )?;
    ensure!(
        (1..=gent_protocol::MAX_REGISTRATION_GENERATION as i64).contains(&integer(&values[2])?),
        "hosted migration requires a valid chat generation"
    );
    Ok(values)
}

pub(super) fn agents(
    parent: &Connection,
    source: &Connection,
    child: &str,
    anchor: &gent_crypto::TrustAnchor,
) -> Result<()> {
    let mut query = source
        .prepare("SELECT id,credential_hash,node_id,name,provider,last_seen,revoked FROM agents")?;
    for incoming in query.query_map([], row)? {
        let mut incoming = incoming?;
        let id = incoming[0].clone();
        let binding = origin(source, &id)?;
        let node = text(&incoming[2])?;
        let local = node == child;
        match (&binding[0], &binding[1]) {
            (Value::Text(nonce), Value::Null) => ensure!(
                gent_crypto::agent_id(node, uuid::Uuid::parse_str(nonce)?)? == text(&id)?,
                "hosted chat origin does not match its ID"
            ),
            (Value::Null, Value::Blob(bytes)) if !local => {
                let certificate: gent_crypto::SignedLegacyAgentBinding =
                    serde_json::from_slice(bytes)?;
                certificate.verify(anchor, text(&id)?, node)?;
            }
            _ => anyhow::bail!("hosted migration requires a nonce-bound local chat"),
        }
        let placeholder = Value::Text(format!("remote:{}", text(&id)?));
        let credential = text(&incoming[1])?;
        ensure!(
            if local {
                credential.len() == 64 && credential.bytes().all(|c| c.is_ascii_hexdigit())
            } else {
                incoming[1] == placeholder
            },
            "hosted source has an unexpected chat credential"
        );
        let previous = parent.query_row("SELECT id,credential_hash,node_id,name,provider,last_seen,revoked FROM agents WHERE id=?1", [&id], row).optional()?;
        let mut generation = binding[2].clone();
        if let Some(previous) = previous {
            ensure!(
                previous[2] == incoming[2],
                "hosted chat ID belongs to another node"
            );
            let saved = origin(parent, &id)?;
            ensure!(saved[..2] == binding[..2], "hosted chat binding changed");
            let old = integer(&saved[2])?;
            let new = integer(&binding[2])?;
            if old == new {
                ensure!(
                    previous[3..5] == incoming[3..5] && previous[6] == incoming[6],
                    "conflicting hosted chat generation"
                );
            }
            if local {
                ensure!(
                    previous[1] == placeholder || previous[1] == incoming[1],
                    "hosted migration cannot replace a local credential"
                );
                ensure!(
                    old <= new && (previous[6] == Value::Integer(0) || incoming[6] == previous[6]),
                    "hosted child registration regressed"
                );
            } else {
                if previous[1] != placeholder {
                    ensure!(
                        new <= old,
                        "remote directory is ahead of a parent local chat"
                    );
                }
                if old >= new || previous[1] != placeholder {
                    incoming[3..5].clone_from_slice(&previous[3..5]);
                    incoming[6] = previous[6].clone();
                    generation = saved[2].clone();
                } else {
                    ensure!(
                        previous[6] == Value::Integer(0) || incoming[6] == previous[6],
                        "remote revocation regressed"
                    );
                }
                incoming[1] = previous[1].clone();
            }
            incoming[5] = Value::Integer(integer(&incoming[5])?.max(integer(&previous[5])?));
            parent.execute("UPDATE agents SET credential_hash=?2,name=?4,provider=?5,last_seen=?6,revoked=?7 WHERE id=?1 AND node_id=?3", params_from_iter(&incoming))?;
            parent.execute(
                "UPDATE network_origins SET generation=?2 WHERE agent=?1",
                params![id, generation],
            )?;
        } else {
            parent.execute(
                "INSERT INTO agents VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params_from_iter(&incoming),
            )?;
            parent.execute(
                "INSERT INTO network_origins VALUES(?1,?2,?3,?4)",
                params![id, binding[0], binding[1], generation],
            )?;
        }
    }
    Ok(())
}

fn columns(db: &Connection, table: &str) -> Result<Vec<(String, bool)>> {
    Ok(db
        .prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |r| Ok((r.get(1)?, r.get::<_, u32>(5)? != 0)))?
        .collect::<rusqlite::Result<_>>()?)
}

/// Only the publishing child's records are authoritative. Its directory can
/// also contain replicas of native boards belonging to this parent or peers.
pub(super) fn dashboards(parent: &Connection, source: &Connection, child: &str) -> Result<()> {
    use gent_protocol::dashboard::Board;
    ensure!(
        columns(source, "dashboards")? == columns(parent, "dashboards")?,
        "unsupported hosted dashboard schema"
    );
    let mut query = source.prepare(
        "SELECT d.agent,d.revision,d.body,d.mutation FROM dashboards d
        JOIN agents a ON a.id=d.agent WHERE a.node_id=?1",
    )?;
    let mut rows = query.query([child])?;
    while let Some(row) = rows.next()? {
        let id = row.get_ref(0)?.as_str()?;
        let revision: u64 = row.get(1)?;
        ensure!(
            (1..=gent_protocol::MAX_REGISTRATION_GENERATION).contains(&revision),
            "invalid hosted dashboard revision"
        );
        let body: Option<&str> = row.get_ref(2)?.as_str_or_null()?;
        let decode = |raw: &str| -> Result<Board> {
            ensure!(raw.len() <= 32 * 1024, "hosted dashboard exceeds 32 KiB");
            let board: Board = serde_json::from_str(raw)?;
            board.validate().map_err(anyhow::Error::msg)?;
            Ok(board)
        };
        let board = body.map(decode).transpose()?;
        let mutation = row.get_ref(3)?.as_str_or_null()?;
        ensure!(
            mutation.is_none_or(|v| v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            "invalid hosted dashboard retry fingerprint"
        );
        let previous: Option<(u64, Option<String>, Option<String>)> = parent
            .query_row(
                "SELECT revision,body,mutation FROM dashboards WHERE agent=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((old, previous, op)) = previous {
            ensure!(old <= revision, "hosted dashboard revision regressed");
            if old == revision {
                ensure!(
                    previous.as_deref().map(decode).transpose()? == board
                        && op.as_deref().is_none_or(|v| Some(v) == mutation),
                    "conflicting hosted dashboard revision"
                );
            }
        }
        parent.execute("INSERT INTO dashboards(agent,revision,body,mutation) VALUES(?1,?2,?3,?4)
            ON CONFLICT(agent) DO UPDATE SET revision=excluded.revision,body=excluded.body,mutation=excluded.mutation",
            params![id,revision,body,mutation])?;
    }
    Ok(())
}

// Only primary-key matches can merge. Other UNIQUE/CHECK/FK failures propagate;
// INSERT OR IGNORE/REPLACE would silently discard retries or unrelated records.
pub(super) fn copy(
    parent: &Connection,
    source: &Connection,
    table: &str,
    child: &str,
) -> Result<()> {
    let columns = columns(source, table)?;
    ensure!(
        !columns.is_empty()
            && columns == self::columns(parent, table)?
            && columns.iter().any(|(_, key)| *key),
        "unsupported hosted table schema"
    );
    let names = columns
        .iter()
        .map(|(name, _)| format!("\"{name}\""))
        .collect::<Vec<_>>();
    let values = (1..=names.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>();
    let keys = columns
        .iter()
        .enumerate()
        .filter(|(_, (_, key))| *key)
        .map(|(i, _)| format!("{} IS ?{}", names[i], i + 1))
        .collect::<Vec<_>>()
        .join(" AND ");
    let assignments = names
        .iter()
        .zip(&values)
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    let fields = names.join(",");
    let mut query = source.prepare(&format!("SELECT {fields} FROM {table}"))?;
    let mut find = parent.prepare(&format!("SELECT {fields} FROM {table} WHERE {keys}"))?;
    let mut insert = parent.prepare(&format!(
        "INSERT INTO {table}({fields}) VALUES({})",
        values.join(",")
    ))?;
    let mut update = parent.prepare(&format!("UPDATE {table} SET {assignments} WHERE {keys}"))?;
    for incoming in query.query_map([], row)? {
        let mut incoming = incoming?;
        // Numbered placeholders reserve slots through the highest key position.
        let key_count = columns.iter().rposition(|(_, key)| *key).unwrap() + 1;
        if let Some(previous) = find
            .query_row(params_from_iter(&incoming[..key_count]), row)
            .optional()?
        {
            for (i, (name, _)) in columns.iter().enumerate() {
                if incoming[i] == previous[i] {
                    continue;
                }
                match (table, name.as_str()) {
                    ("messages", "acknowledged")
                    | ("exchanges", "count")
                    | ("request_clock", "floor" | "legacy_until")
                    | ("agent_activity", "last_activity_at")
                    | ("file_chunks", "uploaded")
                    | ("file_objects", "complete" | "incomplete_until")
                    | ("relay_attachments", "detached")
                    | ("file_imports", "retire_after") => {
                        incoming[i] =
                            Value::Integer(integer(&incoming[i])?.max(integer(&previous[i])?));
                    }
                    ("relay_turns", "final_message" | "cancel_message" | "closed_reason") => {
                        ensure!(
                            incoming[i] == Value::Null || previous[i] == Value::Null,
                            "conflicting hosted relay outcome"
                        );
                        if incoming[i] == Value::Null {
                            incoming[i] = previous[i].clone();
                        }
                    }
                    ("messages", "fingerprint") => {
                        let message: gent_protocol::Message =
                            serde_json::from_str(text(&incoming[5])?)?;
                        ensure!(
                            incoming[5] == previous[5],
                            "conflicting hosted message payload"
                        );
                        let remote = Value::Text(crate::store::message_fingerprint(
                            &message.recipient,
                            &message.text,
                            &message.files,
                            &message.reply_to,
                            &message.relay,
                            &[],
                        )?);
                        let sender_node: String = source.query_row(
                            "SELECT node_id FROM agents WHERE id=?1",
                            [&message.sender],
                            |r| r.get(0),
                        )?;
                        if sender_node == child {
                            ensure!(
                                previous[i] == remote,
                                "conflicting hosted sender retry fingerprint"
                            );
                        } else {
                            ensure!(
                                incoming[i] == remote,
                                "conflicting remote retry fingerprint"
                            );
                            incoming[i] = previous[i].clone();
                        }
                    }
                    // Directory labels are local presentation; keep the parent's
                    // already known node label, including its signed revision.
                    ("directory_nodes", _) => {
                        incoming.clone_from(&previous);
                        break;
                    }
                    _ => anyhow::bail!("conflicting hosted record in {table}.{name}"),
                }
            }
            if incoming != previous {
                update.execute(params_from_iter(&incoming))?;
            }
        } else {
            insert.execute(params_from_iter(&incoming))?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
