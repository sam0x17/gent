//! Portable web application records, excluding native keys and transport state.
use super::*;
use rusqlite::{params_from_iter, types::Value as SqlValue};
use serde::{Deserialize, Serialize};

const SCOPE: &str = "WITH wa AS (SELECT id FROM agents WHERE node_id=?1),
    wm AS (SELECT id FROM messages WHERE sender IN wa OR recipient IN wa),
    wp AS (SELECT id FROM wa UNION SELECT sender FROM messages WHERE id IN wm
        UNION SELECT recipient FROM messages WHERE id IN wm
        UNION SELECT target FROM relay_attachments WHERE intermediary IN wa),
    wf AS (SELECT object_id FROM agent_files WHERE agent IN wa OR message IN wm
        UNION SELECT json_extract(j.value,'$.id') FROM messages m,json_each(m.payload,'$.attachments') j WHERE m.id IN wm) ";

const TABLES: &[(&str, &str)] = &[
    ("agents", "id IN wp"),
    ("network_origins", "agent IN wp"),
    ("exchanges", "a IN wa OR b IN wa"),
    ("messages", "id IN wm"),
    ("relay_attachments", "intermediary IN wa"),
    ("relay_turns", "intermediary IN wa OR target IN wa"),
    ("request_clock", "1=1"),
    ("work_entries", "agent IN wa"),
    (
        "work_events",
        "message_id IN (SELECT message_id FROM work_entries WHERE agent IN wa)",
    ),
    ("wake_dispatches", "agent IN wa"),
    ("dashboards", "agent IN wa"),
    ("file_objects", "id IN wf"),
    ("agent_files", "object_id IN wf"),
    ("file_imports", "agent IN wa"),
    ("message_file_proofs", "message IN wm"),
    ("network_rejections", "message IN wm"),
    ("agent_activity", "agent IN wp"),
    ("chat_message_dates", "agent IN wa"),
    ("recovered_sources", "target IN wa"),
    (
        "recovered_messages",
        "source IN (SELECT id FROM recovered_sources WHERE target IN wa)",
    ),
    (
        "recovered_files",
        "source IN (SELECT id FROM recovered_sources WHERE target IN wa)",
    ),
    (
        "recovered_chunks",
        "source IN (SELECT id FROM recovered_sources WHERE target IN wa)",
    ),
];

// Typed cells preserve blobs, NULLs and integers exactly, without executable SQL.
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Cell {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(String),
}

impl Cell {
    fn read(value: SqlValue) -> Self {
        match value {
            SqlValue::Null => Self::Null,
            SqlValue::Integer(v) => Self::Integer(v),
            SqlValue::Real(v) => Self::Real(v),
            SqlValue::Text(v) => Self::Text(v),
            SqlValue::Blob(v) => Self::Blob(STANDARD.encode(v)),
        }
    }
    fn sql(&self) -> Result<SqlValue> {
        Ok(match self {
            Self::Null => SqlValue::Null,
            Self::Integer(v) => SqlValue::Integer(*v),
            Self::Real(v) => {
                ensure!(v.is_finite(), "invalid checkpoint number");
                SqlValue::Real(*v)
            }
            Self::Text(v) => SqlValue::Text(v.clone()),
            Self::Blob(v) => SqlValue::Blob(STANDARD.decode(v)?),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    columns: Vec<String>,
    rows: Vec<Vec<Cell>>,
}

pub(super) fn read(path: &Path) -> Result<Snapshot> {
    use rustix::fs::{Mode, OFlags, open};
    use std::{io::Read, os::unix::fs::MetadataExt};
    let file = std::fs::File::from(open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    let limit = gent_protocol::web_failover::CHUNK_BYTES * gent_protocol::web_failover::MAX_CHUNKS;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= limit as u64,
        "web checkpoint must be a bounded private owned file"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "web checkpoint too large");
    Ok(serde_json::from_slice(&bytes)?)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    version: u8,
    pub cluster: String,
    pub node: String,
    pub revision: u64,
    tables: BTreeMap<String, Table>,
}

fn columns(db: &Connection, table: &str) -> Result<Vec<String>> {
    Ok(db
        .prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |r| r.get(1))?
        .collect::<rusqlite::Result<_>>()?)
}

pub fn export(home: &Path, node: &str) -> Result<Snapshot> {
    export_scoped(home, node, None)
}

pub fn export_for_epoch(home: &Path, node: &str, epoch: u64) -> Result<Snapshot> {
    export_scoped(home, node, Some(epoch))
}

fn export_scoped(home: &Path, node: &str, epoch: Option<u64>) -> Result<Snapshot> {
    let cfg = config::load_for_runtime(home)?;
    super::require_pro(home, &cfg, "Hosted node checkpoints")?;
    let mut db = encrypted::open_database(home, "state.sqlite3")?;
    db.execute_batch("PRAGMA query_only=ON;")?;
    let tx = db.transaction()?;
    super::check_epoch(&tx, node, epoch)?;
    let revision = tx.query_row(
        "SELECT revision FROM hosted_checkpoints WHERE node=?1 AND lease_until>?2",
        params![node, now()],
        |r| r.get(0),
    )?;
    // Every referenced blob is already durable in the encrypted object relay.
    // A replacement lazily fetches chunks; no native file bytes enter this bundle.
    let uploading: bool = tx.query_row(
        &format!(
            "{SCOPE} SELECT EXISTS(SELECT 1 FROM file_chunks
        WHERE object_id IN wf AND uploaded=0)"
        ),
        [node],
        |r| r.get(0),
    )?;
    ensure!(
        !uploading,
        "web file upload is pending; checkpoint will retry"
    );
    // V10 and older carriers reject unknown checkpoint tables. Keep their
    // checkpoint readable during rollout; new carriers can index its messages.
    let portable_dates: bool = tx.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM network_links l LEFT JOIN wire_peers w
        ON w.peer=l.peer AND w.peer_key=l.peer_key WHERE COALESCE(w.version,0)<?1)",
        [crate::messages::wire::MESSAGE_DATES_VERSION],
        |r| r.get(0),
    )?;
    let mut tables = BTreeMap::new();
    for &(table, predicate) in TABLES {
        if table == "chat_message_dates" && !portable_dates {
            continue;
        }
        let names = columns(&tx, table)?;
        if matches!(table, "dashboards" | "chat_message_dates") && names.is_empty() {
            continue;
        }
        let mut rows = tx
            .prepare(&format!("{SCOPE} SELECT * FROM {table} WHERE {predicate}"))?
            .query_map([node], |r| {
                (0..r.as_ref().column_count())
                    .map(|i| r.get(i).map(Cell::read))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if matches!(table, "dashboards" | "chat_message_dates") && rows.is_empty() {
            continue;
        }
        for row in &mut rows {
            if table == "agents" && !matches!(&row[2], Cell::Text(n) if n == node) {
                let Cell::Text(id) = &row[0] else {
                    anyhow::bail!("invalid chat identity");
                };
                row[1] = Cell::Text(format!("remote:{id}"));
            }
            if table == "messages" {
                let Cell::Text(payload) = &row[5] else {
                    anyhow::bail!("invalid message payload");
                };
                let message: Message = serde_json::from_str(payload)?;
                let own: bool = tx.query_row(
                    "SELECT node_id=?2 FROM agents WHERE id=?1",
                    params![message.sender, node],
                    |r| r.get(0),
                )?;
                if !own {
                    row[4] = Cell::Text(message_fingerprint(
                        &message.recipient,
                        &message.text,
                        &message.files,
                        &message.reply_to,
                        &message.relay,
                        &[],
                    )?);
                }
            }
            if table == "file_objects" {
                row[5] = Cell::Integer(0);
            }
            if table == "agent_files"
                && let Cell::Text(agent) = &row[1]
            {
                let own: bool = tx.query_row(
                    "SELECT node_id=?2 FROM agents WHERE id=?1",
                    params![agent, node],
                    |r| r.get(0),
                )?;
                if !own {
                    let Cell::Text(object) = &row[0] else {
                        anyhow::bail!("invalid file identity");
                    };
                    let message: String = tx.query_row(&format!("{SCOPE} SELECT m.id FROM messages m,json_each(m.payload,'$.attachments') j
                        WHERE m.id IN wm AND json_extract(j.value,'$.id')=?2 ORDER BY m.rowid LIMIT 1"), params![node,object], |r|r.get(0))?;
                    row[1] = Cell::Null;
                    row[2] = Cell::Text(message);
                }
            }
        }
        tables.insert(
            table.into(),
            Table {
                columns: names,
                rows,
            },
        );
    }
    // Recheck against a fresh read after capturing the stable snapshot.
    tx.commit()?;
    if epoch.is_some() {
        super::check_epoch(&db, node, epoch)?;
    }
    Ok(Snapshot {
        version: 1,
        cluster: cfg.cluster.id,
        node: node.into(),
        revision,
        tables,
    })
}

pub(in crate::store) fn restore(
    parent: &Connection,
    snapshot: &Snapshot,
    anchor: &gent_crypto::TrustAnchor,
    node: &str,
) -> Result<()> {
    ensure!(!parent.is_autocommit(), "web restore requires transaction");
    ensure!(
        snapshot.version == 1
            && snapshot.cluster == anchor.cluster_id
            && snapshot.node == node
            && snapshot
                .tables
                .keys()
                .all(|t| TABLES.iter().any(|(name, _)| *name == t)),
        "web checkpoint scope or version mismatch"
    );
    let source = Connection::open_in_memory()?;
    for &(table, _) in TABLES {
        // DDL comes exclusively from the local trusted schema, never the bundle.
        let ddl: String = parent.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |r| r.get(0),
        )?;
        source.execute_batch(&ddl)?;
        if matches!(table, "dashboards" | "chat_message_dates")
            && !snapshot.tables.contains_key(table)
        {
            continue;
        }
        let incoming = snapshot
            .tables
            .get(table)
            .context("checkpoint table missing")?;
        ensure!(
            incoming.columns == columns(parent, table)?,
            "web checkpoint schema mismatch"
        );
        let marks = (1..=incoming.columns.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let mut insert = source.prepare(&format!("INSERT INTO {table} VALUES({marks})"))?;
        for row in &incoming.rows {
            ensure!(
                row.len() == incoming.columns.len(),
                "invalid checkpoint row"
            );
            let values = row.iter().map(Cell::sql).collect::<Result<Vec<_>>>()?;
            insert.execute(params_from_iter(values))?;
        }
    }
    // Enforce each selection predicate again before importing any data.
    for &(table, predicate) in TABLES {
        let outside: bool = source.query_row(
            &format!(
                "{SCOPE} SELECT EXISTS(SELECT 1 FROM {table} WHERE ({predicate}) IS NOT TRUE)"
            ),
            [node],
            |r| r.get(0),
        )?;
        ensure!(!outside, "checkpoint contains unrelated native records");
    }
    // A completed object may be older than its original download window.
    // Give the replacement time to fetch ciphertext without extending retention.
    source.execute(
        "UPDATE file_objects SET incomplete_until=MIN(expires_at,?1) WHERE complete=0",
        [now() + crate::file_objects::INCOMPLETE_TTL_SECONDS as i64],
    )?;
    let finals=parent.prepare("SELECT t.id,t.final_message FROM relay_turns t JOIN messages m ON m.id=t.final_message
        JOIN agents a ON a.id=m.sender WHERE a.node_id!=?1 AND t.intermediary IN (SELECT id FROM agents WHERE node_id=?1)")?
        .query_map([node],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
    rollback_speculative(parent, &source, node)?;
    import::agents(parent, &source, node, anchor)?;
    // A file created by a native chat on this carrier retains its local owner.
    // The web checkpoint includes only the grant already attached to a message.
    let files = source
        .prepare("SELECT object_id FROM agent_files")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for file in files {
        if let Some((agent, message, manifest)) = parent
            .query_row(
                "SELECT agent,message,manifest FROM agent_files WHERE object_id=?1",
                [&file],
                |r| {
                    Ok((
                        r.get::<_, Option<String>>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
        {
            source.execute(
                "UPDATE agent_files SET agent=?2,message=?3,manifest=?4 WHERE object_id=?1",
                params![file, agent, message, manifest],
            )?;
        }
    }
    for &(table, _) in &TABLES[2..] {
        if table == "dashboards" {
            import::dashboards(parent, &source, node)?;
        } else {
            import::copy(parent, &source, table, node)?;
        }
    }
    if !snapshot.tables.contains_key("chat_message_dates") {
        crate::store::message_dates::backfill(parent, &source, node)?;
    }
    for (id, final_message) in finals {
        parent.execute(
            "UPDATE relay_turns SET final_message=COALESCE(final_message,?2)
            WHERE id=?1 AND EXISTS(SELECT 1 FROM messages WHERE id=?2)",
            params![id, final_message],
        )?;
    }
    import::capacity(parent)?;
    parent.execute("DELETE FROM hosted_directory WHERE node=?1", [node])?;
    for registration in source
        .prepare(
            "SELECT a.id,a.name,a.provider,a.revoked,o.nonce,o.legacy,o.generation
        FROM agents a JOIN network_origins o ON o.agent=a.id WHERE a.node_id=?1",
        )?
        .query_map([node], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<Vec<u8>>>(5)?,
                r.get::<_, u64>(6)?,
            ))
        })?
    {
        let (id, name, provider, revoked, nonce, legacy, generation) = registration?;
        let registration = crate::messages::Registration {
            id,
            name,
            provider,
            revoked,
            node: node.into(),
            nonce: nonce.map(|n| uuid::Uuid::parse_str(&n)).transpose()?,
            legacy: legacy.map(|b| serde_json::from_slice(&b)).transpose()?,
            generation,
        };
        parent.execute(
            "INSERT INTO hosted_directory VALUES(?1,?2,?3,?4)",
            params![
                registration.id,
                node,
                snapshot.revision,
                serde_json::to_vec(&registration)?
            ],
        )?;
    }
    ensure!(
        !parent.prepare("PRAGMA foreign_key_check")?.exists([])?,
        "invalid checkpoint references"
    );
    Ok(())
}

fn rollback_speculative(parent: &Connection, source: &Connection, node: &str) -> Result<()> {
    // The service checkpoint is authoritative for web-originated mutations.
    // Preserve native state and arrivals not yet consumed by the web chat.
    parent.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS web_restore_messages(id TEXT PRIMARY KEY);
        DELETE FROM web_restore_messages;",
    )?;
    for id in source
        .prepare("SELECT id FROM messages")?
        .query_map([], |r| r.get::<_, String>(0))?
    {
        parent.execute("INSERT INTO web_restore_messages VALUES(?1)", [id?])?;
    }
    let extra = "SELECT id FROM messages WHERE sender IN (SELECT id FROM agents WHERE node_id=?1)
        AND id NOT IN web_restore_messages";
    for (table, column) in [
        ("relay_turns", "id"),
        ("message_file_proofs", "message"),
        ("agent_files", "message"),
    ] {
        parent.execute(
            &format!("DELETE FROM {table} WHERE {column} IN ({extra})"),
            [node],
        )?;
    }
    parent.execute(
        &format!("DELETE FROM messages WHERE id IN ({extra})"),
        [node],
    )?;
    parent.execute("DELETE FROM exchanges WHERE a IN (SELECT id FROM agents WHERE node_id=?1)
        AND NOT EXISTS(SELECT 1 FROM messages WHERE json_extract(payload,'$.exchange_id')=exchanges.id)",[node])?;
    for (table, condition) in [
        (
            "relay_attachments",
            "intermediary IN (SELECT id FROM agents WHERE node_id=?1)",
        ),
        (
            "relay_turns",
            "intermediary IN (SELECT id FROM agents WHERE node_id=?1)",
        ),
        (
            "work_events",
            "message_id IN (SELECT message_id FROM work_entries WHERE agent IN (SELECT id FROM agents WHERE node_id=?1))",
        ),
        (
            "dashboards",
            "agent IN (SELECT id FROM agents WHERE node_id=?1)",
        ),
        (
            "dashboard_sent",
            "agent IN (SELECT id FROM agents WHERE node_id=?1)",
        ),
        ("hosted_dashboard_gates", "node=?1"),
        (
            "work_entries",
            "agent IN (SELECT id FROM agents WHERE node_id=?1)",
        ),
        (
            "file_imports",
            "agent IN (SELECT id FROM agents WHERE node_id=?1)",
        ),
    ] {
        parent.execute(&format!("DELETE FROM {table} WHERE {condition}"), [node])?;
    }
    // Consumption that was not checkpointed must not retire a pending reply.
    parent.execute("UPDATE messages SET acknowledged=0 WHERE recipient IN (SELECT id FROM agents WHERE node_id=?1)",[node])?;
    for (id,name,provider,last_seen,revoked,generation) in source.prepare("SELECT a.id,a.name,a.provider,a.last_seen,a.revoked,o.generation FROM agents a JOIN network_origins o ON o.agent=a.id WHERE a.node_id=?1")?
        .query_map([node], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(3)?,r.get::<_,bool>(4)?,r.get::<_,u64>(5)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()? {
        parent.execute("UPDATE agents SET name=?2,provider=?3,last_seen=?4,revoked=?5 WHERE id=?1 AND node_id=?6", params![id,name,provider,last_seen,revoked,node])?;
        parent.execute("UPDATE network_origins SET generation=?2 WHERE agent=?1 AND EXISTS(SELECT 1 FROM agents WHERE id=?1 AND node_id=?3)",params![id,generation,node])?;
    }
    // Drop only speculative publication cursors. Reconciliation recreates
    // committed message/receipt work under the new signed route.
    parent.execute(
        "DELETE FROM network_events WHERE id IN (SELECT id FROM hosted_event_gates WHERE node=?1)",
        [node],
    )?;
    parent.execute("DELETE FROM hosted_event_gates WHERE node=?1", [node])?;
    parent.execute("DELETE FROM hosted_message_gates WHERE node=?1", [node])?;
    // An interrupted registration has no committed handle. Delete only orphan
    // records; never erase native arrivals that refer to an uncommitted chat.
    let committed: std::collections::BTreeSet<String> = source
        .prepare("SELECT id FROM agents WHERE node_id=?1")?
        .query_map([node], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let candidates = parent
        .prepare(
            "SELECT id FROM agents WHERE node_id=?1
        AND id NOT IN (SELECT sender FROM messages UNION SELECT recipient FROM messages
        UNION SELECT a FROM exchanges UNION SELECT b FROM exchanges
        UNION SELECT target FROM relay_attachments UNION SELECT target FROM recovered_sources)",
        )?
        .query_map([node], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for id in candidates.into_iter().filter(|id| !committed.contains(id)) {
        for (table, column) in [
            ("agent_activity", "agent"),
            ("directory_cleared", "agent"),
            ("network_origins", "agent"),
            ("agent_files", "agent"),
            ("wake_dispatches", "agent"),
            ("file_exports", "agent"),
            ("file_handoffs", "agent"),
        ] {
            parent.execute(&format!("DELETE FROM {table} WHERE {column}=?1"), [&id])?;
        }
        parent.execute("DELETE FROM agents WHERE id=?1", [&id])?;
    }
    parent.execute_batch("DROP TABLE web_restore_messages;")?;
    Ok(())
}
