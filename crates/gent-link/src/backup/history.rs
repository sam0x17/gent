//! Historical records only: never open Store, MLS, credentials or live queues.
use super::{destination, format, publish_directory, read_key};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gent_crypto::files::{FileGrant, MAX_GRANT_BYTES, validate_metadata};
use gent_daemon::{config, recovery};
use gent_protocol::{Agent, FileDescriptor, Message};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

const MAX_RECORDS: u64 = 65_536;
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;
mod recovered;

pub(super) fn export(archive: &Path, identity: &Path, output: &Path) -> Result<Value> {
    export_selected(archive, identity, output, None)
}

pub(super) fn export_import(
    archive: &Path,
    identity: &Path,
    output: &Path,
    import: &str,
) -> Result<Value> {
    id(import)?;
    export_selected(archive, identity, output, Some(import))
}

pub(super) fn list(archive: &Path, identity: &Path) -> Result<Value> {
    let (source, manifest) = source(archive, identity, &std::env::temp_dir())?;
    let db = database(&source.path().join("state.sqlite3"), &manifest)?;
    let imports = recovered::inventory(&db, &manifest)?;
    let live: u64 = db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?;
    drop(db);
    source.close()?;
    Ok(
        json!({"archive_id":manifest.archive_id,"live_messages":live,"historical_imports":imports,
        "scope":"archived receipts; content is verified when selected for export; no current authority"}),
    )
}

fn source(
    archive: &Path,
    identity: &Path,
    parent: &Path,
) -> Result<(tempfile::TempDir, format::Manifest)> {
    let key = read_key(identity)?;
    let source = tempfile::Builder::new()
        .prefix(".gent-history-source-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    config::write_private(
        &source.path().join(recovery::MARKER),
        b"{\"state\":\"offline_history_source\"}\n",
    )?;
    let manifest = format::read_database(archive, &key, source.path())?;
    ensure!(
        !manifest.entries.iter().any(|e| matches!(
            e.path.as_str(),
            "state.sqlite3-wal" | "state.sqlite3-shm" | "state.sqlite3-journal"
        )),
        "archived database has journal sidecars"
    );
    Ok((source, manifest))
}

fn export_selected(
    archive: &Path,
    identity: &Path,
    output: &Path,
    selected: Option<&str>,
) -> Result<Value> {
    let output = destination(output)?;
    let parent = output.parent().context("missing history output parent")?;
    let (source, manifest) = source(archive, identity, parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".gent-history-export-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    config::write_private(
        &staging.path().join(recovery::MARKER),
        b"{\"version\":1,\"state\":\"historical_export\"}\n",
    )?;
    config::private_dir(&staging.path().join("files"))?;
    let report = if let Some(import) = selected {
        let db = database(&source.path().join("state.sqlite3"), &manifest)?;
        recovered::export(&db, &manifest, staging.path(), import)?
    } else {
        export_database(
            &source.path().join("state.sqlite3"),
            &manifest,
            staging.path(),
        )?
    };
    config::write_private(
        &staging.path().join("history.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    // Remove the temporary database (which contains historical secrets) before
    // publishing the allowlisted history. A failed removal leaves no output.
    source.close()?;
    File::open(staging.path().join("files"))?.sync_all()?;
    File::open(staging.path())?.sync_all()?;
    publish_directory(staging.path(), &output)?;
    File::open(parent)?.sync_all()?;
    let mut result = json!({"state":"exported_history", "archive_id":manifest.archive_id,
        "output":output, "agents":report["agents"]["records"],
        "messages":report["messages"]["records"], "files":report["files"],
        "activation":"unsupported", "scope":"offline Gent history; no provider conversation history or live authority"});
    if let Some(last) = report["lineage"].as_array().and_then(|a| a.last()) {
        result["source_agent"] = last["source_agent"].clone();
        result["from_import"] = last["import_id"].clone();
    }
    Ok(result)
}

fn table(db: &Connection, name: &str) -> Result<()> {
    let kind: String = db.query_row(
        "SELECT type FROM pragma_table_list WHERE schema='main' AND name=?1",
        [name],
        |r| r.get(0),
    )?;
    ensure!(kind == "table", "unsupported archived history table");
    Ok(())
}

fn id(value: &str) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value),
        "invalid archived history identity"
    );
    Ok(())
}

fn descriptor(file: &FileDescriptor) -> Result<()> {
    ensure!(
        gent_protocol::file_objects::valid_id(&file.id),
        "invalid archived file identity"
    );
    validate_metadata(&file.name, &file.media_type)?;
    ensure!(
        file.byte_length <= gent_crypto::files::MAX_FILE_BYTES as u64
            && file.sha256.len() == 64
            && file
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid archived file descriptor"
    );
    Ok(())
}

fn database(path: &Path, manifest: &format::Manifest) -> Result<Connection> {
    let mut uri = url::Url::from_file_path(path)
        .map_err(|_| anyhow::anyhow!("invalid archive database path"))?;
    uri.set_query(Some("mode=ro&immutable=1"));
    let db = Connection::open_with_flags(
        uri.as_str(),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")?;
    let check: String = db.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    ensure!(check == "ok", "archived database integrity check failed");
    for name in ["agents", "messages", "exchanges", "metadata"] {
        table(&db, name)?;
    }
    for (name, expected) in [
        ("cluster", &manifest.cluster_id),
        ("node", &manifest.node_id),
    ] {
        let value: String = db.query_row(
            "SELECT value FROM metadata WHERE key=?1 AND length(CAST(value AS BLOB))=36",
            [name],
            |r| r.get(0),
        )?;
        ensure!(
            &value == expected,
            "archived database identity differs from manifest"
        );
    }
    Ok(db)
}

fn export_database(path: &Path, manifest: &format::Manifest, output: &Path) -> Result<Value> {
    let db = database(path, manifest)?;
    for name in ["agents", "messages"] {
        let count: u64 = db.query_row(&format!("SELECT COUNT(*) FROM {name}"), [], |r| r.get(0))?;
        ensure!(
            count <= MAX_RECORDS,
            "archived history record limit exceeded"
        );
    }
    let mut remaining = MAX_OUTPUT_BYTES;
    let mut agents = Records::new(output, "agents.jsonl")?;
    let mut query = db.prepare(
        "SELECT id,node_id,name,provider,last_seen,revoked,
        length(CAST(id||node_id||name||provider AS BLOB)) FROM agents ORDER BY id",
    )?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        ensure!(
            row.get::<_, u64>(6)? <= 4096,
            "archived agent record too large"
        );
        let revoked = row.get::<_, i64>(5)?;
        ensure!(matches!(revoked, 0 | 1), "invalid archived agent status");
        let agent = Agent {
            id: row.get(0)?,
            node_id: row.get(1)?,
            name: row.get(2)?,
            provider: row.get(3)?,
            last_seen: row.get(4)?,
            revoked: revoked == 1,
        };
        id(&agent.id)?;
        id(&agent.node_id)?;
        config::label(&agent.name)?;
        config::label(&agent.provider)?;
        agents.write(&json!(agent), &mut remaining)?;
    }
    let agents = agents.finish()?;
    let mut messages = Records::new(output, "messages.jsonl")?;
    let mut files = FileCounts::default();
    let mut query = db.prepare(
        "SELECT id,sender,recipient,payload,acknowledged,
        length(CAST(payload AS BLOB)),length(CAST(id||sender||recipient AS BLOB)) FROM messages ORDER BY rowid",
    )?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        ensure!(
            row.get::<_, u64>(5)? <= gent_protocol::MAX_FRAME_BYTES as u64
                && row.get::<_, u64>(6)? == 108,
            "archived message record too large"
        );
        let payload = Zeroizing::new(row.get::<_, String>(3)?);
        let mut message: Message = serde_json::from_str(&payload)
            .map_err(|_| anyhow::anyhow!("invalid archived message"))?;
        ensure!(
            message.id == row.get::<_, String>(0)?
                && message.sender == row.get::<_, String>(1)?
                && message.recipient == row.get::<_, String>(2)?,
            "archived message identity mismatch"
        );
        for value in [
            &message.id,
            &message.sender,
            &message.recipient,
            &message.exchange_id,
        ] {
            id(value)?;
        }
        if let Some(reply) = &message.reply_to {
            id(reply)?;
        }
        if let Some(relay) = &message.relay {
            for value in [&relay.attachment_id, &relay.grant_id, &relay.turn_id] {
                id(value)?;
            }
        }
        ensure!(
            message.text.len() <= gent_protocol::MAX_TEXT_BYTES
                && message.files.len() <= 128
                && message.attachments.len() <= 128,
            "archived message limits exceeded"
        );
        let ack: i64 = row.get(4)?;
        ensure!(
            matches!(ack, 0 | 1),
            "invalid archived message acknowledgment"
        );
        message.acknowledged = ack == 1;
        let (a, b): (String, String) = db.query_row(
            "SELECT a,b FROM exchanges WHERE id=?1 AND length(CAST(a AS BLOB))=36 AND length(CAST(b AS BLOB))=36",
            [&message.exchange_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            (a == message.sender && b == message.recipient)
                || (b == message.sender && a == message.recipient),
            "archived exchange participants differ"
        );
        let participants: u64 = db.query_row(
            "SELECT COUNT(*) FROM agents WHERE id IN (?1,?2)",
            [&message.sender, &message.recipient],
            |r| r.get(0),
        )?;
        ensure!(participants == 2, "archived message participant missing");
        let mut assets = Vec::new();
        let mut inline_bytes = 0;
        for (index, file) in message.files.iter().enumerate() {
            validate_metadata(&file.name, &file.media_type)?;
            let bytes = Zeroizing::new(
                STANDARD
                    .decode(&file.data_base64)
                    .map_err(|_| anyhow::anyhow!("invalid archived inline file"))?,
            );
            inline_bytes += bytes.len();
            ensure!(
                inline_bytes <= gent_protocol::MAX_FILE_BYTES,
                "archived inline files exceed limit"
            );
            let relative = format!("files/{}-inline-{index}", message.id);
            reserve(&mut remaining, bytes.len() as u64)?;
            let mut target = new_file(&output.join(&relative))?;
            target.write_all(&bytes)?;
            target.sync_all()?;
            assets.push(
                json!({"source":"inline", "index":index, "status":"exported", "path":relative,
                "name":file.name, "media_type":file.media_type, "byte_length":bytes.len(),
                "sha256":format!("{:x}", Sha256::digest(&bytes))}),
            );
            files.exported += 1;
        }
        let mut seen = BTreeSet::new();
        for file in &message.attachments {
            descriptor(file)?;
            ensure!(seen.insert(&file.id), "duplicate archived file reference");
            assets.push(export_attachment(
                &db,
                &message.id,
                file,
                output,
                &mut remaining,
                &mut files,
            )?);
        }
        messages.write(&json!({"message":message,"assets":assets}), &mut remaining)?;
    }
    let messages = messages.finish()?;
    let database = manifest
        .entries
        .iter()
        .find(|e| e.path == "state.sqlite3")
        .context("missing database digest")?;
    Ok(
        json!({"version":1, "kind":"gent_offline_history", "archive_id":manifest.archive_id,
        "cluster_id":manifest.cluster_id, "node_id":manifest.node_id, "captured_at":manifest.created_at,
        "database_sha256":database.sha256, "agents":agents, "messages":messages,
        "files":files, "content_bytes":MAX_OUTPUT_BYTES-remaining,
        "scope":"retained Gent history only; no provider transcripts, credentials, grants, live requests or authority",
        "provenance":"authenticated archive at export time; this plaintext export is not independently signed",
        "activation":"unsupported"}),
    )
}

#[derive(Default, serde::Serialize)]
struct FileCounts {
    exported: u64,
    missing: u64,
    incomplete: u64,
}

fn export_attachment(
    db: &Connection,
    message: &str,
    file: &FileDescriptor,
    output: &Path,
    remaining: &mut u64,
    counts: &mut FileCounts,
) -> Result<Value> {
    for name in [
        "file_object_schema",
        "file_objects",
        "file_chunks",
        "agent_files",
    ] {
        table(db, name)?;
    }
    let version: u64 = db.query_row(
        "SELECT version FROM file_object_schema WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    ensure!(version == 1, "unsupported archived file storage version");
    let mut statement =
        db.prepare("SELECT complete,length(grant),grant FROM file_objects WHERE id=?1")?;
    let mut rows = statement.query([&file.id])?;
    let mut result = json!({"source":"attachment", "file":file});
    let Some(row) = rows.next()? else {
        counts.missing += 1;
        result["status"] = json!("missing");
        return Ok(result);
    };
    let complete: i64 = row.get(0)?;
    ensure!(
        matches!(complete, 0 | 1) && row.get::<_, usize>(1)? <= MAX_GRANT_BYTES,
        "invalid archived file object"
    );
    let grant = FileGrant::decode_private(&Zeroizing::new(row.get::<_, Vec<u8>>(2)?))?;
    ensure!(
        grant.descriptor() == file,
        "archived file descriptor mismatch"
    );
    let bound: Option<Option<String>> = db
        .query_row(
            "SELECT message FROM agent_files WHERE object_id=?1 AND length(CAST(message AS BLOB))=36",
            [&file.id],
            |r| r.get(0),
        )
        .optional()?;
    ensure!(
        bound.as_ref().and_then(|v| v.as_deref()) == Some(message),
        "archived file message binding mismatch"
    );
    if complete == 0 {
        counts.incomplete += 1;
        result["status"] = json!("incomplete");
        return Ok(result);
    }
    reserve(remaining, file.byte_length)?;
    let relative = format!("files/{}", file.id);
    let mut target = new_file(&output.join(&relative))?;
    let mut chunks = db.prepare("SELECT position,length(ciphertext),ciphertext FROM file_chunks WHERE object_id=?1 ORDER BY position")?;
    let mut rows = chunks.query([&file.id])?;
    let mut index = 0;
    let mut digest = Sha256::new();
    while let Some(row) = rows.next()? {
        ensure!(
            row.get::<_, u32>(0)? == index
                && row.get::<_, usize>(1)? == grant.ciphertext_len(index)?,
            "invalid archived file chunk"
        );
        let bytes = grant.decrypt_chunk(index, &row.get::<_, Vec<u8>>(2)?)?;
        target.write_all(&bytes)?;
        digest.update(&bytes);
        index += 1;
    }
    ensure!(
        index == grant.chunk_count() && format!("{:x}", digest.finalize()) == file.sha256,
        "archived file is incomplete or corrupt"
    );
    target.sync_all()?;
    counts.exported += 1;
    result["status"] = json!("exported");
    result["path"] = json!(relative);
    Ok(result)
}

fn new_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

fn reserve(remaining: &mut u64, bytes: u64) -> Result<()> {
    *remaining = remaining
        .checked_sub(bytes)
        .context("history export exceeds 1 GiB")?;
    Ok(())
}

struct Records {
    file: File,
    path: String,
    digest: Sha256,
    bytes: u64,
    records: u64,
}
impl Records {
    fn new(output: &Path, name: &str) -> Result<Self> {
        Ok(Self {
            file: new_file(&output.join(name))?,
            path: name.into(),
            digest: Sha256::new(),
            bytes: 0,
            records: 0,
        })
    }
    fn write(&mut self, value: &Value, remaining: &mut u64) -> Result<()> {
        let mut bytes = Zeroizing::new(serde_json::to_vec(value)?);
        bytes.push(b'\n');
        reserve(remaining, bytes.len() as u64)?;
        self.file.write_all(&bytes)?;
        self.digest.update(&bytes);
        self.bytes += bytes.len() as u64;
        self.records += 1;
        Ok(())
    }
    fn finish(self) -> Result<Value> {
        self.file.sync_all()?;
        Ok(
            json!({"path":self.path,"bytes":self.bytes,"records":self.records,"sha256":format!("{:x}",self.digest.finalize())}),
        )
    }
}
