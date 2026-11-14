//! Read-only recovery of owner-assigned history from an authenticated snapshot.
use super::*;
use gent_protocol::{
    FilePart,
    history::{
        Assignment, MAX_LINEAGE, MAX_METADATA_BYTES, Origin, RecoveredFile, RecoveredMessage,
    },
};
use std::collections::BTreeMap;

const TABLES: [&str; 5] = [
    "recovered_schema",
    "recovered_sources",
    "recovered_messages",
    "recovered_files",
    "recovered_chunks",
];

struct Receipt {
    id: String,
    digest: String,
    origin: Origin,
    revision: u64,
    retired: bool,
    target_revoked: bool,
    bytes: u64,
}

fn receipts(db: &Connection, manifest: &format::Manifest) -> Result<Vec<Receipt>> {
    let present: u64 = db.query_row("SELECT COUNT(*) FROM pragma_table_list WHERE schema='main' AND name IN ('recovered_schema','recovered_sources','recovered_messages','recovered_files','recovered_chunks')", [], |r| r.get(0))?;
    if present == 0 {
        return Ok(Vec::new());
    }
    ensure!(
        present == TABLES.len() as u64,
        "incomplete archived history schema"
    );
    for name in TABLES {
        table(db, name)?;
    }
    let version: u64 =
        db.query_row("SELECT version FROM recovered_schema WHERE id=1", [], |r| {
            r.get(0)
        })?;
    ensure!(
        version == 1,
        "unsupported archived recovered storage version"
    );
    let count: u64 = db.query_row("SELECT COUNT(*) FROM recovered_sources", [], |r| r.get(0))?;
    ensure!(count <= 256, "archived history receipt limit exceeded");
    let mut statement = db.prepare(
        "SELECT id,target,source_agent,digest,summary,revision,retired,bytes,
        length(CAST(id||target||source_agent||digest AS BLOB)),length(CAST(summary AS BLOB))
        FROM recovered_sources ORDER BY id",
    )?;
    let mut rows = statement.query([])?;
    let mut result = Vec::new();
    let mut metadata = 0usize;
    while let Some(row) = rows.next()? {
        let size: usize = row.get(9)?;
        metadata = metadata
            .checked_add(size)
            .context("archived receipt size overflow")?;
        ensure!(
            row.get::<_, usize>(8)? == 172
                && size <= MAX_METADATA_BYTES
                && metadata <= 2 * 1024 * 1024,
            "archived history receipt too large"
        );
        let id: String = row.get(0)?;
        let target: String = row.get(1)?;
        let source: String = row.get(2)?;
        let digest: String = row.get(3)?;
        let origin: Origin = serde_json::from_str(&Zeroizing::new(row.get::<_, String>(4)?))
            .map_err(|_| anyhow::anyhow!("invalid archived history origin"))?;
        let revision: u64 = row.get(5)?;
        let retired: i64 = row.get(6)?;
        let bytes: u64 = row.get(7)?;
        ensure!(
            origin.valid()
                && origin.source_agent.id == source
                && origin.target_agent == target
                && gent_protocol::history::valid_digest(&digest)
                && (1..=(1u64 << 53) - 1).contains(&revision)
                && matches!(retired, 0 | 1)
                && revision.is_multiple_of(2) == (retired == 1)
                && bytes <= 256 * 1024 * 1024
                && (retired == 0 || bytes == 0),
            "invalid archived history receipt"
        );
        validate_agent(&origin.source_agent)?;
        let expected = gent_crypto::scoped_id(
            b"gent/history-import/v1",
            &[
                manifest.cluster_id.as_bytes(),
                digest.as_bytes(),
                source.as_bytes(),
                target.as_bytes(),
            ],
        );
        ensure!(
            id == expected.to_string(),
            "archived import identity mismatch"
        );
        let revoked: i64 = db.query_row(
            "SELECT revoked FROM agents WHERE id=?1 AND node_id=?2",
            [&target, &manifest.node_id],
            |r| r.get(0),
        )?;
        ensure!(
            matches!(revoked, 0 | 1),
            "invalid archived recipient status"
        );
        result.push(Receipt {
            id,
            digest,
            origin,
            revision,
            retired: retired == 1,
            target_revoked: revoked == 1,
            bytes,
        });
    }
    Ok(result)
}

pub(super) fn inventory(db: &Connection, manifest: &format::Manifest) -> Result<Value> {
    Ok(json!(receipts(db, manifest)?.iter().map(|r| json!({
        "import_id":r.id,"revision":r.revision,"retired":r.retired,"target_revoked":r.target_revoked,
        "bytes":r.bytes,"origin":r.origin
    })).collect::<Vec<_>>()))
}

pub(super) fn export(
    db: &Connection,
    manifest: &format::Manifest,
    output: &Path,
    selected: &str,
) -> Result<Value> {
    let receipt = receipts(db, manifest)?
        .into_iter()
        .find(|r| r.id == selected)
        .context("archived import unavailable")?;
    ensure!(
        !receipt.retired,
        "archived import was removed; no content can be recovered"
    );
    ensure!(
        receipt.origin.lineage.len() < MAX_LINEAGE,
        "historical provenance exceeds 64 assignments"
    );
    let count: u64 = db.query_row(
        "SELECT COUNT(*) FROM recovered_messages WHERE source=?1",
        [selected],
        |r| r.get(0),
    )?;
    ensure!(count <= 8192, "archived recovered message limit exceeded");
    let orphan: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM recovered_files f LEFT JOIN recovered_messages m ON m.source=f.source AND m.id=f.message WHERE f.source=?1 AND m.id IS NULL)
        OR EXISTS(SELECT 1 FROM recovered_chunks c LEFT JOIN recovered_files f ON f.source=c.source AND f.message=c.message AND f.slot=c.slot WHERE c.source=?1 AND f.slot IS NULL)",
        [selected], |r| r.get(0))?;
    ensure!(!orphan, "orphaned archived history files");
    let mut remaining = MAX_OUTPUT_BYTES;
    let mut stored = 0u64;
    let mut agents = BTreeMap::new();
    agents.insert(
        receipt.origin.source_agent.id.clone(),
        receipt.origin.source_agent.clone(),
    );
    let mut messages = Records::new(output, "messages.jsonl")?;
    let mut files = FileCounts::default();
    let mut statement = db.prepare("SELECT id,ordinal,payload,length(CAST(payload AS BLOB)),length(CAST(id AS BLOB)) FROM recovered_messages WHERE source=?1 ORDER BY ordinal")?;
    let mut rows = statement.query([selected])?;
    let mut ordinal = 0u64;
    while let Some(row) = rows.next()? {
        let size: u64 = row.get(3)?;
        ensure!(
            size <= 1024 * 1024 && row.get::<_, usize>(4)? == 36,
            "archived recovered message too large"
        );
        stored = stored
            .checked_add(size)
            .context("archived history size overflow")?;
        let mut record: RecoveredMessage =
            serde_json::from_str(&Zeroizing::new(row.get::<_, String>(2)?))
                .map_err(|_| anyhow::anyhow!("invalid archived recovered message"))?;
        ordinal += 1;
        let message = &record.message;
        ensure!(
            row.get::<_, u64>(1)? == ordinal
                && message.id == row.get::<_, String>(0)?
                && record.historical
                && message.files.is_empty()
                && message.attachments.is_empty()
                && record.files.len() <= 128
                && message.text.len() <= gent_protocol::MAX_TEXT_BYTES
                && message.sender == record.sender.id
                && message.recipient == record.recipient.id
                && message.sender != message.recipient
                && (message.sender == receipt.origin.source_agent.id
                    || message.recipient == receipt.origin.source_agent.id),
            "archived recovered message binding mismatch"
        );
        for value in [
            &message.id,
            &message.exchange_id,
            &message.sender,
            &message.recipient,
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
        for agent in [&record.sender, &record.recipient] {
            validate_agent(agent)?;
            if let Some(old) = agents.insert(agent.id.clone(), agent.clone()) {
                ensure!(old == *agent, "conflicting historical agent labels");
            }
        }
        let mut assets = Vec::new();
        let mut inline_bytes = 0u64;
        let mut ready = 0u64;
        for (slot, file) in record.files.iter().enumerate() {
            ensure!(
                file.file_index as usize == slot
                    && matches!(file.state.as_str(), "ready" | "missing" | "incomplete"),
                "invalid archived recovered file"
            );
            validate_metadata(&file.name, &file.media_type)?;
            ensure!(
                file.byte_length <= gent_protocol::file_objects::MAX_FILE_BYTES as u64
                    && gent_protocol::history::valid_digest(&file.sha256),
                "invalid archived file descriptor"
            );
            let relative = if let Some(original) = &file.original_file_id {
                id(original)?;
                format!("files/{original}")
            } else {
                ensure!(
                    record.message.attachments.is_empty() && file.state == "ready",
                    "invalid archived inline ordering or state"
                );
                inline_bytes = inline_bytes
                    .checked_add(file.byte_length)
                    .context("inline history size overflow")?;
                ensure!(
                    inline_bytes <= gent_protocol::MAX_FILE_BYTES as u64,
                    "archived inline files exceed limit"
                );
                format!("files/{}-inline-{slot}", record.message.id)
            };
            let status = match file.state.as_str() {
                "ready" => {
                    ready += 1;
                    files.exported += 1;
                    reserve(&mut remaining, file.byte_length)?;
                    stored = stored
                        .checked_add(file.byte_length)
                        .context("archived history size overflow")?;
                    copy_file(
                        db,
                        selected,
                        &record.message.id,
                        file,
                        &output.join(&relative),
                    )?;
                    "exported"
                }
                "missing" => {
                    files.missing += 1;
                    "missing"
                }
                _ => {
                    files.incomplete += 1;
                    "incomplete"
                }
            };
            if let Some(original) = &file.original_file_id {
                let descriptor = FileDescriptor {
                    id: original.clone(),
                    name: file.name.clone(),
                    media_type: file.media_type.clone(),
                    byte_length: file.byte_length,
                    sha256: file.sha256.clone(),
                };
                let mut asset = json!({"source":"attachment","file":descriptor,"status":status});
                if file.state == "ready" {
                    asset["path"] = json!(relative);
                }
                assets.push(asset);
                record.message.attachments.push(descriptor);
            } else {
                let bytes = Zeroizing::new(fs::read(output.join(&relative))?);
                record.message.files.push(FilePart {
                    name: file.name.clone(),
                    media_type: file.media_type.clone(),
                    data_base64: STANDARD.encode(&bytes),
                });
                assets.push(json!({"source":"inline","index":slot,"status":status,"path":relative,
                    "name":file.name,"media_type":file.media_type,"byte_length":file.byte_length,"sha256":file.sha256}));
            }
        }
        let saved: u64 = db.query_row(
            "SELECT COUNT(*) FROM recovered_files WHERE source=?1 AND message=?2",
            [selected, &record.message.id],
            |r| r.get(0),
        )?;
        ensure!(saved == ready, "archived recovered file inventory mismatch");
        messages.write(
            &json!({"message":record.message,"assets":assets}),
            &mut remaining,
        )?;
    }
    ensure!(
        stored == receipt.bytes,
        "archived recovered content size mismatch"
    );
    let messages = messages.finish()?;
    let mut agent_records = Records::new(output, "agents.jsonl")?;
    for agent in agents.values() {
        agent_records.write(&json!(agent), &mut remaining)?;
    }
    let agents = agent_records.finish()?;
    let mut lineage = receipt.origin.lineage.clone();
    lineage.push(Assignment {
        archive: receipt.origin.archive(),
        import_id: receipt.id,
        manifest_sha256: receipt.digest,
        source_agent: receipt.origin.source_agent.id,
        target_agent: receipt.origin.target_agent,
        target_revoked: receipt.target_revoked,
        imported_at: receipt.origin.imported_at,
        revision: receipt.revision,
    });
    let database = manifest
        .entries
        .iter()
        .find(|e| e.path == "state.sqlite3")
        .context("missing database digest")?;
    Ok(
        json!({"version":2,"kind":"gent_offline_history","archive_id":manifest.archive_id,
        "cluster_id":manifest.cluster_id,"node_id":manifest.node_id,"captured_at":manifest.created_at,
        "database_sha256":database.sha256,"agents":agents,"messages":messages,"files":files,
        "content_bytes":MAX_OUTPUT_BYTES-remaining,"lineage":lineage,
        "scope":"selected historical assignment; no live credentials, permissions or authority",
        "provenance":"authenticated archive at export time; lineage records historical assignments, not present access",
        "activation":"unsupported"}),
    )
}

fn validate_agent(agent: &Agent) -> Result<()> {
    id(&agent.id)?;
    id(&agent.node_id)?;
    config::label(&agent.name)?;
    config::label(&agent.provider)?;
    Ok(())
}

fn copy_file(
    db: &Connection,
    source: &str,
    message: &str,
    expected: &RecoveredFile,
    output: &Path,
) -> Result<()> {
    let (size, raw): (usize, String) = db.query_row("SELECT length(CAST(descriptor AS BLOB)),CASE WHEN length(CAST(descriptor AS BLOB))<=4096 THEN descriptor ELSE '' END FROM recovered_files WHERE source=?1 AND message=?2 AND slot=?3",
        rusqlite::params![source, message, expected.file_index], |r| Ok((r.get(0)?,r.get(1)?)))?;
    ensure!(size <= 4096, "archived file descriptor too large");
    let saved: RecoveredFile = serde_json::from_str(&raw)
        .map_err(|_| anyhow::anyhow!("invalid archived file descriptor"))?;
    ensure!(
        &saved == expected,
        "archived recovered file descriptor mismatch"
    );
    let mut file = new_file(output)?;
    let mut digest = Sha256::new();
    let chunks = expected
        .byte_length
        .div_ceil(gent_protocol::file_objects::CHUNK_BYTES as u64)
        .max(1);
    let mut statement = db.prepare("SELECT position,length(bytes),bytes,CASE WHEN length(CAST(digest AS BLOB))=64 THEN digest ELSE '' END FROM recovered_chunks WHERE source=?1 AND message=?2 AND slot=?3 ORDER BY position")?;
    let mut rows = statement.query(rusqlite::params![source, message, expected.file_index])?;
    let mut position = 0u64;
    let mut remaining = expected.byte_length;
    while let Some(row) = rows.next()? {
        let size = remaining.min(gent_protocol::file_objects::CHUNK_BYTES as u64);
        ensure!(
            position < chunks && row.get::<_, u64>(0)? == position && row.get::<_, u64>(1)? == size,
            "invalid archived recovered chunk"
        );
        let bytes = Zeroizing::new(row.get::<_, Vec<u8>>(2)?);
        ensure!(
            row.get::<_, String>(3)? == format!("{:x}", Sha256::digest(&bytes)),
            "archived recovered chunk integrity mismatch"
        );
        file.write_all(&bytes)?;
        digest.update(&bytes);
        remaining -= size;
        position += 1;
    }
    ensure!(
        position == chunks
            && remaining == 0
            && format!("{:x}", digest.finalize()) == expected.sha256,
        "archived recovered file integrity mismatch"
    );
    file.sync_all()?;
    Ok(())
}
