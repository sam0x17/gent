use super::*;
use anyhow::bail;
use gent_protocol::history::{Assignment, valid_lineage};
use rustix::fs::{Mode, OFlags, open, openat};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    os::unix::fs::MetadataExt,
};
use zeroize::Zeroizing;

const MAX_RECORDS: u64 = 65_536;
const MAX_EXPORT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Records {
    path: String,
    bytes: u64,
    records: u64,
    sha256: String,
}

#[derive(Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
struct Counts {
    exported: u64,
    missing: u64,
    incomplete: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    kind: String,
    archive_id: String,
    cluster_id: String,
    node_id: String,
    captured_at: u64,
    database_sha256: String,
    agents: Records,
    messages: Records,
    files: Counts,
    content_bytes: u64,
    scope: String,
    provenance: String,
    activation: String,
    #[serde(default)]
    lineage: Vec<Assignment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    message: Message,
    assets: Vec<Asset>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Availability {
    Exported,
    Missing,
    Incomplete,
}

#[derive(Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
enum Asset {
    Inline {
        index: usize,
        status: Availability,
        path: String,
        name: String,
        media_type: String,
        byte_length: u64,
        sha256: String,
    },
    Attachment {
        file: FileDescriptor,
        status: Availability,
        path: Option<String>,
    },
}

fn identity(id: &str) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(id).is_ok_and(|u| !u.is_nil() && u.to_string() == id),
        "invalid historical identity"
    );
    Ok(())
}
fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid history digest"
    );
    Ok(())
}

impl Manifest {
    fn validate(&self) -> Result<()> {
        ensure!(
            ((self.version == 1 && self.lineage.is_empty())
                || (self.version == 2 && !self.lineage.is_empty()))
                && self.kind == "gent_offline_history"
                && self.activation == "unsupported",
            "unsupported history export"
        );
        for id in [&self.archive_id, &self.cluster_id, &self.node_id] {
            identity(id)?;
        }
        digest(&self.database_sha256)?;
        ensure!(
            (1..MAX_REVISION).contains(&self.captured_at)
                && self.content_bytes <= MAX_EXPORT_BYTES
                && self.scope.len() <= 1024
                && self.provenance.len() <= 1024,
            "invalid history export metadata"
        );
        for (records, name) in [
            (&self.agents, "agents.jsonl"),
            (&self.messages, "messages.jsonl"),
        ] {
            ensure!(
                records.path == name
                    && records.bytes <= MAX_EXPORT_BYTES
                    && records.records <= MAX_RECORDS,
                "history record limits exceeded"
            );
            digest(&records.sha256)?;
        }
        Ok(())
    }
}

fn directory(path: &Path) -> Result<File> {
    let file: File = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into();
    private(&file.metadata()?, true)?;
    Ok(file)
}
fn private(metadata: &fs::Metadata, directory: bool) -> Result<()> {
    ensure!(
        metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file() && metadata.nlink() == 1
            },
        "history input must be private and owned by this user"
    );
    Ok(())
}
fn open_file(root: &File, name: &str, limit: u64) -> Result<File> {
    ensure!(
        !name.is_empty() && !name.contains(['/', '\\']) && !matches!(name, "." | ".."),
        "unsafe history path"
    );
    let file: File = openat(
        root,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into();
    let metadata = file.metadata()?;
    private(&metadata, false)?;
    ensure!(metadata.len() <= limit, "history file exceeds size limit");
    Ok(file)
}
fn stamp(file: &File) -> Result<(u64, u64, u64, i64, i64, i64, i64)> {
    let m = file.metadata()?;
    Ok((
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ))
}

fn records<T: serde::de::DeserializeOwned>(
    root: &File,
    summary: &Records,
    max_line: u64,
    mut accept: impl FnMut(T) -> Result<()>,
) -> Result<()> {
    let file = open_file(root, &summary.path, summary.bytes)?;
    ensure!(
        file.metadata()?.len() == summary.bytes,
        "history record file length changed"
    );
    let before = stamp(&file)?;
    let mut reader = BufReader::new(&file);
    let mut hash = Sha256::new();
    let mut count = 0;
    let mut total = 0u64;
    loop {
        let mut line = Zeroizing::new(Vec::new());
        let size = (&mut reader)
            .take(max_line + 1)
            .read_until(b'\n', &mut line)?;
        if size == 0 {
            break;
        }
        total = total
            .checked_add(size as u64)
            .context("history record size overflow")?;
        ensure!(
            size as u64 <= max_line
                && total <= summary.bytes
                && line.last() == Some(&b'\n')
                && count < summary.records,
            "invalid or oversized history record"
        );
        hash.update(&line);
        let value = serde_json::from_slice(&line)
            .map_err(|_| anyhow::anyhow!("invalid historical record"))?;
        accept(value)?;
        count += 1;
    }
    ensure!(
        count == summary.records
            && format!("{:x}", hash.finalize()) == summary.sha256
            && stamp(&file)? == before,
        "history records differ from pinned manifest"
    );
    Ok(())
}

impl StoreSession<'_> {
    pub(in crate::store) fn recovered_import(
        &self,
        path: &Path,
        pin: &str,
        source: &str,
        target: &str,
        restore: Option<u64>,
    ) -> Result<Value> {
        identity(source)?;
        identity(target)?;
        digest(pin)?;
        self.state.authorize_node(
            self.identity.node.id(),
            &self.identity.node.public_key(),
            self.timestamp as u64,
        )?;
        let recipient = self.get_agent(target)?;
        ensure!(
            !recipient.revoked && recipient.node_id == self.identity.node.id(),
            "history recipient must be an active local chat"
        );
        let id = gent_crypto::scoped_id(
            b"gent/history-import/v1",
            &[
                self.config.cluster.id.as_bytes(),
                pin.as_bytes(),
                source.as_bytes(),
                target.as_bytes(),
            ],
        )
        .to_string();
        let previous: Option<(String,String,String,u64,bool)> = self.db.query_row(
            "SELECT digest,source_agent,target,revision,retired FROM recovered_sources WHERE id=?1",[&id],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let revision = if let Some((saved, original, agent, revision, retired)) = &previous {
            ensure!(
                saved == pin && original == source && agent == target,
                "conflicting history import identity"
            );
            match restore {
                None if !retired => {
                    return Ok(
                        json!({"import_id":id,"revision":revision,"duplicate":true,"retired":false}),
                    );
                }
                Some(expected)
                    if expected < MAX_REVISION && !retired && *revision == expected + 1 =>
                {
                    return Ok(
                        json!({"import_id":id,"revision":revision,"duplicate":true,"retired":false}),
                    );
                }
                Some(expected) if *retired && *revision == expected && expected < MAX_REVISION => {
                    expected + 1
                }
                _ => bail!(
                    "historical import was removed or access revision changed; explicit current restore revision required"
                ),
            }
        } else {
            ensure!(
                restore.is_none(),
                "cannot restore an unknown history import"
            );
            let count: u64 =
                self.db
                    .query_row("SELECT COUNT(*) FROM recovered_sources", [], |r| r.get(0))?;
            ensure!(count < MAX_SOURCES, "history import receipt limit reached");
            1
        };
        let root = directory(path)?;
        let mut manifest_file = open_file(&root, "history.json", 128 * 1024)?;
        let before = stamp(&manifest_file)?;
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut manifest_file)
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 128 * 1024
                && format!("{:x}", Sha256::digest(&bytes)) == pin
                && stamp(&manifest_file)? == before,
            "history manifest pin mismatch"
        );
        let manifest: Manifest = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid history manifest"))?;
        manifest.validate()?;
        ensure!(
            valid_lineage(&manifest.lineage, source),
            "invalid historical provenance lineage"
        );
        let files: File = openat(
            &root,
            "files",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
        private(&files.metadata()?, true)?;
        let mut agents = BTreeMap::new();
        records::<Agent>(&root, &manifest.agents, 4096, |agent| {
            identity(&agent.id)?;
            identity(&agent.node_id)?;
            config::label(&agent.name)?;
            config::label(&agent.provider)?;
            ensure!(
                agents.insert(agent.id.clone(), agent).is_none(),
                "duplicate historical chat"
            );
            Ok(())
        })?;
        let original = agents
            .get(source)
            .context("archived chat is absent from this history")?;
        let mut summary = json!({"archive_id":manifest.archive_id,"cluster_id":manifest.cluster_id,"node_id":manifest.node_id,
            "captured_at":manifest.captured_at,"database_sha256":manifest.database_sha256,
            "source_agent":original,"target_agent":target,"imported_at":self.timestamp,
            "provenance":"owner-supplied archive history; historical labels, not current identities or authority"});
        if !manifest.lineage.is_empty() {
            summary["lineage"] = serde_json::to_value(&manifest.lineage)?;
        }
        let encoded_summary = summary.to_string();
        let metadata: u64 = self.db.query_row(
            "SELECT COALESCE(SUM(length(CAST(summary AS BLOB))),0) FROM recovered_sources WHERE id<>?1",
            [&id], |r| r.get(0))?;
        ensure!(
            encoded_summary.len() <= gent_protocol::history::MAX_METADATA_BYTES
                && metadata.saturating_add(encoded_summary.len() as u64) <= MAX_METADATA_BYTES,
            "historical provenance metadata quota exceeded"
        );
        if previous.is_none() {
            self.db.execute(
                "INSERT INTO recovered_sources VALUES(?1,?2,?3,?4,?5,?6,0,0)",
                params![id, target, source, pin, encoded_summary, revision],
            )?;
        } else {
            self.db.execute(
                "UPDATE recovered_sources SET summary=?2,revision=?3,retired=0 WHERE id=?1",
                params![id, encoded_summary, revision],
            )?;
        }
        let used: u64 = self.db.query_row(
            "SELECT COALESCE(SUM(bytes),0) FROM recovered_sources",
            [],
            |r| r.get(0),
        )?;
        let existing: u64 =
            self.db
                .query_row("SELECT COUNT(*) FROM recovered_messages", [], |r| r.get(0))?;
        let mut budget = MAX_BYTES
            .checked_sub(used)
            .context("recovered history byte quota exceeded")?;
        let initial = budget;
        let mut selected = 0;
        let mut counts = Counts::default();
        let mut content = manifest
            .agents
            .bytes
            .checked_add(manifest.messages.bytes)
            .context("history size overflow")?;
        let mut message_ids = BTreeSet::new();
        records::<Record>(&root, &manifest.messages, 6 * 1024 * 1024, |mut record| {
            let message = &record.message;
            for field in [
                &message.id,
                &message.exchange_id,
                &message.sender,
                &message.recipient,
            ] {
                identity(field)?;
            }
            if let Some(reply) = &message.reply_to {
                identity(reply)?;
            }
            if let Some(relay) = &message.relay {
                for field in [&relay.attachment_id, &relay.turn_id]
                    .into_iter()
                    .chain(relay.grant_id.iter())
                {
                    identity(field)?;
                }
            }
            ensure!(
                message_ids.insert(message.id.clone()),
                "duplicate historical message"
            );
            ensure!(
                message.text.len() <= MAX_TEXT_BYTES
                    && message.files.len() + message.attachments.len() <= 128
                    && record.assets.len() == message.files.len() + message.attachments.len(),
                "historical message limits exceeded"
            );
            let sender = agents
                .get(&message.sender)
                .context("historical sender missing")?;
            let recipient = agents
                .get(&message.recipient)
                .context("historical recipient missing")?;
            ensure!(sender.id != recipient.id, "invalid historical participants");
            let keep = message.sender == source || message.recipient == source;
            let mut descriptors = Vec::new();
            let mut inline_bytes = 0;
            for (slot, asset) in record.assets.iter().enumerate() {
                let (name, mime, length, sha, path, status, original_id) = match asset {
                    Asset::Inline {
                        index,
                        status,
                        path,
                        name,
                        media_type,
                        byte_length,
                        sha256,
                    } => {
                        ensure!(
                            slot < message.files.len()
                                && *index == slot
                                && *status == Availability::Exported
                                && *path == format!("files/{}-inline-{index}", message.id),
                            "invalid historical inline reference"
                        );
                        let original = &message.files[*index];
                        let raw = Zeroizing::new(
                            STANDARD
                                .decode(&original.data_base64)
                                .map_err(|_| anyhow::anyhow!("invalid historical inline data"))?,
                        );
                        inline_bytes += raw.len();
                        ensure!(
                            inline_bytes <= MAX_FILE_BYTES
                                && original.name == *name
                                && original.media_type == *media_type
                                && raw.len() as u64 == *byte_length
                                && format!("{:x}", Sha256::digest(&raw)) == *sha256,
                            "historical inline descriptor mismatch"
                        );
                        (
                            name,
                            media_type,
                            *byte_length,
                            sha256,
                            Some(path),
                            *status,
                            None,
                        )
                    }
                    Asset::Attachment { file, status, path } => {
                        ensure!(
                            slot >= message.files.len()
                                && message.attachments.get(slot - message.files.len())
                                    == Some(file)
                                && file_objects::valid_id(&file.id),
                            "invalid historical attachment reference"
                        );
                        ensure!(
                            if *status == Availability::Exported {
                                path.as_deref() == Some(&format!("files/{}", file.id))
                            } else {
                                path.is_none()
                            },
                            "invalid historical attachment path"
                        );
                        (
                            &file.name,
                            &file.media_type,
                            file.byte_length,
                            &file.sha256,
                            path.as_ref(),
                            *status,
                            Some(&file.id),
                        )
                    }
                };
                gent_crypto::files::validate_metadata(name, mime)?;
                digest(sha)?;
                ensure!(
                    length <= file_objects::MAX_FILE_BYTES as u64,
                    "historical file exceeds 32 MiB"
                );
                match status {
                    Availability::Exported => {
                        counts.exported += 1;
                        content = content
                            .checked_add(length)
                            .context("history size overflow")?;
                    }
                    Availability::Missing => counts.missing += 1,
                    Availability::Incomplete => counts.incomplete += 1,
                }
                let state = match status {
                    Availability::Exported => "ready",
                    Availability::Missing => "missing",
                    Availability::Incomplete => "incomplete",
                };
                let descriptor = json!({"file_index":slot,"name":name,"media_type":mime,"byte_length":length,
                    "sha256":sha,"state":state,"original_file_id":original_id});
                if keep {
                    descriptors.push((descriptor, path.cloned()));
                }
            }
            if !keep {
                return Ok(());
            }
            ensure!(
                existing + selected < MAX_MESSAGES,
                "recovered message quota exceeded"
            );
            selected += 1;
            record.message.files.clear();
            record.message.attachments.clear();
            let normalized = json!({"message":record.message,"sender":sender,"recipient":recipient,
                "files":descriptors.iter().map(|(d,_)|d).collect::<Vec<_>>(),"historical":true});
            let payload = normalized.to_string();
            ensure!(
                payload.len() <= MAX_PAGE_BYTES,
                "historical message exceeds page limit"
            );
            consume(&mut budget, payload.len() as u64)?;
            self.db.execute(
                "INSERT INTO recovered_messages VALUES(?1,?2,?3,?4)",
                params![id, record.message.id, selected, payload],
            )?;
            for (slot, (descriptor, path)) in descriptors.iter().enumerate() {
                if let Some(path) = path {
                    self.recovered_copy_file(
                        &files,
                        (&id, &record.message.id, slot as u32),
                        descriptor,
                        path,
                        &mut budget,
                    )?;
                }
            }
            Ok(())
        })?;
        ensure!(
            counts == manifest.files && content == manifest.content_bytes,
            "history inventory totals differ"
        );
        self.db.execute(
            "UPDATE recovered_sources SET bytes=?2 WHERE id=?1",
            params![id, initial - budget],
        )?;
        Ok(
            json!({"import_id":id,"revision":revision,"duplicate":false,"retired":false,"messages":selected,"bytes":initial-budget,"origin":summary}),
        )
    }

    fn recovered_copy_file(
        &self,
        directory: &File,
        binding: (&str, &str, u32),
        descriptor: &Value,
        path: &str,
        budget: &mut u64,
    ) -> Result<()> {
        let (source, message, slot) = binding;
        let length = descriptor["byte_length"]
            .as_u64()
            .context("missing historical file length")?;
        consume(budget, length)?;
        let name = path
            .strip_prefix("files/")
            .context("invalid historical file path")?;
        let mut file = open_file(directory, name, length)?;
        ensure!(
            file.metadata()?.len() == length,
            "historical file size changed"
        );
        let before = stamp(&file)?;
        self.db.execute(
            "INSERT INTO recovered_files VALUES(?1,?2,?3,?4)",
            params![source, message, slot, descriptor.to_string()],
        )?;
        let mut hash = Sha256::new();
        let mut remaining = length;
        let mut buffer = Zeroizing::new(vec![0u8; CHUNK_BYTES]);
        for index in 0..length.div_ceil(CHUNK_BYTES as u64).max(1) {
            let size = remaining.min(CHUNK_BYTES as u64) as usize;
            file.read_exact(&mut buffer[..size])?;
            hash.update(&buffer[..size]);
            self.db.execute(
                "INSERT INTO recovered_chunks VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    source,
                    message,
                    slot,
                    index,
                    &buffer[..size],
                    format!("{:x}", Sha256::digest(&buffer[..size]))
                ],
            )?;
            remaining -= size as u64;
        }
        ensure!(
            format!("{:x}", hash.finalize()) == descriptor["sha256"] && stamp(&file)? == before,
            "historical file integrity changed"
        );
        Ok(())
    }
}

fn consume(remaining: &mut u64, bytes: u64) -> Result<()> {
    *remaining = remaining
        .checked_sub(bytes)
        .context("recovered history quota exceeds 256 MiB")?;
    Ok(())
}
