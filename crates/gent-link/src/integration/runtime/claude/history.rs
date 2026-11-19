//! Conservative cold-recovery evidence from a stable native JSONL transcript.
//! No transcript text is returned or written into Gent's configuration or logs.

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    fs::{self, Metadata, OpenOptions},
    io::{BufRead, BufReader, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

mod graph;

const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LINE: usize = 8 * 1024 * 1024;
const MAX_RECORDS: usize = 200_000;

#[derive(PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn stamp(meta: &Metadata) -> Result<Stamp> {
    ensure!(
        meta.is_file() && meta.nlink() == 1 && crate::managed_file::owned_not_world_writable(meta),
        "native history must be an owned regular file without links or world write access"
    );
    ensure!(
        meta.len() <= MAX_BYTES,
        "native history exceeds the recovery inspection limit"
    );
    Ok(Stamp {
        device: meta.dev(),
        inode: meta.ino(),
        size: meta.len(),
        mode: meta.mode(),
        modified: (meta.mtime(), meta.mtime_nsec()),
        changed: (meta.ctime(), meta.ctime_nsec()),
    })
}

pub(super) struct Evidence {
    path: PathBuf,
    stamp: Stamp,
}
impl Evidence {
    pub(super) fn verify(&self) -> Result<()> {
        ensure!(
            stamp(&fs::symlink_metadata(&self.path)?)? == self.stamp,
            "native history changed during recovery inspection"
        );
        Ok(())
    }
}

fn uuid(value: &str) -> bool {
    crate::integration::wake::valid_thread(value)
}

fn inspect(mut input: impl BufRead, session: &str, cwd: &Path) -> Result<()> {
    ensure!(uuid(session), "invalid native history session");
    let mut graph = graph::Graph::default();
    let mut durations = Vec::new();
    let mut last_request = 0;
    let mut queued = 0usize;
    let mut bytes = Vec::new();
    let mut total = 0u64;
    let mut records = 0usize;
    loop {
        bytes.clear();
        (&mut input)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut bytes)?;
        if bytes.is_empty() {
            break;
        }
        total += bytes.len() as u64;
        records += 1;
        ensure!(
            total <= MAX_BYTES && bytes.len() <= MAX_LINE && records <= MAX_RECORDS,
            "native history exceeds the recovery inspection limit"
        );
        ensure!(
            bytes.last() == Some(&b'\n'),
            "native history has an incomplete record"
        );
        let row: Value = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid native history record"))?;
        let kind = row["type"]
            .as_str()
            .context("native history record has no type")?;
        if let Some(id) = row.get("sessionId") {
            ensure!(id == session, "native history contains another session");
        }
        ensure!(
            row["isSidechain"].is_null() || row["isSidechain"] == false,
            "native history contains an unsupported sidechain"
        );
        let id = row
            .get("uuid")
            .map(|id| {
                id.as_str()
                    .filter(|id| uuid(id))
                    .context("invalid native history identity")
            })
            .transpose()?;
        let parent = match row.get("parentUuid") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .filter(|id| uuid(id))
                    .context("invalid native history parent")?,
            ),
        };
        let mut completion = None;
        match kind {
            "queue-operation" => {
                ensure!(
                    row["sessionId"] == session,
                    "native queue has no session identity"
                );
                match row["operation"].as_str() {
                    Some("enqueue") => {
                        ensure!(
                            row["content"].as_str().is_some_and(|s| !s.is_empty()),
                            "native queue entry is unsupported"
                        );
                        queued += 1;
                    }
                    Some("dequeue") if queued > 0 => queued -= 1,
                    _ => anyhow::bail!("native queue operation is unsupported or unmatched"),
                }
            }
            "api-request" => {
                last_request = records;
            }
            "user" | "assistant" => {
                ensure!(
                    row["sessionId"] == session && row["cwd"].as_str() == cwd.to_str(),
                    "native conversation scope changed"
                );
                ensure!(id.is_some(), "native message has no identity");
                let ended = kind == "assistant"
                    && row["message"]["stop_reason"] == "end_turn"
                    && row["message"]["role"] == "assistant"
                    && (row["isApiErrorMessage"].is_null() || row["isApiErrorMessage"] == false);
                completion = Some(ended);
            }
            "system" if row["subtype"] == "turn_duration" => {
                durations.push((parent.map(str::to_owned), records));
            }
            "system" if row["subtype"] == "compact_boundary" => {
                anyhow::bail!("compacted native history requires owner review");
            }
            "mode"
            | "permission-mode"
            | "atis-latch"
            | "tools-used"
            | "file-history-snapshot"
            | "attachment"
            | "api-request-shape"
            | "api-request-blob"
            | "cost-state"
            | "last-prompt"
            | "ai-title"
            | "agent-name" => {}
            _ => anyhow::bail!("unsupported native history record requires owner review"),
        }
        if let Some(id) = id {
            graph.add(id, parent, completion, records)?;
        }
    }
    ensure!(queued == 0, "native history retains unmatched queued input");
    graph.completed(&durations, last_request)
}

pub(super) fn read(path: &Path, session: &str, cwd: &Path) -> Result<Evidence> {
    let expected = stamp(&fs::symlink_metadata(path)?)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    ensure!(
        stamp(&file.metadata()?)? == expected,
        "native history changed before inspection"
    );
    inspect(BufReader::new(&file), session, cwd)?;
    ensure!(
        stamp(&file.metadata()?)? == expected,
        "native history changed during inspection"
    );
    let evidence = Evidence {
        path: path.into(),
        stamp: expected,
    };
    evidence.verify()?;
    Ok(evidence)
}

#[cfg(test)]
mod tests;
