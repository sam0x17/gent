//! A StopFailure observes one native transcript revision. Only the normalized
//! reason and opaque provenance leave this reader; prompts stay in Claude.
use crate::babysitter::fingerprint;
use anyhow::{Context, Result, ensure};
use gent_protocol::notifications::Failure;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::Path,
};
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub turn: Uuid,
    pub reason: Failure,
    pub failed_at: i64,
    pub source: Source,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    project: String,
    // Read from this goal attachment when replaying a saved observation.
    offset: u64,
    pub goal: String,
    witness: String,
}

fn project_id(path: &Path) -> Option<String> {
    Some(fingerprint(&[path.file_name()?.to_str()?]))
}

fn owned_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && crate::managed_file::owned_not_world_writable(&meta),
        "unexpected Claude project directory"
    );
    Ok(())
}

pub(super) fn capture(
    directory: &Path,
    session: &str,
    path: &Path,
    started_ms: i64,
    observed_ms: i64,
) -> Result<Option<Source>> {
    let root = directory.join("projects");
    owned_dir(&root)?;
    let project = path.parent().context("missing Claude project")?;
    owned_dir(project)?;
    ensure!(
        project.canonicalize()?.parent() == Some(root.canonicalize()?.as_path())
            && path.file_name().and_then(|v| v.to_str()) == Some(&format!("{session}.jsonl")),
        "unexpected Claude session transcript"
    );
    Ok(inspect(path, session, 0, Some((started_ms, observed_ms)), None)?.map(|(source, _)| source))
}

impl Record {
    /// Return the observed EOF only when the saved goal and input history still match.
    pub(super) fn current(
        &self,
        directory: &Path,
        session: &str,
        queued: Option<(u64, &str)>,
    ) -> Result<Option<u64>> {
        let root = directory.join("projects");
        owned_dir(&root)?;
        for entry in fs::read_dir(root)? {
            let project = entry?.path();
            if project_id(&project).as_ref() == Some(&self.source.project) {
                owned_dir(&project)?;
                let path = project.join(format!("{session}.jsonl"));
                return Ok(inspect(&path, session, self.source.offset, None, queued)?
                    .filter(|(source, _)| source == &self.source)
                    .map(|(_, end)| end));
            }
        }
        Ok(None)
    }
}

fn inspect(
    path: &Path,
    session: &str,
    start: u64,
    window: Option<(i64, i64)>,
    queued: Option<(u64, &str)>,
) -> Result<Option<(Source, u64)>> {
    let mut file = super::super::naming::open_metadata(path)?;
    let meta = file.metadata()?;
    if start >= meta.len() || queued.is_some_and(|(end, _)| end > meta.len()) {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(start))?;
    let mut input = BufReader::new((&file).take(meta.len() - start));
    let mut offset = start;
    let mut bytes = Vec::new();
    let mut goal = None;
    let mut terminal_failure = false;
    let mut witness = Sha256::new();
    let mut queue_ops = ["enqueue", "dequeue"].into_iter();
    while offset < meta.len() {
        bytes.clear();
        let count = (&mut input)
            .take(8 * 1024 * 1024 + 1)
            .read_until(b'\n', &mut bytes)?;
        ensure!(
            count <= 8 * 1024 * 1024 && bytes.last() == Some(&b'\n'),
            "incomplete Claude transcript record"
        );
        let at = offset;
        offset += count as u64;
        let row: Value =
            serde_json::from_slice(&bytes).context("invalid Claude transcript record")?;
        if row["isSidechain"] == true {
            continue;
        }
        let kind = row["type"].as_str().context("missing Claude record type")?;
        // Claude can record our own enqueue/dequeue before running UserPromptSubmit.
        // Only the retained guard, after a strict pre-enqueue check, permits this pair.
        if kind == "queue-operation"
            && let Some((end, prompt)) = queued
            && at >= end
        {
            if row["sessionId"] != session
                || row["timestamp"].as_str().is_none()
                || !row.as_object().is_some_and(|obj| {
                    obj.keys().all(|k| {
                        matches!(
                            k.as_str(),
                            "type" | "operation" | "timestamp" | "sessionId" | "content"
                        )
                    })
                })
                || row.get("content").is_some_and(|content| content != prompt)
                || !queue_ops
                    .next()
                    .is_some_and(|expected| row["operation"] == expected)
            {
                return Ok(None);
            }
            continue;
        }
        let attachment = &row["attachment"];
        if kind == "attachment" && attachment["type"] == "goal_status" {
            ensure!(
                row["sessionId"] == session,
                "goal belongs to another session"
            );
            goal = None;
            if attachment["met"] == false
                && attachment["failed"] != true
                && let Some(condition) = attachment["condition"].as_str().filter(|s| !s.is_empty())
            {
                goal = Some((at, fingerprint(&[session, condition])));
                witness = Sha256::new();
                witness.update(meta.dev().to_be_bytes());
                witness.update(meta.ino().to_be_bytes());
            }
        } else if (kind == "system" && row["subtype"] == "compact_boundary")
            || (kind == "last-prompt" && row["explicit"] == true)
        {
            // A selected transcript leaf can rewind past the failure or its goal.
            goal = None;
            continue;
        } else if !match kind {
            "user" | "queue-operation" | "api-request" => true,
            "assistant" => true,
            "system" => row["subtype"] == "local_command",
            _ => false,
        } {
            // Native StopFailure bookkeeping can arrive after the hook.
            continue;
        }
        if goal.is_some() {
            ensure!(
                row["sessionId"] == session,
                "turn belongs to another session"
            );
            terminal_failure = kind == "assistant" && row["isApiErrorMessage"] == true;
            if let Some((since, when)) = window {
                let at_ms = chrono::DateTime::parse_from_rfc3339(
                    row["timestamp"]
                        .as_str()
                        .context("missing Claude event timestamp")?,
                )?
                .timestamp_millis();
                if at_ms > when {
                    return Ok(None);
                }
                terminal_failure &= at_ms >= since;
            }
            witness.update(at.to_be_bytes());
            witness.update((count as u64).to_be_bytes());
            witness.update(&bytes);
        }
    }
    let current = fs::symlink_metadata(path)?;
    ensure!(
        (
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.ctime(),
            meta.ctime_nsec()
        ) == (
            current.dev(),
            current.ino(),
            current.len(),
            current.ctime(),
            current.ctime_nsec()
        ),
        "Claude transcript changed during inspection"
    );
    let project =
        project_id(path.parent().context("missing project")?).context("invalid project")?;
    Ok(goal.filter(|_| terminal_failure).map(|(offset, goal)| {
        (
            Source {
                project,
                offset,
                goal,
                witness: format!("{:x}", witness.finalize()),
            },
            meta.len(),
        )
    }))
}

#[cfg(test)]
mod tests;
