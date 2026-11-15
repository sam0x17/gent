//! Pin the native job's transcript and require no unfinished or retained work.

use super::*;
use crate::managed_file::{Snapshot, normalize};
use serde::Deserialize;
use std::path::Component;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Job {
    session_id: String,
    cwd: PathBuf,
    link_scan_path: PathBuf,
    in_flight: InFlight,
    children: Option<Vec<Value>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InFlight {
    tasks: u64,
    queued: u64,
    drainable_monitors: u64,
    kinds: Vec<String>,
}

pub(super) struct Evidence {
    job: Snapshot,
    history: history::Evidence,
}
impl Evidence {
    pub(super) fn verify(&self) -> Result<()> {
        self.job.verify()?;
        self.history.verify()
    }
}

fn read(directory: &Path, session: &str, cwd: &Path) -> Result<Evidence> {
    ensure!(
        crate::integration::wake::valid_thread(session),
        "invalid Claude recovery session"
    );
    let job = Snapshot::read(
        &directory
            .join("jobs")
            .join(&session[..8])
            .join("state.json"),
    )?;
    job.private()?;
    let text = job
        .text
        .as_deref()
        .context("native background job is unavailable")?;
    ensure!(
        text.len() <= 64 * 1024,
        "native job exceeds the recovery inspection limit"
    );
    let value: Job = serde_json::from_str(text)
        .map_err(|_| anyhow::anyhow!("unsupported native background job"))?;
    ensure!(
        value.session_id == session && value.cwd == cwd,
        "native background job scope changed"
    );
    ensure!(
        value.in_flight.tasks == 0
            && value.in_flight.queued == 0
            && value.in_flight.drainable_monitors == 0
            && value.in_flight.kinds.is_empty()
            && value.children.is_none_or(|children| children.is_empty()),
        "native background job retains unfinished work"
    );
    let path = &value.link_scan_path;
    ensure!(
        path.is_absolute() && !path.components().any(|c| matches!(c, Component::ParentDir)),
        "native history path is unsupported"
    );
    let path = normalize(path)?;
    let projects = normalize(&directory.join("projects"))?;
    ensure!(
        path.starts_with(&projects)
            && path.file_name().and_then(|p| p.to_str()) == Some(&format!("{session}.jsonl")),
        "native history path belongs to another profile or session"
    );
    let history = history::read(&path, session, cwd)?;
    let evidence = Evidence { job, history };
    evidence.verify()?;
    Ok(evidence)
}

pub(super) async fn inspect(directory: &Path, session: &str, cwd: &Path) -> Result<Evidence> {
    let (directory, session, cwd) = (directory.to_owned(), session.to_owned(), cwd.to_owned());
    tokio::task::spawn_blocking(move || read(&directory, &session, &cwd))
        .await
        .context("native history inspection stopped unexpectedly")?
}

#[cfg(test)]
mod tests;
