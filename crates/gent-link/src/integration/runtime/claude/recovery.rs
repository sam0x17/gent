//! Selection and eligibility checks for the daemon's existing recovery scheduler.

use super::*;
use gent_daemon::config::{RecoveryAgent, RecoveryHost};
use gent_protocol::{AgentOp, Request};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(in crate::integration) struct Selection {
    pub directory: PathBuf,
    pub working_dir: PathBuf,
    pub agent: String,
    pub credential: Zeroizing<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::integration) enum Readiness {
    Loaded,
    CleanHistory,
    NeedsOwner,
}

#[derive(Serialize)]
pub(in crate::integration) struct Inspection {
    pub readiness: Readiness,
    pub reason: Option<String>,
}

pub(in crate::integration) async fn select(
    home: &Path,
    directory: Option<PathBuf>,
    binary: &Path,
    session: &str,
) -> Result<Selection> {
    let target = start::target(home, directory).await?;
    let bound = start::binding(home, session).await?;
    let row = start::select(inspect(binary, &target).await?, session)?;
    ensure!(
        row.pid.is_some(),
        "load this native Claude background chat before enabling recovery"
    );
    ensure!(
        start::pinned(home, &target.directory).await? == target
            && start::binding(home, session).await? == bound,
        "Claude installation or binding changed during selection"
    );
    Ok(Selection {
        directory: target.directory,
        working_dir: row.cwd,
        agent: bound.agent,
        credential: bound.credential,
    })
}

pub(super) fn authorize(
    entry: &RecoveryAgent,
    agent: &str,
    bound: &start::Binding,
    row: &sessions::Session,
) -> Result<()> {
    ensure!(
        entry.host == RecoveryHost::ClaudeCode
            && bound.agent == agent
            && format!("{:x}", Sha256::digest(bound.credential.as_bytes()))
                == entry.credential_hash
            && entry.working_dir.as_ref() == Some(&row.cwd)
            && row.session_id.as_deref() == Some(&entry.thread_id),
        "selected Claude chat, binding or working directory changed"
    );
    Ok(())
}

pub(super) async fn pending(home: &Path, bound: &start::Binding) -> Result<bool> {
    let value = tokio::time::timeout(
        Duration::from_secs(5),
        gent_daemon::request(
            home,
            Request::Agent {
                credential: bound.credential.to_string(),
                action: AgentOp::WakePending,
            },
        ),
    )
    .await
    .context("Gent pending-work inspection timed out")??;
    ensure!(
        value["agent"] == bound.agent,
        "Claude pending-work identity changed"
    );
    Ok(!value["pending"]
        .as_array()
        .context("invalid Claude pending-work response")?
        .is_empty())
}

pub(in crate::integration) async fn check(
    home: &Path,
    agent: &str,
    entry: &RecoveryAgent,
) -> Result<Inspection> {
    let target = start::pinned(home, &entry.config_dir).await?;
    let bound = start::binding(home, &entry.thread_id).await?;
    let row = start::select(
        inspect(&entry.host_binary, &target).await?,
        &entry.thread_id,
    )?;
    authorize(entry, agent, &bound, &row)?;
    let result = if row.pid.is_some() {
        Inspection {
            readiness: Readiness::Loaded,
            reason: None,
        }
    } else {
        match eligibility::inspect(&target.directory, &entry.thread_id, &row.cwd).await {
            Ok(evidence) => {
                evidence.verify()?;
                Inspection {
                    readiness: Readiness::CleanHistory,
                    reason: None,
                }
            }
            Err(error) => Inspection {
                readiness: Readiness::NeedsOwner,
                reason: Some(format!("{error:#}")),
            },
        }
    };
    ensure!(
        start::pinned(home, &entry.config_dir).await? == target
            && start::binding(home, &entry.thread_id).await? == bound,
        "Claude installation or binding changed during recovery inspection"
    );
    Ok(result)
}

pub(in crate::integration) async fn restore(
    home: &Path,
    agent: &str,
    entry: &RecoveryAgent,
) -> Result<&'static str> {
    let value = start::automatic(
        home,
        super::super::Args {
            host: Host::ClaudeCode,
            session_id: Some(entry.thread_id.clone()),
            config_dir: Some(entry.config_dir.clone()),
            host_binary: Some(entry.host_binary.clone()),
        },
        entry,
        agent,
    )
    .await?;
    match value["action"].as_str() {
        Some("already_running") => Ok("already_loaded"),
        Some("attached") => Ok("resumed"),
        Some("needs_owner") => Ok("needs_owner"),
        Some("waiting") => Ok("waiting"),
        _ => anyhow::bail!("unexpected automatic Claude recovery result"),
    }
}
