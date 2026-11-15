//! Explicit node-owner intent for bounded native Codex startup and cold resume.
//! The ordinary MCP watcher retains sole responsibility for input submission.
mod journal;

use super::{Host, install, runtime, wake::Registry};
use anyhow::{Context, Result, ensure};
use gent_daemon::config::{self, CodexRecovery, HostRecovery, MAX_RECOVERY_AGENTS};
use gent_protocol::{AgentOp, Request};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(clap::Subcommand)]
pub enum Command {
    /// List node-local automatic recovery selections. Does not contact a host.
    List,
    /// Restore this Codex conversation for pending messages after a host outage.
    Enable {
        host: Host,
        thread_id: String,
        #[arg(long)]
        config_dir: Option<PathBuf>,
        #[arg(long, default_value = "codex")]
        host_binary: PathBuf,
    },
    /// Stop automatic startup/resume for this agent; leave loaded hosts running.
    Disable { agent: String },
}

fn hash(credential: &str) -> String {
    format!("{:x}", Sha256::digest(credential.as_bytes()))
}

fn binary(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() || path.components().count() > 1 {
        ensure!(path.is_file(), "Codex executable not found");
        return Ok(std::path::absolute(path)?);
    }
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let candidate = directory.join(path);
        if candidate.is_file() {
            return Ok(std::path::absolute(candidate)?);
        }
    }
    anyhow::bail!("Codex executable not found; use --host-binary")
}

fn lock(home: &Path) -> Result<std::fs::File> {
    config::state_lock(home, "host-recovery.lock")
        .context("another host recovery operation is in progress; retry after it finishes")
}

async fn agent(home: &Path, credential: &str, action: AgentOp) -> Result<Value> {
    gent_daemon::request(
        home,
        Request::Agent {
            credential: credential.into(),
            action,
        },
    )
    .await
}

fn selections(cfg: &config::Config) -> Result<HostRecovery> {
    Ok(cfg
        .host_recovery()?
        .unwrap_or_else(|| HostRecovery::new(cfg)))
}

pub(crate) async fn execute(home: &Path, command: Command) -> Result<Value> {
    match command {
        Command::List => {
            let cfg = config::load(home)?;
            Ok(
                json!({"recovery":selections(&cfg)?,"budget":journal::status(home,&cfg)?,
                "scope":"node-local","maximum_agents":MAX_RECOVERY_AGENTS}),
            )
        }
        Command::Disable { agent } => {
            let _lock = lock(home)?;
            let removed = config::edit_local(home, |cfg| {
                let Some(mut saved) = cfg.host_recovery()? else {
                    return Ok(false);
                };
                let removed = saved.agents.remove(&agent).is_some();
                cfg.set_host_recovery(saved)?;
                Ok(removed)
            })?;
            Ok(json!({"agent":agent,"enabled":false,"changed":removed}))
        }
        Command::Enable {
            host,
            thread_id,
            config_dir,
            host_binary,
        } => {
            ensure!(
                host == Host::Codex,
                "automatic cold recovery currently supports Codex"
            );
            let cfg = config::load(home)?;
            let (directory, socket) = install::codex_runtime_target(home, config_dir, true)?;
            let registry = Registry::codex(home, &socket)?;
            let credential = registry.credential(&thread_id)?.context(
                "use a Gent tool in this Codex conversation with --wake enabled before selecting recovery")?;
            let identity = agent(home, &credential, AgentOp::Identity).await?;
            ensure!(
                identity["cluster_id"] == cfg.cluster.id
                    && identity["agent"]["node_id"] == cfg.node.id,
                "host recovery requires a local registration in this cluster"
            );
            let id = identity["agent"]["id"]
                .as_str()
                .context("missing local agent identity")?
                .to_owned();
            ensure!(
                crate::wake::codex::recovery::inspect(&socket, &thread_id).await?
                    == crate::wake::codex::recovery::Readiness::Loaded,
                "load the selected conversation in Codex before enabling recovery"
            );
            let mut entry = CodexRecovery {
                id: uuid::Uuid::new_v4().to_string(),
                thread_id,
                config_dir: directory,
                host_binary: binary(&host_binary)?,
                credential_hash: hash(&credential),
            };
            let _lock = lock(home)?;
            let latest = config::load(home)?;
            ensure!(
                latest.cluster.id == cfg.cluster.id && latest.node.id == cfg.node.id,
                "node changed during host recovery setup"
            );
            journal::initialize(home, &latest)?;
            config::edit_local(home, |current| {
                ensure!(
                    current.cluster.id == cfg.cluster.id && current.node.id == cfg.node.id,
                    "node changed during host recovery setup"
                );
                let mut saved = selections(current)?;
                if let Some(old) = saved.agents.get(&id) {
                    let mut same = entry.clone();
                    same.id = old.id.clone();
                    if &same == old {
                        entry.id = old.id.clone();
                    }
                }
                saved.agents.insert(id.clone(), entry.clone());
                current.set_host_recovery(saved)
            })?;
            Ok(json!({"agent":id,"enabled":true,"selection":entry,
                "next":"The Gent daemon may start Codex and resume this conversation for unclaimed pending messages. Incomplete history or a retained native queue requires owner review."}))
        }
    }
}

async fn recover(home: &Path, agent_id: &str, expected: &CodexRecovery) -> Result<&'static str> {
    let _lock = lock(home)?;
    let cfg = config::load(home)?;
    ensure!(
        selections(&cfg)?.agents.get(agent_id) == Some(expected),
        "host recovery selection changed"
    );
    let (_, socket) = install::codex_runtime_target(home, Some(expected.config_dir.clone()), true)?;
    let registry = Registry::codex(home, &socket)?;
    let credential = registry
        .credential(&expected.thread_id)?
        .context("host recovery binding is unavailable")?;
    ensure!(
        hash(&credential) == expected.credential_hash,
        "host recovery credential changed"
    );
    let pending = agent(home, &credential, AgentOp::WakePending).await?;
    ensure!(pending["agent"] == agent_id, "host recovery agent changed");
    if pending["pending"]
        .as_array()
        .context("invalid pending messages")?
        .is_empty()
    {
        return Ok("waiting");
    }
    use crate::wake::codex::recovery::{Readiness, inspect, restore};
    match inspect(&socket, &expected.thread_id).await {
        Ok(Readiness::Loaded) => return Ok("already_loaded"),
        Ok(Readiness::NeedsOwner) => return Ok("needs_owner"),
        _ => {}
    }
    if !journal::claim(home, &cfg, agent_id)? {
        return Ok("limited");
    }
    runtime::start(
        home,
        runtime::Args {
            host: Host::Codex,
            config_dir: Some(expected.config_dir.clone()),
            host_binary: expected.host_binary.clone(),
        },
    )
    .await?;
    // Recheck the intact installation and current local credential after native
    // startup, before any conversation is loaded. Uninstall/opt-out must refuse.
    install::codex_runtime_target(home, Some(expected.config_dir.clone()), true)?;
    ensure!(
        registry.credential(&expected.thread_id)?.as_deref() == Some(&credential),
        "host recovery binding changed during startup"
    );
    let pending = agent(home, &credential, AgentOp::WakePending).await?;
    ensure!(pending["agent"] == agent_id, "host recovery agent changed");
    if pending["pending"]
        .as_array()
        .context("invalid pending messages")?
        .is_empty()
    {
        return Ok("waiting");
    }
    restore(&socket, &expected.thread_id).await
}

pub(crate) async fn maintain(home: &Path) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut cursor = 0usize;
    let mut notices = std::collections::BTreeMap::new();
    loop {
        interval.tick().await;
        let selected = config::load(home).and_then(|cfg| selections(&cfg));
        let selected = match selected {
            Ok(selected) => selected,
            Err(error) => {
                notice(&mut notices, "config", Some(error.to_string()));
                continue;
            }
        };
        notices.retain(|id, _| selected.agents.contains_key(id));
        let entries: Vec<_> = selected.agents.into_iter().collect();
        if entries.is_empty() {
            continue;
        }
        let start = cursor % entries.len();
        let count = entries.len().min(4);
        cursor = (start + count) % entries.len();
        // Advance before I/O so failed hosts cannot starve later selections.
        for offset in 0..count {
            let (id, entry) = &entries[(start + offset) % entries.len()];
            let result =
                tokio::time::timeout(Duration::from_secs(90), recover(home, id, entry)).await;
            let message = match result {
                Ok(Ok("needs_owner")) => {
                    Some("needs owner review: inspect the last turn and native queue".into())
                }
                Ok(Ok("limited")) => {
                    Some("automatic recovery is waiting for its retry budget".into())
                }
                Ok(Ok(_)) => None,
                Ok(Err(error)) => Some(error.to_string()),
                Err(_) => Some("automatic recovery timed out; inspect the native host".into()),
            };
            notice(&mut notices, id, message);
        }
    }
}

fn notice(
    notices: &mut std::collections::BTreeMap<String, String>,
    id: &str,
    message: Option<String>,
) {
    if let Some(message) = message {
        if notices.get(id) != Some(&message) {
            eprintln!("Gent host recovery {id}: {message}");
            notices.insert(id.into(), message);
        }
    } else {
        notices.remove(id);
    }
}
