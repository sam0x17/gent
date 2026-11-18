//! Explicit node-owner intent and bounded scheduling for native host recovery.
//! The ordinary MCP watcher retains sole responsibility for input submission.
mod claude;
mod codex;
mod journal;
mod selection;

use super::Host;
use anyhow::{Context, Result, ensure};
use gent_daemon::config::{self, HostRecovery, MAX_RECOVERY_AGENTS, RecoveryAgent, RecoveryHost};
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
    /// Inspect a selected chat's native recovery readiness without starting it.
    Inspect {
        #[arg(value_name = "CHAT_ID")]
        agent: String,
    },
    /// Restore this native conversation for pending messages after a host outage.
    Enable {
        host: Host,
        thread_id: String,
        #[arg(long)]
        config_dir: Option<PathBuf>,
        #[arg(long)]
        host_binary: Option<PathBuf>,
    },
    /// Stop automatic startup/resume for this chat; leave loaded hosts running.
    Disable {
        #[arg(value_name = "CHAT_ID")]
        agent: String,
    },
}

fn hash(credential: &str) -> String {
    format!("{:x}", Sha256::digest(credential.as_bytes()))
}

pub(super) fn lock(home: &Path) -> Result<std::fs::File> {
    config::state_lock(home, "host-recovery.lock")
        .context("another host recovery operation is in progress; retry after it finishes")
}

pub(super) use journal::initialize as initialize_discovery;
pub(super) use lock as discovery_lock;

pub(super) async fn recover_discovered(
    home: &Path,
    agent: &str,
    entry: &RecoveryAgent,
) -> Result<&'static str> {
    let _lock = lock(home)?;
    let cfg = config::load(home)?;
    ensure!(cfg.discovery()?.enabled, "chat discovery is disabled");
    let mut validation = cfg.clone();
    let mut selected = HostRecovery::new(&cfg);
    selected.agents.insert(agent.into(), entry.clone());
    validation.set_host_recovery(selected)?;
    match entry.host {
        RecoveryHost::Codex => codex::recover(home, &cfg, agent, entry).await,
        RecoveryHost::ClaudeCode => claude::recover(home, &cfg, agent, entry).await,
    }
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
        Command::Inspect { agent } => {
            let _lock = lock(home)?;
            let cfg = config::load(home)?;
            let selected = selections(&cfg)?;
            let entry = selected
                .agents
                .get(&agent)
                .context("chat is not selected for recovery")?;
            let readiness = match entry.host {
                RecoveryHost::Codex => codex::inspect(home, &agent, entry).await?,
                RecoveryHost::ClaudeCode => serde_json::to_value(
                    crate::integration::runtime::claude_recovery::check(home, &agent, entry)
                        .await?,
                )?,
            };
            Ok(json!({"agent":agent,"host":entry.host,"inspection":readiness}))
        }
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
        } => selection::enable(home, host, thread_id, config_dir, host_binary).await,
    }
}

pub(super) async fn recover(
    home: &Path,
    agent_id: &str,
    expected: &RecoveryAgent,
) -> Result<&'static str> {
    let _lock = lock(home)?;
    let cfg = config::load(home)?;
    ensure!(
        selections(&cfg)?.agents.get(agent_id) == Some(expected),
        "host recovery selection changed"
    );
    match expected.host {
        RecoveryHost::Codex => codex::recover(home, &cfg, agent_id, expected).await,
        RecoveryHost::ClaudeCode => claude::recover(home, &cfg, agent_id, expected).await,
    }
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
