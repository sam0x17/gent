//! Opt-in indexing and wake of native chats, without requiring a first MCP call.
mod activity;
mod bindings;
mod claude;
pub(super) mod hosts;
mod scheduler;
mod storage;
pub(crate) use scheduler::maintain;
#[cfg(test)]
mod tests;

use super::{Host, install};
use anyhow::{Context, Result, ensure};
use gent_daemon::config;
use gent_protocol::{AgentOp, Request};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use storage::Entry;

#[derive(clap::Subcommand)]
pub(crate) enum Command {
    /// Inspect local discovery settings, indexed chats and host limitations.
    Status,
    /// Publish supported native chats and permit waking them for incoming messages.
    Enable,
    /// Stop new discovery and automatic recovery; existing registrations remain.
    Disable,
    /// Refresh the inventory now without starting any model turns.
    Refresh,
}

fn enabled(home: &Path, expected: &config::Config) -> Result<()> {
    let cfg = config::load(home)?;
    ensure!(
        cfg.discovery()?.enabled
            && cfg.node.id == expected.node.id
            && cfg.cluster.id == expected.cluster.id,
        "chat discovery was disabled or the node changed"
    );
    Ok(())
}

async fn agent(home: &Path, key: &str, action: AgentOp) -> Result<Value> {
    gent_daemon::request(
        home,
        Request::Agent {
            credential: key.into(),
            action,
        },
    )
    .await
}

pub(crate) fn configure(home: &Path, value: bool) -> Result<()> {
    let cfg = config::load(home)?;
    if cfg.extra.contains_key("discovery") && cfg.discovery()?.enabled == value {
        return Ok(());
    }
    let _lock = super::recovery::discovery_lock(home)?;
    if value {
        super::recovery::initialize_discovery(home, &cfg)?;
    }
    config::edit_local(home, |cfg| {
        cfg.set_discovery(config::Discovery { enabled: value })
    })
}

pub(crate) async fn execute(home: &Path, command: Command) -> Result<Value> {
    match command {
        Command::Enable => {
            configure(home, true)?;
            let _progress = crate::ui::Progress::start("Discovering native chats");
            refresh(home).await?;
        }
        Command::Disable => configure(home, false)?,
        Command::Refresh => {
            let _progress = crate::ui::Progress::start("Refreshing native chats");
            refresh(home).await?;
        }
        Command::Status => {}
    }
    status(home)
}

fn status(home: &Path) -> Result<Value> {
    let cfg = config::load(home)?;
    let (_, catalog) = storage::read(home, &cfg)?;
    let enabled = cfg.discovery()?.enabled;
    let scanning = home.join("chat-discovery.lock").exists() && scan_lock(home)?.is_none();
    let scan = if !enabled {
        "disabled"
    } else if scanning {
        "running"
    } else if catalog.checked.is_none() {
        "pending"
    } else {
        "idle"
    };
    Ok(
        json!({"chat_discovery":true,"enabled":enabled,"checked_at":catalog.checked,"scan":scan,
        "hosts":catalog.hosts,"agents":catalog.entries.values().map(|entry| json!({
            "id":entry.agent,"name":entry.name,"host":entry.host,"native_id":entry.native,
            "automatic_recovery":entry.recovery.is_some()
        })).collect::<Vec<_>>(),
        "note":"Disabling stops indexing and discovery-driven recovery. Already published registrations and loaded native chats remain; use chat revoke or integration uninstall to remove their access."}),
    )
}

pub(crate) fn print(value: &Value) {
    crate::ui::heading("Chat discovery");
    crate::ui::field(
        "Enabled",
        if value["enabled"] == true {
            "yes"
        } else {
            "no"
        },
    );
    if let Some(agents) = value["agents"].as_array() {
        crate::ui::field("Indexed chats", &agents.len().to_string());
    }
    crate::ui::field(
        "Scan",
        match value["scan"].as_str() {
            Some("running") => "in progress; showing saved results",
            Some("pending") => "waiting for first scan",
            Some("disabled") => "disabled",
            _ => "idle; showing last results",
        },
    );
    if let Some(checked) = value["checked_at"].as_u64() {
        crate::ui::field(
            "Last check",
            &format!(
                "{}s ago",
                super::now().unwrap_or(checked).saturating_sub(checked)
            ),
        );
    }
    if let Some(hosts) = value["hosts"].as_object() {
        for (host, state) in hosts {
            crate::ui::field(host, state["status"].as_str().unwrap_or("unknown"));
            if let Some(error) = state["error"].as_str() {
                crate::ui::field("Details", error);
            }
        }
    }
    if value["enabled"] == true {
        println!(
            "  Indexed names sync to the cluster. Unavailable hosts are retried automatically."
        );
    } else {
        println!("  Enable with gent node discovery enable.");
    }
    println!("  Existing registrations remain when discovery is disabled.");
}

async fn register(
    home: &Path,
    cfg: &config::Config,
    host: Host,
    inventory: &hosts::Inventory,
    chat: &hosts::Chat,
) -> Result<Entry> {
    enabled(home, cfg)?;
    let credential = bindings::credential(home, cfg, host, &chat.id)?;
    let name = chat
        .name
        .clone()
        .unwrap_or_else(|| format!("{}-{}", host.name(), &chat.id[24..]));
    let identity = agent(
        home,
        &credential,
        AgentOp::Register {
            name,
            provider: host.name().into(),
        },
    )
    .await?;
    ensure!(
        identity["cluster_id"] == cfg.cluster.id && identity["agent"]["node_id"] == cfg.node.id,
        "discovered chat registration belongs to another node"
    );
    let id = identity["agent"]["id"]
        .as_str()
        .context("missing registered identity")?
        .to_owned();
    let name = identity["agent"]["name"]
        .as_str()
        .context("missing registered name")?
        .to_owned();
    enabled(home, cfg)?;
    if let Some(socket) = &inventory.socket {
        // Never redirect an already bound chat from its live native endpoint.
        bindings::remember(home, cfg, &chat.id, &credential, socket)?;
    }
    use sha2::{Digest, Sha256};
    let recovery = chat.recoverable.then(|| config::RecoveryAgent {
        host: match host {
            Host::Codex => config::RecoveryHost::Codex,
            Host::ClaudeCode => config::RecoveryHost::ClaudeCode,
        },
        id: uuid::Uuid::new_v4().to_string(),
        thread_id: chat.id.clone(),
        config_dir: inventory.directory.clone(),
        host_binary: inventory.binary.clone(),
        credential_hash: format!("{:x}", Sha256::digest(credential.as_bytes())),
        working_dir: chat.working_dir.clone(),
    });
    Ok(Entry {
        agent: id,
        host,
        native: chat.id.clone(),
        name,
        last_activity_at: None,
        last_native_message_at: None,
        endpoint: inventory.socket.clone(),
        recovery,
    })
}

fn scan_lock(home: &Path) -> Result<Option<std::fs::File>> {
    match config::state_lock(home, "chat-discovery.lock") {
        Ok(lock) => Ok(Some(lock)),
        Err(error)
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
            }) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

async fn refresh(home: &Path) -> Result<()> {
    let Some(_lock) = scan_lock(home)? else {
        return Ok(());
    };
    let cfg = config::load(home)?;
    enabled(home, &cfg)?;
    {
        let _recovery_lock = super::recovery::discovery_lock(home)?;
        super::recovery::initialize_discovery(home, &cfg)?;
    }
    let (saved, mut catalog) = storage::read(home, &cfg)?;
    for host in [Host::Codex, Host::ClaudeCode] {
        let result = tokio::time::timeout(Duration::from_secs(45), async {
            match host {
                Host::Codex => hosts::codex(home, catalog.hosts.get(host.name())).await,
                Host::ClaudeCode => hosts::claude(home).await,
            }
        })
        .await
        .unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "native inventory timed out; the next scan retries"
            ))
        });
        match result {
            Ok(inventory) => {
                let mut failures = 0;
                let mut indexed = 0;
                let mut error = None;
                let mut added = 0;
                let count = inventory.chats.len();
                let start = catalog
                    .hosts
                    .get(host.name())
                    .and_then(|state| state["cursor"].as_u64())
                    .unwrap_or(0) as usize
                    % count.max(1);
                let mut next = 0;
                for offset in 0..count {
                    let index = (start + offset) % count;
                    let chat = &inventory.chats[index];
                    enabled(home, &cfg)?;
                    let key = storage::key(host, &chat.id);
                    if catalog.entries.len() >= storage::LIMIT
                        && !catalog.entries.contains_key(&key)
                    {
                        break;
                    }
                    if let Some(entry) = catalog.entries.get_mut(&key) {
                        match observe_activity(home, entry, chat).await {
                            Ok(()) => indexed += 1,
                            Err(e) => {
                                failures += 1;
                                error = Some(e.to_string());
                            }
                        }
                        continue;
                    }
                    if added >= 32 {
                        next = index;
                        break;
                    }
                    added += 1;
                    match register(home, &cfg, host, &inventory, chat).await {
                        Ok(mut entry) => {
                            if let Err(e) = observe_activity(home, &mut entry, chat).await {
                                failures += 1;
                                error = Some(e.to_string());
                            }
                            catalog.entries.insert(key, entry);
                            indexed += 1;
                        }
                        Err(e) => {
                            failures += 1;
                            error = Some(e.to_string());
                        }
                    }
                }
                let truncated = inventory.truncated || indexed + failures < inventory.chats.len();
                let more = inventory
                    .page
                    .as_ref()
                    .is_some_and(|page| page.next.is_some());
                let count = catalog
                    .entries
                    .values()
                    .filter(|entry| entry.host == host)
                    .count();
                catalog.hosts.insert(host.name().into(), json!({"status":if failures > 0 || truncated { "partial" } else if more { "scanning" } else { "indexed" },"count":count,"failed":failures,"truncated":truncated,"cursor":next,"error":error,
                    "next_page":inventory.page.and_then(|page| page.next),
                    "scope":if host == Host::Codex { "native interactive history, including archived chats; wake requires a supported shared server" } else { "local session titles and native background chats; closed interactive sessions require manual reopening" }}));
            }
            Err(error) => {
                let previous = catalog
                    .hosts
                    .entry(host.name().into())
                    .or_insert_with(|| json!({}));
                record_failure(previous, &error.to_string());
            }
        }
    }
    enabled(home, &cfg)?;
    catalog.checked = Some(super::now()?);
    storage::save(&saved, &catalog)
}

fn record_failure(previous: &mut Value, error: &str) {
    // Preserve the continuation across a failed read. After three failures,
    // restart the read-only scan in case the host expired its cursor.
    if !previous.is_object() {
        *previous = json!({});
    }
    let failures = previous["consecutive_failures"]
        .as_u64()
        .unwrap_or(0)
        .saturating_add(1);
    previous["status"] = json!("unavailable");
    previous["error"] = json!(error);
    previous["consecutive_failures"] = json!(failures);
    if failures >= 3 {
        previous["next_page"] = Value::Null;
    }
}

async fn observe_activity(home: &Path, entry: &mut Entry, chat: &hosts::Chat) -> Result<()> {
    let activity = chat
        .last_activity_at
        .filter(|v| Some(*v) > entry.last_activity_at);
    let native = chat
        .last_native_message_at
        .filter(|v| Some(*v) > entry.last_native_message_at);
    if let Some(timestamp) = activity.or(native) {
        crate::owner(
            home,
            gent_protocol::OwnerOp::ObserveActivity {
                agent_id: entry.agent.clone(),
                last_activity_at: timestamp,
                last_native_message_at: native,
            },
        )
        .await?;
        entry.last_activity_at = entry.last_activity_at.max(activity);
        entry.last_native_message_at = entry.last_native_message_at.max(native);
    }
    Ok(())
}
