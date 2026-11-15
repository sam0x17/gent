//! Native Codex selection and recovery; input remains owned by the MCP watcher.
use super::*;
use crate::integration::{install, runtime, wake::Registry};

pub(super) async fn inspect(home: &Path, agent_id: &str, entry: &RecoveryAgent) -> Result<Value> {
    let (_, socket) = install::codex_runtime_target(home, Some(entry.config_dir.clone()), true)?;
    let credential = Registry::codex(home, &socket)?
        .credential(&entry.thread_id)?
        .context("host recovery binding is unavailable")?;
    ensure!(
        hash(&credential) == entry.credential_hash,
        "host recovery credential changed"
    );
    let identity = agent(home, &credential, AgentOp::Identity).await?;
    ensure!(
        identity["agent"]["id"] == agent_id,
        "host recovery agent changed"
    );
    use crate::wake::codex::recovery::{Readiness, inspect};
    let state = match inspect(&socket, &entry.thread_id).await? {
        Readiness::Loaded => "loaded",
        Readiness::IdleHistory => "clean_history",
        Readiness::NeedsOwner => "needs_owner",
    };
    Ok(json!({"readiness":state}))
}

pub(super) async fn select(
    home: &Path,
    cfg: &config::Config,
    thread_id: String,
    config_dir: Option<PathBuf>,
    host_binary: PathBuf,
) -> Result<(String, RecoveryAgent)> {
    let (directory, socket) = install::codex_runtime_target(home, config_dir, true)?;
    let registry = Registry::codex(home, &socket)?;
    let credential = registry.credential(&thread_id)?.context(
        "use a Gent tool in this Codex conversation with --wake enabled before selecting recovery",
    )?;
    let identity = agent(home, &credential, AgentOp::Identity).await?;
    ensure!(
        identity["cluster_id"] == cfg.cluster.id && identity["agent"]["node_id"] == cfg.node.id,
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
    let entry = RecoveryAgent {
        host: RecoveryHost::Codex,
        working_dir: None,
        id: uuid::Uuid::new_v4().to_string(),
        thread_id,
        config_dir: directory,
        host_binary,
        credential_hash: hash(&credential),
    };
    Ok((id, entry))
}

pub(super) async fn recover(
    home: &Path,
    cfg: &config::Config,
    agent_id: &str,
    expected: &RecoveryAgent,
) -> Result<&'static str> {
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
    if !journal::claim(home, cfg, agent_id)? {
        return Ok("limited");
    }
    runtime::start(
        home,
        runtime::Args {
            host: Host::Codex,
            session_id: None,
            config_dir: Some(expected.config_dir.clone()),
            host_binary: Some(expected.host_binary.clone()),
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
