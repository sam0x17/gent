//! Claude eligibility is checked before spending the shared startup budget.
use super::*;
use crate::integration::{claude_binding, install, runtime::claude_recovery};

pub(super) async fn recover(
    home: &Path,
    cfg: &config::Config,
    agent_id: &str,
    entry: &RecoveryAgent,
) -> Result<&'static str> {
    install::claude_runtime_pinned(home, &entry.config_dir)?.require_wake()?;
    let credential = zeroize::Zeroizing::new(
        claude_binding::credential(home, cfg, &entry.thread_id)?
            .context("host recovery binding is unavailable")?,
    );
    ensure!(
        hash(&credential) == entry.credential_hash,
        "host recovery credential changed"
    );
    let pending = agent(home, &credential, AgentOp::WakePending).await?;
    ensure!(pending["agent"] == agent_id, "host recovery chat changed");
    if pending["pending"]
        .as_array()
        .context("invalid pending messages")?
        .is_empty()
    {
        return Ok("waiting");
    }
    use claude_recovery::Readiness;
    match claude_recovery::check(home, agent_id, entry)
        .await?
        .readiness
    {
        Readiness::Loaded => return Ok("already_loaded"),
        Readiness::NeedsOwner => return Ok("needs_owner"),
        Readiness::CleanHistory => {}
    }
    if !journal::claim(home, cfg, agent_id)? {
        return Ok("limited");
    }
    claude_recovery::restore(home, agent_id, entry).await
}
