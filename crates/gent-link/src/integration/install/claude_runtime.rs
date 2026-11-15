//! Validate the exact managed profile before and after native inspection.

use super::*;

#[derive(PartialEq, Eq)]
pub(crate) struct ClaudeRuntime {
    pub directory: PathBuf,
    pub custom_directory: bool,
    spec: Spec,
    cluster_id: String,
    node_id: String,
}

pub(crate) fn claude_runtime_target(
    home: &Path,
    directory: Option<PathBuf>,
) -> Result<ClaudeRuntime> {
    let home = normalize(home)?;
    gent_daemon::recovery::ensure_active(&home)?;
    let cfg = config::load(&home)?;
    let layout = Layout::resolve(Host::ClaudeCode, directory)?;
    let (snapshot, state) = layout.read()?;
    state.owner(&home)?;
    ensure!(
        state.pending.is_none(),
        "Claude integration update is pending"
    );
    let spec = state
        .installed
        .as_ref()
        .context("Claude integration is not installed")?;
    if let Some(wake) = &spec.claude_wake {
        ensure!(
            wake.cluster_id == cfg.cluster.id && wake.node_id == cfg.node.id,
            "Claude wake node or cluster changed; reinstall the integration"
        );
    }
    for edit in layout.edits(Some(spec), Some(spec), false, true)? {
        edit.snapshot.verify()?;
    }
    snapshot.verify()?;
    Ok(ClaudeRuntime {
        custom_directory: layout.server == layout.directory.join(".claude.json"),
        directory: layout.directory,
        spec: spec.clone(),
        cluster_id: cfg.cluster.id,
        node_id: cfg.node.id,
    })
}
