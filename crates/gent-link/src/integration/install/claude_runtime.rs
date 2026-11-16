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

impl ClaudeRuntime {
    pub(crate) fn require_wake(&self) -> Result<()> {
        ensure!(
            self.spec
                .claude_wake
                .as_ref()
                .is_some_and(|wake| wake.version == 3 && wake.module == claude_wake::MODULE),
            "install current Claude queued delivery with gent integration install claude-code --wake"
        );
        Ok(())
    }
}

pub(crate) fn claude_runtime_target(
    home: &Path,
    directory: Option<PathBuf>,
) -> Result<ClaudeRuntime> {
    validate(home, Layout::resolve(Host::ClaudeCode, directory)?)
}

/// Recover the recorded layout without consulting a daemon's ambient profile.
pub(crate) fn claude_runtime_pinned(home: &Path, directory: &Path) -> Result<ClaudeRuntime> {
    let layout = Layout::resolve(Host::ClaudeCode, Some(directory.into()))?;
    let snapshot = Snapshot::read(&layout.record())?;
    snapshot.private()?;
    let state: State = serde_json::from_str(
        snapshot
            .text
            .as_deref()
            .context("Claude integration is not installed")?,
    )
    .map_err(|_| anyhow::anyhow!("invalid Claude installation record"))?;
    state.owner(&normalize(home)?, false)?;
    let default_server = layout
        .directory
        .parent()
        .map(|parent| parent.join(".claude.json"));
    ensure!(
        state.server == layout.server
            || (layout
                .directory
                .file_name()
                .is_some_and(|name| name == ".claude")
                && Some(&state.server) == default_server.as_ref()),
        "Claude installation has an unsupported profile layout"
    );
    let target = validate(
        home,
        Layout::at(Host::ClaudeCode, layout.directory, state.server)?,
    )?;
    snapshot.verify()?;
    Ok(target)
}

fn validate(home: &Path, layout: Layout) -> Result<ClaudeRuntime> {
    let home = normalize(home)?;
    gent_daemon::recovery::ensure_active(&home)?;
    let cfg = config::load(&home)?;
    let (snapshot, state) = layout.read()?;
    state.owner(&home, false)?;
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
