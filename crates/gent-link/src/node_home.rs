//! Every CLI, service and MCP process uses the same node directory.
//! Explicit homes are retained for isolated development and installed services.
use crate::managed_file::{self, Snapshot};
use anyhow::{Context, Result, ensure};
use gent_daemon::config::{self, Config};
use std::path::{Path, PathBuf};
pub(crate) mod provision;
pub(crate) mod reset;

pub(crate) fn inspect(home: &Path) -> Result<Config> {
    gent_daemon::recovery::ensure_active(home)?;
    // Read-only checks: status and selection never create a missing directory.
    let metadata = std::fs::symlink_metadata(home).context("node directory is unavailable")?;
    use std::os::unix::fs::MetadataExt;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0,
        "node directory must be private and owned by this user"
    );
    let snapshot = Snapshot::read(&config::path(home))?;
    snapshot.private()?;
    let cfg: Config = toml::from_str(
        snapshot
            .text
            .as_deref()
            .context("node configuration is missing")?,
    )?;
    cfg.validate_local()?;
    snapshot.verify()?;
    Ok(cfg)
}

/// The old --cluster option is only an identity assertion, never a selector.
pub fn resolve(root: &Path, expected: Option<&str>) -> Result<PathBuf> {
    gent_daemon::recovery::ensure_active(root)?;
    let root = managed_file::normalize(root)?;
    reset::ensure_idle(&root)?;
    for marker in ["profile-setup.json", "auth/account-source.json"] {
        ensure!(
            !root.join(marker).try_exists()?,
            "legacy profile state found; run gent node reset, then re-enroll this machine"
        );
    }
    if Snapshot::read(&config::path(&root))?.text.is_none() {
        ensure!(
            expected.is_none(),
            "this node has no cluster; run gent cluster join CODE or gent cluster new NAME"
        );
        return Ok(root);
    }
    let cfg = inspect(&root)?;
    ensure!(
        cfg.contexts()?.is_none()
            && cfg.account_source()?.is_none()
            && cfg.profile_setup()?.is_none(),
        "legacy profile state found; run gent node reset, then re-enroll this machine"
    );
    ensure!(
        expected.is_none_or(|id| id == cfg.cluster.id || id == cfg.cluster.name),
        "this node belongs to cluster {}; a node can belong to only one cluster",
        cfg.cluster.name
    );
    Ok(root)
}

#[cfg(test)]
pub(crate) mod tests;
