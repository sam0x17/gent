//! Reuse dependency artifacts while invalidating Gent's Git/path packages.
use anyhow::{Result, ensure};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};
use tokio::fs;

const SHARED: &str = "shared";

async fn directory(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir(),
                "update cache directory must not be a link or file: {}",
                path.display()
            );
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Called under the installation's update lock. Adopt the installed release's
/// old cache once, then reuse it across revisions. Cargo still checks dependency
/// versions, compiler versions, targets and flags itself.
pub(super) async fn prepare(cache: &Path, installed: &str) -> Result<PathBuf> {
    fs::create_dir_all(cache).await?;
    let shared = cache.join(SHARED);
    if !directory(&shared).await? {
        let legacy = cache.join(installed);
        if crate::build_info::valid_commit(installed) && directory(&legacy).await? {
            fs::rename(legacy, &shared).await?;
        } else {
            fs::create_dir(&shared).await?;
        }
    }
    invalidate(&shared.join("release")).await?;
    // CARGO_BUILD_TARGET places target artifacts below a triple, while host
    // build scripts and proc macros remain directly below the shared directory.
    let mut entries = fs::read_dir(&shared).await?;
    while let Some(entry) = entries.next_entry().await? {
        if entry.file_type().await?.is_dir() {
            invalidate(&entry.path().join("release")).await?;
        }
    }
    Ok(shared)
}

async fn invalidate(profile: &Path) -> Result<()> {
    if !directory(profile).await? {
        return Ok(());
    }
    // Older Cargo uses .fingerprint/package-hash; newer Cargo puts each
    // package's fingerprints and intermediates under build/package/hash.
    for name in [".fingerprint", "build"] {
        let directory_path = profile.join(name);
        if !directory(&directory_path).await? {
            continue;
        }
        let mut entries = fs::read_dir(directory_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            // All Gent workspace packages use the gent- prefix. Cargo can
            // otherwise consider path dependencies fresh across Git checkouts
            // with matching timestamps. Always invalidate our crates and build
            // scripts, including after an interrupted update.
            if entry.file_name().to_string_lossy().starts_with("gent-") {
                if entry.file_type().await?.is_dir() {
                    fs::remove_dir_all(entry.path()).await?;
                } else {
                    fs::remove_file(entry.path()).await?;
                }
            }
        }
    }
    Ok(())
}
