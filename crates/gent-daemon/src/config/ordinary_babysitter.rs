//! Node-local opt-in for continuing ordinary chats after provider errors.
use super::{load_for_runtime, state_lock, write_private};
use anyhow::{Result, ensure};
use std::{fs, io::ErrorKind, os::unix::fs::MetadataExt, path::Path};

const MARKER: &str = "babysitter-ordinary-enabled";

/// The saved node preference. The host also checks the chat's opt-out.
pub fn ordinary_babysitter_enabled(home: &Path) -> Result<bool> {
    match fs::symlink_metadata(home.join(MARKER)) {
        Ok(meta) => {
            ensure!(
                meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o077 == 0,
                "ordinary chat recovery marker must be a private regular file"
            );
            Ok(true)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub fn set_ordinary_babysitter_enabled(home: &Path, enabled: bool) -> Result<()> {
    load_for_runtime(home)?;
    let _lock = state_lock(home, "babysitter-ordinary.lock")?;
    if ordinary_babysitter_enabled(home)? != enabled {
        if enabled {
            write_private(&home.join(MARKER), b"enabled\n")?;
        } else {
            fs::remove_file(home.join(MARKER))?;
            fs::File::open(home)?.sync_all()?;
        }
    }
    Ok(())
}
