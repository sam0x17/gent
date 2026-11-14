//! Activation boundary for offline recovery material. Marker contents are
//! informational; any directory entry at the marker path keeps state offline.
use anyhow::{Context, Result, bail};
use std::{fs, io::ErrorKind, path::Path};

pub const MARKER: &str = "recovery-required.json";
const OFFLINE: &str = "offline recovery directory: activating saved node or encryption state is unsupported; use a fresh directory and authenticated enrollment";

/// Refuse operational access before reading configuration, keys, or databases.
/// Check both supplied and resolved ancestors so nested profiles, missing child
/// directories, and filesystem aliases cannot accidentally bypass the guard.
/// This does not defend against the trusted OS user removing/copying markers.
pub fn ensure_active(home: &Path) -> Result<()> {
    let absolute = std::path::absolute(home)?;
    check_ancestors(&absolute)?;
    // A new node directory need not exist yet. Resolve its nearest existing
    // ancestor without creating anything or lexically collapsing `..` first.
    for ancestor in absolute.ancestors() {
        match fs::canonicalize(ancestor) {
            Ok(resolved) => return check_ancestors(&resolved),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("cannot check recovery directory"),
        }
    }
    bail!("cannot resolve recovery directory boundary")
}

fn check_ancestors(home: &Path) -> Result<()> {
    for ancestor in home.ancestors() {
        match fs::symlink_metadata(ancestor.join(MARKER)) {
            Ok(_) => bail!(OFFLINE),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("cannot check recovery guard"),
        }
    }
    Ok(())
}
