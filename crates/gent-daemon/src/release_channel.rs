//! Read the last accepted channel with or without a running daemon.
use crate::{config, recovery, runtime};
use anyhow::{Result, ensure};
pub use gent_protocol::ReleaseChannel;
use rusqlite::{Connection, OpenFlags};
use std::{fs, io::ErrorKind, os::unix::fs::PermissionsExt, path::Path};

/// Reads a consistent signed snapshot without running migrations, repairing
/// configuration, or requiring an unexpired lease to read the last decision.
pub fn current(home: &Path) -> Result<ReleaseChannel> {
    recovery::ensure_active(home)?;
    let path = home.join("state.sqlite3");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            ensure!(
                !home.join(runtime::KEY_FILE).try_exists()?
                    && (!config::path(home).try_exists()?
                        || config::load_for_runtime(home)?.applied_revision.is_none()),
                "saved cluster authority is missing"
            );
            return Ok(ReleaseChannel::Stable);
        }
        Err(err) => return Err(err.into()),
    };
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
        "cluster database must be a private regular file"
    );
    let cfg = config::load_for_runtime(home)?;
    let identity = runtime::Identity::load(home, &cfg)?;
    let mut db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction()?;
    let state = identity.state(&tx)?;
    ensure!(
        state
            .state()
            .nodes
            .get(identity.node.id())
            .is_some_and(|n| n.signing_key == identity.node.public_key()),
        "local node is no longer enrolled"
    );
    Ok(state.state().release_channel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    #[test]
    fn stable_before_enrollment_without_initializing_or_repairing_a_home() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("node");
        assert_eq!(current(&home).unwrap(), ReleaseChannel::Stable);
        assert!(!home.exists());
        config::initialize(&home, "scratch").unwrap();
        assert_eq!(current(&home).unwrap(), ReleaseChannel::Stable);
        assert!(!home.join("state.sqlite3").exists());
        drop(Store::open(&home).unwrap());
        fs::remove_file(home.join("state.sqlite3")).unwrap();
        assert!(current(&home).is_err());
        assert!(!home.join("state.sqlite3").exists());
    }

    #[test]
    fn reject_unverified_channel_even_when_revision_and_local_config_match() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("node");
        config::initialize(&home, "scratch").unwrap();
        drop(Store::open(&home).unwrap());
        let db = Connection::open(home.join("state.sqlite3")).unwrap();
        db.execute("UPDATE authority SET state=CAST(json_set(state,'$.state.release_channel','beta') AS BLOB)", []).unwrap();
        assert!(current(&home).is_err());
    }
}
