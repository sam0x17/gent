//! Explicit bindings keep their cluster/node across context changes. The scope
//! is local metadata, not a credential and not a remote enrollment mechanism.
use crate::managed_file::Snapshot;
use anyhow::{Result, ensure};
use gent_daemon::config::Config;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    version: u32,
    cluster_id: String,
    node_id: String,
    credential_hash: String,
}

/// Caller holds the binding file's exclusive lock through pinning and use.
pub(super) fn pin(path: &Path, cfg: &Config, credential: &str, may_initialize: bool) -> Result<()> {
    let mut name = path.as_os_str().to_owned();
    name.push(".scope.json");
    let snapshot = Snapshot::read(&PathBuf::from(name))?;
    snapshot.private()?;
    let expected = Scope {
        version: 1,
        cluster_id: cfg.cluster.id.clone(),
        node_id: cfg.node.id.clone(),
        credential_hash: format!("{:x}", Sha256::digest(credential.as_bytes())),
    };
    if let Some(text) = &snapshot.text {
        let saved: Scope = serde_json::from_str(text)
            .map_err(|_| anyhow::anyhow!("invalid MCP binding scope; restore it from backup"))?;
        ensure!(
            saved == expected,
            "MCP binding belongs to another cluster, node or credential; reconnect using its original --home or --cluster"
        );
        snapshot.verify()?;
    } else {
        ensure!(
            may_initialize,
            "existing MCP binding needs an explicit --home or --cluster to pin its original identity once"
        );
        snapshot.write(&(serde_json::to_string(&expected)? + "\n"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gent_daemon::config;
    #[test]
    fn binding_scope_survives_reconnect_and_refuses_another_cluster_node_or_key() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("node");
        let cfg = config::initialize(&home, "binding").unwrap();
        let path = home.join("a.key");
        let credential = config::binding(&path).unwrap();
        assert!(pin(&path, &cfg, &credential, false).is_err());
        pin(&path, &cfg, &credential, true).unwrap();
        pin(&path, &cfg, &credential, false).unwrap();
        let mut other = cfg.clone();
        other.cluster.id = uuid::Uuid::new_v4().to_string();
        assert!(pin(&path, &other, &credential, true).is_err());
        other = cfg.clone();
        other.node.id = uuid::Uuid::new_v4().to_string();
        assert!(pin(&path, &other, &credential, true).is_err());
        assert!(pin(&path, &cfg, &config::secret(), true).is_err());
        pin(&path, &cfg, &credential, false).unwrap();
    }

    #[test]
    fn invalid_or_linked_binding_scope_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("node");
        let cfg = config::initialize(&home, "binding").unwrap();
        let path = home.join("a.key");
        let credential = config::binding(&path).unwrap();
        let scope = home.join("a.key.scope.json");
        config::write_private(&scope, b"invalid").unwrap();
        assert!(pin(&path, &cfg, &credential, true).is_err());
        assert_eq!(std::fs::read(&scope).unwrap(), b"invalid");
        std::fs::remove_file(&scope).unwrap();
        std::os::unix::fs::symlink(home.join("missing"), &scope).unwrap();
        assert!(pin(&path, &cfg, &credential, true).is_err());
        assert!(scope.symlink_metadata().unwrap().file_type().is_symlink());
    }
}
