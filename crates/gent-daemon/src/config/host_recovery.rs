//! Node-local opt-in to restore selected native conversations. Never replicated.
use super::*;
use serde::{Deserialize, Serialize};

pub const MAX_RECOVERY_AGENTS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecovery {
    pub version: u8,
    pub cluster_id: String,
    pub node_id: String,
    pub agents: BTreeMap<String, CodexRecovery>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexRecovery {
    pub id: String,
    pub thread_id: String,
    pub config_dir: PathBuf,
    pub host_binary: PathBuf,
    pub credential_hash: String,
}

fn identifier(value: &str) -> Result<()> {
    let id = uuid::Uuid::parse_str(value)?;
    ensure!(
        !id.is_nil() && id.to_string() == value,
        "invalid host recovery identity"
    );
    Ok(())
}

impl HostRecovery {
    pub fn new(config: &Config) -> Self {
        Self {
            version: 1,
            cluster_id: config.cluster.id.clone(),
            node_id: config.node.id.clone(),
            agents: BTreeMap::new(),
        }
    }

    fn validate(&self, config: &Config) -> Result<()> {
        ensure!(
            self.version == 1
                && self.cluster_id == config.cluster.id
                && self.node_id == config.node.id
                && self.agents.len() <= MAX_RECOVERY_AGENTS,
            "host recovery belongs to another node, is unsupported or exceeds its limit"
        );
        let mut targets = std::collections::BTreeSet::new();
        for (agent, entry) in &self.agents {
            identifier(agent)?;
            identifier(&entry.id)?;
            identifier(&entry.thread_id)?;
            for path in [&entry.config_dir, &entry.host_binary] {
                ensure!(
                    path.is_absolute()
                        && path
                            .to_str()
                            .is_some_and(|s| !s.chars().any(char::is_control) && s.len() <= 4096),
                    "host recovery paths must be absolute UTF-8 paths without controls"
                );
            }
            ensure!(
                entry.credential_hash.len() == 64
                    && entry
                        .credential_hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid host recovery credential binding"
            );
            ensure!(
                targets.insert((&entry.config_dir, &entry.thread_id)),
                "host recovery has a duplicate conversation"
            );
        }
        Ok(())
    }
}

impl Config {
    pub fn host_recovery(&self) -> Result<Option<HostRecovery>> {
        self.extra
            .get("host_recovery")
            .cloned()
            .map(|value| {
                let saved: HostRecovery = value
                    .try_into()
                    .context("invalid host recovery configuration")?;
                saved.validate(self)?;
                Ok(saved)
            })
            .transpose()
    }

    pub fn set_host_recovery(&mut self, value: HostRecovery) -> Result<()> {
        value.validate(self)?;
        self.extra
            .insert("host_recovery".into(), toml::Value::try_from(value)?);
        self.update_local_version()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> CodexRecovery {
        CodexRecovery {
            id: uuid::Uuid::new_v4().to_string(),
            thread_id: uuid::Uuid::new_v4().to_string(),
            config_dir: "/private/codex".into(),
            host_binary: "/private/bin/codex".into(),
            credential_hash: "a".repeat(64),
        }
    }

    #[test]
    fn projections_preserve_enabled_and_removed_recovery_selections() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let original = initialize(root.path(), "local").unwrap();
        let agent = uuid::Uuid::new_v4().to_string();
        let mut selected = HostRecovery::new(&original);
        selected.agents.insert(agent.clone(), entry());
        edit_local(root.path(), |cfg| cfg.set_host_recovery(selected.clone())).unwrap();
        save(root.path(), &original).unwrap();
        let enabled = load(root.path()).unwrap();
        assert_eq!(enabled.version, 3);
        assert_eq!(enabled.host_recovery().unwrap(), Some(selected));
        edit_local(root.path(), |cfg| {
            let mut selected = cfg.host_recovery()?.unwrap();
            selected.agents.clear();
            cfg.set_host_recovery(selected)
        })
        .unwrap();
        save(root.path(), &enabled).unwrap();
        assert!(
            load(root.path())
                .unwrap()
                .host_recovery()
                .unwrap()
                .unwrap()
                .agents
                .is_empty()
        );
        let mut foreign = fresh("foreign").unwrap();
        foreign.extra = enabled.extra;
        foreign.version = 3;
        assert!(foreign.validate_local().is_err());
    }

    #[test]
    fn recovery_scope_paths_duplicates_and_feature_marker_are_validated() {
        let mut cfg = fresh("test").unwrap();
        let agent = uuid::Uuid::new_v4().to_string();
        let mut selected = HostRecovery::new(&cfg);
        selected.agents.insert(agent.clone(), entry());
        cfg.set_host_recovery(selected.clone()).unwrap();
        cfg.validate_local().unwrap();
        let mut downgrade = cfg.clone();
        downgrade.extra.remove("local_features");
        assert!(downgrade.validate_local().is_err());
        let mut changed = selected.clone();
        changed.agents.get_mut(&agent).unwrap().host_binary = "relative".into();
        assert!(cfg.set_host_recovery(changed).is_err());
        let mut changed = selected.clone();
        changed.agents.get_mut(&agent).unwrap().credential_hash = "X".repeat(64);
        assert!(cfg.set_host_recovery(changed).is_err());
        let mut changed = selected.clone();
        changed.agents.insert(
            uuid::Uuid::new_v4().to_string(),
            selected.agents[&agent].clone(),
        );
        assert!(cfg.set_host_recovery(changed).is_err());
        for _ in 0..MAX_RECOVERY_AGENTS {
            selected
                .agents
                .insert(uuid::Uuid::new_v4().to_string(), entry());
        }
        assert!(cfg.set_host_recovery(selected).is_err());
    }
}
