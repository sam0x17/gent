//! Durable recovery attempt limits. Restarting Gent does not reset the budget.
use super::*;
use crate::managed_file::Snapshot;

const NODE_HOURLY: usize = 24;
const AGENT_HOURLY: usize = 6;
const RETRY_SECONDS: u64 = 60;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    version: u8,
    cluster_id: String,
    node_id: String,
    attempts: Vec<Attempt>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    agent: String,
    at: u64,
}

impl Journal {
    fn new(cfg: &config::Config) -> Self {
        Self {
            version: 1,
            cluster_id: cfg.cluster.id.clone(),
            node_id: cfg.node.id.clone(),
            attempts: Vec::new(),
        }
    }
    fn admit(&mut self, agent: &str, now: u64) -> bool {
        self.attempts.retain(|a| a.at.saturating_add(3600) > now);
        let own: Vec<_> = self.attempts.iter().filter(|a| a.agent == agent).collect();
        if self.attempts.len() >= NODE_HOURLY
            || own.len() >= AGENT_HOURLY
            || own.iter().any(|a| a.at.saturating_add(RETRY_SECONDS) > now)
        {
            return false;
        }
        self.attempts.push(Attempt {
            agent: agent.into(),
            at: now,
        });
        true
    }
}

fn read(home: &Path, cfg: &config::Config, create: bool) -> Result<(Snapshot, Journal)> {
    let path = home.join("host-recovery-budget.json");
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        ensure!(
            meta.len() <= 16 * 1024,
            "host recovery journal is too large"
        );
    }
    let saved = Snapshot::read(&path)?;
    saved.private()?;
    let journal = match &saved.text {
        Some(text) => {
            serde_json::from_str::<Journal>(text).context("invalid host recovery journal")?
        }
        None if create
            && cfg.host_recovery()?.is_none()
            && !home.join("chat-discovery.json").exists() =>
        {
            Journal::new(cfg)
        }
        None => anyhow::bail!("host recovery journal is missing; restore this node's state"),
    };
    ensure!(
        journal.version == 1
            && journal.cluster_id == cfg.cluster.id
            && journal.node_id == cfg.node.id
            && journal.attempts.len() <= NODE_HOURLY,
        "host recovery journal scope changed"
    );
    for attempt in &journal.attempts {
        ensure!(
            uuid::Uuid::parse_str(&attempt.agent)
                .is_ok_and(|id| !id.is_nil() && id.to_string() == attempt.agent),
            "invalid host recovery budget identity"
        );
    }
    Ok((saved, journal))
}

pub(in crate::integration) fn initialize(home: &Path, cfg: &config::Config) -> Result<()> {
    let (saved, journal) = read(home, cfg, true)?;
    if saved.text.is_none() {
        saved.write(&(serde_json::to_string(&journal)? + "\n"))?;
    }
    Ok(())
}

pub(super) fn status(home: &Path, cfg: &config::Config) -> Result<Value> {
    if cfg.host_recovery()?.is_none() {
        return Ok(Value::Null);
    }
    let (_, journal) = read(home, cfg, false)?;
    Ok(
        json!({"attempts":journal.attempts,"node_hourly_limit":NODE_HOURLY,
        "agent_hourly_limit":AGENT_HOURLY,"retry_seconds":RETRY_SECONDS}),
    )
}

pub(super) fn claim(home: &Path, cfg: &config::Config, agent: &str) -> Result<bool> {
    let (saved, mut journal) = read(home, cfg, false)?;
    if !journal.admit(agent, super::super::now()?) {
        return Ok(false);
    }
    saved.write(&(serde_json::to_string(&journal)? + "\n"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn budgets_survive_serialization_and_clock_rollback() {
        let cfg = config::fresh("test").unwrap();
        let mut journal = Journal::new(&cfg);
        let agent = uuid::Uuid::new_v4().to_string();
        assert!(journal.admit(&agent, 100));
        let mut journal: Journal =
            serde_json::from_str(&serde_json::to_string(&journal).unwrap()).unwrap();
        assert!(!journal.admit(&agent, 99));
        assert!(!journal.admit(&agent, 159));
        for at in [160, 220, 280, 340, 400] {
            assert!(journal.admit(&agent, at));
        }
        assert!(!journal.admit(&agent, 500));
        for _ in 0..18 {
            assert!(journal.admit(&uuid::Uuid::new_v4().to_string(), 500));
        }
        assert!(!journal.admit(&uuid::Uuid::new_v4().to_string(), 500));
        assert!(journal.admit(&agent, 3700));
    }

    #[test]
    fn missing_or_corrupt_budget_cannot_reset_an_enabled_nodes_limits() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut cfg = config::initialize(root.path(), "test").unwrap();
        initialize(root.path(), &cfg).unwrap();
        cfg.set_host_recovery(HostRecovery::new(&cfg)).unwrap();
        config::save(root.path(), &cfg).unwrap();
        let agent = uuid::Uuid::new_v4().to_string();
        assert!(claim(root.path(), &cfg, &agent).unwrap());
        assert!(!claim(root.path(), &cfg, &agent).unwrap());
        let path = root.path().join("host-recovery-budget.json");
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(initialize(root.path(), &cfg).is_err());
        assert!(claim(root.path(), &cfg, &agent).is_err());
        config::write_private(&path, b"{}").unwrap();
        assert!(claim(root.path(), &cfg, &agent).is_err());
        config::write_private(&path, &bytes).unwrap();
        assert!(!claim(root.path(), &cfg, &agent).unwrap());
        let other = config::fresh("other").unwrap();
        assert!(claim(root.path(), &other, &agent).is_err());
    }
}
