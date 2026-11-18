//! Small, node-scoped inventory. Conversation bodies and credentials stay out.
use super::*;
use crate::managed_file::Snapshot;
use serde::{Deserialize, Serialize};

pub(super) const LIMIT: usize = 4096;
const BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub agent: String,
    pub host: Host,
    pub native: String,
    pub name: String,
    pub endpoint: Option<PathBuf>,
    pub recovery: Option<config::RecoveryAgent>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Catalog {
    version: u8,
    cluster: String,
    node: String,
    pub checked: Option<u64>,
    pub hosts: BTreeMap<String, Value>,
    pub entries: BTreeMap<String, Entry>,
}

pub(super) fn read(home: &Path, cfg: &config::Config) -> Result<(Snapshot, Catalog)> {
    let path = home.join("chat-discovery.json");
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        ensure!(
            meta.len() <= BYTES,
            "chat discovery inventory exceeds its limit"
        );
    }
    let saved = Snapshot::read(&path)?;
    saved.private()?;
    let value = match &saved.text {
        Some(text) => {
            serde_json::from_str::<Catalog>(text).context("invalid chat discovery inventory")?
        }
        None => Catalog {
            version: 1,
            cluster: cfg.cluster.id.clone(),
            node: cfg.node.id.clone(),
            checked: None,
            hosts: BTreeMap::new(),
            entries: BTreeMap::new(),
        },
    };
    ensure!(
        value.version == 1
            && value.cluster == cfg.cluster.id
            && value.node == cfg.node.id
            && value.entries.len() <= LIMIT,
        "chat discovery inventory belongs to another node or exceeds its limit"
    );
    for (id, entry) in &value.entries {
        ensure!(
            id == &key(entry.host, &entry.native)
                && super::super::wake::valid_thread(&entry.native)
                && super::super::wake::valid_thread(&entry.agent),
            "invalid discovered chat identity"
        );
        config::label(&entry.name)?;
        ensure!(
            entry.endpoint.as_ref().is_none_or(|p| p.is_absolute()),
            "invalid discovery endpoint"
        );
    }
    Ok((saved, value))
}

pub(super) fn save(saved: &Snapshot, value: &Catalog) -> Result<()> {
    let text = serde_json::to_string(value)? + "\n";
    ensure!(
        text.len() as u64 <= BYTES,
        "chat discovery inventory exceeds its limit"
    );
    if saved.text.as_deref() != Some(&text) {
        saved.write(&text)?;
    }
    Ok(())
}

pub(super) fn key(host: Host, native: &str) -> String {
    format!("{}:{native}", host.name())
}
