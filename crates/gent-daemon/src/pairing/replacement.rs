//! Durable replacement intent. Only pending authenticated enrollment can create
//! this record; extracted archives are never used as live runtime state.
use super::*;
use sha2::{Digest, Sha256};

const FILE: &str = "node-replacement.json";
const PIN: &str = "node_replacement";

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    version: u8,
    cluster: String,
    node: String,
    key: [u8; 32],
    pub(crate) replaces: ReplacedNode,
}

pub fn installed_replacement(home: &Path) -> Result<Option<ReplacedNode>> {
    Ok(check_intent(home, &config::load(home)?, None)?.map(|record| record.replaces))
}

impl Record {
    pub(crate) fn verify_node(&self, node: &NodeIdentity) -> Result<()> {
        ensure!(
            self.node == node.id() && self.key == node.public_key(),
            "replacement record does not match the local signing identity"
        );
        Ok(())
    }
}

pub(crate) fn check_intent(
    home: &Path,
    cfg: &config::Config,
    expected: Option<&str>,
) -> Result<Option<Record>> {
    let path = home.join(FILE);
    let pin = cfg.extra.get(PIN);
    if pin.is_none() && !path.try_exists()? {
        ensure!(
            expected.is_none(),
            "installed node was not enrolled as this replacement"
        );
        return Ok(None);
    }
    let pin = pin
        .and_then(toml::Value::as_str)
        .context("node replacement pin is missing or invalid")?;
    let bytes = read_private_bytes(&path, 4096)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == pin,
        "node replacement record changed"
    );
    let record: Record =
        serde_json::from_slice(&bytes).context("invalid node replacement record")?;
    ensure!(
        record.version == 1
            && record.cluster == cfg.cluster.id
            && record.node == cfg.node.id
            && record.node != record.replaces.id
            && record.key != record.replaces.signing_key
            && Uuid::parse_str(&record.replaces.id)
                .is_ok_and(|u| !u.is_nil() && u.to_string() == record.replaces.id),
        "node replacement record belongs to another identity"
    );
    ensure!(
        expected.is_none_or(|id| id == record.replaces.id),
        "installed node replaced a different node"
    );
    Ok(Some(record))
}

impl Pending {
    pub(super) fn pin_replacement(&mut self, state: &VerifiedState, writer: &str) -> Result<()> {
        let Some(id) = &self.seed.replace_node else {
            ensure!(
                self.seed.replacement.is_none(),
                "unexpected pending replacement pin"
            );
            return Ok(());
        };
        ensure!(
            id != writer && id != self.node.id(),
            "cannot replace the signing owner or the new identity"
        );
        if let Some(target) = &self.seed.replacement {
            ensure!(&target.id == id, "pending replacement target changed");
            if let Some(member) = state.state().nodes.get(id) {
                ensure!(
                    member.signing_key == target.signing_key,
                    "replacement target key changed"
                );
            } else {
                ensure!(
                    state.state().retired_nodes.contains(id)
                        && state.state().retired_keys.contains(&target.signing_key),
                    "replacement target disappeared without retirement"
                );
            }
        } else {
            ensure!(
                !config::path(&self.runtime).exists(),
                "pending replacement target pin is missing"
            );
            let member = state.state().nodes.get(id).context("replacement target is unavailable; resume the original pending join if it already committed")?;
            self.seed.replacement = Some(ReplacedNode {
                id: id.clone(),
                signing_key: member.signing_key,
            });
            self.save_seed()?;
        }
        Ok(())
    }

    pub(super) fn save_replacement(&self) -> Result<()> {
        let Some(target) = &self.seed.replacement else {
            return Ok(());
        };
        let record = Record {
            version: 1,
            cluster: self.seed.cluster.clone(),
            node: self.node.id().into(),
            key: self.node.public_key(),
            replaces: target.clone(),
        };
        let path = self.runtime.join(FILE);
        let bytes = if path.try_exists()? {
            let bytes = read_private_bytes(&path, 4096)?;
            let previous: Record = serde_json::from_slice(&bytes)?;
            ensure!(previous == record, "staged node replacement changed");
            bytes
        } else {
            let cfg = config::load(&self.runtime)?;
            ensure!(
                !cfg.extra.contains_key(PIN),
                "staged replacement record is missing"
            );
            let bytes = Zeroizing::new(serde_json::to_vec(&record)?);
            config::write_private(&path, &bytes)?;
            bytes
        };
        let mut cfg = config::load(&self.runtime)?;
        let pin = toml::Value::String(format!("{:x}", Sha256::digest(&bytes)));
        ensure!(
            cfg.extra.get(PIN).is_none_or(|previous| previous == &pin),
            "staged replacement pin changed"
        );
        cfg.extra.insert(PIN.into(), pin);
        config::save(&self.runtime, &cfg)
    }
}
