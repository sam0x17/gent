//! Private machine-local routing for a web identity served by its native host.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedParent {
    pub home: PathBuf,
    pub node_id: String,
}

impl Config {
    pub fn hosted_parent(&self) -> Result<Option<HostedParent>> {
        self.extra
            .get("hosted_parent")
            .cloned()
            .map(|value| {
                let parent: HostedParent = value.try_into().context("invalid hosted parent")?;
                let node = uuid::Uuid::parse_str(&parent.node_id)?;
                ensure!(
                    parent.home.is_absolute()
                        && !node.is_nil()
                        && node.to_string() == parent.node_id
                        && parent.node_id != self.node.id,
                    "invalid hosted parent identity or path"
                );
                Ok(parent)
            })
            .transpose()
    }

    pub fn set_hosted_parent(&mut self, parent: HostedParent) -> Result<()> {
        self.extra
            .insert("hosted_parent".into(), toml::Value::try_from(parent)?);
        self.update_local_version()?;
        self.hosted_parent()?;
        Ok(())
    }
}
