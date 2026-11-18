//! Local consent to publish native chat identities and enable their wake paths.
use super::*;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub enabled: bool,
}

impl Config {
    pub fn discovery(&self) -> Result<Discovery> {
        self.extra
            .get("discovery")
            .cloned()
            .map(|value| value.try_into().context("invalid chat discovery settings"))
            .transpose()
            .map(Option::unwrap_or_default)
    }

    pub fn set_discovery(&mut self, settings: Discovery) -> Result<()> {
        self.extra
            .insert("discovery".into(), toml::Value::try_from(settings)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_is_opt_in_and_projections_preserve_local_changes() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let original = initialize(root.path(), "discovery").unwrap();
        assert!(!original.discovery().unwrap().enabled);
        edit_local(root.path(), |cfg| {
            cfg.set_discovery(Discovery { enabled: true })
        })
        .unwrap();
        save(root.path(), &original).unwrap();
        let enabled = load(root.path()).unwrap();
        assert!(enabled.discovery().unwrap().enabled);
        edit_local(root.path(), |cfg| cfg.set_discovery(Discovery::default())).unwrap();
        save(root.path(), &enabled).unwrap();
        assert!(!load(root.path()).unwrap().discovery().unwrap().enabled);
    }
}
