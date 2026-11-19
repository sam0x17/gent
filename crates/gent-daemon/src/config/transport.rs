//! Node-local direct transport policy. Empty relay list uses reachable IP paths
//! and Gent's durable Cloudflare fallback, never an implicit third-party relay.
use super::*;
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direct {
    #[default]
    Auto,
    Off,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    #[serde(default)]
    pub direct: Direct,
    #[serde(default)]
    pub relays: Vec<String>,
}
impl Config {
    pub fn transport(&self) -> Result<Transport> {
        let value: Transport = self
            .extra
            .get("transport")
            .cloned()
            .map(toml::Value::try_into)
            .transpose()?
            .unwrap_or_default();
        ensure!(value.relays.len() <= 4, "too many direct transport relays");
        for relay in &value.relays {
            let url = reqwest::Url::parse(relay)?;
            ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "invalid direct transport relay"
            );
        }
        Ok(value)
    }
}
