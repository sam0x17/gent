//! Native transport settings. External Iroh relays always require an explicit URL.
use super::*;
use std::net::SocketAddr;
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direct {
    #[default]
    Auto,
    Off,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Transport {
    pub direct: Direct,
    pub relays: Vec<String>,
    /// Permit IP-based QUIC paths. TCP-only peers can still use a cluster helper.
    pub udp: bool,
    /// Serve a helper for enrolled peers. Clients can use another node's helper in either mode.
    pub helper: Direct,
    pub helper_port: Option<u16>,
    pub helper_public_address: Option<SocketAddr>,
}
impl Default for Transport {
    fn default() -> Self {
        Self {
            direct: Direct::Auto,
            relays: Vec::new(),
            udp: true,
            helper: Direct::Auto,
            helper_port: None,
            helper_public_address: None,
        }
    }
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
        if let Some(address) = value.helper_public_address {
            ensure!(
                matches!(address, SocketAddr::V4(addr) if addr.port() != 0
                    && !addr.ip().is_unspecified() && !addr.ip().is_multicast()
                    && !addr.ip().is_broadcast()),
                "expected a usable IPv4 address and port for the helper"
            );
        }
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
