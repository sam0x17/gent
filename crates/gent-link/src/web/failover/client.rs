use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use gent_protocol::web_failover::{Admission, Control, MAX_CONTROL_BYTES};
use sha2::{Digest, Sha256};

pub(in crate::web) struct Client {
    pub parent: PathBuf,
    pub node: String,
    url: String,
    http: reqwest::Client,
}

impl Client {
    pub fn new(parent: &Path, node: &str, origin: &str) -> Result<Self> {
        let cfg = node_home::inspect(parent)?;
        let base = gent_protocol::hosted_mcp::node_base(&cfg.cluster.id, node)
            .context("invalid web identity")?;
        Ok(Self {
            parent: parent.into(),
            node: node.into(),
            url: format!("{origin}{base}"),
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(12))
                .build()?,
        })
    }

    pub fn credential(&self) -> Result<String> {
        let cfg = node_home::inspect(&self.parent)?;
        let relay = cfg
            .relay
            .context("web hosting requires the service relay")?;
        config::read_relay_credential(&self.parent.join(relay.credential_file))
    }

    pub async fn call(&self, operation: &Control) -> Result<(u16, Vec<u8>)> {
        self.post("control", serde_json::to_vec(operation)?).await
    }

    pub async fn manage(
        &self,
        action: &gent_protocol::hosted_mcp::ConnectorAction,
    ) -> Result<String> {
        let (status, bytes) = self.post("manage", serde_json::to_vec(action)?).await?;
        match status {
            200 => Ok(serde_json::from_slice(&bytes)?),
            410 => anyhow::bail!("web node is revoked"),
            403 => anyhow::bail!("current cluster configuration authority required"),
            422 => {
                anyhow::bail!("connector URL unavailable or expired; use gent node web rotate NAME")
            }
            _ => anyhow::bail!(
                "web connector management unavailable ({status}); retry when the cluster has an updated online carrier"
            ),
        }
    }

    async fn post(&self, route: &str, bytes: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        ensure!(
            bytes.len() <= MAX_CONTROL_BYTES,
            "web control exceeds limits"
        );
        let proof: Admission = serde_json::from_value(
            owner(
                &self.parent,
                OwnerOp::WebAdmission {
                    node_id: self.node.clone(),
                    body_hash: Sha256::digest(&bytes).into(),
                },
            )
            .await?,
        )?;
        let response = self
            .http
            .post(format!("{}/{route}", self.url))
            .timeout(Duration::from_secs(if route == "manage" { 40 } else { 12 }))
            .bearer_auth(self.credential()?)
            .header(
                "X-Gent-Web-Admission",
                STANDARD.encode(serde_json::to_vec(&proof)?),
            )
            .header("Content-Type", "application/json")
            .body(bytes)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("web checkpoint service unavailable"))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(part) = stream.next().await {
            let part = part.map_err(|_| anyhow::anyhow!("web checkpoint response unavailable"))?;
            ensure!(
                bytes.len() + part.len() <= MAX_CONTROL_BYTES,
                "web checkpoint response too large"
            );
            bytes.extend(part);
        }
        Ok((status, bytes))
    }

    pub async fn required<T: serde::de::DeserializeOwned>(&self, operation: &Control) -> Result<T> {
        let (status, bytes) = self.call(operation).await?;
        ensure!(
            status == 200,
            "web checkpoint operation rejected ({status}); retry the original operation"
        );
        Ok(serde_json::from_slice(&bytes)?)
    }
}
