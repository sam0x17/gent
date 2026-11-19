use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use gent_protocol::web_failover::{Admission, Control, MAX_CONTROL_BYTES};
use sha2::{Digest, Sha256};

pub(super) struct Client {
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
            url: format!("{origin}{base}/control"),
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
        let bytes = serde_json::to_vec(operation)?;
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
            .post(&self.url)
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
