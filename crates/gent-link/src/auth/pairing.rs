use super::*;
use gent_protocol::service::pairing::{Approval, MAX_BODY, Record, Registration, valid_id};

impl Service {
    pub async fn available_clusters(&self) -> Result<Vec<ServiceCluster>> {
        let (status, value) = response(
            self.request(Method::GET, "v1/clusters")?
                .bearer_auth(&self.saved.token),
        )
        .await?;
        let clusters: Vec<ServiceCluster> = serde_json::from_value(success(status, value)?)
            .map_err(|_| anyhow::anyhow!("invalid service cluster list"))?;
        ensure!(
            clusters.len() <= 128
                && clusters.iter().all(|c| uuid::Uuid::parse_str(&c.id)
                    .is_ok_and(|v| !v.is_nil() && v.to_string() == c.id)),
            "invalid service cluster list"
        );
        Ok(clusters.into_iter().filter(|c| c.role == "owner").collect())
    }

    async fn pairing_exchange(
        &self,
        id: &str,
        method: Method,
        body: Option<Value>,
    ) -> Result<Record> {
        ensure!(valid_id(id), "invalid pairing ID");
        let mut request = self
            .request(method, &format!("v1/pairings/{id}"))?
            .bearer_auth(&self.saved.token);
        if let Some(value) = body {
            request = request.json(&value);
        }
        let (status, value) = response_limit(request, MAX_BODY + 8192).await?;
        let record: Record = serde_json::from_value(success(status, value)?)
            .map_err(|_| anyhow::anyhow!("invalid pairing service response"))?;
        ensure!(
            record.id == id
                && record.expires_at
                    == record
                        .created_at
                        .saturating_add(gent_protocol::service::pairing::LIFETIME),
            "pairing service changed request binding"
        );
        Ok(record)
    }

    pub async fn pairing_create(&self, id: &str, input: &Registration) -> Result<Record> {
        self.pairing_exchange(id, Method::PUT, Some(serde_json::to_value(input)?))
            .await
    }
    pub async fn pairing_read(&self, id: &str) -> Result<Record> {
        self.pairing_exchange(id, Method::GET, None).await
    }
    pub async fn pairing_approve(&self, id: &str, input: &Approval) -> Result<Record> {
        self.pairing_exchange(id, Method::POST, Some(serde_json::to_value(input)?))
            .await
    }
}
