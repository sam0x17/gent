use super::*;
use gent_protocol::service::pairing::{MAX_BODY, Record, Registration, valid_id};

impl Service {
    async fn pairing_exchange(
        &self,
        id: &str,
        method: Method,
        body: Option<Value>,
    ) -> Result<Record> {
        ensure!(valid_id(id), "invalid pairing ID");
        let mut request = self
            .request(method, &format!("v1/node-invitations/{id}"))?
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
}
