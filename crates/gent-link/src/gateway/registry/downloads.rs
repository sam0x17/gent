//! File-scoped bearer delegation. No file keys or agent credentials enter URLs.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};

pub(crate) const TTL: u64 = 300;

pub(crate) struct DownloadTarget {
    pub(crate) file: String,
    pub(crate) origin: String,
    pub(crate) expires_at: u64,
}
pub(crate) struct Download {
    pub(crate) client: String,
    pub(crate) credential: String,
    pub(crate) file: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    version: u8,
    registry: String,
    client: String,
    binding: String,
    file: String,
    audience: String,
    issued_at: u64,
    expires_at: u64,
    grant: Option<GrantScope>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantScope {
    id: String,
    subject: Option<String>,
}

fn mac(credential: &str, bytes: &[u8]) -> Hmac<Sha256> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(credential.as_bytes()).expect("HMAC accepts credential key");
    mac.update(b"gent-file-download-v1\0");
    mac.update(bytes);
    mac
}

impl Registry {
    pub(crate) fn with_file_downloads(mut self, clients: &[String], origin: &str) -> Result<Self> {
        let state = self.read()?;
        let now = auth::now()?;
        self.downloads = Arc::new(super::super::downloads::Runtime::new(
            clients,
            origin,
            |id| {
                let client = state
                    .clients
                    .get(id)
                    .context("unknown file-download client")?;
                ensure!(
                    !client.revoked && now < client.expires_at,
                    "file-download client is inactive"
                );
                Ok(())
            },
        )?);
        Ok(self)
    }

    pub(crate) async fn issue_download(
        &self,
        permit: Permit,
        meta: Value,
        credential: String,
        target: DownloadTarget,
    ) -> Result<(String, u64)> {
        self.blocking(move |registry| {
            registry.issue_download_local(&permit, &meta, &credential, &target)
        })
        .await
    }
    pub(super) fn issue_download_local(
        &self,
        permit: &Permit,
        meta: &Value,
        expected: &str,
        target: &DownloadTarget,
    ) -> Result<(String, u64)> {
        let credential = self.credential(permit, meta)?;
        ensure!(credential == expected, "download binding changed");
        directory_check(&self.directory())?;
        let _lock = managed_file::lock(&self.directory().join("state.lock"))?;
        let mut state = self.read()?;
        let now = auth::now()?;
        let client = Self::client(&state, permit, now)?;
        let binding = client
            .bindings
            .iter()
            .find(|(_, v)| **v == credential)
            .map(|(k, _)| k.clone())
            .context("download binding unavailable")?;
        ensure!(
            gent_protocol::file_objects::valid_id(&target.file),
            "invalid file ID"
        );
        let mut expiry = now
            .checked_add(TTL)
            .context("invalid download clock")?
            .min(target.expires_at)
            .min(client.expires_at);
        let grant = if let Some((id, resource)) = &permit.oauth {
            ensure!(
                *resource == format!("{}/mcp", target.origin),
                "download audience mismatch"
            );
            let (subject, until) =
                oauth::download_scope(&state, &permit.client, id, resource, now)?;
            expiry = expiry.min(until);
            Some(GrantScope {
                id: id.clone(),
                subject,
            })
        } else {
            None
        };
        ensure!(expiry > now, "download authorization expired");
        let claims = Claims {
            version: 1,
            registry: self.id.clone(),
            client: permit.client.clone(),
            binding,
            file: target.file.clone(),
            audience: target.origin.clone(),
            issued_at: now,
            expires_at: expiry,
            grant,
        };
        let bytes = serde_json::to_vec(&claims)?;
        let tag = mac(&credential, &bytes).finalize().into_bytes();
        if state.clock != now {
            state.clock = now;
            self.save(&state)?;
        }
        Ok((
            format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(bytes),
                URL_SAFE_NO_PAD.encode(tag)
            ),
            expiry,
        ))
    }

    pub(crate) async fn check_download(&self, token: String, origin: String) -> Result<Download> {
        self.blocking(move |registry| registry.check_download_local(&token, &origin))
            .await
    }
    pub(super) fn check_download_local(&self, token: &str, origin: &str) -> Result<Download> {
        ensure!(token.len() <= 4096, "invalid download token");
        let (payload, signature) = token.split_once('.').context("invalid download token")?;
        let bytes = URL_SAFE_NO_PAD.decode(payload)?;
        let tag = URL_SAFE_NO_PAD.decode(signature)?;
        let claims: Claims = serde_json::from_slice(&bytes)?;
        ensure!(
            claims.version == 1
                && claims.registry == self.id
                && claims.audience == origin
                && gent_protocol::file_objects::valid_id(&claims.file)
                && URL_SAFE_NO_PAD.encode(&bytes) == payload
                && URL_SAFE_NO_PAD.encode(&tag) == signature,
            "invalid download scope"
        );
        directory_check(&self.directory())?;
        let _lock = managed_file::lock(&self.directory().join("state.lock"))?;
        let mut state = self.read()?;
        let now = auth::now()?;
        ensure!(
            now >= state.clock
                && claims.issued_at <= now
                && now < claims.expires_at
                && claims.expires_at - claims.issued_at <= TTL,
            "download expired or clock moved backward"
        );
        let client = state
            .clients
            .get(&claims.client)
            .context("download host unavailable")?;
        ensure!(
            !client.revoked && now < client.expires_at,
            "download host inactive"
        );
        let credential = client
            .bindings
            .get(&claims.binding)
            .context("download binding unavailable")?;
        mac(credential, &bytes)
            .verify_slice(&tag)
            .context("invalid download signature")?;
        match (&client.oauth, &claims.grant) {
            (Some(_), Some(grant)) => {
                let (subject, _) = oauth::download_scope(
                    &state,
                    &claims.client,
                    &grant.id,
                    &format!("{origin}/mcp"),
                    now,
                )?;
                ensure!(subject == grant.subject, "download user binding changed");
            }
            (None, None) => {}
            _ => anyhow::bail!("download grant mismatch"),
        }
        let credential = credential.clone();
        if state.clock != now {
            state.clock = now;
            self.save(&state)?;
        }
        Ok(Download {
            client: claims.client,
            credential,
            file: claims.file,
        })
    }
}
