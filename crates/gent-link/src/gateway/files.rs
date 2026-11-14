//! Opt-in host file inputs. Temporary URLs remain in memory; only a hash of
//! the host file identity and metadata is retained for exact import retries.
use super::{Permit, Registry};
use anyhow::{Context, Result, ensure};
use gent_protocol::{AgentOp, Request, file_objects::IncomingFile};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Semaphore};
use url::{Host, Url};
use zeroize::Zeroizing;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BYTES: usize = gent_protocol::file_objects::MAX_FILE_BYTES;

pub(crate) fn tool() -> rmcp::model::Tool {
    serde_json::from_value(json!({
        "name":"gent_file_import_remote",
        "description":"Import a host-provided file up to 32 MiB from an owner-approved HTTPS download origin. Supply a UUIDv7 from gent_request_ids and the host's actual file object. Returns a Gent file ID for send/reply/relay file_ids. Keep the request ID, host file ID, name and MIME type on retries; download_url may refresh. Completed retries do not download again. Omitted file_name defaults to attachment and mime_type to application/octet-stream. This imports only; it does not send a message.",
        "inputSchema":{"type":"object","additionalProperties":false,"required":["request_id","file"],"properties":{
            "request_id":{"type":"string","format":"uuid"},
            "file":{"type":"object","additionalProperties":false,"required":["download_url","file_id"],"properties":{
                "download_url":{"type":"string"},"file_id":{"type":"string"},"file_name":{"type":"string"},"mime_type":{"type":"string"}
            }}
        }},
        "annotations":{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":true},
        "_meta":{"openai/fileParams":["file"]}
    })).expect("valid host file tool")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    request_id: String,
    file: HostFile,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFile {
    download_url: String,
    file_id: String,
    #[serde(default, deserialize_with = "provided_string")]
    file_name: Option<String>,
    #[serde(default, deserialize_with = "provided_string")]
    mime_type: Option<String>,
}
fn provided_string<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(de).map(Some)
}

struct Entry {
    origins: BTreeSet<String>,
    attempt: Mutex<Option<Instant>>,
}
pub(crate) struct Runtime {
    clients: BTreeMap<String, Entry>,
    slots: Semaphore,
    #[cfg(test)]
    pub(crate) fetcher: Option<TestFetcher>,
}
#[cfg(test)]
type TestFetcher = std::sync::Arc<
    dyn Fn(
            Url,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Zeroizing<Vec<u8>>>> + Send>,
        > + Send
        + Sync,
>;
impl Default for Runtime {
    fn default() -> Self {
        Self {
            clients: BTreeMap::new(),
            slots: Semaphore::new(2),
            #[cfg(test)]
            fetcher: None,
        }
    }
}

fn endpoint(raw: &str) -> Result<Url> {
    ensure!(raw.len() <= 8192, "file URL is too long");
    let url = Url::parse(raw).context("invalid file URL")?;
    ensure!(
        url.as_str() == raw
            && url.scheme() == "https"
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "file URL must be canonical HTTPS on port 443 without credentials or fragment"
    );
    let Some(Host::Domain(host)) = url.host() else {
        anyhow::bail!("file URL requires a public DNS name")
    };
    ensure!(
        host.contains('.')
            && host.len() <= 253
            && host.split('.').all(|s| !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "invalid file DNS name"
    );
    Ok(url)
}

impl Runtime {
    pub(crate) fn new(entries: &[String], active: impl Fn(&str) -> Result<()>) -> Result<Self> {
        ensure!(entries.len() <= 64, "select at most 64 file origins");
        let mut runtime = Self::default();
        for entry in entries {
            let (id, origin) = entry
                .split_once('=')
                .context("file origin must be CLIENT_UUID=https://host")?;
            ensure!(
                uuid::Uuid::parse_str(id).is_ok_and(|v| v.to_string() == id),
                "invalid file-import client ID"
            );
            active(id)?;
            let url = endpoint(&format!("{origin}/"))?;
            ensure!(
                url.origin().ascii_serialization() == origin,
                "file origin must have no path, query or trailing slash"
            );
            let client = runtime.clients.entry(id.into()).or_insert_with(|| Entry {
                origins: BTreeSet::new(),
                attempt: Mutex::new(None),
            });
            ensure!(
                client.origins.len() < 8 && client.origins.insert(origin.into()),
                "duplicate or excessive file origins for host"
            );
        }
        Ok(runtime)
    }
    pub(crate) fn enabled(&self) -> bool {
        !self.clients.is_empty()
    }

    pub(crate) async fn import(
        &self,
        registry: &Registry,
        permit: Permit,
        meta: Value,
        home: &Path,
        credential: String,
        input: Input,
    ) -> Result<Value> {
        let entry = self
            .clients
            .get(permit.client_id())
            .context("file imports are disabled for this host")?;
        let url = endpoint(&input.file.download_url)?;
        ensure!(
            entry.origins.contains(&url.origin().ascii_serialization()),
            "file download origin is not approved for this host"
        );
        ensure!(
            !input.file.file_id.is_empty()
                && input.file.file_id.len() <= 512
                && !input.file.file_id.chars().any(char::is_control),
            "invalid host file identity"
        );
        let name = input.file.file_name.unwrap_or_else(|| "attachment".into());
        let media_type = input
            .file
            .mime_type
            .unwrap_or_else(|| "application/octet-stream".into());
        gent_crypto::files::validate_metadata(&name, &media_type)?;
        let source_id = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&json!([
                "gent-host-file-v1",
                input.file.file_id,
                name,
                media_type
            ]))?)
        );
        let file = IncomingFile {
            request_id: input.request_id,
            source_id,
            name,
            media_type,
        };
        let status = gent_daemon::request(
            home,
            Request::Agent {
                credential: credential.clone(),
                action: AgentOp::FileReceiveStatus { file: file.clone() },
            },
        )
        .await?;
        if status["state"] == "ready" {
            return Ok(status);
        }
        ensure!(status["state"] == "upload", "invalid import status");
        let _slot = self
            .slots
            .try_acquire()
            .context("file imports busy; retry the same request ID")?;
        let mut attempt = entry
            .attempt
            .try_lock()
            .context("host file import busy; retry the same request ID")?;
        ensure!(
            attempt.is_none_or(|last| last.elapsed() >= Duration::from_secs(1)),
            "file imports limited to one attempt per second per host"
        );
        *attempt = Some(Instant::now());
        let bytes = self.fetch(&url).await.map_err(|_| {
            anyhow::anyhow!(
                "file download failed; obtain a fresh URL and retry the same request ID"
            )
        })?;
        // A download may overlap grant expiry/revocation or binding changes.
        ensure!(
            registry.credential_remote(permit, meta).await? == credential,
            "file import binding changed"
        );
        gent_daemon::receive_file(home, credential, file, &bytes).await
    }

    async fn fetch(&self, url: &Url) -> Result<Zeroizing<Vec<u8>>> {
        #[cfg(test)]
        if let Some(fetcher) = &self.fetcher {
            return fetcher(url.clone()).await;
        }
        fetch(url).await
    }
}

async fn fetch(url: &Url) -> Result<Zeroizing<Vec<u8>>> {
    tokio::time::timeout(TIMEOUT, async {
        let addresses = tokio::net::lookup_host((url.host_str().unwrap(), 443))
            .await?
            .take(33)
            .collect();
        let addresses = super::metadata::destinations(addresses)?;
        let client = super::metadata::client(url, &addresses).build()?;
        response(&client, url).await
    })
    .await
    .context("file fetch timed out")?
}

async fn response(client: &reqwest::Client, url: &Url) -> Result<Zeroizing<Vec<u8>>> {
    let mut response = client
        .get(url.clone())
        .header("accept-encoding", "identity")
        .send()
        .await?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "file endpoint must return HTTP 200 without redirects"
    );
    ensure!(
        !response.headers().contains_key("content-encoding"),
        "encoded file responses are unsupported"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= MAX_BYTES as u64),
        "file exceeds 32 MiB"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= MAX_BYTES - bytes.len(),
            "file exceeds 32 MiB"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
