//! Optional five-minute bearer downloads from the user's gateway. The issuing
//! host authenticates at mint time; the URL delegates only this file's bytes.
use super::{
    Permit, Registry,
    registry::{Download, DownloadTarget},
};
use anyhow::{Context, Result, ensure};
use axum::{
    body::Body,
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use gent_protocol::{
    AgentOp, FileDescriptor, Request,
    file_objects::{CHUNK_BYTES, MAX_FILE_BYTES},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

pub(crate) struct Runtime {
    clients: BTreeSet<String>,
    origin: String,
    slots: Arc<Semaphore>,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            clients: BTreeSet::new(),
            origin: String::new(),
            slots: Arc::new(Semaphore::new(2)),
        }
    }
}
struct Payload {
    bytes: Zeroizing<Vec<u8>>,
    _slot: OwnedSemaphorePermit,
}
impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) fn tool() -> rmcp::model::Tool {
    serde_json::from_value(json!({"name":"gent_file_link",
        "description":"Create a download link for an authorized complete file up to 32 MiB, only when the owner enables links for this host. Anyone holding the URL can fetch this file for up to five minutes without host credentials. Current host/grant, agent, message and expiry rules still apply. Use for a user-requested download; keep it private. Forward file_ids for agent messaging. Call again for a new link after expiry. Host support for MCP resource links varies.",
        "inputSchema":{"type":"object","additionalProperties":false,"required":["file_id"],"properties":{"file_id":{"type":"string","format":"uuid"}}},
        "annotations":{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":true}
    })).expect("valid download tool")
}

impl Runtime {
    pub(crate) fn new(
        clients: &[String],
        origin: &str,
        active: impl Fn(&str) -> Result<()>,
    ) -> Result<Self> {
        ensure!(clients.len() <= 32, "select at most 32 download clients");
        let url = url::Url::parse(origin).context("invalid download origin")?;
        ensure!(
            origin.len() <= 2048
                && url.origin().ascii_serialization() == origin
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
                && (url.scheme() == "https"
                    || (url.scheme() == "http"
                        && matches!(url.host_str(), Some("127.0.0.1" | "[::1]")))),
            "invalid download origin"
        );
        let mut runtime = Self {
            origin: origin.into(),
            ..Self::default()
        };
        for id in clients {
            active(id)?;
            ensure!(
                runtime.clients.insert(id.clone()),
                "duplicate download client"
            );
        }
        Ok(runtime)
    }
    pub(crate) fn enabled(&self) -> bool {
        !self.clients.is_empty()
    }

    pub(crate) async fn link(
        &self,
        registry: &Registry,
        permit: Permit,
        meta: Value,
        home: &Path,
        credential: String,
        file_id: String,
    ) -> Result<Value> {
        ensure!(
            self.clients.contains(permit.client_id()),
            "download links are disabled for this host"
        );
        let value = status(home, &credential, &file_id).await?;
        let expiry = value["expires_at"]
            .as_u64()
            .context("invalid file expiry")?;
        let (token, expiry) = registry
            .issue_download(
                permit,
                meta,
                credential,
                DownloadTarget {
                    file: file_id,
                    origin: self.origin.clone(),
                    expires_at: expiry,
                },
            )
            .await?;
        Ok(
            json!({"file":value["file"],"download_url":format!("{}/files/{token}",self.origin),"expires_at":expiry,"access":"bearer_url"}),
        )
    }

    pub(crate) async fn handle(
        &self,
        registry: &Registry,
        home: &Path,
        token: &str,
        method: &Method,
        headers: &HeaderMap,
    ) -> Response {
        if !self.enabled() || token.is_empty() || token.contains('/') {
            return StatusCode::NOT_FOUND.into_response();
        }
        if !matches!(*method, Method::GET | Method::HEAD) {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        let result = async {
            let access = registry
                .check_download(token.into(), self.origin.clone())
                .await?;
            ensure!(
                self.clients.contains(&access.client),
                "download links disabled"
            );
            let value = status(home, &access.credential, &access.file).await?;
            let descriptor: FileDescriptor = serde_json::from_value(value["file"].clone())?;
            if headers.contains_key(header::RANGE) {
                return Ok::<_, anyhow::Error>(
                    (
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        [(
                            header::CONTENT_RANGE,
                            format!("bytes */{}", descriptor.byte_length),
                        )],
                    )
                        .into_response(),
                );
            }
            let body = if *method == Method::HEAD {
                Body::empty()
            } else {
                let Ok(slot) = self.slots.clone().try_acquire_owned() else {
                    return Ok((
                        StatusCode::SERVICE_UNAVAILABLE,
                        [(header::RETRY_AFTER, "1")],
                    )
                        .into_response());
                };
                let bytes = read(home, &access, &descriptor).await?;
                registry
                    .check_download(token.into(), self.origin.clone())
                    .await?;
                let final_status = status(home, &access.credential, &access.file).await?;
                ensure!(
                    final_status["file"] == value["file"],
                    "download file changed"
                );
                // The slot follows the Bytes owner until Hyper releases all body
                // references, including after a slow reader or disconnect.
                Body::from(hyper::body::Bytes::from_owner(Payload {
                    bytes,
                    _slot: slot,
                }))
            };
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, &descriptor.media_type)
                .header(header::CONTENT_LENGTH, descriptor.byte_length)
                .header(header::CONTENT_DISPOSITION, disposition(&descriptor.name))
                .header(header::ACCEPT_RANGES, "none")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header(
                    "content-security-policy",
                    "sandbox; default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
                )
                .body(body)?)
        }
        .await;
        result.unwrap_or_else(|_| StatusCode::NOT_FOUND.into_response())
    }
}

async fn status(home: &Path, credential: &str, id: &str) -> Result<Value> {
    let value = gent_daemon::request(
        home,
        Request::Agent {
            credential: credential.into(),
            action: AgentOp::FileStatus { file_id: id.into() },
        },
    )
    .await?;
    ensure!(value["state"] == "ready", "file is pending");
    Ok(value)
}

async fn read(home: &Path, access: &Download, file: &FileDescriptor) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        file.id == access.file && file.byte_length <= MAX_FILE_BYTES as u64,
        "invalid download descriptor"
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity(file.byte_length as usize));
    let count = (file.byte_length as usize).div_ceil(CHUNK_BYTES).max(1);
    for index in 0..count {
        let part = gent_daemon::request(
            home,
            Request::Agent {
                credential: access.credential.clone(),
                action: AgentOp::FileRead {
                    file_id: access.file.clone(),
                    chunk_index: index as u32,
                },
            },
        )
        .await?;
        ensure!(
            part["file"] == json!(file)
                && part["chunk_index"] == index
                && part["offset"] == bytes.len()
                && part["chunks_total"] == count
                && part["next_chunk_index"] == json!((index + 1 < count).then_some(index + 1)),
            "invalid download chunk"
        );
        let encoded = part["data_base64"]
            .as_str()
            .context("missing download bytes")?;
        ensure!(
            encoded.len() <= CHUNK_BYTES.div_ceil(3) * 4,
            "download chunk too large"
        );
        let decoded = Zeroizing::new(STANDARD.decode(encoded)?);
        ensure!(
            decoded.len() == (file.byte_length as usize - bytes.len()).min(CHUNK_BYTES)
                && part["byte_length"] == decoded.len(),
            "invalid download chunk length"
        );
        bytes.extend_from_slice(&decoded);
    }
    ensure!(
        bytes.len() as u64 == file.byte_length
            && format!("{:x}", Sha256::digest(&bytes)) == file.sha256,
        "download integrity check failed"
    );
    Ok(bytes)
}

fn disposition(name: &str) -> String {
    let mut encoded = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
            encoded.push(b as char)
        } else {
            encoded.push_str(&format!("%{b:02X}"))
        }
    }
    format!("attachment; filename=\"download\"; filename*=UTF-8''{encoded}")
}
