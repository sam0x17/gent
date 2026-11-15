//! Native image bytes, scoped to the authenticated caller's Codex thread.
//! No host lifecycle calls, transcript files, arbitrary paths or URL fetches.
use anyhow::{Context, Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use gent_protocol::{AgentOp, Request, file_objects::IncomingFile};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::LazyLock,
};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const MAX_RESPONSE: usize = 64 * 1024 * 1024;
const MAX_FILE: usize = gent_protocol::file_objects::MAX_FILE_BYTES;
const MAX_CURSOR: usize = 2048;
const MAX_TOKEN: usize = 8192;
// Bound concurrent native history responses and decoded images per MCP process.
static SLOTS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(1));

pub(crate) struct Source {
    endpoint: PathBuf,
    thread: String,
    credential: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Selection {
    Page {
        cursor: String,
    },
    Image {
        cursor: String,
        turn: String,
        item: String,
        index: usize,
        sha256: String,
        media_type: String,
    },
}

impl Source {
    pub(super) fn new(endpoint: PathBuf, thread: String, credential: String) -> Self {
        Self {
            endpoint,
            thread,
            credential,
        }
    }

    fn mac(&self, bytes: &[u8]) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.credential.as_bytes())
            .expect("HMAC accepts any key size");
        mac.update(
            &serde_json::to_vec(&json!(["gent-codex-image-v1", self.thread, self.endpoint]))
                .expect("scope serializes"),
        );
        mac.update(bytes);
        mac
    }

    fn token(&self, selection: &Selection) -> Result<String> {
        let bytes = serde_json::to_vec(selection)?;
        let tag = self.mac(&bytes).finalize().into_bytes();
        let token = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&bytes),
            URL_SAFE_NO_PAD.encode(tag)
        );
        ensure!(
            token.len() <= MAX_TOKEN,
            "native attachment reference too large"
        );
        Ok(token)
    }

    fn selection(&self, token: &str) -> Result<Selection> {
        ensure!(
            token.len() <= MAX_TOKEN,
            "invalid native attachment reference"
        );
        let (data, tag) = token
            .split_once('.')
            .context("invalid native attachment reference")?;
        let bytes = URL_SAFE_NO_PAD
            .decode(data)
            .context("invalid native attachment reference")?;
        let tag = URL_SAFE_NO_PAD
            .decode(tag)
            .context("invalid native attachment reference")?;
        self.mac(&bytes)
            .verify_slice(&tag)
            .context("native attachment belongs to another binding or was changed")?;
        serde_json::from_slice(&bytes).context("invalid native attachment reference")
    }

    async fn page(&self, cursor: Option<&str>, direction: &str) -> Result<Value> {
        if let Some(cursor) = cursor {
            valid_cursor(cursor)?;
        }
        let mut host =
            crate::wake::codex::Host::connect_with_limit(&self.endpoint, MAX_RESPONSE).await?;
        host.rpc(
            "thread/turns/list",
            json!({
                "threadId":self.thread, "limit":1, "sortDirection":direction,
                "itemsView":"full", "cursor":cursor
            }),
        )
        .await
    }

    pub(crate) async fn list(&self, home: &Path, cursor: Option<&str>) -> Result<Value> {
        // Registration/revocation is checked before any native conversation read.
        gent_daemon::request(
            home,
            Request::Agent {
                credential: self.credential.clone(),
                action: AgentOp::Identity,
            },
        )
        .await?;
        let cursor = cursor
            .map(|token| match self.selection(token)? {
                Selection::Page { cursor } => Ok(cursor),
                _ => anyhow::bail!("expected an attachment page cursor"),
            })
            .transpose()?;
        let _slot = SLOTS
            .try_acquire()
            .context("native attachment reader busy; retry later")?;
        let page = self.page(cursor.as_deref(), "desc").await?;
        let turns = turns(&page)?;
        let mut images = Vec::new();
        let mut unavailable = 0;
        if let Some(turn) = turns.first() {
            let anchor = page["backwardsCursor"]
                .as_str()
                .context("native attachment anchor unavailable")?;
            valid_cursor(anchor)?;
            let turn_id = bounded_id(&turn["id"])?;
            for item in items(turn)? {
                if item["type"] != "userMessage" {
                    continue;
                }
                let item_id = bounded_id(&item["id"])?;
                for (index, input) in contents(item)?.iter().enumerate() {
                    if !matches!(input["type"].as_str(), Some("image" | "localImage")) {
                        continue;
                    }
                    let Some((media_type, bytes)) = image(input)? else {
                        unavailable += 1;
                        continue;
                    };
                    ensure!(images.len() < 64, "too many native images in one turn");
                    let sha256 = format!("{:x}", Sha256::digest(&bytes));
                    let token = self.token(&Selection::Image {
                        cursor: anchor.into(),
                        turn: turn_id.into(),
                        item: item_id.into(),
                        index,
                        sha256: sha256.clone(),
                        media_type: media_type.into(),
                    })?;
                    images.push(
                        json!({"attachment_id":token,"name":name(index, media_type)?,
                        "media_type":media_type,"byte_length":bytes.len(),"sha256":sha256}),
                    );
                }
            }
        }
        let next = match page.get("nextCursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(next)) => {
                valid_cursor(next)?;
                ensure!(
                    Some(next) != cursor.as_ref() && !turns.is_empty(),
                    "invalid native page continuation"
                );
                Some(self.token(&Selection::Page {
                    cursor: next.clone(),
                })?)
            }
            _ => anyhow::bail!("invalid native page continuation"),
        };
        // Recheck access after the host read, including concurrent revocation.
        gent_daemon::request(
            home,
            Request::Agent {
                credential: self.credential.clone(),
                action: AgentOp::Identity,
            },
        )
        .await?;
        Ok(
            json!({"attachments":images,"next_cursor":next,"unavailable_images":unavailable,
            "scope":"embedded user images in one turn of this conversation; newest first"}),
        )
    }

    pub(crate) async fn import(
        &self,
        home: &Path,
        request_id: String,
        token: &str,
    ) -> Result<Value> {
        let Selection::Image {
            cursor,
            turn,
            item,
            index,
            sha256,
            media_type,
        } = self.selection(token)?
        else {
            anyhow::bail!("expected an attachment ID")
        };
        let file = IncomingFile {
            request_id,
            source_id: format!("{:x}", Sha256::digest(token.as_bytes())),
            name: name(index, &media_type)?,
            media_type: media_type.clone(),
        };
        let status = gent_daemon::request(
            home,
            Request::Agent {
                credential: self.credential.clone(),
                action: AgentOp::FileReceiveStatus { file: file.clone() },
            },
        )
        .await?;
        if status["state"] == "ready" {
            return Ok(status);
        }
        ensure!(status["state"] == "upload", "invalid native import status");
        let _slot = SLOTS
            .try_acquire()
            .context("native attachment reader busy; retry the same request ID")?;
        // The native reverse cursor includes its anchor, so new turns cannot
        // retarget a saved selection. Check turn, item, index and digest too.
        let page = self.page(Some(&cursor), "asc").await?;
        let turns = turns(&page)?;
        let selected = turns
            .first()
            .filter(|t| t["id"] == turn)
            .context("selected native attachment is no longer available")?;
        let mut matching = items(selected)?
            .iter()
            .filter(|i| i["id"] == item && i["type"] == "userMessage");
        let selected = matching
            .next()
            .context("selected native attachment is no longer available")?;
        ensure!(matching.next().is_none(), "ambiguous native image item");
        let input = contents(selected)?
            .get(index)
            .context("selected native attachment is no longer available")?;
        let (actual_type, bytes) =
            image(input)?.context("selected native attachment has no embedded bytes")?;
        ensure!(
            actual_type == media_type && format!("{:x}", Sha256::digest(&bytes)) == sha256,
            "selected native attachment changed; original request was not imported"
        );
        // The daemon rechecks identity/permissions and commits retry state atomically.
        gent_daemon::receive_file(home, self.credential.clone(), file, &bytes).await
    }
}

fn valid_cursor(cursor: &str) -> Result<()> {
    ensure!(
        !cursor.is_empty() && cursor.len() <= MAX_CURSOR,
        "invalid native attachment cursor"
    );
    Ok(())
}
fn bounded_id(value: &Value) -> Result<&str> {
    let id = value.as_str().context("invalid native item identity")?;
    ensure!(
        !id.is_empty() && id.len() <= 256,
        "invalid native item identity"
    );
    Ok(id)
}
fn turns(page: &Value) -> Result<&Vec<Value>> {
    let data = page["data"]
        .as_array()
        .context("invalid native attachment page")?;
    ensure!(data.len() <= 1, "native attachment page too large");
    Ok(data)
}
fn items(turn: &Value) -> Result<&Vec<Value>> {
    ensure!(
        turn.get("itemsView").is_none_or(|v| v == "full"),
        "native turn is incomplete"
    );
    let items = turn["items"].as_array().context("invalid native turn")?;
    ensure!(items.len() <= 16384, "native turn has too many items");
    Ok(items)
}
fn contents(item: &Value) -> Result<&Vec<Value>> {
    let inputs = item["content"]
        .as_array()
        .context("invalid native user input")?;
    ensure!(inputs.len() <= 1024, "native user input too large");
    Ok(inputs)
}
fn name(index: usize, media_type: &str) -> Result<String> {
    let ext = match media_type {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/webp" => "webp",
        "image/gif" => "gif",
        _ => anyhow::bail!("unsupported embedded image type"),
    };
    ensure!(index < 1024, "invalid native image index");
    Ok(format!("pasted-image-{}.{}", index + 1, ext))
}
type EmbeddedImage<'a> = (&'a str, Zeroizing<Vec<u8>>);
fn image(input: &Value) -> Result<Option<EmbeddedImage<'_>>> {
    if input["type"] != "image" {
        return Ok(None);
    }
    let Some(url) = input["url"].as_str() else {
        return Ok(None);
    };
    let Some(data) = url.strip_prefix("data:") else {
        return Ok(None);
    };
    let Some((media_type, encoded)) = data.split_once(";base64,") else {
        return Ok(None);
    };
    if !matches!(
        media_type,
        "image/png" | "image/jpeg" | "image/webp" | "image/gif"
    ) {
        return Ok(None);
    }
    ensure!(
        encoded.len() <= MAX_FILE.div_ceil(3) * 4,
        "native image exceeds 32 MiB"
    );
    let bytes = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .context("invalid native image encoding")?,
    );
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_FILE,
        "native image is empty or exceeds 32 MiB"
    );
    Ok(Some((media_type, bytes)))
}

pub(crate) fn tools() -> Vec<rmcp::model::Tool> {
    [
        json!({"name":"gent_host_attachments","description":"List embedded images supplied by the user in this authenticated native Codex conversation, one turn at a time, newest first. Follow next_cursor to older turns. Returns only image descriptors, without conversation text. Does not read local files or fetch external URLs. unavailable_images counts image inputs requiring native filesystem tools or other host support. Available only with a configured native Codex socket. Use returned attachment_id with gent_file_import_host; never reconstruct an image from its appearance.",
            "inputSchema":{"type":"object","additionalProperties":false,"properties":{"cursor":{"type":"string","maxLength":MAX_TOKEN}}},
            "annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}}),
        json!({"name":"gent_file_import_host","description":"Import exact image bytes selected by gent_host_attachments into encrypted Gent storage, up to 32 MiB. Pass the returned attachment_id and a fresh request_id from gent_request_ids. Retain identical arguments for retries; a completed import remains retryable after native history is removed. Returns file.id for file_ids on send/reply/relay tools. No plaintext staging file or model-supplied path, URL or conversation ID.",
            "inputSchema":{"type":"object","additionalProperties":false,"properties":{"attachment_id":{"type":"string","maxLength":MAX_TOKEN},"request_id":{"type":"string","format":"uuid"}},"required":["attachment_id","request_id"]},
            "annotations":{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":false}}),
    ].into_iter().map(|v| serde_json::from_value(v).expect("valid native attachment tool")).collect()
}

#[cfg(test)]
mod tests;
