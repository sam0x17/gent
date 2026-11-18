//! Display labels from the already-bound host conversation. Titles never select
//! credentials, grant permissions, or cause a host turn to start.
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

const TITLE_BYTES: usize = 128;
const TAIL_BYTES: u64 = 256 * 1024;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
static LOOKUPS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

pub(crate) enum Source {
    Title(Option<String>),
    Codex { endpoint: PathBuf, thread: String },
}

impl Source {
    pub(crate) async fn resolve(self, credential: &str, provider: &str) -> String {
        let title = match self {
            Self::Title(title) => title,
            Self::Codex { endpoint, thread } => {
                let lookup = async {
                    let _slot = LOOKUPS.try_acquire().ok()?;
                    let mut host = crate::wake::codex::Host::connect_with_limit(
                        &endpoint,
                        TAIL_BYTES as usize,
                    )
                    .await
                    .ok()?;
                    let result = host
                        .rpc(
                            "thread/read",
                            json!({"threadId":thread,"includeTurns":false}),
                        )
                        .await
                        .ok()?;
                    (result["thread"]["id"] == thread)
                        .then(|| title(&result["thread"]["name"]))
                        .flatten()
                };
                tokio::time::timeout(LOOKUP_TIMEOUT, lookup)
                    .await
                    .ok()
                    .flatten()
            }
        };
        title.unwrap_or_else(|| {
            let suffix = format!(
                "{:x}",
                Sha256::digest(format!("gent-display-name-v1:{credential}"))
            );
            let prefix = match provider {
                "codex" => "codex",
                "claude-code" => "claude-code",
                _ => "agent",
            };
            format!("{prefix}-{}", &suffix[..12])
        })
    }
}

/// Normalize native titles to Gent's byte-limited labels without copying a
/// preview, prompt, or other conversation content as a guessed title.
pub(super) fn title(value: &Value) -> Option<String> {
    let value = value.as_str()?.trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        return None;
    }
    let mut end = value.len().min(TITLE_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let value = value[..end].trim_end();
    (!value.is_empty()).then(|| value.to_owned())
}

pub(super) fn open_metadata(path: &Path) -> Result<std::fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(
            rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32,
        )
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.mode() & 0o022 == 0,
        "native title metadata is not an owned regular file"
    );
    Ok(file)
}

/// Claude supplies this path through its PreToolUse hook, never tool arguments.
/// Subagents must not inherit their parent's title. Only the title is persisted
/// in the short-lived private hook ticket, not the path or transcript contents.
pub(super) fn claude_title(input: &Value) -> Option<String> {
    if input.get("agent_id").is_some() {
        return None;
    }
    let session = input["session_id"].as_str()?;
    if !super::wake::valid_thread(session) {
        return None;
    }
    let path = Path::new(input["transcript_path"].as_str()?);
    if !path.is_absolute() || path.file_name()?.to_str()? != format!("{session}.jsonl") {
        return None;
    }
    // Current Claude versions keep explicit /rename titles in this small sidecar.
    let sidecar = path.parent()?.join(session).join("custom-title.json");
    if let Ok(file) = open_metadata(&sidecar) {
        let mut bytes = Vec::new();
        if file.take(4097).read_to_end(&mut bytes).is_ok()
            && bytes.len() <= 4096
            && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
            && let Some(name) = title(&value["customTitle"])
        {
            return Some(name);
        }
    }
    // Older hosts and generated titles use explicit metadata records in JSONL.
    // Read a bounded tail, discarding partial records and all conversation text.
    let mut file = open_metadata(path).ok()?;
    let start = file.metadata().ok()?.len().saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::new();
    file.take(TAIL_BYTES).read_to_end(&mut bytes).ok()?;
    let mut custom = None;
    let mut generated = None;
    for (index, line) in bytes.split_inclusive(|b| *b == b'\n').enumerate() {
        if (start > 0 && index == 0) || line.last() != Some(&b'\n') || line.len() > 4096 {
            continue;
        }
        let Ok(row) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        if row["sessionId"] != session {
            continue;
        }
        match row["type"].as_str() {
            Some("custom-title") => custom = title(&row["customTitle"]),
            Some("ai-title") => generated = title(&row["aiTitle"]),
            _ => {}
        }
    }
    custom.or(generated)
}

#[cfg(test)]
mod tests;
