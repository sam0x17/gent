//! Remember opt-in host bindings without taking ownership of another live MCP
//! connection. Recovery only reads existing keys and validated scope records.
use super::{config, session_key};
use crate::{managed_file::Snapshot, mcp::binding};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
};

const MAX_BYTES: u64 = 4096;

pub(crate) fn valid_thread(thread: &str) -> bool {
    uuid::Uuid::parse_str(thread).is_ok_and(|id| !id.is_nil() && id.to_string() == thread)
}

/// Preserve the advertised socket name across server restarts; resolve parent
/// aliases such as macOS /tmp without following Codex's final rendezvous link.
fn endpoint(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute() && path.file_name().is_some(),
        "wake socket must be an absolute file path"
    );
    ensure!(
        !path
            .to_str()
            .context("wake path must be UTF-8")?
            .chars()
            .any(char::is_control),
        "invalid wake path"
    );
    // Reject ambiguous traversal instead of collapsing it across symlinks.
    ensure!(
        !path.components().any(|c| matches!(c, Component::ParentDir)),
        "wake path cannot contain parent traversal"
    );
    let parent = path.parent().context("wake socket has no parent")?;
    for ancestor in parent.ancestors() {
        match fs::canonicalize(ancestor) {
            Ok(base) => return Ok(base.join(path.strip_prefix(ancestor)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("cannot resolve wake socket parent")
}

fn hash(credential: &str) -> String {
    format!("{:x}", Sha256::digest(credential.as_bytes()))
}

pub(super) fn snapshot(path: &Path) -> Result<Snapshot> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        ensure!(meta.len() <= MAX_BYTES, "wake attachment file is too large");
    }
    let saved = Snapshot::read(path)?;
    saved.private()?;
    ensure!(
        saved
            .text
            .as_ref()
            .is_none_or(|s| s.len() as u64 <= MAX_BYTES),
        "wake attachment file is too large"
    );
    Ok(saved)
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    cluster_id: String,
    node_id: String,
    thread: String,
    credential_hash: String,
    endpoint: Option<PathBuf>,
}
impl Record {
    fn validate(&self, cfg: &config::Config, thread: &str) -> Result<()> {
        ensure!(
            self.version == 1
                && self.cluster_id == cfg.cluster.id
                && self.node_id == cfg.node.id
                && self.thread == thread
                && valid_thread(thread)
                && self.credential_hash.len() == 64
                && self.credential_hash.bytes().all(|b| b.is_ascii_hexdigit()),
            "wake attachment scope changed"
        );
        if let Some(path) = &self.endpoint {
            ensure!(path.is_absolute(), "invalid wake attachment endpoint");
        }
        Ok(())
    }
}

fn key_path(folder: &Path, thread: &str) -> PathBuf {
    folder.join(format!("{}.key", session_key(thread, None)))
}

/// The calling MCP binding already holds its stable and credential locks.
pub(super) fn remember(
    folder: &Path,
    cfg: &config::Config,
    thread: &str,
    credential: &str,
    endpoint: Option<&Path>,
) -> Result<()> {
    remember_at(folder, cfg, thread, credential, endpoint, false)
}

fn remember_at(
    folder: &Path,
    cfg: &config::Config,
    thread: &str,
    credential: &str,
    endpoint: Option<&Path>,
    preserve_endpoint: bool,
) -> Result<()> {
    let path = binding::sidecar(&key_path(folder, thread), ".wake.json");
    let saved = snapshot(&path)?;
    if endpoint.is_none() && saved.text.is_none() {
        return Ok(());
    }
    let desired = Record {
        version: 1,
        cluster_id: cfg.cluster.id.clone(),
        node_id: cfg.node.id.clone(),
        thread: thread.into(),
        credential_hash: hash(credential),
        endpoint: endpoint.map(Path::to_path_buf),
    };
    if let Some(text) = &saved.text {
        let current: Record = serde_json::from_str(text)?;
        current.validate(cfg, thread)?;
        ensure!(
            current.credential_hash == desired.credential_hash,
            "wake attachment credential changed"
        );
        ensure!(
            !preserve_endpoint
                || current.endpoint.is_none()
                || current.endpoint == desired.endpoint,
            "chat already belongs to another native endpoint"
        );
        // A connection without a native endpoint cannot revoke another
        // connection's attachment. Checking an inbox must never downgrade
        // automatic delivery.
        if endpoint.is_none() || current == desired {
            return Ok(());
        }
    }
    let text = serde_json::to_string(&desired)? + "\n";
    ensure!(text.len() as u64 <= MAX_BYTES, "wake attachment too large");
    saved.write(&text)
}

pub(super) fn remember_discovered(
    folder: &Path,
    cfg: &config::Config,
    thread: &str,
    credential: &str,
    socket: &Path,
) -> Result<()> {
    remember_at(
        folder,
        cfg,
        thread,
        credential,
        Some(&endpoint(socket)?),
        true,
    )
}

pub(crate) struct Registry {
    home: PathBuf,
    folder: PathBuf,
    cfg: config::Config,
    pub(crate) endpoint: PathBuf,
}
impl Registry {
    pub(crate) fn codex(home: &Path, socket: &Path) -> Result<Self> {
        let cfg = config::load(home)?;
        let folder = super::scope_path(home, &cfg, super::Host::Codex);
        Self::new(home, folder, cfg, socket)
    }

    pub(super) fn new(
        home: &Path,
        folder: PathBuf,
        cfg: config::Config,
        socket: &Path,
    ) -> Result<Self> {
        gent_daemon::recovery::ensure_active(home)?;
        Ok(Self {
            home: home.into(),
            folder,
            cfg,
            endpoint: endpoint(socket)?,
        })
    }

    /// A nonblocking lease elects one watcher per endpoint and node/cluster.
    /// The OS releases it on process exit. It never locks a model credential.
    pub(crate) fn coordinator(&self) -> Result<Option<File>> {
        gent_daemon::recovery::ensure_active(&self.home)?;
        let id = super::digest(&serde_json::json!(self.endpoint));
        let path = self.folder.join(format!("wake-{id}.lock"));
        let saved = snapshot(&path)?;
        ensure!(
            saved.text.as_ref().is_none_or(|s| s.is_empty()),
            "invalid wake coordinator lock"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Some(file)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) fn credential(&self, thread: &str) -> Result<Option<String>> {
        ensure!(valid_thread(thread), "invalid Codex thread ID");
        gent_daemon::recovery::ensure_active(&self.home)?;
        let path = key_path(&self.folder, thread);
        let saved = snapshot(&binding::sidecar(&path, ".wake.json"))?;
        let Some(text) = &saved.text else {
            return Ok(None);
        };
        let record: Record = serde_json::from_str(text)?;
        record.validate(&self.cfg, thread)?;
        if record.endpoint.as_ref() != Some(&self.endpoint) {
            return Ok(None);
        }
        let key = snapshot(&path)?;
        let credential = key
            .text
            .as_deref()
            .context("wake binding key is missing")?
            .trim();
        ensure!(
            credential.len() == 64
                && credential.bytes().all(|b| b.is_ascii_hexdigit())
                && hash(credential) == record.credential_hash,
            "wake binding credential changed"
        );
        crate::agent_recovery::ensure_ready(&path, &self.cfg)?;
        binding::verify_existing_scope(&path, &self.cfg, credential)?;
        key.verify()?;
        saved.verify()?;
        Ok(Some(credential.into()))
    }
}

#[cfg(test)]
mod tests;
