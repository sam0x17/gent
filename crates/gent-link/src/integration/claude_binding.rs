//! Read an existing Claude binding without creating keys or taking live MCP locks.

use super::{Host, scope_path, session_key, wake};
use crate::mcp::binding;
use anyhow::{Result, ensure};
use gent_daemon::config;
use std::path::Path;

pub(super) fn credential(
    home: &Path,
    cfg: &config::Config,
    session: &str,
) -> Result<Option<String>> {
    ensure!(wake::valid_thread(session), "invalid Claude session ID");
    gent_daemon::recovery::ensure_active(home)?;
    let path =
        scope_path(home, cfg, Host::ClaudeCode).join(format!("{}.key", session_key(session, None)));
    let key = wake::snapshot(&path)?;
    crate::agent_recovery::ensure_ready(&path, cfg)?;
    let Some(text) = &key.text else {
        return Ok(None);
    };
    let credential = text.trim();
    ensure!(
        credential.len() == 64 && credential.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid Claude binding credential"
    );
    binding::verify_existing_scope(&path, cfg, credential)?;
    key.verify()?;
    Ok(Some(credential.into()))
}
