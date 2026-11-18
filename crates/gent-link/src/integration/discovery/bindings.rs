//! Owner-enabled registration uses the same native-ID binding as future MCP calls.
use super::*;
use crate::mcp::binding;

pub(super) fn credential(
    home: &Path,
    cfg: &config::Config,
    host: Host,
    native: &str,
) -> Result<String> {
    ensure!(
        super::super::wake::valid_thread(native),
        "invalid native chat identity"
    );
    let path = super::super::recovery_binding(home, host, native, None)?;
    let saved = super::super::wake::snapshot(&path)?;
    if let Some(text) = &saved.text {
        crate::agent_recovery::ensure_ready(&path, cfg)?;
        let key = text.trim();
        ensure!(
            key.len() == 64 && key.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid chat binding"
        );
        binding::verify_existing_scope(&path, cfg, key)?;
        saved.verify()?;
        return Ok(key.into());
    }
    // Do not retain a live MCP connection's locks or replace an existing key.
    let _lock = super::super::lock(
        &path
            .parent()
            .context("missing binding directory")?
            .join("bindings.lock"),
    )?;
    Ok(binding::open(&path, cfg, true)?.credential.clone())
}

pub(super) fn remember(
    home: &Path,
    cfg: &config::Config,
    native: &str,
    key: &str,
    socket: &Path,
) -> Result<()> {
    super::super::wake::remember_discovered(
        &super::super::scope_path(home, cfg, Host::Codex),
        cfg,
        native,
        key,
        socket,
    )
}
