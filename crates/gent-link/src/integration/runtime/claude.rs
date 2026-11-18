//! Native Claude observations and exact-session attachment with pinned bindings.

mod eligibility;
mod history;
pub(in crate::integration) mod recovery;
mod sessions;
mod start;
pub(super) use start::run as start;

use super::{Host, install, process};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::Command;

const OUTPUT_LIMIT: u64 = 1024 * 1024;

fn command(binary: &Path, target: &install::ClaudeRuntime) -> Result<Command> {
    // Resolve explicit relative paths before changing to the host's directory.
    let binary = if binary.components().count() > 1 {
        std::path::absolute(binary)?
    } else {
        binary.into()
    };
    let mut command = Command::new(binary);
    command.current_dir(&target.directory);
    if target.custom_directory {
        command.env("CLAUDE_CONFIG_DIR", &target.directory);
    } else {
        // Setting an explicit directory also changes Claude's .claude.json
        // location. Preserve the default installation's sibling-file layout.
        command.env_remove("CLAUDE_CONFIG_DIR");
    }
    Ok(command)
}

/// Automatic startup belongs to the selected native profile, not the shell
/// which happened to launch Gent. Native settings/keychain retain authority
/// over provider credentials, endpoints, model routing and host extensions.
fn automatic_command(binary: &Path, target: &install::ClaudeRuntime) -> Result<Command> {
    let mut command = command(binary, target)?;
    command.env_clear();
    for name in [
        "HOME",
        "PATH",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    if target.custom_directory {
        command.env("CLAUDE_CONFIG_DIR", &target.directory);
    } else {
        command.env(
            "HOME",
            target.directory.parent().context("missing Claude home")?,
        );
    }
    Ok(command)
}

async fn inspect(binary: &Path, target: &install::ClaudeRuntime) -> Result<Vec<sessions::Session>> {
    let mut command = command(binary, target)?;
    command.args(["agents", "--json", "--all"]);
    let output = process::output(command, Duration::from_secs(15), OUTPUT_LIMIT).await?;
    // Native stderr may contain account diagnostics; do not copy it into status.
    ensure!(
        output.status.success(),
        "Claude session inspection failed; run claude agents --json --all in the selected profile for details"
    );
    sessions::parse(&output.stdout)
}

fn report(sessions: &[sessions::Session]) -> Value {
    let running = sessions.iter().filter(|row| row.pid.is_some()).count();
    json!({"inspected":true,"source":"claude_agents","reported_running":running,
        "session_count":sessions.len(),"sessions":sessions,"gent_bindings_checked":false})
}

pub(in crate::integration) async fn discovery(
    home: &Path,
    binary: &Path,
) -> Result<(PathBuf, Vec<crate::integration::discovery::hosts::Chat>)> {
    let target = install::claude_runtime_target(home, None)?;
    target.require_wake()?;
    let sessions = inspect(binary, &target).await?;
    ensure!(
        install::claude_runtime_target(home, None)? == target,
        "Claude installation changed during discovery"
    );
    let chats = sessions
        .into_iter()
        .filter_map(|row| {
            let id = row.session_id?;
            Some(crate::integration::discovery::hosts::Chat {
                last_activity_at: None,
                id,
                name: row.name,
                working_dir: Some(row.cwd),
                recoverable: row.native_id.is_some() && row.native_kind == "background",
            })
        })
        .collect();
    Ok((target.directory, chats))
}

pub(super) async fn status(
    home: &Path,
    directory: Option<PathBuf>,
    binary: &Path,
) -> Result<Value> {
    let mut status = crate::managed_file::retry_read(|| {
        install::status(home, Some(Host::ClaudeCode), directory.clone())
    })
    .await?;
    let result = async {
        let target = crate::managed_file::retry_read(|| {
            install::claude_runtime_target(home, directory.clone())
        })
        .await?;
        let observed = inspect(binary, &target)
            .await
            .context("cannot inspect native Claude sessions")?;
        let current = crate::managed_file::retry_read(|| {
            install::claude_runtime_target(home, directory.clone())
        })
        .await?;
        ensure!(
            current == target,
            "Claude integration changed during native inspection"
        );
        Ok::<_, anyhow::Error>(report(&observed))
    }
    .await;
    status["runtime"] =
        result.unwrap_or_else(|error| json!({"inspected":false,"error":format!("{error:#}")}));
    Ok(status)
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
