//! Native Claude session observations, separate from Gent registration or recovery.

mod sessions;

use super::{Host, install, process};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::Command;

const OUTPUT_LIMIT: u64 = 1024 * 1024;

async fn inspect(binary: &Path, target: &install::ClaudeRuntime) -> Result<Value> {
    let mut command = Command::new(binary);
    command
        .args(["agents", "--json", "--all"])
        .current_dir(&target.directory);
    if target.custom_directory {
        command.env("CLAUDE_CONFIG_DIR", &target.directory);
    } else {
        // Setting an explicit directory also changes Claude's .claude.json
        // location. Preserve the default installation's sibling-file layout.
        command.env_remove("CLAUDE_CONFIG_DIR");
    }
    let output = process::output(command, Duration::from_secs(15), OUTPUT_LIMIT).await?;
    // Native stderr may contain account diagnostics; do not copy it into status.
    ensure!(
        output.status.success(),
        "Claude session inspection failed; run claude agents --json --all in the selected profile for details"
    );
    let sessions = sessions::parse(&output.stdout)?;
    let running = sessions.iter().filter(|row| row.pid.is_some()).count();
    Ok(
        json!({"inspected":true,"source":"claude_agents","reported_running":running,
        "session_count":sessions.len(),"sessions":sessions,"gent_bindings_checked":false}),
    )
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
        Ok::<_, anyhow::Error>(observed)
    }
    .await;
    status["runtime"] =
        result.unwrap_or_else(|error| json!({"inspected":false,"error":format!("{error:#}")}));
    Ok(status)
}

#[cfg(test)]
mod tests;
