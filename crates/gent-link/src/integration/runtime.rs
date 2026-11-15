//! Native runtime observations and owner-invoked Codex startup. Hosts retain
//! lifecycle ownership; inspecting Claude never starts or resumes a session.
mod claude;
mod process;
use super::{Host, install};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::Command;

#[derive(clap::Args)]
pub struct Args {
    pub host: Host,
    /// Host configuration directory (defaults to CODEX_HOME or ~/.codex).
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
    /// Codex executable to use for a missing background server.
    #[arg(long, default_value = "codex")]
    pub host_binary: PathBuf,
}

async fn probe(socket: &Path) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(3), crate::wake::codex::inspect(socket))
        .await
        .context("Codex did not respond to the live probe")?
}

pub(crate) async fn status(
    home: &Path,
    host: Host,
    directory: Option<PathBuf>,
    binary: Option<&Path>,
) -> Result<Value> {
    if host == Host::ClaudeCode {
        return claude::status(
            home,
            directory,
            binary.unwrap_or_else(|| Path::new("claude")),
        )
        .await;
    }
    ensure!(
        binary.is_none(),
        "--host-binary applies to live Claude inspection; Codex uses its installed socket"
    );
    let mut status = install::status(home, Some(host), directory.clone())?;
    let result = async {
        let (_, socket) = install::codex_runtime_target(home, directory, false)?;
        probe(&socket).await
    }
    .await;
    status["runtime"] =
        result.unwrap_or_else(|e| json!({"connected":false,"error":format!("{e:#}")}));
    Ok(status)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeStart {
    status: String,
    socket_path: PathBuf,
    app_server_version: Option<String>,
}

async fn launch(binary: &Path, directory: &Path) -> Result<NativeStart> {
    let mut command = Command::new(binary);
    command
        .args(["app-server", "daemon", "start"])
        .env("CODEX_HOME", directory);
    let output = process::output(command, Duration::from_secs(60), 64 * 1024)
        .await
        .context(
            "Codex startup failed; inspect gent integration status codex --live before retrying",
        )?;
    ensure!(
        output.status.success(),
        "Codex startup failed: {}",
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(4096)
            .collect::<String>()
            .trim()
    );
    let value: NativeStart =
        serde_json::from_slice(&output.stdout).context("invalid Codex startup result")?;
    ensure!(
        matches!(value.status.as_str(), "started" | "alreadyRunning"),
        "unexpected Codex startup state"
    );
    Ok(value)
}

pub(crate) async fn start(home: &Path, args: Args) -> Result<Value> {
    ensure!(
        args.host == Host::Codex,
        "Gent startup currently supports Codex; start Claude Code normally"
    );
    let (directory, socket) = install::codex_runtime_target(home, args.config_dir, true)?;
    let (action, native, runtime) = match probe(&socket).await {
        Ok(runtime) => ("already_running", None, runtime),
        Err(error) => {
            // A missing/refused endpoint can be started by Codex. A responsive
            // but unsupported host, unsafe socket or timeout must not be replaced.
            ensure!(
                error
                    .chain()
                    .any(
                        |e| e.downcast_ref::<std::io::Error>().is_some_and(|e| matches!(
                            e.kind(),
                            ErrorKind::NotFound | ErrorKind::ConnectionRefused
                        ))
                    ),
                "existing Codex endpoint could not be verified: {error:#}"
            );
            let native = launch(&args.host_binary, &directory).await?;
            ensure!(
                native.socket_path == socket,
                "Codex started with an unexpected socket; inspect codex app-server daemon version"
            );
            let runtime = probe(&socket)
                .await
                .context("Codex started but its Gent endpoint could not be verified")?;
            let action = if native.status == "alreadyRunning" {
                "already_running"
            } else {
                "started"
            };
            (action, Some(native), runtime)
        }
    };
    let target = install::codex_runtime_target(home, Some(directory.clone()), true)?;
    ensure!(
        target == (directory.clone(), socket),
        "Codex integration changed during startup"
    );
    let mut status = install::status(home, Some(Host::Codex), Some(directory.clone()))?;
    status["action"] = action.into();
    status["runtime"] = runtime;
    status["native_start"] = json!(native);
    status["launch"] = json!({"command":args.host_binary,"args":["--remote","unix://"],"env":{"CODEX_HOME":directory}});
    status["next"] = "Open Codex with --remote unix:// using the displayed CODEX_HOME. Resume an existing conversation explicitly if needed.".into();
    Ok(status)
}

#[cfg(test)]
mod tests;
