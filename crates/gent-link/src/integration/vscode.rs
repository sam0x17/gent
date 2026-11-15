//! Framing transport for the IDE's development-only executable override.
//! The IDE sends every protocol request, including initialization and approvals.
//! Gent does not reconnect, start hosts, alter fields or replay partial messages.
use super::{install, shell_arg};
use anyhow::{Context, Result, ensure};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

const LIMIT: usize = 8 * 1024 * 1024;
// Recognize the tested extension invocation. The already-running native server
// owns its configuration; these process flags are not reapplied by this bridge.
const INVOCATION: &[&str] = &[
    "-c",
    "features.code_mode_host=true",
    "-c",
    "features.windows_sandbox_service=true",
    "app-server",
    "--analytics-default-enabled",
];

#[derive(clap::Args)]
pub struct Args {
    #[arg(long)]
    pub config_dir: PathBuf,
    #[arg(long)]
    pub installation_id: String,
    #[arg(last = true)]
    pub invocation: Vec<OsString>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Installation {
    pub version: u8,
    pub id: String,
    pub settings: PathBuf,
}
impl Installation {
    pub fn new(settings: PathBuf) -> Self {
        Self {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            settings,
        }
    }
    pub fn validate(&self) -> Result<()> {
        let id = uuid::Uuid::parse_str(&self.id)?;
        ensure!(
            self.version == 1 && !id.is_nil() && id.to_string() == self.id,
            "unsupported Codex IDE installation"
        );
        ensure!(
            self.settings.is_absolute()
                && !self
                    .settings
                    .to_str()
                    .context("VS Code settings path must be UTF-8")?
                    .chars()
                    .any(char::is_control),
            "invalid VS Code settings path"
        );
        Ok(())
    }
    pub fn launcher(&self, home: &Path, binary: &Path, directory: &Path) -> Result<String> {
        self.validate()?;
        let parts = [
            binary.to_str().context("invalid Gent executable")?,
            "--home",
            home.to_str().context("invalid Gent home")?,
            "integration",
            "codex-ide",
            "--config-dir",
            directory.to_str().context("invalid Codex directory")?,
            "--installation-id",
            &self.id,
            "--",
        ];
        Ok(format!(
            "#!/bin/sh\n# Gent-managed Codex IDE transport v1\nexec {} \"$@\"\n",
            parts.map(shell_arg).join(" ")
        ))
    }
}

pub(super) fn settings_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    let path = if let Some(path) = explicit {
        path
    } else {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("cannot locate VS Code settings; pass --vscode-settings")?;
        if cfg!(target_os = "macos") {
            home.join("Library/Application Support/Code/User/settings.json")
        } else {
            std::env::var_os("XDG_CONFIG_HOME")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config"))
                .join("Code/User/settings.json")
        }
    };
    crate::managed_file::normalize(&path)
}

pub(crate) async fn execute(home: &Path, args: Args) -> Result<()> {
    ensure!(
        args.invocation
            .iter()
            .map(|s| s.to_str())
            .eq(INVOCATION.iter().map(|s| Some(*s))),
        "unsupported Codex IDE invocation; inspect the installed extension version before updating Gent"
    );
    let socket = install::codex_ide_target(home, &args.config_dir, &args.installation_id)?;
    let host = crate::wake::codex::connect_socket(&socket, LIMIT).await.context("start the selected Codex server with gent integration start codex before opening the IDE")?;
    transport(
        BufReader::new(tokio::io::stdin()),
        tokio::io::stdout(),
        host,
    )
    .await
}

async fn transport(
    input: impl AsyncBufRead + Unpin,
    output: impl AsyncWrite + Unpin,
    host: WebSocketStream<UnixStream>,
) -> Result<()> {
    let (mut sink, mut source) = host.split();
    let upstream = async {
        let mut input = input;
        let mut bytes = Vec::new();
        loop {
            let available = input.fill_buf().await?;
            if available.is_empty() {
                ensure!(bytes.is_empty(), "incomplete Codex IDE input at EOF");
                return Ok::<_, anyhow::Error>(());
            }
            let count = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |i| i + 1);
            ensure!(
                bytes.len() + count <= LIMIT,
                "Codex IDE input exceeds frame limit"
            );
            bytes.extend_from_slice(&available[..count]);
            input.consume(count);
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
                let text = std::str::from_utf8(&bytes).context("Codex IDE input is not UTF-8")?;
                // Check validity without logging content or reserializing it.
                ensure!(
                    serde_json::from_str::<serde_json::Value>(text).is_ok_and(|v| v.is_object()),
                    "invalid Codex IDE JSON message"
                );
                sink.send(Message::Text(text.to_owned().into())).await?;
                bytes.clear();
            }
        }
    };
    let downstream = async {
        let mut output = output;
        while let Some(frame) = source.next().await {
            match frame? {
                Message::Text(text) => {
                    ensure!(
                        !text.contains(['\n', '\r'])
                            && serde_json::from_str::<serde_json::Value>(&text)
                                .is_ok_and(|v| v.is_object()),
                        "invalid Codex IDE server message"
                    );
                    output.write_all(text.as_bytes()).await?;
                    output.write_all(b"\n").await?;
                    output.flush().await?;
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
                _ => anyhow::bail!("unexpected Codex IDE server frame"),
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! { result = upstream => result, result = downstream => result }
}

#[cfg(test)]
mod tests;
