//! Bounded native CLI execution. Callers choose literal arguments and profile.

use anyhow::{Context, Result, ensure};
use std::{
    process::{Output, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};

async fn read(mut reader: impl AsyncRead + Unpin, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    (&mut reader)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() as u64 <= limit,
        "native command output exceeded its limit"
    );
    Ok(bytes)
}

pub(super) async fn output(mut command: Command, timeout: Duration, limit: u64) -> Result<Output> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("cannot execute native host; check --host-binary")?;
    let stdout = child.stdout.take().context("native stdout unavailable")?;
    let stderr = child.stderr.take().context("native stderr unavailable")?;
    let result = tokio::time::timeout(timeout, async {
        let (status, stdout, stderr) = tokio::try_join!(
            async { child.wait().await.map_err(anyhow::Error::from) },
            read(stdout, limit),
            read(stderr, limit)
        )?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    })
    .await
    .context("native command timed out")
    .and_then(|result| result);
    if result.is_err() {
        // Reap a failed bounded read rather than leaving it until runtime exit.
        let _ = child.kill().await;
    }
    result
}
