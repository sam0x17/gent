use anyhow::{Context, Result, ensure};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
};

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        // Give cargo and its compiler children their own process group. On
        // cancellation, terminate that group before the child is reaped.
        if let Some(pid) = self.0.id()
            && let Some(pid) = rustix::process::Pid::from_raw(pid as i32)
        {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
        }
    }
}

pub(super) fn unattended(command: &mut Command) {
    command
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .process_group(0);
    command.env("GIT_TERMINAL_PROMPT", "0");
    if std::env::var_os("GIT_SSH_COMMAND").is_none() {
        command.env(
            "GIT_SSH_COMMAND",
            "ssh -o BatchMode=yes -o ConnectTimeout=10",
        );
    }
}

pub(super) async fn capture(
    command: &mut Command,
    limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
    unattended(command);
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut process = Running(command.spawn().context("cannot start update subprocess")?);
    tokio::time::timeout(timeout, async {
        let mut bytes = Vec::new();
        process
            .0
            .stdout
            .take()
            .unwrap()
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= limit,
            "update subprocess output exceeded its limit"
        );
        ensure!(
            process.0.wait().await?.success(),
            "update subprocess failed"
        );
        Ok::<_, anyhow::Error>(bytes)
    })
    .await
    .context("update subprocess timed out")?
}

pub(super) async fn build(command: &mut Command, log: &Path) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    unattended(command);
    command.stdout(Stdio::null()).stderr(Stdio::piped());
    // Replace the log through a private temporary file; never follow an old
    // log symlink or truncate an inode another path may share.
    let file = tempfile::NamedTempFile::new_in(log.parent().context("missing log directory")?)?;
    let file = file.persist(log).map_err(|error| error.error)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut process = Running(
        command
            .spawn()
            .context("cargo is unavailable; install Rust or configure its PATH")?,
    );
    tokio::time::timeout(Duration::from_secs(30 * 60), async {
        let mut stderr = process.0.stderr.take().unwrap();
        let mut buffer = [0; 8192];
        let mut remaining = 8 * 1024 * 1024;
        loop {
            let count = stderr.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            let saved = count.min(remaining);
            file.write_all(&buffer[..saved]).await?;
            remaining -= saved;
        }
        file.flush().await?;
        ensure!(
            process.0.wait().await?.success(),
            "cargo install failed; see the update build log"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("cargo install exceeded 30 minutes; the running installation was preserved")?
}
