//! Reconnect before sending any request bytes across a short daemon restart.
use anyhow::{Context, Result};
use std::{io::ErrorKind, path::Path, time::Duration};
use tokio::{net::UnixStream, time::Instant};

pub(crate) async fn connect(home: &Path, wait_for_restart: bool) -> Result<UnixStream> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match UnixStream::connect(home.join("daemon.sock")).await {
            Ok(socket) => return Ok(socket),
            Err(error)
                if wait_for_restart
                    && matches!(
                        error.kind(),
                        ErrorKind::NotFound | ErrorKind::ConnectionRefused
                    )
                    && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => {
                return Err(error)
                    .context("daemon unavailable; run gent daemon start or gent daemon run");
            }
        }
    }
}
