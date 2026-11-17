//! Manual requests wait for the existing updater; scheduled checks skip it.
use super::install::Installation;
use anyhow::{Context, Result};
use std::{fs::File, time::Duration};

pub(super) async fn acquire(installation: &Installation, automatic: bool) -> Result<Option<File>> {
    if let Some(lock) = installation.try_lock()? {
        return Ok(Some(lock));
    }
    if automatic {
        return Ok(None);
    }
    let _progress = crate::ui::Progress::start("Waiting for running update; Ctrl-C stops waiting");
    // A build is bounded at 30 minutes. Leave room for discovery, verification
    // and publication, but do not hide an indefinitely held lock.
    tokio::time::timeout(Duration::from_secs(35 * 60), async {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if let Some(lock) = installation.try_lock()? {
                return Ok(Some(lock));
            }
        }
    })
    .await
    .context(
        "update is still busy after 35 minutes; run gent update status and inspect its build log",
    )?
}
