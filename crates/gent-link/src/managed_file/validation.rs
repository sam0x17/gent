//! Bounded retries for read-only validation of host-owned configuration.

use anyhow::Result;
use std::{fmt, path::PathBuf, time::Duration};

#[derive(Debug)]
pub struct SnapshotChanged(pub(super) PathBuf);

impl fmt::Display for SnapshotChanged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configuration changed; retry: {}", self.0.display())
    }
}

impl std::error::Error for SnapshotChanged {}

/// The caller must reread and validate every snapshot on each attempt. This
/// must never wrap file writes, RPCs, dispatch claims, or native submissions.
pub async fn retry_read<T>(mut validate: impl FnMut() -> Result<T>) -> Result<T> {
    for attempt in 0..3 {
        match validate() {
            Err(error) if attempt < 2 && error.is::<SnapshotChanged>() => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            result => return result,
        }
    }
    unreachable!("the final attempt always returns")
}

#[cfg(test)]
mod tests;
