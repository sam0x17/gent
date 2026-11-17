//! One-time, retryable migration of an existing cluster. The local daemon fences
//! the old signing key and retains the exact bootstrap before network admission.
use crate::{auth, owner};
use anyhow::{Context, Result, ensure};
use gent_daemon::config;
use gent_protocol::{OwnerOp, configuration_log::Bootstrap};
use serde_json::Value;
use std::{path::Path, time::Duration};

pub async fn upgrade(home: &Path) -> Result<Value> {
    let status = owner(home, OwnerOp::Status).await?;
    if status["authority"]["mode"] == "peers" {
        return Ok(status);
    }
    let cfg = config::load(home)?;
    let pin = cfg
        .service
        .as_ref()
        .context("ordered configuration requires a connected service cluster")?;
    let service = auth::Service::open_pinned(home, Some(pin)).await?;
    let bootstrap: Bootstrap =
        serde_json::from_value(owner(home, OwnerOp::PreparePeerConfiguration).await?)?;
    service.initialize_configuration(&bootstrap).await?;
    // Wake reconciliation again after provisioning; a daemon restart also
    // recovers this prepared transition without generating another bootstrap.
    owner(home, OwnerOp::PreparePeerConfiguration).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        let value = owner(home, OwnerOp::Status).await?;
        if value["authority"]["mode"] == "peers" {
            return Ok(value);
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "cluster upgrade is pending; rerun gent cluster upgrade to resume"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
