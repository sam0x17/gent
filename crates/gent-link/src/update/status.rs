//! Report the CLI, installed binary and authenticated daemon independently.
use super::{
    build_info, config,
    install::{self, Installation},
};
use anyhow::Result;
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

pub(super) async fn report(home: &Path, installation: &Installation) -> Result<Value> {
    let probe = tokio::time::timeout(
        Duration::from_secs(2),
        crate::owner(home, gent_protocol::OwnerOp::Status),
    )
    .await;
    let (running, daemon) = match probe {
        Ok(Ok(status)) => (
            status.get("build").cloned().unwrap_or(Value::Null),
            json!({"reachable":true,"process_id":status["process_id"],"error":null}),
        ),
        Ok(Err(error)) => (
            Value::Null,
            json!({"reachable":false,"error":error.to_string()}),
        ),
        Err(_) => (
            Value::Null,
            json!({"reachable":false,"error":"daemon status timed out"}),
        ),
    };
    let pending = installation.pending()?;
    Ok(json!({
        "enabled":config::load(home)?.updates()?.enabled,
        "check_interval_seconds":300,
        "cli":build_info::current(),
        "running":running,
        "daemon":daemon,
        "installed":install::inspect(&installation.binary).await?,
        "update_in_progress":installation.try_lock()?.is_none(),
        "update":installation.status()?,
        "activation_pending":pending.is_some(),
        "activation_home":pending.as_ref().map(|p| &p.home),
        "activation_starting":pending.as_ref().map(|p| p.starting),
        "build_log":installation.directory.join("build.log"),
    }))
}
