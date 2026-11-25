//! Report the CLI, installed binary and authenticated daemon independently.
use super::{
    ReleaseRef, build_info, config,
    install::{self, Installation},
};
use anyhow::Result;
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

// Status must remain readable during a channel lookup failure, particularly
// when an operator is diagnosing an older daemon's pending activation.
pub(super) fn with_channel(home: &Path, mut report: Value) -> Value {
    match ReleaseRef::current(home) {
        Ok(channel) => {
            report["channel"] = json!(channel.channel);
            report["release_ref"] = json!(channel.reference);
        }
        Err(error) => {
            report["channel"] = Value::Null;
            report["release_ref"] = Value::Null;
            report["channel_error"] = json!(error.to_string());
        }
    }
    report
}

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
    let applied = installation.applied_channel(home);
    Ok(with_channel(
        home,
        json!({
            "applied_channel":applied.as_ref().ok(),
            "applied_channel_error":applied.as_ref().err().map(|_| "cannot read the applied release channel"),
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
            "integrations":crate::integration::refresh::status(home).unwrap_or_else(|e| json!({"state":"needs_attention","error":e.to_string()})),
        }),
    ))
}
