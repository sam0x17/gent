//! Service reconciliation follows an already committed signed removal. It can
//! fail or be cancelled at any await without losing the native cleanup intent.
use crate::{auth, cluster, owner};
use anyhow::{Context, Result, ensure};
use gent_daemon::config::{self, ServiceConfig};
use gent_protocol::OwnerOp;
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

/// Give newly requested probes time to return. Cached inventory reads used by
/// background services never trigger a probe or wait on a remote machine.
pub async fn connections(home: &Path) -> Result<Value> {
    let mut nodes = owner(home, OwnerOp::RefreshNodes).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline
        && nodes.as_array().is_some_and(|rows| {
            rows.iter()
                .any(|n| n["status"] == "unknown" && n["presence"]["probe_started_at"].is_i64())
        })
    {
        tokio::time::sleep(Duration::from_millis(150)).await;
        nodes = owner(home, OwnerOp::Nodes).await?;
    }
    Ok(nodes)
}

async fn reconcile(home: &Path, removal: &Value) -> Result<Value> {
    if removal["service_status"] != "pending" {
        return Ok(removal.clone());
    }
    let pin: ServiceConfig = serde_json::from_value(removal["service"].clone())?;
    pin.validate()?;
    let cfg = config::load(home)?;
    let installed = cluster::installation(home)?.context("service setup journal is missing")?;
    ensure!(
        !installed.pending
            && cfg.service.as_ref() == Some(&pin)
            && removal["cluster_id"] == cfg.cluster.id,
        "node removal is pinned to its original cluster, owner, service and account"
    );
    let node = removal["node_id"]
        .as_str()
        .context("missing removed node ID")?;
    let revision = removal["revision"]
        .as_u64()
        .context("missing removal revision")?;
    ensure!(node != cfg.node.id, "cannot revoke this node from itself");
    let service = auth::Service::open_pinned(home, Some(&pin)).await?;
    service.revoke_node(&cfg.cluster.id, node).await?;
    owner(
        home,
        OwnerOp::ConfirmNodeRemoval {
            node_id: node.into(),
            revision,
        },
    )
    .await
}

pub async fn remove(home: &Path, node: String) -> Result<Value> {
    // Read-only check before membership mutation. No account access is needed
    // to commit a removal while offline.
    cluster::installation(home)?;
    let mut removal = owner(
        home,
        OwnerOp::RemoveNode {
            node_id: node.clone(),
        },
    )
    .await?;
    if removal["state"] == "queued" {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while removal["state"] == "queued" && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
            removal = owner(
                home,
                OwnerOp::RemoveNode {
                    node_id: node.clone(),
                },
            )
            .await?;
        }
        if removal["state"] == "queued" {
            return Ok(removal);
        }
    }
    ensure!(
        removal["state"] != "rejected",
        "node removal rejected: {}",
        removal["reason"]
    );
    match reconcile(home, &removal).await {
        Ok(value) => Ok(value),
        Err(error) => {
            let mut result = removal;
            result["service_error"] = json!(error.to_string());
            result["retry"] =
                json!("gent node remove NODE_ID; authorized node daemons also retry while running");
            Ok(result)
        }
    }
}

pub async fn maintain(home: &Path) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_error = None;
    let mut cursor = None;
    loop {
        interval.tick().await;
        let outcome = async {
            let cfg = config::load(home)?;
            if cfg.service.is_none() {
                return Ok(());
            }
            if !cluster::installation(home)?.is_some_and(|i| !i.pending) {
                return Ok(());
            }
            let page = owner(
                home,
                OwnerOp::NodeRemovals {
                    after: cursor.clone(),
                    pending_only: true,
                },
            )
            .await?;
            let removals = page["removals"]
                .as_array()
                .context("invalid removal list")?;
            let mut failure = None;
            // Limit each pass and move past failures so one pending node cannot
            // starve other removals. Wrap after the end of the journal.
            for removal in removals.iter().take(16) {
                cursor = removal["node_id"].as_str().map(str::to_owned);
                if let Err(error) = reconcile(home, removal).await {
                    failure = Some(error);
                }
            }
            if removals.len() <= 16 && page["next"].is_null() {
                cursor = None;
            }
            if let Some(error) = failure {
                return Err(error);
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        match outcome {
            Ok(()) => last_error = None,
            Err(error) => {
                let error = error.to_string();
                if last_error.as_ref() != Some(&error) {
                    eprintln!("Gent node removal pending: {error}");
                    last_error = Some(error);
                }
            }
        }
    }
}
