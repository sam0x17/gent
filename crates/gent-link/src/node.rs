//! Cluster node selection, signed configuration and service reconciliation.
use crate::{auth, cluster, owner};
use anyhow::{Context, Result, ensure};
use gent_daemon::config::{self, ServiceConfig};
use gent_protocol::{ConfigurationEdit, OwnerOp};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

pub(crate) fn find_member<'a>(directory: &'a Value, selector: &str) -> Result<Option<&'a Value>> {
    let nodes = directory
        .as_array()
        .context("invalid cluster node directory")?;
    if let Some(node) = nodes.iter().find(|n| n["id"] == selector) {
        return Ok(Some(node));
    }
    let matches = nodes
        .iter()
        .filter(|n| n["name"] == selector)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [node] => Ok(Some(node)),
        _ => {
            let ids = matches
                .iter()
                .map(|n| n["id"].as_str().context("missing node ID"))
                .collect::<Result<Vec<_>>>()?;
            anyhow::bail!(
                "ambiguous node name; select one of these IDs: {}",
                ids.join(", ")
            )
        }
    }
}

pub(crate) fn resolve_id<'a>(directory: &'a Value, selector: &str) -> Result<&'a str> {
    find_member(directory, selector)?
        .context("unknown node; run gent nodes to see enrolled nodes")?["id"]
        .as_str()
        .context("missing node ID")
}

/// Submit a rename by signed member ID. An identical retry uses the same request UUID.
pub(crate) async fn rename(
    home: &Path,
    request_id: &str,
    node_id: &str,
    new_name: &str,
) -> Result<Value> {
    crate::configure(
        home,
        request_id,
        ConfigurationEdit::RenameMember {
            node_id: node_id.into(),
            name: new_name.into(),
        },
    )
    .await
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_signed_members_by_exact_id_or_unique_name() {
        let nodes = json!([
            {"id":"a", "name":"shared"},
            {"id":"b", "name":"shared"},
            {"id":"c", "name":"studio", "hosted_by":"b"},
            {"id":"d", "name":"a"}
        ]);
        assert!(
            resolve_id(&nodes, "shared")
                .unwrap_err()
                .to_string()
                .contains("a, b")
        );
        assert!(resolve_id(&nodes, "missing").is_err());
        assert_eq!(resolve_id(&nodes, "studio").unwrap(), "c");
        // An ID wins even if another node has that name.
        assert_eq!(resolve_id(&nodes, "a").unwrap(), "a");
    }
}
