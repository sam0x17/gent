//! Resolve the web identity in signed membership. The bridge dispatches to the
//! live lease holder, including when the caller has never hosted the connector.
use super::*;
use failover::client::Client;
use gent_protocol::{
    hosted_mcp::{ConnectorAction, valid_id},
    web_failover::Control,
};

pub(super) fn resolve<'a>(directory: &'a Value, selector: &str) -> Result<Option<&'a Value>> {
    let Some(node) = crate::node::find_member(directory, selector)? else {
        return Ok(None);
    };
    ensure!(
        node["hosted_by"].is_string(),
        "name belongs to a native node"
    );
    Ok(Some(node))
}

pub(super) async fn execute(
    parent: &Path,
    node: &Value,
    out: Option<&Path>,
    rotate: bool,
    revoke: bool,
) -> Result<Value> {
    let id = node["id"]
        .as_str()
        .filter(|id| valid_id(id))
        .context("invalid web node identity")?;
    let client = Client::new(parent, id)?;
    let mut response = json!({"name":node["name"],"node_id":id,"web_node":true});
    if revoke {
        let (status, _) = client.call(&Control::RevokeConnector).await?;
        ensure!(
            matches!(status, 200 | 410),
            "cluster rejected connector revocation ({status})"
        );
        response["revoked"] = true.into();
        return Ok(response);
    }
    let cluster = node_home::inspect(parent)?.cluster.id;
    let mut pending = None;
    let mut lock = None;
    let action = if rotate {
        let dir = parent.join("web-management");
        config::private_dir(&dir)?;
        lock = Some(managed_file::lock(
            &dir.join(format!("{cluster}-{id}.lock")),
        )?);
        let file = dir.join(format!("{cluster}-{id}.json"));
        let snapshot = managed_file::Snapshot::read(&file)?;
        snapshot.private()?;
        let expected = if let Some(hash) = snapshot.text.as_deref() {
            hash.to_owned()
        } else {
            let hash = client.manage(&ConnectorAction::Fingerprint).await?;
            snapshot.write(&hash)?;
            hash
        };
        pending = Some(file);
        ConnectorAction::Rotate { expected }
    } else {
        ConnectorAction::Url
    };
    ensure!(action.valid(), "invalid pending connector rotation");
    let url = client.manage(&action).await?;
    let base =
        gent_protocol::hosted_mcp::node_base(&cluster, id).context("invalid connector identity")?;
    ensure!(
        url.strip_prefix(&format!("{}{base}", origin(parent)?))
            .and_then(gent_protocol::hosted_mcp::capability_token)
            .is_some(),
        "connector URL scope mismatch"
    );
    response["rotated"] = rotate.into();
    let value = output_url(response, &url, out)?;
    if let Some(file) = pending {
        managed_file::Snapshot::read(&file)?.remove()?;
    }
    drop(lock);
    Ok(value)
}

pub(super) async fn update_status(parent: &Path, row: &mut Value) {
    let Some(id) = row["node_id"].as_str() else {
        return;
    };
    let result = async {
        Client::new(parent, id)?
            .manage(&ConnectorAction::Status)
            .await
    }
    .await;
    match result.as_deref() {
        Ok(status @ ("ready" | "offline" | "revoked")) => {
            row["ready"] = (status == "ready").into();
            row["revoked"] = (status == "revoked").into();
        }
        _ => {
            row["ready"] = Value::Null;
            row["revoked"] = Value::Null;
        }
    }
}
