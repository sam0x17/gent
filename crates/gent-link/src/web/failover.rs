//! A named web connector can move between authorized native cluster nodes.
pub(super) mod client;
mod session;
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use client::Client;
use gent_protocol::web_failover::{CHUNK_BYTES, Control, Lease, MAX_BATCH, MAX_CHUNKS};
use serde::{Deserialize, Serialize};
pub(crate) use session::Session;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    version: u8,
    snapshot: gent_daemon::hosted::Snapshot,
    registry: gateway::registry::portable::Checkpoint,
}

async fn download(client: &Client, lease: &Lease) -> Result<Bundle> {
    let checkpoint = lease
        .checkpoint
        .as_ref()
        .context("web checkpoint missing")?;
    ensure!(checkpoint.valid(), "invalid web checkpoint");
    let mut bytes = Vec::with_capacity(checkpoint.bytes);
    for start in (0..checkpoint.chunks).step_by(MAX_BATCH) {
        let parts: Vec<String> = client
            .required(&Control::Read {
                generation: checkpoint.generation,
                start,
            })
            .await?;
        ensure!(
            parts.len() == MAX_BATCH.min(checkpoint.chunks - start),
            "web checkpoint has a gap"
        );
        for part in parts {
            let part = STANDARD.decode(part)?;
            ensure!(
                part.len() <= CHUNK_BYTES && bytes.len() + part.len() <= checkpoint.bytes,
                "web checkpoint exceeds limits"
            );
            bytes.extend(part);
        }
    }
    ensure!(
        bytes.len() == checkpoint.bytes
            && format!("{:x}", Sha256::digest(&bytes)) == checkpoint.sha256,
        "web checkpoint digest mismatch"
    );
    let bundle: Bundle = serde_json::from_slice(&bytes)?;
    ensure!(
        bundle.version == 1 && bundle.snapshot.node == client.node,
        "web checkpoint identity changed"
    );
    Ok(bundle)
}

async fn restore(
    parent: &Path,
    home: &Path,
    node: &str,
    name: &str,
    mut bundle: Bundle,
) -> Result<()> {
    let cfg = node_home::inspect(parent)?;
    ensure!(
        bundle.snapshot.cluster == cfg.cluster.id,
        "web checkpoint belongs to another cluster"
    );
    config::private_dir(home)?;
    if home.join("config.toml").exists() {
        let existing = node_home::inspect(home)?;
        ensure!(
            existing.node.id == node && existing.cluster.id == cfg.cluster.id,
            "web checkpoint destination belongs to another identity"
        );
    }
    let mut child = cfg.clone();
    child.node.id = node.into();
    child.node.name = name.into();
    child.extra.clear();
    child.service = None;
    child.set_hosted_parent(config::HostedParent {
        home: parent.into(),
        node_id: cfg.node.id.clone(),
    })?;
    child.enable_portable_web()?;
    // The local socket secret belongs only to this carrier and is never copied.
    let secret = managed_file::Snapshot::read(&home.join("owner.key"))?;
    secret.private()?;
    if secret.text.is_none() {
        secret.write(&config::secret())?;
    }
    config::save(home, &child)?;
    gateway::registry::portable::restore(home, &mut bundle.registry)?;
    let file = home.join("restore-checkpoint.json");
    let snapshot = managed_file::Snapshot::read(&file)?;
    snapshot.private()?;
    snapshot.write(&serde_json::to_string(&bundle.snapshot)?)?;
    owner(
        parent,
        OwnerOp::RestoreWebNode {
            node_id: node.into(),
            home: home.into(),
            checkpoint: file.clone(),
        },
    )
    .await?;
    managed_file::Snapshot::read(&file)?.remove()?;
    storage::save(
        home,
        &Record {
            version: 1,
            cluster: cfg.cluster.id,
            parent: cfg.node.id,
            name: name.into(),
            node: Some(node.into()),
            revoked: false,
        },
    )?;
    Ok(())
}

pub(super) async fn run(
    parent: &Path,
    home: &Path,
    node: &str,
    name: &str,
    create: bool,
    stop: CancellationToken,
    budget: gent_daemon::hosted::ConnectionBudget,
) -> Result<()> {
    let client = Arc::new(Client::new(parent, node, ORIGIN)?);
    let (status, bytes) = client.call(&Control::Acquire { create }).await?;
    if matches!(status, 404 | 409 | 410) {
        return Ok(());
    }
    ensure!(status == 200, "web carrier admission unavailable");
    let lease: Lease = serde_json::from_slice(&bytes)?;
    config::edit_local(parent, |cfg| cfg.enable_portable_web())?;
    if home.join("config.toml").exists() {
        config::edit_local(home, |cfg| cfg.enable_portable_web())?;
    }
    let session = Arc::new(Session::new(client.clone(), home.into(), &lease));
    let heartbeat = session.heartbeat(stop.clone());
    let serve = async {
        if lease.checkpoint.is_some() {
            restore(parent, home, node, name, download(&client, &lease).await?).await?;
        }
        owner(
            parent,
            OwnerOp::WebLease {
                node_id: node.into(),
                seconds: 20,
            },
        )
        .await?;
        let request = gent_crypto::scoped_id(
            b"gent/web-takeover/v1\0",
            &[node.as_bytes(), &lease.epoch.to_be_bytes()],
        )
        .to_string();
        let cfg = node_home::inspect(parent)?;
        let nodes = owner(parent, OwnerOp::Nodes).await?;
        if !nodes.as_array().is_some_and(|nodes| {
            nodes
                .iter()
                .any(|n| n["id"] == node && n["hosted_by"] == cfg.node.id)
        }) {
            let result = owner(
                parent,
                OwnerOp::Configure {
                    request_id: request.clone(),
                    edit: gent_protocol::ConfigurationEdit::HostNode {
                        node_id: node.into(),
                        parent: cfg.node.id.clone(),
                    },
                },
            )
            .await?;
            ensure!(result["state"] != "rejected", "web route takeover rejected");
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            let nodes = owner(parent, OwnerOp::Nodes).await?;
            if nodes.as_array().is_some_and(|nodes| {
                nodes
                    .iter()
                    .any(|n| n["id"] == node && n["hosted_by"] == cfg.node.id)
            }) {
                break;
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "web route synchronization pending"
            );
            tokio::select! {_=stop.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_millis(500))=>{}}
        }
        // Seed the existing URL and all its handles before accepting web calls.
        session.flush().await?;
        let daemon_stop = CancellationToken::new();
        let gateway_stop = CancellationToken::new();
        crate::lifecycle::run(
            gent_daemon::hosted::run_with_budget(
                home,
                daemon_stop.clone().cancelled_owned(),
                budget,
            ),
            gateway::run_web(home.into(), gateway_stop.clone(), Some(session.clone())),
            session.maintain(stop.clone()),
            stop.cancelled(),
            daemon_stop,
            gateway_stop,
        )
        .await
    };
    tokio::pin!(heartbeat, serve);
    let result = tokio::select! {result=&mut heartbeat=>result,result=&mut serve=>result};
    stop.cancel();
    let _ = owner(
        parent,
        OwnerOp::WebLease {
            node_id: node.into(),
            seconds: 0,
        },
    )
    .await;
    // Expiry fences a crashed connection even when release cannot reach the service.
    let _ = client.call(&Control::Release { epoch: lease.epoch }).await;
    result
}

pub(super) async fn management(parent: &Path, home: &Path, node: &str, revoke: bool) -> Result<()> {
    let marker = gateway::registry::portable::mark_management(home)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(status) = gateway::control::probe(home).await
            && status["checkpoint_management"] == marker
        {
            if revoke {
                let epoch = status["carrier_epoch"]
                    .as_u64()
                    .context("web carrier lease unavailable")?;
                let client = Client::new(parent, node, ORIGIN)?;
                let (status, _) = client.call(&Control::Disable { epoch }).await?;
                ensure!(
                    matches!(status, 200 | 410),
                    "connector revocation is pending; retry on its active carrier"
                );
            }
            return Ok(());
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "web management checkpoint pending; retry on the active carrier"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub(super) async fn status(parent: &Path, node: &str) -> Result<Option<Lease>> {
    let client = Client::new(parent, node, ORIGIN)?;
    let (status, bytes) = client.call(&Control::Inspect).await?;
    if status == 404 {
        return Ok(None);
    }
    ensure!(status == 200, "web checkpoint status unavailable");
    Ok(Some(serde_json::from_slice(&bytes)?))
}
