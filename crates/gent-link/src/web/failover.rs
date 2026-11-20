//! A named web connector can move between authorized native cluster nodes.
pub(super) mod client;
mod session;
mod standby;
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use client::Client;
use gent_protocol::web_failover::{CHUNK_BYTES, Control, Lease, MAX_BATCH, MAX_CHUNKS};
use serde::{Deserialize, Serialize};
pub(crate) use session::Session;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub(crate) fn passive_echo(headers: &axum::http::HeaderMap) -> Result<bool> {
    let all = headers.get_all(gent_protocol::hosted_mcp::PASSIVE_HEADER);
    let mut values = all.iter();
    let Some(value) = values.next() else {
        return Ok(false);
    };
    ensure!(
        value == "1" && values.next().is_none(),
        "invalid web passive negotiation"
    );
    Ok(true)
}

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
    epoch: u64,
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
    let file = home.join("restore-checkpoint.json");
    let snapshot = managed_file::Snapshot::read(&file)?;
    snapshot.private()?;
    snapshot.write(&serde_json::to_string(&bundle.snapshot)?)?;
    owner(
        parent,
        OwnerOp::RestoreWebNode {
            epoch: Some(epoch),
            node_id: node.into(),
            home: home.into(),
            checkpoint: file.clone(),
        },
    )
    .await?;
    gateway::registry::portable::restore(home, &mut bundle.registry)?;
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
    let client = Arc::new(Client::new(parent, node)?);
    // Serialize this node's registry restore, active filesystem operations and
    // release, even when two supervisors resolve different local homes.
    let locks = parent.join("web-carriers");
    config::private_dir(&locks)?;
    let files = Arc::new(config::state_lock(&locks, &format!("{node}.lock"))?);
    let mut invitation = None;
    let (lease, passive, started) = loop {
        let started = crate::auth::now()?;
        let (status, bytes, passive) = tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            result = client.acquire(create) => result?,
        };
        // Hold the invited socket until the bridge processes this acquire.
        drop(invitation.take());
        match status {
            200 => break (serde_json::from_slice::<Lease>(&bytes)?, passive, started),
            409 if passive => tokio::select! {
                _ = stop.cancelled() => return Ok(()),
                result = Box::pin(standby::invited(&client)) => invitation = Some(Box::new(result?)),
            },
            404 | 409 | 410 => return Ok(()),
            _ => anyhow::bail!("web carrier admission unavailable"),
        }
    };
    ensure!(
        lease.epoch > 0 && !lease.revoked && lease.owner == node_home::inspect(parent)?.node.id,
        "invalid web carrier admission"
    );
    let session = Arc::new(Session::new(
        client.clone(),
        home.into(),
        &lease,
        passive,
        files,
    ));
    // Both negotiation modes own these phases. Keep their state on the heap
    // before moving it through select and the long-lived grant supervisor.
    let start = Box::pin(async {
        config::edit_local(parent, |cfg| cfg.enable_portable_web())?;
        if home.join("config.toml").exists() {
            config::edit_local(home, |cfg| cfg.enable_portable_web())?;
        }
        if lease.checkpoint.is_some() {
            restore(
                parent,
                home,
                node,
                name,
                lease.epoch,
                download(&client, &lease).await?,
            )
            .await?;
        }
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
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        // Seed the existing URL and all its handles before accepting web calls.
        session.flush().await
    });
    let serve = Box::pin(async {
        let daemon_stop = CancellationToken::new();
        let gateway_stop = CancellationToken::new();
        crate::lifecycle::run(
            Box::pin(gent_daemon::hosted::run_with_epoch(
                home,
                daemon_stop.clone().cancelled_owned(),
                budget,
                lease.epoch,
            )),
            Box::pin(gateway::run_web(
                home.into(),
                gateway_stop.clone(),
                Some(session.clone()),
            )),
            Box::pin(session.maintain(stop.clone())),
            stop.cancelled(),
            daemon_stop,
            gateway_stop,
        )
        .await
    });
    let result = {
        let active = async {
            let until = session.acquired(&lease, started).await?;
            let starting = Box::pin(async {
                tokio::select! {
                    _ = stop.cancelled() => anyhow::bail!("web startup cancelled"),
                    result = start => result,
                }
            });
            if passive {
                session.while_granted(until, starting).await?;
                serve.await
            } else {
                session
                    .while_granted(
                        until,
                        Box::pin(async {
                            starting.await?;
                            serve.await
                        }),
                    )
                    .await
            }
        };
        tokio::select! {
            result = active => result,
            _ = session.lost.cancelled() => Err(anyhow::anyhow!("web carrier grant lost")),
        }
    };
    stop.cancel();
    let fenced = owner(
        parent,
        OwnerOp::WebGrant {
            node_id: node.into(),
            epoch: lease.epoch,
            expires_at: 0,
        },
    )
    .await;
    // Invite another standby only after this daemon has fenced its effects.
    // If the local fence fails the bridge must honor the outstanding grant.
    if let Err(error) = fenced {
        // A prior parent restart or a newer epoch can already have fenced us.
        // Release this cloud epoch so a legacy same-owner Acquire cannot keep
        // extending a grant the native daemon will never accept.
        let state = owner(
            parent,
            OwnerOp::WebCheckpoint {
                node_id: node.into(),
            },
        )
        .await?;
        if !state["epoch"].as_u64().is_some_and(|epoch| {
            epoch > lease.epoch
                || (epoch == lease.epoch && state["lease_until"].as_u64() == Some(0))
        }) {
            return Err(error);
        }
    }
    let (status, _) = client
        .call(&Control::Release { epoch: lease.epoch })
        .await?;
    ensure!(
        matches!(status, 200 | 204 | 409 | 410),
        "web carrier release failed"
    );
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
                let client = Client::new(parent, node)?;
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
    let client = Client::new(parent, node)?;
    let (status, bytes) = client.call(&Control::Inspect).await?;
    if status == 404 {
        return Ok(None);
    }
    ensure!(status == 200, "web checkpoint status unavailable");
    Ok(Some(serde_json::from_slice(&bytes)?))
}
