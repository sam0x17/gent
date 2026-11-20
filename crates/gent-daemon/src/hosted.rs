//! A web node's local socket carries scoped RPCs to its native hosting daemon.
//! It owns no replicated store, sync loop, notification socket or updater.
pub use crate::store::hosted::snapshot::{
    Snapshot, export as checkpoint, export_for_epoch as checkpoint_for_epoch,
};
use crate::{config, connection};
use anyhow::{Context, Result, ensure};
use gent_protocol::{AgentOp, MAX_FRAME_BYTES, OwnerOp, Request, Response};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

fn wrap(request: Request, node: &str, gateway: &str, epoch: Option<u64>) -> Result<Request> {
    match request {
        Request::Agent { credential, action } => {
            ensure!(
                !matches!(
                    action,
                    AgentOp::FilePaths | AgentOp::FileImport { .. } | AgentOp::FileExport { .. }
                ),
                "local filesystem tools are unavailable to hosted chats"
            );
            Ok(Request::HostedAgent {
                node_id: node.into(),
                gateway_credential: gateway.into(),
                epoch,
                credential,
                action,
            })
        }
        Request::Owner {
            credential,
            action: OwnerOp::Status,
        } if credential == gateway => Ok(Request::HostedStatus {
            node_id: node.into(),
            gateway_credential: gateway.into(),
        }),
        _ => anyhow::bail!("operation unavailable on a hosted node"),
    }
}

async fn serve(
    stream: UnixStream,
    parent: &Path,
    node: &str,
    key: &str,
    epoch: Option<u64>,
) -> Result<()> {
    let mut stream = BufReader::new(stream);
    let mut frame = Vec::new();
    (&mut stream)
        .take(MAX_FRAME_BYTES as u64 + 1)
        .read_until(b'\n', &mut frame)
        .await?;
    ensure!(
        frame.len() <= MAX_FRAME_BYTES && frame.last() == Some(&b'\n'),
        "invalid hosted request"
    );
    let request = serde_json::from_slice(&frame)
        .map_err(anyhow::Error::from)
        .and_then(|request| wrap(request, node, key, epoch));
    let request = match request {
        Ok(request) => request,
        Err(_) => {
            let mut error = serde_json::to_vec(&Response::Error(
                "operation unavailable on a hosted node".into(),
            ))?;
            error.push(b'\n');
            stream.write_all(&error).await?;
            return Ok(());
        }
    };
    let mut upstream = connection::connect(parent, true).await?;
    let mut data = serde_json::to_vec(&request)?;
    data.push(b'\n');
    ensure!(data.len() <= MAX_FRAME_BYTES, "hosted request too large");
    upstream.write_all(&data).await?;
    // Keep buffered binary upload bytes, and stream both response phases. The
    // parent rechecks child membership and the chat credential at each commit.
    tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
    Ok(())
}

/// All web nodes supervised by one native daemon share this descriptor budget.
#[derive(Clone)]
pub struct ConnectionBudget(Arc<Semaphore>);

impl Default for ConnectionBudget {
    fn default() -> Self {
        Self(Arc::new(Semaphore::new(16)))
    }
}

pub async fn run(home: &Path, shutdown: impl std::future::Future<Output = ()>) -> Result<()> {
    run_with_budget(home, shutdown, ConnectionBudget::default()).await
}

pub async fn run_with_budget(
    home: &Path,
    shutdown: impl std::future::Future<Output = ()>,
    budget: ConnectionBudget,
) -> Result<()> {
    run_scoped(home, shutdown, budget, None).await
}

pub async fn run_with_epoch(
    home: &Path,
    shutdown: impl std::future::Future<Output = ()>,
    budget: ConnectionBudget,
    epoch: u64,
) -> Result<()> {
    run_scoped(home, shutdown, budget, Some(epoch)).await
}

async fn run_scoped(
    home: &Path,
    shutdown: impl std::future::Future<Output = ()>,
    budget: ConnectionBudget,
    epoch: Option<u64>,
) -> Result<()> {
    tokio::pin!(shutdown);
    let cfg = config::load_for_runtime(home)?;
    let parent = cfg
        .hosted_parent()?
        .context("web node has no hosting daemon")?;
    let host = config::load_for_runtime(&parent.home)?;
    ensure!(
        host.node.id == parent.node_id
            && host.cluster.id == cfg.cluster.id
            && host.hosted_parent()?.is_none(),
        "hosting daemon identity changed"
    );
    let _lock = config::state_lock(home, "daemon.lock")?;
    let key = Arc::new(zeroize::Zeroizing::new(config::read_private(
        &home.join("owner.key"),
    )?));
    crate::request(
        &parent.home,
        Request::HostedStatus {
            node_id: cfg.node.id.clone(),
            gateway_credential: (**key).clone(),
        },
    )
    .await?;
    let socket = home.join("daemon.sock");
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let permits = budget.0;
    let mut pending = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _=&mut shutdown=>break,
            _=pending.join_next(), if !pending.is_empty()=>{},
            accepted=listener.accept()=> {
                let (socket,_) = accepted?;
                let Ok(permit)=permits.clone().try_acquire_owned() else {continue;};
                let parent=parent.home.clone();
                let node=cfg.node.id.clone();
                let key=key.clone();
                pending.spawn(async move {
                    let _permit=permit;
                    let _=tokio::time::timeout(Duration::from_secs(35),serve(socket,&parent,&node,&key,epoch)).await;
                });
            }
        }
    }
    drop(listener);
    fs::remove_file(socket)?;
    while pending.join_next().await.is_some() {}
    Ok(())
}
