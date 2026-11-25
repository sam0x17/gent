//! Native daemon with local agent RPC and encrypted configuration/message sync.
mod access;
pub mod config;
pub mod configuration_log;
mod connection;
pub mod encrypted;
pub mod entitlements;
pub mod file_objects;
pub mod file_transport;
pub mod hosted;
pub mod invitation_transport;
pub mod messages;
pub mod pairing;
mod receive;
pub mod recovery;
pub mod release_channel;
pub mod replica;
mod runtime;
pub mod shutdown;
mod storage;
pub use receive::receive_file;
pub mod store;
pub mod sync;

use anyhow::{Context, Result, ensure};
use gent_protocol::{MAX_FRAME_BYTES, Request, Response};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};

pub async fn request(home: &Path, request: Request) -> Result<serde_json::Value> {
    recovery::ensure_active(home)?;
    let timeout = if matches!(
        &request,
        Request::Owner {
            action: gent_protocol::OwnerOp::HistoryImport { .. }
                | gent_protocol::OwnerOp::AgentRecover { .. },
            ..
        }
    ) {
        Duration::from_secs(185)
    } else {
        Duration::from_secs(15)
    };
    let operation = async {
        // Status is a liveness probe used by service management and must report
        // a stopped daemon immediately. Ordinary calls bridge a brief restart.
        let probe = matches!(
            &request,
            Request::Owner {
                action: gent_protocol::OwnerOp::Status,
                ..
            }
        );
        let mut socket = connection::connect(home, !probe).await?;
        let mut data = serde_json::to_vec(&request)?;
        data.push(b'\n');
        ensure!(data.len() <= MAX_FRAME_BYTES, "request too large");
        socket.write_all(&data).await?;
        let mut data = Vec::new();
        BufReader::new(socket.take(MAX_FRAME_BYTES as u64 + 1))
            .read_until(b'\n', &mut data)
            .await?;
        ensure!(
            data.len() <= MAX_FRAME_BYTES && data.last() == Some(&b'\n'),
            "invalid daemon response"
        );
        match serde_json::from_slice(&data)? {
            Response::Ok(value) => Ok(value),
            Response::Error(message) => Err(anyhow::anyhow!(message)),
        }
    };
    tokio::time::timeout(timeout, operation)
        .await
        .context("daemon request timed out")?
}

pub async fn run(home: &Path) -> Result<()> {
    run_until(home, std::future::pending()).await
}

/// Ownership acquired before update recovery or opening the node database.
pub struct DaemonLock {
    home: std::path::PathBuf,
    _file: fs::File,
    build_info: serde_json::Value,
}

impl DaemonLock {
    pub fn acquire(home: &Path) -> Result<Self> {
        recovery::ensure_active(home)?;
        config::private_dir(home)?;
        Ok(Self {
            home: home.to_owned(),
            _file: config::state_lock(home, "daemon.lock")?,
            build_info: serde_json::Value::Null,
        })
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Executable metadata reported only by authenticated owner status calls.
    pub fn with_build_info(mut self, build_info: serde_json::Value) -> Self {
        self.build_info = build_info;
        self
    }
}

/// A cooperative update stops accepting new RPCs, drains accepted requests,
/// and waits for in-progress database transactions before releasing ownership.
pub async fn run_until(home: &Path, shutdown: impl std::future::Future<Output = ()>) -> Result<()> {
    run_locked(DaemonLock::acquire(home)?, shutdown).await
}

pub async fn run_locked(
    lock: DaemonLock,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    run_locked_until(lock, shutdown::with_signals(shutdown)?).await
}

/// Run until the caller requests shutdown, without installing signal handlers.
/// Supervisors use this to drain dependent services before stopping native RPC.
pub async fn run_locked_until(
    lock: DaemonLock,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    tokio::pin!(shutdown);
    let home = lock.home();
    let build_info = Arc::new(lock.build_info.clone());
    let store = Arc::new(Mutex::new(store::Store::open(home)?));
    let socket = home.join("daemon.sock");
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let permits = Arc::new(Semaphore::new(32));
    let uploads = Arc::new(Semaphore::new(2));
    let mut maintenance = tokio::time::interval(Duration::from_secs(15 * 60));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut maintenance_tasks = tokio::task::JoinSet::new();
    let mut requests = tokio::task::JoinSet::new();
    let mut busy = serde_json::to_vec(&Response::Error(
        "daemon is busy; retry the same request".into(),
    ))?;
    busy.push(b'\n');
    let sync_task = sync::start(store.clone())?;
    let invitation_task = invitation_transport::owner::start(store.clone());
    eprintln!("Gent daemon listening at {}", socket.display());
    loop {
        tokio::select! {
            _=&mut shutdown=>break,
            _=maintenance.tick(), if maintenance_tasks.is_empty()=> {
                let store = store.clone();
                maintenance_tasks.spawn(access::run(store, "maintenance", |store| store.maintain()));
            }
            result=maintenance_tasks.join_next(), if !maintenance_tasks.is_empty()=> {
                if let Some(result) = result
                    && let Err(error) = result? {
                    eprintln!("Gent configuration maintenance pending: {error}");
                }
            }
            _=requests.join_next(), if !requests.is_empty()=> {}
            connection=listener.accept()=> {
                let (stream,_)=connection?;
                let Ok(permit)=permits.clone().try_acquire_owned() else {
                    let _ = stream.try_write(&busy);
                    continue;
                };
                let store=store.clone();
                let uploads=uploads.clone();
                let build_info=build_info.clone();
                requests.spawn(async move {
                    let _=serve(stream,store,uploads,permit,build_info).await;
                });
            }
        }
    }
    drop(listener);
    fs::remove_file(&socket)?;
    if let Some(task) = sync_task {
        task.abort();
        let _ = task.await;
    }
    invitation_task.stop().await;
    // Request handlers already enforce their own deadlines. Dropping them here
    // could lose the response after a committed send; let accepted RPCs finish.
    while requests.join_next().await.is_some() {}
    while maintenance_tasks.join_next().await.is_some() {}
    access::run(store, "shutdown", |_| Ok(())).await?;
    Ok(())
}

async fn serve(
    stream: UnixStream,
    store: Arc<Mutex<store::Store>>,
    uploads: Arc<Semaphore>,
    permit: OwnedSemaphorePermit,
    build_info: Arc<serde_json::Value>,
) -> Result<()> {
    let started = tokio::time::Instant::now();
    let mut stream = BufReader::new(stream);
    let mut frame = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        (&mut stream)
            .take(MAX_FRAME_BYTES as u64 + 1)
            .read_until(b'\n', &mut frame),
    )
    .await
    .context("request frame timed out")??;
    ensure!(
        frame.len() <= MAX_FRAME_BYTES && frame.last() == Some(&b'\n'),
        "invalid request frame"
    );
    let decoded = serde_json::from_slice::<Request>(&frame);
    let report_build = matches!(
        &decoded,
        Ok(Request::Owner {
            action: gent_protocol::OwnerOp::Status,
            ..
        })
    );
    let deadline = started
        + if matches!(
            &decoded,
            Ok(Request::Owner {
                action: gent_protocol::OwnerOp::HistoryImport { .. }
                    | gent_protocol::OwnerOp::AgentRecover { .. },
                ..
            })
        ) {
            Duration::from_secs(180)
        } else {
            Duration::from_secs(10)
        };
    let mut response = match decoded {
        Ok(request) => {
            if matches!(
                &request,
                Request::Agent {
                    action: gent_protocol::AgentOp::FileReceive { .. },
                    ..
                } | Request::HostedAgent {
                    action: gent_protocol::AgentOp::FileReceive { .. },
                    ..
                }
            ) {
                return tokio::time::timeout_at(
                    deadline,
                    receive::serve(stream, store, uploads, request),
                )
                .await
                .context("file receive timed out")?;
            }
            match tokio::time::timeout_at(
                deadline,
                access::run(store, "local request", move |store| {
                    // Keep capacity reserved until the transaction or cancelled
                    // queue entry exits, even after its socket times out.
                    let _permit = permit;
                    Ok(store.handle(request))
                }),
            )
            .await {
                Ok(result) => result?,
                Err(_) => Response::Error("daemon operation timed out; local storage is busy or the operation is still finishing; retry with the same request ID".into()),
            }
        }
        Err(_) => Response::Error("invalid request".into()),
    };
    if report_build
        && !build_info.is_null()
        && let Response::Ok(value) = &mut response
    {
        value["build"] = (*build_info).clone();
    }
    let mut response = serde_json::to_vec(&response)?;
    response.push(b'\n');
    ensure!(response.len() <= MAX_FRAME_BYTES, "response too large");
    // A timed-out transaction still deserves a complete protocol error frame.
    tokio::time::timeout(
        Duration::from_secs(2),
        stream.get_mut().write_all(&response),
    )
    .await
    .context("response write timed out")??;
    Ok(())
}

#[cfg(test)]
mod tests;
