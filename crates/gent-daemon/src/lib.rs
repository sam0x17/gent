//! Native daemon with local agent RPC and encrypted configuration/message sync.
pub mod config;
pub mod encrypted;
pub mod file_objects;
pub mod file_transport;
pub mod messages;
pub mod pairing;
pub mod replica;
mod runtime;
pub mod store;
pub mod sync;

use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use gent_protocol::{MAX_FRAME_BYTES, Request, Response};
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

pub async fn request(home: &Path, request: Request) -> Result<serde_json::Value> {
    let operation = async {
        let mut socket = UnixStream::connect(home.join("daemon.sock"))
            .await
            .context("daemon unavailable; run gent daemon start or gent daemon run")?;
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
    tokio::time::timeout(Duration::from_secs(15), operation)
        .await
        .context("daemon request timed out")?
}

pub async fn run(home: &Path) -> Result<()> {
    config::private_dir(home)?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(home.join("daemon.lock"))?;
    lock.try_lock_exclusive()
        .context("a daemon is already running for this state directory")?;
    let store = Arc::new(Mutex::new(store::Store::open(home)?));
    let socket = home.join("daemon.sock");
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let permits = Arc::new(Semaphore::new(32));
    let mut maintenance = tokio::time::interval(Duration::from_secs(15 * 60));
    let sync_task = sync::start(store.clone())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    eprintln!(
        "Gent daemon listening at {} (development build)",
        socket.display()
    );
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
            _=maintenance.tick()=> {
                let store = store.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(error) = store.lock().expect("store lock poisoned").maintain() {
                        eprintln!("Gent configuration maintenance pending: {error}");
                    }
                }).await?;
            }
            connection=listener.accept()=> {
                let (stream,_)=connection?;
                let Ok(permit)=permits.clone().try_acquire_owned() else { continue; };
                let store=store.clone();
                tokio::spawn(async move {
                    let _permit=permit;
                    let _=tokio::time::timeout(Duration::from_secs(10),serve(stream,store)).await;
                });
            }
        }
    }
    if let Some(task) = sync_task {
        task.abort();
        let _ = task.await;
    }
    fs::remove_file(socket)?;
    Ok(())
}

async fn serve(mut stream: UnixStream, store: Arc<Mutex<store::Store>>) -> Result<()> {
    let mut frame = Vec::new();
    BufReader::new((&mut stream).take(MAX_FRAME_BYTES as u64 + 1))
        .read_until(b'\n', &mut frame)
        .await?;
    ensure!(
        frame.len() <= MAX_FRAME_BYTES && frame.last() == Some(&b'\n'),
        "invalid request frame"
    );
    let response = match serde_json::from_slice::<Request>(&frame) {
        Ok(request) => {
            tokio::task::spawn_blocking(move || {
                store.lock().expect("store lock poisoned").handle(request)
            })
            .await?
        }
        Err(_) => Response::Error("invalid request".into()),
    };
    let mut response = serde_json::to_vec(&response)?;
    response.push(b'\n');
    ensure!(response.len() <= MAX_FRAME_BYTES, "response too large");
    stream.write_all(&response).await?;
    Ok(())
}
