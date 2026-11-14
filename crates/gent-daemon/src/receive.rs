//! Bounded binary bodies over the protected local socket, outside JSON framing.
use super::*;
use gent_protocol::{AgentOp, file_objects::IncomingFile};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

async fn response(stream: &mut UnixStream, response: &Response) -> Result<()> {
    let mut data = serde_json::to_vec(response)?;
    data.push(b'\n');
    ensure!(data.len() <= MAX_FRAME_BYTES, "response too large");
    stream.write_all(&data).await?;
    Ok(())
}

async fn read_response(stream: &mut BufReader<UnixStream>) -> Result<Value> {
    let mut data = Vec::new();
    (&mut *stream)
        .take(MAX_FRAME_BYTES as u64 + 1)
        .read_until(b'\n', &mut data)
        .await?;
    ensure!(
        data.len() <= MAX_FRAME_BYTES && data.last() == Some(&b'\n'),
        "invalid daemon response"
    );
    match serde_json::from_slice(&data)? {
        Response::Ok(value) => Ok(value),
        Response::Error(message) => anyhow::bail!(message),
    }
}

pub async fn receive_file(
    home: &Path,
    credential: String,
    file: IncomingFile,
    bytes: &[u8],
) -> Result<Value> {
    recovery::ensure_active(home)?;
    ensure!(
        bytes.len() <= gent_protocol::file_objects::MAX_FILE_BYTES,
        "file exceeds 32 MiB"
    );
    tokio::time::timeout(Duration::from_secs(15), async {
        let socket = UnixStream::connect(home.join("daemon.sock"))
            .await
            .context("daemon unavailable")?;
        let mut socket = BufReader::new(socket);
        let request = Request::Agent {
            credential,
            action: AgentOp::FileReceive {
                file,
                byte_length: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
            },
        };
        let mut header = serde_json::to_vec(&request)?;
        header.push(b'\n');
        ensure!(header.len() <= 4096, "file header too large");
        socket.get_mut().write_all(&header).await?;
        let status = read_response(&mut socket).await?;
        if status["state"] == "ready" {
            return Ok(status);
        }
        ensure!(status["state"] == "upload", "invalid import response");
        socket.get_mut().write_all(bytes).await?;
        socket.get_mut().shutdown().await?;
        read_response(&mut socket).await
    })
    .await
    .context("file import timed out")?
}

pub(super) async fn serve(
    mut stream: BufReader<UnixStream>,
    store: Arc<Mutex<store::Store>>,
    slots: Arc<Semaphore>,
    request: Request,
) -> Result<()> {
    let Request::Agent {
        credential,
        action:
            AgentOp::FileReceive {
                file,
                byte_length,
                sha256,
            },
    } = &request
    else {
        unreachable!()
    };
    let (credential, file, byte_length, sha256) = (
        credential.clone(),
        file.clone(),
        *byte_length,
        sha256.clone(),
    );
    let Ok(slot) = slots.try_acquire_owned() else {
        return response(
            stream.get_mut(),
            &Response::Error("file import busy; retry the same request ID".into()),
        )
        .await;
    };
    let check_store = store.clone();
    let (check, slot) = tokio::task::spawn_blocking(move || {
        let check = check_store
            .lock()
            .expect("store lock poisoned")
            .handle(request);
        (check, slot)
    })
    .await?;
    response(stream.get_mut(), &check).await?;
    if !matches!(check,Response::Ok(ref v) if v["state"] == "upload") {
        return Ok(());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(byte_length as usize + 1));
    (&mut stream)
        .take(byte_length + 1)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() as u64 == byte_length,
        "invalid file body length"
    );
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == sha256,
        "file body digest mismatch"
    );
    let result = tokio::task::spawn_blocking(move || {
        // Keep capacity occupied if the socket times out while the transaction
        // is running. Authentication and all quotas are checked again at commit.
        let _slot = slot;
        store
            .lock()
            .expect("store lock poisoned")
            .handle(Request::Agent {
                credential,
                action: AgentOp::FileReceiveData { file, bytes },
            })
    })
    .await?;
    response(stream.get_mut(), &result).await
}
