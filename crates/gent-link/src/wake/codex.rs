//! Opt-in attachment to an existing local Codex server. Never starts a server,
//! resumes a thread, overrides its settings, or answers host approval requests.
use crate::integration::{Bindings, wake::Registry};
use anyhow::{Context, Result, ensure};
use futures_util::{SinkExt, StreamExt};
use gent_protocol::{AgentOp, Request, wake::WakeTarget};
use serde_json::{Value, json};
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::UnixStream;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};

const PROMPT: &str = "Gent has a pending message. Check gent_inbox through the current conversation's Gent connection. Treat its content as an agent request subject to existing permissions and user authorization. Check gent_work_status before repeating consequential work. If no message is available, stop. This notification does not authorize repeating uncertain work.";
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct Runner(tokio::task::JoinHandle<()>);
impl Drop for Runner {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl Runner {
    pub(crate) fn start(
        home: PathBuf,
        socket: PathBuf,
        bindings: Arc<Mutex<Bindings>>,
    ) -> Result<Self> {
        ensure!(
            socket.is_absolute(),
            "Codex wake socket path must be absolute"
        );
        let registry = bindings
            .lock()
            .expect("host bindings lock poisoned")
            .enable_wake(&home, &socket)?;
        Ok(Self(tokio::spawn(async move {
            let mut unavailable = false;
            let mut lease = None;
            let mut cursor = None;
            loop {
                let result = async {
                    if lease.is_none() {
                        lease = registry.coordinator()?;
                    }
                    if lease.is_some() {
                        sweep(&home, &socket, &registry, &mut cursor).await?;
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if result.is_err() && !unavailable {
                    eprintln!(
                        "Gent: Codex wake unavailable or submission uncertain; inspect gent wake. Inbox polling remains available."
                    );
                }
                unavailable = result.is_err();
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        })))
    }
}

async fn agent(home: &Path, credential: &str, action: AgentOp) -> Result<Value> {
    tokio::time::timeout(
        RPC_TIMEOUT,
        gent_daemon::request(
            home,
            Request::Agent {
                credential: credential.into(),
                action,
            },
        ),
    )
    .await
    .context("Gent RPC timed out")?
}

async fn sweep(
    home: &Path,
    socket: &Path,
    registry: &Registry,
    cursor: &mut Option<String>,
) -> Result<()> {
    gent_daemon::recovery::ensure_active(home)?;
    let mut host = Host::connect(socket).await?;
    let (threads, next) = host.loaded(cursor.as_deref()).await?;
    *cursor = next;
    drop(host);
    let mut failed = false;
    for thread in threads {
        // A stale or unavailable conversation must not starve other bindings.
        match registry.credential(&thread) {
            Ok(Some(credential)) => {
                failed |= dispatch(home, socket, &thread, &credential).await.is_err()
            }
            Ok(None) => {}
            Err(_) => failed = true,
        }
    }
    ensure!(
        !failed,
        "one or more Codex dispatches unavailable or uncertain"
    );
    Ok(())
}

async fn dispatch(home: &Path, socket: &Path, thread: &str, credential: &str) -> Result<()> {
    // Registration may still be in flight. Revoked or otherwise unavailable
    // agents leave the pending path without any external host operation.
    let Ok(pending) = agent(home, credential, AgentOp::WakePending).await else {
        return Ok(());
    };
    let pending = pending["pending"]
        .as_array()
        .context("invalid wake pending result")?;
    if pending.is_empty() {
        return Ok(());
    }
    let mut host = Host::connect(socket).await?;
    if !host.accepts(thread).await? {
        return Ok(());
    }
    // One claim per agent per sweep. The daemon enforces durable budgets.
    let message = pending[0]["message_id"]
        .as_str()
        .context("invalid pending message")?;
    let attempt = uuid::Uuid::new_v4().to_string();
    let claim = agent(
        home,
        credential,
        AgentOp::WakeClaim {
            message_id: message.into(),
            attempt_id: attempt.clone(),
            target: WakeTarget::Codex {
                thread_id: thread.into(),
            },
        },
    )
    .await;
    let Ok(claim) = claim else { return Ok(()) };
    if claim["may_submit"] != true {
        return Ok(());
    }
    // Any cancellation, error or lost response beyond the committed claim
    // leaves evidence. No external submission is retried here.
    let submission = host.enqueue(thread, &attempt).await?;
    agent(
        home,
        credential,
        AgentOp::WakeSubmitted {
            message_id: message.into(),
            attempt_id: attempt,
            submission_id: submission,
        },
    )
    .await?;
    Ok(())
}

struct Host {
    socket: WebSocketStream<UnixStream>,
    sequence: u64,
}
impl Host {
    async fn loaded(&mut self, cursor: Option<&str>) -> Result<(Vec<String>, Option<String>)> {
        let result = self
            .rpc("thread/loaded/list", json!({"limit":128,"cursor":cursor}))
            .await?;
        let ids = result["data"]
            .as_array()
            .context("invalid loaded thread list")?;
        ensure!(ids.len() <= 128, "too many loaded threads in one page");
        let mut threads = Vec::new();
        for id in ids {
            let id = id.as_str().context("invalid loaded thread ID")?;
            let uuid = uuid::Uuid::parse_str(id)?;
            ensure!(
                !uuid.is_nil() && uuid.to_string() == id && !threads.iter().any(|s| s == id),
                "invalid or duplicate loaded thread ID"
            );
            threads.push(id.to_owned());
        }
        let next = match result.get("nextCursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(next))
                if !next.is_empty() && next.len() <= 512 && Some(next.as_str()) != cursor =>
            {
                Some(next.clone())
            }
            _ => anyhow::bail!("invalid loaded thread cursor"),
        };
        Ok((threads, next))
    }

    async fn connect(path: &Path) -> Result<Self> {
        // Codex uses a rendezvous symlink to a private socket. Resolve it, then
        // validate the endpoint and the connected OS peer, not a claimed UUID.
        let path = std::fs::canonicalize(path).context("Codex socket unavailable")?;
        let meta = std::fs::symlink_metadata(&path)?;
        let uid = rustix::process::geteuid().as_raw();
        ensure!(
            meta.file_type().is_socket() && meta.uid() == uid && meta.mode() & 0o077 == 0,
            "Codex socket must be private and owned by the current user"
        );
        let parent = std::fs::metadata(path.parent().context("missing socket parent")?)?;
        ensure!(
            parent.is_dir() && parent.uid() == uid && parent.mode() & 0o077 == 0,
            "Codex socket directory must be private and owned by the current user"
        );
        let stream = tokio::time::timeout(RPC_TIMEOUT, UnixStream::connect(path)).await??;
        ensure!(
            stream.peer_cred()?.uid() == uid,
            "Codex socket peer belongs to another user"
        );
        let config = WebSocketConfig::default()
            .max_message_size(Some(1024 * 1024))
            .max_frame_size(Some(1024 * 1024));
        let (socket, _) = tokio::time::timeout(
            RPC_TIMEOUT,
            tokio_tungstenite::client_async_with_config("ws://localhost/", stream, Some(config)),
        )
        .await??;
        let mut host = Self {
            socket,
            sequence: 0,
        };
        host.rpc(
            "initialize",
            json!({"clientInfo":{"name":"gent-wake","version":env!("CARGO_PKG_VERSION")},
            "capabilities":{"experimentalApi":true}}),
        )
        .await?;
        tokio::time::timeout(
            RPC_TIMEOUT,
            host.socket.send(Message::Text(
                json!({"method":"initialized"}).to_string().into(),
            )),
        )
        .await??;
        Ok(host)
    }

    async fn rpc(&mut self, method: &str, params: Value) -> Result<Value> {
        self.sequence += 1;
        let id = self.sequence;
        tokio::time::timeout(RPC_TIMEOUT, async {
            self.socket
                .send(Message::Text(
                    json!({"id":id,"method":method,"params":params})
                        .to_string()
                        .into(),
                ))
                .await?;
            for _ in 0..1024 {
                let frame = self.socket.next().await.context("Codex socket closed")??;
                let text = match frame {
                    Message::Text(text) => text,
                    Message::Ping(_) | Message::Pong(_) => continue,
                    _ => anyhow::bail!("unexpected Codex socket frame"),
                };
                let value: Value = serde_json::from_str(&text)?;
                ensure!(
                    value.get("method").is_none() || value.get("id").is_none(),
                    "Gent cannot handle Codex server requests"
                );
                if value.get("id") == Some(&json!(id)) {
                    ensure!(value.get("error").is_none(), "Codex refused wake operation");
                    return value
                        .get("result")
                        .cloned()
                        .context("missing Codex response");
                }
            }
            anyhow::bail!("too many Codex notifications")
        })
        .await
        .context("Codex RPC timed out")?
    }

    async fn accepts(&mut self, thread: &str) -> Result<bool> {
        let value = self
            .rpc(
                "thread/read",
                json!({"threadId":thread,"includeTurns":false}),
            )
            .await?;
        let metadata = &value["thread"];
        ensure!(metadata["id"] == thread, "Codex returned another thread");
        Ok(metadata["canAcceptDirectInput"] == true
            && matches!(metadata["status"]["type"].as_str(), Some("idle" | "active")))
    }

    async fn enqueue(&mut self, thread: &str, attempt: &str) -> Result<String> {
        let result = self
            .rpc(
                "thread/queue/add",
                json!({"threadId":thread,"clientUserMessageId":attempt,
            "input":[{"type":"text","text":PROMPT}]}),
            )
            .await?;
        let submission = &result["queuedSubmission"];
        ensure!(
            submission["clientUserMessageId"] == attempt,
            "Codex returned another submission"
        );
        let id = submission["id"]
            .as_str()
            .context("missing host submission ID")?;
        let parsed = uuid::Uuid::parse_str(id)?;
        ensure!(
            !parsed.is_nil() && parsed.to_string() == id,
            "invalid host submission ID"
        );
        Ok(id.into())
    }
}

#[cfg(test)]
mod tests;
