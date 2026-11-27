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

const RPC_TIMEOUT: Duration = Duration::from_secs(10);

mod babysit;
mod daemon;
pub(crate) use daemon::maintain_babysitter;
mod direct;
mod ordinary;
pub(crate) mod recovery;

/// Owner diagnostic only. Initialization and a bounded list never load a thread
/// or submit input; returning a count avoids exporting unrelated conversation IDs.
pub(crate) async fn inspect(socket: &Path) -> Result<Value> {
    let mut host = Host::connect(socket).await?;
    let (threads, next) = host.loaded(None).await?;
    Ok(json!({"connected":true,"loaded_threads_on_page":threads.len(),"has_more":next.is_some()}))
}

pub(crate) struct Runner(tokio::task::JoinHandle<()>);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sweep {
    WakeOnly,
    GoalsOnly,
    WakeAndGoals,
}

#[derive(Default)]
struct Attached {
    wake: Option<std::fs::File>,
    goals: Option<std::fs::File>,
}

impl Attached {
    fn work(&mut self, registry: &Registry, home: &Path) -> Result<Option<Sweep>> {
        if self.wake.is_none() {
            self.wake = registry.coordinator()?;
        }
        let goals = self.inspect_goals(registry, home);
        match (self.wake.is_some(), goals) {
            (true, Ok(true)) => Ok(Some(Sweep::WakeAndGoals)),
            // A Babysitter opt-out or election failure must preserve inbox delivery.
            (true, _) => Ok(Some(Sweep::WakeOnly)),
            (false, goals) => Ok(goals?.then_some(Sweep::GoalsOnly)),
        }
    }

    fn inspect_goals(&mut self, registry: &Registry, home: &Path) -> Result<bool> {
        if !babysitter_running(home)? {
            self.goals = None;
        } else if self.goals.is_none() {
            self.goals = registry.attached_babysitter()?;
        }
        // Keep this probe out of the host sweep. The daemon can take ownership
        // even while a standalone fallback is waiting on a slow host.
        Ok(self.goals.is_some() && registry.daemon_babysitter()?.is_some())
    }
}

fn babysitter_running(home: &Path) -> Result<bool> {
    Ok(!home.join("babysitter-disabled").try_exists()?
        || gent_daemon::config::ordinary_babysitter_enabled(home)?)
}

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
        let mut attached = Attached::default();
        Ok(Self::spawn(home, registry, move |registry, home| {
            attached.work(registry, home)
        }))
    }

    fn spawn(
        home: PathBuf,
        registry: Registry,
        mut work: impl FnMut(&Registry, &Path) -> Result<Option<Sweep>> + Send + 'static,
    ) -> Self {
        Self(tokio::spawn(async move {
            let mut unavailable = false;
            let mut cursor = None;
            loop {
                let result = async {
                    if let Some(mode) = work(&registry, &home)? {
                        sweep(&home, &registry, &mut cursor, mode).await?;
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if result.is_err() && !unavailable {
                    eprintln!(
                        "Gent: Codex endpoint unavailable or submission uncertain. Inbox polling remains available."
                    );
                }
                unavailable = result.is_err();
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }))
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
    registry: &Registry,
    cursor: &mut Option<String>,
    mode: Sweep,
) -> Result<()> {
    gent_daemon::recovery::ensure_active(home)?;
    let socket = &registry.endpoint;
    let mut host = Host::connect(socket).await?;
    // Cursors belong to the host session. Start over if the host rejects one after a restart.
    let (threads, next) = host.loaded(cursor.take().as_deref()).await?;
    *cursor = next;
    drop(host);
    let mut failed = false;
    for thread in threads {
        // A stale or unavailable conversation must not starve other bindings.
        match registry.credential(&thread) {
            Ok(Some(credential)) => {
                if mode != Sweep::GoalsOnly {
                    failed |= dispatch(home, registry, &thread, &credential, None)
                        .await
                        .is_err();
                }
                if mode != Sweep::WakeOnly {
                    if gent_daemon::config::ordinary_babysitter_enabled(home).unwrap_or(false) {
                        failed |= ordinary::inspect(home, registry, &thread, &credential)
                            .await
                            .is_err()
                            && mode == Sweep::GoalsOnly;
                    }
                    let inspection = babysit::inspect(home, socket, &thread, &credential).await;
                    // Older servers may support inbox delivery without a goal API.
                    failed |= mode == Sweep::GoalsOnly && inspection.is_err();
                }
            }
            Ok(None) => {}
            Err(_) => failed = true,
        }
    }
    ensure!(
        !failed,
        "one or more Codex operations unavailable or uncertain"
    );
    Ok(())
}

/// The daemon reconciles existing managed attachments without taking the MCP
/// wake lease. A current coordinator racing this pass uses the same journal.
pub(crate) async fn catch_up(
    home: &Path,
    socket: &Path,
    thread: &str,
    recipient: &str,
) -> Result<()> {
    let registry = Registry::codex(home, socket)?;
    if registry.coordinator()?.is_none()
        && let Some(credential) = registry.credential(thread)?
    {
        dispatch(home, &registry, thread, &credential, Some(recipient)).await?;
    }
    Ok(())
}

async fn dispatch(
    home: &Path,
    registry: &Registry,
    thread: &str,
    credential: &str,
    recipient: Option<&str>,
) -> Result<()> {
    let socket = &registry.endpoint;
    // The attached wake owner still collects receipts and relay replies. Catch-up
    // handles only new pending messages on a host state that older owners declined.
    let recovery = if recipient.is_some() {
        Ok(())
    } else {
        direct::collect(home, socket, thread, credential).await
    };
    // Registration may still be in flight. Revoked or otherwise unavailable
    // agents leave the pending path without any external host operation.
    let Ok(pending) = agent(home, credential, AgentOp::WakePending).await else {
        return Ok(());
    };
    if recipient.is_some_and(|id| pending["agent"] != id) {
        return Ok(());
    }
    let pending = pending["pending"]
        .as_array()
        .context("invalid wake pending result")?;
    if pending.is_empty() {
        return recovery;
    }
    let mut host = Host::connect(socket).await?;
    let Some(ready) = host.input_ready(thread).await? else {
        return Ok(());
    };
    if recipient.is_some()
        && (ready == InputReady::Normal
            || !crate::integration::refresh::codex_sockets(home)?.contains(socket))
    {
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
        AgentOp::WakeDirectClaim {
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
    if ready != InputReady::Normal
        && (host.input_ready(thread).await? != Some(ready)
            || registry.credential(thread)?.as_deref() != Some(credential)
            || (recipient.is_some()
                && !crate::integration::refresh::codex_sockets(home)?.contains(socket)))
    {
        return Ok(());
    }
    let checked = agent(
        home,
        credential,
        AgentOp::WakeDirectRead {
            message_id: message.into(),
            attempt_id: attempt.clone(),
            target: WakeTarget::Codex {
                thread_id: thread.into(),
            },
        },
    )
    .await?;
    if checked["eligible"] != true {
        return Ok(());
    }
    let delivery: gent_protocol::wake::WakeDelivery =
        serde_json::from_value(checked["delivery"].clone())?;
    let submission = host.submit(thread, &attempt, &delivery.prompt()).await?;
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
    recovery
}

/// Authenticate a local endpoint before any protocol data is sent.
pub(crate) async fn connect_socket(
    path: &Path,
    limit: usize,
) -> Result<WebSocketStream<UnixStream>> {
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
        .max_message_size(Some(limit))
        .max_frame_size(Some(limit));
    let (socket, _) = tokio::time::timeout(
        RPC_TIMEOUT,
        tokio_tungstenite::client_async_with_config("ws://localhost/", stream, Some(config)),
    )
    .await??;
    Ok(socket)
}

#[derive(PartialEq)]
enum InputReady {
    Normal,
    ProviderFailure {
        turn: uuid::Uuid,
        completed: i64,
        reason: gent_protocol::notifications::Failure,
    },
}

pub(crate) struct Host {
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
        Self::connect_with_limit(path, 1024 * 1024).await
    }

    pub(crate) async fn connect_with_limit(path: &Path, limit: usize) -> Result<Self> {
        let socket = connect_socket(path, limit).await?;
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

    pub(crate) async fn rpc(&mut self, method: &str, params: Value) -> Result<Value> {
        self.rpc_with_timeout(method, params, RPC_TIMEOUT).await
    }

    pub(crate) async fn rpc_with_timeout(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value> {
        self.sequence += 1;
        let id = self.sequence;
        tokio::time::timeout(timeout, async {
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
                    ensure!(value.get("error").is_none(), "Codex refused operation");
                    return value
                        .get("result")
                        .cloned()
                        .context("missing Codex response");
                }
            }
            anyhow::bail!("too many Codex notifications")
        })
        .await
        .with_context(|| {
            format!(
                "Codex {method} timed out after {} seconds",
                timeout.as_secs()
            )
        })?
    }

    async fn input_ready(&mut self, thread: &str) -> Result<Option<InputReady>> {
        let value = self
            .rpc(
                "thread/read",
                json!({"threadId":thread,"includeTurns":false}),
            )
            .await?;
        let metadata = &value["thread"];
        ensure!(metadata["id"] == thread, "Codex returned another thread");
        if metadata["canAcceptDirectInput"] != true {
            return Ok(None);
        }
        let status = &metadata["status"];
        match status["type"].as_str() {
            Some("idle" | "active") => return Ok(Some(InputReady::Normal)),
            Some("systemError")
                if status
                    .get("activeFlags")
                    .is_none_or(|flags| flags.as_array().is_some_and(Vec::is_empty)) => {}
            _ => return Ok(None),
        }
        let page = self
            .rpc(
                "thread/turns/list",
                json!({"threadId":thread,
            "sortDirection":"desc","limit":1,"itemsView":"notLoaded"}),
            )
            .await?;
        let Some([head]) = page["data"].as_array().map(Vec::as_slice) else {
            return Ok(None);
        };
        let Some(reason) = babysit::terminal_failure(head) else {
            return Ok(None);
        };
        let Some(id) = head["id"]
            .as_str()
            .filter(|id| crate::integration::wake::valid_thread(id))
        else {
            return Ok(None);
        };
        let Some((started, completed)) =
            head["startedAt"].as_i64().zip(head["completedAt"].as_i64())
        else {
            return Ok(None);
        };
        if !(0..=completed).contains(&started) || completed > gent_daemon::store::now() {
            return Ok(None);
        }
        let queue = self
            .rpc("thread/queue/list", json!({"threadId":thread}))
            .await?;
        Ok(
            (queue["data"].as_array().is_some_and(Vec::is_empty) && queue["nextCursor"].is_null())
                .then_some(InputReady::ProviderFailure {
                    turn: uuid::Uuid::parse_str(id)?,
                    completed,
                    reason,
                }),
        )
    }

    async fn submit(&mut self, thread: &str, attempt: &str, prompt: &str) -> Result<String> {
        // Ordinary native input starts an idle turn or appends to an active
        // one. Do not park it in the next-turn queue, interrupt work, or change
        // the host's model, permission, or execution settings.
        let result = self
            .rpc(
                "turn/start",
                json!({"threadId":thread,"clientUserMessageId":attempt,
            "input":[{"type":"text","text":prompt}]}),
            )
            .await?;
        let id = result["turn"]["id"]
            .as_str()
            .context("missing host turn ID")?;
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
