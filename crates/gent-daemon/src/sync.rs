//! Automatic encrypted configuration and agent-record transport over an opaque relay.
//! Relay transport credentials authorize storage, never cluster key authority.
use crate::{config, store::Store};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{StreamExt, stream};
use gent_crypto::stream::{MAX_RECEIPT_BYTES, Packet, Receipt};
use reqwest::{Client, StatusCode, Url, header};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::Notify, task::JoinHandle, time::Instant};
mod batch;
mod bootstrap;
pub(crate) mod direct;
mod exchange;
mod files;
pub(crate) mod health;
mod network_error;
mod notifications;
#[cfg(test)]
pub(crate) use notifications::wss::tests::exercise_peer_watch;
mod schedule;
mod sweep;
#[cfg(test)]
mod test_http;
mod transfer;

const MAX_FRAME: usize = 1024 * 1024;
type SharedStore = Arc<Mutex<Store>>;

#[derive(Clone)]
pub(crate) struct Stream {
    pub group: Vec<u8>,
    pub outgoing: bool,
    pub configuration: bool,
}

#[derive(Clone)]
pub(crate) struct Relay {
    pub(crate) client: Client,
    pub(crate) origin: Url,
    authorization: header::HeaderValue,
    batches: Arc<batch::Support>,
    states: Arc<batch::Support>,
    exchange: Option<Arc<exchange::Exchange>>,
    cluster: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Position {
    next: u64,
}
struct MailboxState {
    receipt: Option<Receipt>,
    next: u64,
    retired_next: Option<u64>,
}

impl MailboxState {
    fn restore_floor(&self, receipt: &Receipt) -> bool {
        self.next <= receipt.sequence()
            || self
                .retired_next
                .is_some_and(|next| next <= receipt.sequence())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    stored: bool,
    sequence: u64,
}

impl Relay {
    pub(crate) fn open(settings: &config::RelayConfig, home: &std::path::Path) -> Result<Self> {
        let origin = settings.validate()?;
        let credential = zeroize::Zeroizing::new(config::read_relay_credential(
            &home.join(&settings.credential_file),
        )?);
        let mut value = header::HeaderValue::from_str(&format!("Bearer {}", credential.as_str()))?;
        value.set_sensitive(true);
        let mut headers = header::HeaderMap::new();
        headers.insert("X-Gent-Authority", header::HeaderValue::from_static("3"));
        headers.insert(header::AUTHORIZATION, value.clone());
        let cluster = config::load(home).ok().map(|config| config.cluster.id);
        if let Some(cluster) = &cluster {
            headers.insert("X-Gent-Cluster", cluster.parse()?);
        }
        let client = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(15))
            .build()?;
        let exchange = tokio::runtime::Handle::try_current()
            .ok()
            .map(|_| exchange::Exchange::start(client.clone(), origin.clone()));
        Ok(Self {
            client,
            origin,
            authorization: value,
            batches: Arc::default(),
            states: Arc::default(),
            exchange,
            cluster,
        })
    }
    async fn state(&self, group: &[u8]) -> Result<MailboxState> {
        if self.states.enabled() {
            let response = self
                .mailbox("GET", self.checkpoint_route(group, "state")?, vec![])
                .await?;
            if response.status() == StatusCode::NOT_FOUND {
                self.states.unavailable();
            } else {
                ensure!(
                    response.status() == StatusCode::OK,
                    "relay state request failed ({})",
                    response.status()
                );
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct State {
                    next: u64,
                    checkpoint: Option<String>,
                    retired_sequence: Option<i64>,
                }
                let state: State = serde_json::from_slice(&response.bytes(8192)?)?;
                ensure!(
                    state.next <= gent_crypto::stream::MAX_SEQUENCE,
                    "invalid relay position"
                );
                let retired_next = state
                    .retired_sequence
                    .map(|floor| {
                        ensure!(
                            (-1..state.next as i64).contains(&floor),
                            "invalid relay retirement floor"
                        );
                        Ok::<_, anyhow::Error>((floor + 1) as u64)
                    })
                    .transpose()?;
                let receipt = state
                    .checkpoint
                    .map(|s| -> Result<_> {
                        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
                        let receipt = Receipt::decode(&bytes)?;
                        ensure!(
                            receipt.group() == group,
                            "relay returned another stream checkpoint"
                        );
                        Ok(receipt)
                    })
                    .transpose()?;
                return Ok(MailboxState {
                    receipt,
                    next: state.next,
                    retired_next,
                });
            }
        }
        let (receipt, next) = tokio::try_join!(self.checkpoint(group), self.position(group))?;
        Ok(MailboxState {
            receipt,
            next,
            retired_next: None,
        })
    }
    fn route(&self, group: &[u8], sequence: Option<u64>) -> Result<Url> {
        let mut path = format!("v1/mailboxes/{}", URL_SAFE_NO_PAD.encode(group));
        if let Some(sequence) = sequence {
            path.push_str(&format!("/{sequence}"));
        }
        Ok(self.origin.join(&path)?)
    }
    async fn position(&self, group: &[u8]) -> Result<u64> {
        let response = self
            .mailbox("GET", self.route(group, None)?, vec![])
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "relay position request failed ({})",
            response.status()
        );
        let position: Position = serde_json::from_slice(&response.bytes(1024)?)?;
        ensure!(
            position.next <= gent_crypto::stream::MAX_SEQUENCE,
            "invalid relay position"
        );
        Ok(position.next)
    }
    async fn put(&self, packet: &Packet) -> Result<()> {
        let bytes = packet.encode()?;
        ensure!(
            bytes.len() <= MAX_FRAME,
            "encrypted packet exceeds relay frame limit"
        );
        let response = self
            .mailbox(
                "PUT",
                self.route(packet.group(), Some(packet.sequence()))?,
                bytes,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "relay storage request failed ({})",
            response.status()
        );
        let stored: Stored = serde_json::from_slice(&response.bytes(1024)?)?;
        ensure!(
            stored.stored && stored.sequence == packet.sequence(),
            "invalid relay storage acknowledgment"
        );
        // This acknowledges relay storage only. It never removes local history
        // or proves that a recipient accepted the packet or its configuration.
        Ok(())
    }
    async fn get(&self, group: &[u8], sequence: u64) -> Result<Option<Packet>> {
        let response = self
            .mailbox("GET", self.route(group, Some(sequence))?, vec![])
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure!(
            response.status() == StatusCode::OK,
            "relay fetch failed ({})",
            response.status()
        );
        let packet = Packet::decode(&response.bytes(MAX_FRAME)?)?;
        ensure!(
            packet.group() == group && packet.sequence() == sequence,
            "relay returned another stream position"
        );
        Ok(Some(packet))
    }

    fn checkpoint_route(&self, group: &[u8], action: &str) -> Result<Url> {
        Ok(self.origin.join(&format!(
            "v1/mailboxes/{}/{action}",
            URL_SAFE_NO_PAD.encode(group)
        ))?)
    }
    async fn checkpoint(&self, group: &[u8]) -> Result<Option<Receipt>> {
        let response = self
            .mailbox("GET", self.checkpoint_route(group, "checkpoint")?, vec![])
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure!(
            response.status() == StatusCode::OK,
            "relay checkpoint fetch failed ({})",
            response.status()
        );
        let receipt = Receipt::decode(&response.bytes(MAX_RECEIPT_BYTES)?)?;
        ensure!(
            receipt.group() == group,
            "relay returned another stream checkpoint"
        );
        Ok(Some(receipt))
    }
    async fn put_checkpoint(&self, receipt: &Receipt, retire: bool) -> Result<Retirement> {
        let action = if retire { "retire" } else { "checkpoint" };
        let response = self
            .mailbox(
                "PUT",
                self.checkpoint_route(receipt.group(), action)?,
                receipt.encode()?,
            )
            .await?;
        ensure!(
            matches!(response.status(), StatusCode::OK | StatusCode::NO_CONTENT),
            "relay checkpoint storage failed ({})",
            response.status()
        );
        if !retire {
            return Ok(Retirement::Drained);
        }
        let body = response.bytes(128)?;
        if body.is_empty() {
            return Ok(Retirement::Legacy);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Progress {
            more: bool,
        }
        Ok(if serde_json::from_slice::<Progress>(&body)?.more {
            Retirement::More
        } else {
            Retirement::Drained
        })
    }
}

#[derive(Clone, Copy)]
enum Retirement {
    More,
    Drained,
    Legacy,
}

pub(crate) async fn bounded(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        response.content_length().is_none_or(|n| n <= limit as u64),
        "relay response too large"
    );
    let mut chunks = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        ensure!(
            body.len() + chunk.len() <= limit,
            "relay response too large"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn local<T: Send + 'static>(
    store: SharedStore,
    operation: impl FnOnce(&mut Store) -> Result<T> + Send + 'static,
) -> Result<T> {
    crate::access::run(store, "encrypted sync", operation).await
}

struct Retry {
    at: Instant,
    delay: Duration,
}

/// Start only when the owner has configured a relay endpoint and private token
/// file. The task needs no MCP turn and never publishes plaintext pairing metadata.
pub fn start(store: SharedStore) -> Result<Option<JoinHandle<()>>> {
    let (settings, wakeup, health) = {
        let mut guard = store
            .lock()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
        guard.begin_configuration_discovery();
        (
            guard.relay_settings(),
            guard.sync_wakeup.clone(),
            guard.sync_health.clone(),
        )
    };
    let Some((settings, home)) = settings else {
        return Ok(None);
    };
    let relay = Relay::open(&settings, &home).context("encrypted relay setup failed")?;
    let files = files::Scheduler::new(crate::file_transport::FileRelay::open(&settings, &home)?);
    Ok(Some(tokio::spawn(run(store, relay, wakeup, files, health))))
}

async fn run(
    store: SharedStore,
    relay: Relay,
    wakeup: Arc<Notify>,
    files: files::Scheduler,
    health: Arc<health::Health>,
) {
    health.set_exchange(relay.exchange.clone());
    let direct = match direct::Direct::start(store.clone(), health.clone()).await {
        Ok(direct) => direct,
        Err(_) => {
            eprintln!("Gent direct transport unavailable; encrypted relay remains active");
            None
        }
    };
    let hints = Arc::new(schedule::Hints::default());
    let push = notifications::Listener::start(
        relay.clone(),
        store.clone(),
        wakeup.clone(),
        health.connected.clone(),
        hints.clone(),
        health.clone(),
    );
    let peers = transfer::Peers {
        direct: direct.clone(),
        wss: push.wss.clone(),
    };
    let _files = files.start(store.clone());
    let mut retries = BTreeMap::<Vec<u8>, Retry>::new();
    let mut transferred = BTreeMap::<Vec<u8>, u64>::new();
    let mut checkpoints = BTreeMap::<Vec<u8>, transfer::State>::new();
    let mut schedule = schedule::Schedule::default();
    let mut was_connected = false;
    let sweep_support = Arc::new(batch::Support::default());
    let mut previous_error = None;
    let configuration = crate::configuration_log::ConfigurationRelay::from_relay(relay.clone());
    let mut next_control = Instant::now();
    loop {
        let cycle_started = Instant::now();
        if let Some(direct) = &direct {
            let _ = direct.advertise(store.clone()).await;
        }
        let pending_configuration = local(store.clone(), |s| {
            s.queue_configuration_renewal()?;
            Ok(!s.configuration_proposals()?.is_empty()
                || s.configuration_log_migration()?.is_some())
        })
        .await
        .unwrap_or(true);
        let configuration_result =
            if hints.control() || pending_configuration || Instant::now() >= next_control {
                let result = configuration.sync_once(store.clone()).await;
                next_control = Instant::now()
                    + Duration::from_secs(if result.as_ref().is_ok_and(|p| !p) {
                        30
                    } else {
                        1
                    });
                result
            } else {
                Ok(false)
            };
        let bootstrap_result = bootstrap::sync(store.clone(), &relay).await;
        let result = local(store.clone(), |store| {
            let mesh = store.mesh_tick();
            let hosted = store.reconcile_hosted_routes();
            store.reconcile_configuration()?;
            let preparation = store.owner_preparation_tick();
            let transfer = store.owner_transfer_tick();
            let presence = store.presence_tick();
            let directory = store.directory_tick();
            let pending = match (mesh, preparation, transfer, presence, hosted, directory) {
                (Ok(mesh), Ok(preparation), Ok(transfer), Ok(presence), Ok(()), Ok(directory)) => {
                    Ok(mesh || preparation || transfer || presence || directory)
                }
                (Err(error), _, _, _, _, _)
                | (_, Err(error), _, _, _, _)
                | (_, _, Err(error), _, _, _)
                | (_, _, _, Err(error), _, _)
                | (_, _, _, _, Err(error), _)
                | (_, _, _, _, _, Err(error)) => Err(error),
            };
            Ok((store.sync_streams()?, pending, store.sync_pending_groups()?))
        })
        .await;
        let mut progressed = configuration_result.as_ref().copied().unwrap_or(false)
            || bootstrap_result.as_ref().copied().unwrap_or(false);
        let mut mesh_pending = false;
        let mut error = configuration_result
            .err()
            .or_else(|| bootstrap_result.err())
            .map(|error| error.to_string());
        let control_error = error.is_some();
        let (mut successes, mut failures, mut local_error) = (0, 0, false);
        let mut next_sweep = None;
        match result {
            Ok((streams, pending, queued)) => {
                match pending {
                    Ok(pending) => mesh_pending = pending,
                    Err(e) => {
                        local_error = true;
                        // Peer setup cannot prevent configuration recovery or
                        // delivery over already established streams.
                        mesh_pending = true;
                        error = Some(e.to_string());
                    }
                }
                retries.retain(|group, _| streams.iter().any(|s| &s.group == group));
                transferred.retain(|group, _| streams.iter().any(|s| &s.group == group));
                checkpoints.retain(|group, _| streams.iter().any(|s| &s.group == group));
                health.retain(&streams, mesh_pending);
                hints.subscribe(&streams);
                let connected = health.connected.load(std::sync::atomic::Ordering::SeqCst);
                if was_connected && !connected {
                    // Start the five-second disconnected cadence immediately.
                    hints.all();
                }
                was_connected = connected;
                if hints.take_reconnected() {
                    retries.clear();
                }
                let selected =
                    schedule.select(&streams, &hints, queued.clone(), &retries, connected);
                progressed |= schedule.has_ready(&retries);
                next_sweep = Some(schedule.next_full());
                let mut work = sweep::select(
                    selected,
                    schedule.timed_repair,
                    sweep_support.clone(),
                    store.clone(),
                    relay.clone(),
                    health.clone(),
                )
                .map(|(entry, check)| {
                    let group = entry.group.clone();
                    let store = store.clone();
                    let relay = relay.clone();
                    let health = health.clone();
                    let wakeup = wakeup.clone();
                    let peers = peers.clone();
                    let outgoing = entry.outgoing;
                    let peer_work = outgoing && !entry.configuration && queued.contains(&group);
                    let mut checkpoint = checkpoints.remove(&group).unwrap_or_default();
                    async move {
                        if matches!(check, sweep::Check::Current) {
                            health.idle(&group);
                            return (group, outgoing, checkpoint, Ok(None));
                        }
                        if matches!(check, sweep::Check::RestoreCheckpoint) {
                            checkpoint.forget_publication();
                        }
                        checkpoint.collect_direct().await;
                        if peer_work
                            && let Some(result) = peers
                                .transfer(&store, &relay, &entry, &health, &wakeup, &mut checkpoint)
                                .await
                            && !matches!(result, Ok(None))
                        {
                            return (group, outgoing, checkpoint, result);
                        }
                        let result =
                            transfer::run(store, relay, entry, health, wakeup, &mut checkpoint)
                                .await;
                        (group, outgoing, checkpoint, result)
                    }
                })
                .buffer_unordered(4);
                let mut completed = Vec::new();
                while let Some((group, outgoing, checkpoint, result)) = work.next().await {
                    match result {
                        Ok(position) => {
                            successes += 1;
                            if checkpoint.more() || (!outgoing && position.is_some()) {
                                schedule.again(group.clone());
                            }
                            if let Some(position) = position {
                                progressed |=
                                    transferred.insert(group.clone(), position) != Some(position);
                            }
                            retries.remove(&group);
                        }
                        Err(e) => {
                            failures += 1;
                            let delay = retries.get(&group).map_or(Duration::from_secs(1), |r| {
                                (r.delay * 2).min(Duration::from_secs(30))
                            });
                            retries.insert(
                                group.clone(),
                                Retry {
                                    at: Instant::now() + delay,
                                    delay,
                                },
                            );
                            error.get_or_insert_with(|| e.to_string());
                        }
                    }
                    completed.push((group, checkpoint));
                }
                drop(work);
                checkpoints.extend(completed);
                // Large clusters advance through a bounded fair batch without
                // holding the RPC mutex over network I/O.
            }
            Err(e) => {
                local_error = true;
                error = Some(e.to_string());
            }
        }
        health.observe(
            crate::store::now(),
            successes,
            failures,
            retries.len(),
            local_error,
            control_error,
        );
        health.cycle_completed(cycle_started.elapsed());
        if let Some(error) = &error {
            if previous_error.as_ref() != Some(error) {
                eprintln!("Gent encrypted sync waiting: {error}");
            }
            previous_error = error.clone().into();
        }
        let mut pause = if progressed {
            Duration::from_millis(10)
        } else {
            push.reconcile_after()
        };
        if mesh_pending {
            pause = pause.min(Duration::from_secs(1));
        }
        if let Some(at) = next_sweep {
            pause = pause.min(at.saturating_duration_since(Instant::now()));
        }
        if let Some(retry) = retries
            .values()
            .map(|r| r.at.saturating_duration_since(Instant::now()))
            .min()
        {
            pause = pause.min(retry);
        }
        tokio::select! {
            _ = wakeup.notified() => {}
            _ = tokio::time::sleep(pause) => {}
        }
    }
}
