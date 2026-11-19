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
mod files;
pub(crate) mod health;
mod network_error;
mod notifications;
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
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Position {
    next: u64,
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
        let client = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            client,
            origin,
            authorization: value,
            batches: Arc::default(),
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
        let response = network_error::send(self.client.get(self.route(group, None)?)).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "relay position request failed ({})",
            response.status()
        );
        let position: Position = serde_json::from_slice(&bounded(response, 1024).await?)?;
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
        let response = network_error::send(
            self.client
                .put(self.route(packet.group(), Some(packet.sequence()))?)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(bytes),
        )
        .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "relay storage request failed ({})",
            response.status()
        );
        let stored: Stored = serde_json::from_slice(&bounded(response, 1024).await?)?;
        ensure!(
            stored.stored && stored.sequence == packet.sequence(),
            "invalid relay storage acknowledgment"
        );
        // This acknowledges relay storage only. It never removes local history
        // or proves that a recipient accepted the packet or its configuration.
        Ok(())
    }
    async fn get(&self, group: &[u8], sequence: u64) -> Result<Option<Packet>> {
        let response =
            network_error::send(self.client.get(self.route(group, Some(sequence))?)).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure!(
            response.status() == StatusCode::OK,
            "relay fetch failed ({})",
            response.status()
        );
        let packet = Packet::decode(&bounded(response, MAX_FRAME).await?)?;
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
        let response =
            network_error::send(self.client.get(self.checkpoint_route(group, "checkpoint")?))
                .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure!(
            response.status() == StatusCode::OK,
            "relay checkpoint fetch failed ({})",
            response.status()
        );
        let receipt = Receipt::decode(&bounded(response, MAX_RECEIPT_BYTES).await?)?;
        ensure!(
            receipt.group() == group,
            "relay returned another stream checkpoint"
        );
        Ok(Some(receipt))
    }
    async fn put_checkpoint(&self, receipt: &Receipt, retire: bool) -> Result<()> {
        let action = if retire { "retire" } else { "checkpoint" };
        let response = network_error::send(
            self.client
                .put(self.checkpoint_route(receipt.group(), action)?)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(receipt.encode()?),
        )
        .await?;
        ensure!(
            matches!(response.status(), StatusCode::OK | StatusCode::NO_CONTENT),
            "relay checkpoint storage failed ({})",
            response.status()
        );
        // Service replies are availability hints; only a locally verified
        // receiver signature authorizes retirement in the endpoint database.
        Ok(())
    }
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
    let push =
        notifications::Listener::start(relay.clone(), wakeup.clone(), health.connected.clone());
    let _files = files.start(store.clone());
    let mut retries = BTreeMap::<Vec<u8>, Retry>::new();
    let mut transferred = BTreeMap::<Vec<u8>, u64>::new();
    let mut checkpoints = BTreeMap::<Vec<u8>, transfer::State>::new();
    let mut cursor = 0usize;
    let mut previous_error = None;
    let configuration = crate::configuration_log::ConfigurationRelay::from_relay(relay.clone());
    loop {
        let cycle_started = Instant::now();
        let configuration_result = configuration.sync_once(store.clone()).await;
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
            Ok((store.sync_streams()?, pending))
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
        match result {
            Ok((streams, pending)) => {
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
                let begin = cursor.min(streams.len());
                let end = (begin + 32).min(streams.len());
                let selected: Vec<_> = streams[begin..end]
                    .iter()
                    .filter(|s| retries.get(&s.group).is_none_or(|r| r.at <= Instant::now()))
                    .cloned()
                    .collect();
                cursor = if end == streams.len() { 0 } else { end };
                let mut work = stream::iter(selected)
                    .map(|entry| {
                        let group = entry.group.clone();
                        let store = store.clone();
                        let relay = relay.clone();
                        let health = health.clone();
                        let wakeup = wakeup.clone();
                        let mut checkpoint = checkpoints.remove(&group).unwrap_or_default();
                        async move {
                            let result =
                                transfer::run(store, relay, entry, health, wakeup, &mut checkpoint)
                                    .await;
                            (group, checkpoint, result)
                        }
                    })
                    .buffer_unordered(4);
                let mut completed = Vec::new();
                while let Some((group, checkpoint, result)) = work.next().await {
                    match result {
                        Ok(position) => {
                            successes += 1;
                            if let Some(position) = position {
                                progressed |=
                                    transferred.insert(group.clone(), position) != Some(position);
                            }
                            retries.remove(&group);
                            completed.push((group, checkpoint));
                        }
                        Err(e) => {
                            failures += 1;
                            let delay = retries.get(&group).map_or(Duration::from_secs(1), |r| {
                                (r.delay * 2).min(Duration::from_secs(30))
                            });
                            retries.insert(
                                group,
                                Retry {
                                    at: Instant::now() + delay,
                                    delay,
                                },
                            );
                            error.get_or_insert_with(|| e.to_string());
                        }
                    }
                }
                drop(work);
                checkpoints.extend(completed);
                // Large clusters advance through a bounded fair batch without
                // holding the RPC mutex over network I/O.
                progressed |= cursor != 0;
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
