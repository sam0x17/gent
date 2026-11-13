//! Automatic encrypted configuration and agent-record transport over an opaque relay.
//! The development relay token authorizes storage, never cluster authority.
use crate::{config, store::Store};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{StreamExt, stream};
use gent_crypto::stream::Packet;
use reqwest::{Client, StatusCode, Url, header};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::Notify, task::JoinHandle, time::Instant};

const MAX_FRAME: usize = 1024 * 1024;
type SharedStore = Arc<Mutex<Store>>;

#[derive(Clone)]
pub(crate) struct Stream {
    pub group: Vec<u8>,
    pub outgoing: bool,
    pub configuration: bool,
}

#[derive(Clone)]
struct Relay {
    client: Client,
    origin: Url,
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
    fn open(settings: &config::RelayConfig, home: &std::path::Path) -> Result<Self> {
        let origin = settings.validate()?;
        let credential =
            zeroize::Zeroizing::new(config::read_private(&home.join(&settings.credential_file))?);
        let mut value = header::HeaderValue::from_str(&format!("Bearer {}", credential.as_str()))?;
        value.set_sensitive(true);
        let mut headers = header::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, value);
        let client = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()?;
        Ok(Self { client, origin })
    }
    fn route(&self, group: &[u8], sequence: Option<u64>) -> Result<Url> {
        let mut path = format!("v1/mailboxes/{}", URL_SAFE_NO_PAD.encode(group));
        if let Some(sequence) = sequence {
            path.push_str(&format!("/{sequence}"));
        }
        Ok(self.origin.join(&path)?)
    }
    async fn position(&self, group: &[u8]) -> Result<u64> {
        let response = self.client.get(self.route(group, None)?).send().await?;
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
        let response = self
            .client
            .put(self.route(packet.group(), Some(packet.sequence()))?)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(bytes)
            .send()
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
        let response = self
            .client
            .get(self.route(group, Some(sequence))?)
            .send()
            .await?;
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
}

async fn bounded(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
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
    tokio::task::spawn_blocking(move || {
        let mut guard = store
            .lock()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
        operation(&mut guard)
    })
    .await?
}

async fn transfer(store: SharedStore, relay: Relay, entry: Stream) -> Result<Option<u64>> {
    let group = entry.group;
    if entry.outgoing {
        let g = group.clone();
        local(store.clone(), move |store| {
            if entry.configuration {
                store.sync_prepare(&g)
            } else {
                store.data_prepare(&g)
            }
        })
        .await?;
        // Relay position is an untrusted availability hint. Bounds and pinned
        // recipient authorization are checked again before reading the outbox.
        let next = relay.position(&group).await?;
        let packet = local(store, move |store| {
            if entry.configuration {
                store.sync_outgoing(&group, next)
            } else {
                store.data_outgoing(&group, next)
            }
        })
        .await?;
        if let Some(packet) = packet {
            relay.put(&packet).await?;
            return Ok(Some(next));
        }
    } else {
        let g = group.clone();
        let next = local(store.clone(), move |store| {
            if entry.configuration {
                store.sync_next(&g)
            } else {
                store.data_next(&g)
            }
        })
        .await?;
        if let Some(packet) = relay.get(&group, next).await? {
            local(store, move |store| {
                if entry.configuration {
                    store.sync_receive(&packet)
                } else {
                    store.data_receive(&packet)
                }
            })
            .await?;
            return Ok(Some(next));
        }
    }
    Ok(None)
}

struct Retry {
    at: Instant,
    delay: Duration,
}

/// Start only when the owner has configured a relay endpoint and private token
/// file. The task needs no MCP turn and never publishes plaintext pairing metadata.
pub fn start(store: SharedStore) -> Result<Option<JoinHandle<()>>> {
    let (settings, wakeup) = {
        let guard = store
            .lock()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
        (guard.relay_settings(), guard.sync_wakeup.clone())
    };
    let Some((settings, home)) = settings else {
        return Ok(None);
    };
    let relay = Relay::open(&settings, &home).context("encrypted relay setup failed")?;
    Ok(Some(tokio::spawn(run(store, relay, wakeup))))
}

async fn run(store: SharedStore, relay: Relay, wakeup: Arc<Notify>) {
    let mut retries = BTreeMap::<Vec<u8>, Retry>::new();
    let mut transferred = BTreeMap::<Vec<u8>, u64>::new();
    let mut cursor = 0usize;
    let mut previous_error = None;
    loop {
        let result = local(store.clone(), |store| store.sync_streams()).await;
        let mut progressed = false;
        let mut error = None;
        match result {
            Ok(streams) => {
                retries.retain(|group, _| streams.iter().any(|s| &s.group == group));
                transferred.retain(|group, _| streams.iter().any(|s| &s.group == group));
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
                        async move { (group, transfer(store, relay, entry).await) }
                    })
                    .buffer_unordered(4);
                while let Some((group, result)) = work.next().await {
                    match result {
                        Ok(position) => {
                            if let Some(position) = position {
                                progressed |=
                                    transferred.insert(group.clone(), position) != Some(position);
                            }
                            retries.remove(&group);
                        }
                        Err(e) => {
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
                // Large clusters advance through a bounded fair batch without
                // holding the RPC mutex over network I/O.
                progressed |= cursor != 0;
            }
            Err(e) => {
                error = Some(e.to_string());
            }
        }
        if let Some(error) = &error {
            if previous_error.as_ref() != Some(error) {
                eprintln!("Gent encrypted sync waiting: {error}");
            }
            previous_error = error.clone().into();
        }
        let pause = if progressed {
            Duration::from_millis(10)
        } else {
            Duration::from_secs(1)
        };
        tokio::select! {
            _ = wakeup.notified() => {}
            _ = tokio::time::sleep(pause) => {}
        }
    }
}
