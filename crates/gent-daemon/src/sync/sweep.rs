use super::*;
use base64::engine::general_purpose::STANDARD;
use futures_util::stream::BoxStream;
use gent_protocol::transport_sweep::{Changes, Cursor, LIMIT, MAX_BYTES, ROUTE};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Default)]
pub(super) enum Check {
    #[default]
    Reconcile,
    RestoreCheckpoint,
    Current,
}

/// Outgoing streams and urgent single-stream hints can proceed while the
/// independent bulk read checks idle incoming streams.
pub(super) fn select(
    streams: Vec<Stream>,
    timed_repair: bool,
    support: Arc<batch::Support>,
    store: SharedStore,
    relay: Relay,
    health: Arc<health::Health>,
) -> BoxStream<'static, (Stream, Check)> {
    let (incoming, other): (Vec<_>, _) = streams
        .into_iter()
        .partition(|s| timed_repair && !s.configuration && !s.outgoing);
    let ready = stream::iter(other.into_iter().map(|s| (s, Check::Reconcile)));
    if !(1..=LIMIT).contains(&incoming.len()) || !support.enabled() || relay.exchange.is_none() {
        return ready
            .chain(stream::iter(
                incoming.into_iter().map(|s| (s, Check::Reconcile)),
            ))
            .boxed();
    }
    let checked = stream::once(async move {
        let checks = match probe(&incoming, store, &relay, &health).await {
            Ok(checks) => checks,
            Err(_) => {
                // Includes old servers, slow or failed probes, and local
                // receipt errors. Ordinary reconciliation remains due now.
                support.unavailable();
                vec![Check::Reconcile; incoming.len()]
            }
        };
        stream::iter(incoming.into_iter().zip(checks))
    })
    .flatten();
    stream::select(ready, checked).boxed()
}

async fn probe(
    incoming: &[Stream],
    store: SharedStore,
    relay: &Relay,
    health: &health::Health,
) -> Result<Vec<Check>> {
    let mut cursors = Vec::with_capacity(incoming.len());
    for entry in incoming {
        let group = entry.group.clone();
        let cursor = local(store.clone(), move |s| {
            // Process locally staged packets even when the relay contains nothing.
            let next = s.data_next(&group)?;
            let receipt = s.transport_receipt(&group, false)?;
            Ok(Cursor {
                mailbox: URL_SAFE_NO_PAD.encode(group),
                next,
                checkpoint_hash: format!(
                    "{:x}",
                    Sha256::digest(STANDARD.encode(receipt.encode()?))
                ),
            })
        })
        .await?;
        cursors.push(cursor);
    }
    let bytes = serde_json::to_vec(&cursors)?;
    ensure!(bytes.len() <= MAX_BYTES, "mailbox sweep too large");
    health.sweep_request(bytes.len());
    let response = relay
        .client
        .post(relay.origin.join(ROUTE)?)
        .timeout(Duration::from_secs(3))
        .header(header::CONTENT_TYPE, "application/json")
        .body(bytes)
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "mailbox sweep unavailable"
    );
    let bytes = bounded(response, 128).await?;
    let changes: Changes = serde_json::from_slice(&bytes)?;
    let mask = u32::MAX >> (LIMIT - cursors.len());
    ensure!(
        (changes.packets | changes.checkpoints) & !mask == 0,
        "invalid mailbox sweep response"
    );
    let current = mask & !(changes.packets | changes.checkpoints);
    health.sweep_reply(bytes.len(), current.count_ones());
    Ok((0..cursors.len())
        .map(|i| {
            if changes.checkpoints & (1 << i) != 0 {
                Check::RestoreCheckpoint
            } else if current & (1 << i) != 0 {
                Check::Current
            } else {
                Check::Reconcile
            }
        })
        .collect())
}
