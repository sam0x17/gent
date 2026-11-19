//! A fixed coalescing window: further arrivals never postpone the first packet.
use super::*;
use gent_protocol::transport_batch::{Batch, MAX_PACKETS};

const WINDOW: Duration = Duration::from_millis(500);

pub(super) async fn run(
    store: SharedStore,
    relay: &Relay,
    group: &[u8],
    configuration: bool,
    first: u64,
    health: &health::Health,
    wakeup: Arc<Notify>,
) -> Result<Option<u64>> {
    let batch = prepare(store, group, configuration, first, wakeup).await?;
    if batch.packets().is_empty() {
        health.idle(group);
        return Ok(None);
    }
    let count = relay.put_batch(group, first, &batch).await?;
    for _ in 0..count {
        health.progress(group, true, crate::store::now());
    }
    Ok(Some(first + count as u64 - 1))
}

pub(in crate::sync) async fn prepare(
    store: SharedStore,
    group: &[u8],
    configuration: bool,
    first: u64,
    wakeup: Arc<Notify>,
) -> Result<Batch> {
    collect(first, wakeup, |next| {
        let g = group.to_vec();
        let store = store.clone();
        async move {
            let packet = local(store.clone(), move |store| {
                // Reuse durable ciphertext before advancing encryption. A lost HTTP
                // response must never cause a second ratchet step for the same record.
                let existing = if configuration {
                    store.sync_outgoing(&g, next)?
                } else {
                    store.data_outgoing(&g, next)?
                };
                if existing.is_some() {
                    return Ok(existing);
                }
                if configuration {
                    store.sync_prepare(&g)?;
                    store.sync_outgoing(&g, next)
                } else {
                    store.data_prepare(&g)?;
                    store.data_outgoing(&g, next)
                }
            })
            .await?;
            packet
                .map(|packet| {
                    ensure!(
                        packet.sequence() == next,
                        "relay position has no retained packet"
                    );
                    packet.encode()
                })
                .transpose()
        }
    })
    .await
}

async fn collect<F, Fut>(first: u64, wakeup: Arc<Notify>, mut prepare: F) -> Result<Batch>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Result<Option<Vec<u8>>>>,
{
    let mut batch = Batch::default();
    let mut window = None;
    let preparation_deadline = Instant::now() + TIME_SLICE;
    loop {
        let next = first + batch.packets().len() as u64;
        if let Some(packet) = prepare(next).await? {
            if !batch.push(packet)? {
                break;
            }
            let deadline = *window.get_or_insert_with(|| Instant::now() + WINDOW);
            // Drain an existing burst immediately. Preparation also has a time
            // bound so slow storage cannot monopolize a stream's turn.
            if batch.packets().len() == MAX_PACKETS
                || Instant::now() >= deadline.min(preparation_deadline)
            {
                break;
            }
            continue;
        }
        let Some(deadline) = window else {
            return Ok(batch);
        };
        if Instant::now() >= deadline {
            break;
        }
        // No database lock is held while waiting. Notifications can flush a
        // newly full batch early; the deadline never slides with new arrivals.
        tokio::select! {
            _ = wakeup.notified() => {},
            _ = tokio::time::sleep_until(deadline) => {},
        }
    }
    Ok(batch)
}

#[cfg(test)]
mod tests;
