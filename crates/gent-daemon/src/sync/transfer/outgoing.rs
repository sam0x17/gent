//! A fixed coalescing window: further arrivals never postpone the first packet.
use super::*;
use gent_protocol::transport_batch::{Batch, MAX_PACKETS};

const WINDOW: Duration = Duration::from_millis(500);

/// One selected stream, from its first peer attempt through mailbox fallback.
/// The cached batch contains exactly the canonical bytes loaded from the outbox.
pub(crate) struct Prepared {
    wakeup: Arc<Notify>,
    pending: Option<Pending>,
    coalesced: bool,
}

pub(in crate::sync) struct Pending {
    group: Vec<u8>,
    first: u64,
    pub(in crate::sync) batch: Batch,
}

impl Pending {
    pub(in crate::sync) fn last(&self) -> u64 {
        // Only nonempty batches are exposed to the session carriers.
        self.first + self.batch.packets().len() as u64 - 1
    }
}

impl Prepared {
    pub(crate) fn new(wakeup: Arc<Notify>) -> Self {
        Self {
            wakeup,
            pending: None,
            coalesced: false,
        }
    }

    pub(in crate::sync) async fn peer(
        &mut self,
        store: SharedStore,
        group: &[u8],
    ) -> Result<Option<&Pending>> {
        if self.pending.is_none() {
            let g = group.to_vec();
            let first = local(store.clone(), move |s| {
                Ok(s.transport_confirm(&g, false, None)?
                    .map_or(0, |r| r.sequence() + 1))
            })
            .await?;
            let batch = self.collect(store, group, false, first).await?;
            self.pending = Some(Pending {
                group: group.to_vec(),
                first,
                batch,
            });
        }
        let pending = self.pending.as_ref().expect("prepared peer batch");
        ensure!(
            pending.group == group,
            "prepared batch belongs to another stream"
        );
        Ok((!pending.batch.packets().is_empty()).then_some(pending))
    }

    async fn mailbox(
        &mut self,
        store: SharedStore,
        group: &[u8],
        configuration: bool,
        first: u64,
    ) -> Result<Batch> {
        if let Some(pending) = self.pending.take() {
            ensure!(
                !configuration && pending.group == group,
                "prepared batch belongs to another stream"
            );
            if pending.first == first {
                return Ok(pending.batch);
            }
        }
        // Relay rollback, a newer signed receipt, or an already uploaded prefix
        // can change the cursor. Select the correct durable bytes at that cursor.
        self.collect(store, group, configuration, first).await
    }

    async fn collect(
        &mut self,
        store: SharedStore,
        group: &[u8],
        configuration: bool,
        first: u64,
    ) -> Result<Batch> {
        self.collect_with(first, |next| {
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

    async fn collect_with<F, Fut>(&mut self, first: u64, mut prepare: F) -> Result<Batch>
    where
        F: FnMut(u64) -> Fut,
        Fut: std::future::Future<Output = Result<Option<Vec<u8>>>>,
    {
        // Claim the window before awaiting I/O. Cancellation or a changed relay
        // cursor can require another read, but never another coalescing delay.
        let coalesce = !std::mem::replace(&mut self.coalesced, true);
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
            if !coalesce || Instant::now() >= deadline {
                break;
            }
            // No database lock is held while waiting. Notifications can flush a
            // newly full batch early; the deadline never slides with new arrivals.
            tokio::select! {
                _ = self.wakeup.notified() => {},
                _ = tokio::time::sleep_until(deadline) => {},
            }
        }
        Ok(batch)
    }
}

pub(super) async fn run(
    store: SharedStore,
    relay: &Relay,
    group: &[u8],
    configuration: bool,
    first: u64,
    health: &health::Health,
    prepared: &mut Prepared,
) -> Result<Option<u64>> {
    let batch = prepared
        .mailbox(store.clone(), group, configuration, first)
        .await?;
    if batch.packets().is_empty() {
        health.idle(group);
        return Ok(None);
    }
    let count = relay.put_batch(group, first, &batch).await?;
    let next = first + count as u64;
    let g = group.to_vec();
    local(store, move |s| s.record_relay_upload(&g, next)).await?;
    for _ in 0..count {
        health.progress(group, true, crate::store::now());
    }
    Ok(Some(next - 1))
}

#[cfg(test)]
mod tests;
