//! Bounded ordered bursts amortize relay bookkeeping without starving peers.
use super::*;
mod checkpoints;
pub(super) use checkpoints::State;

const PACKETS: usize = 16;
const TIME_SLICE: Duration = Duration::from_secs(2);

pub(super) async fn run(
    store: SharedStore,
    relay: Relay,
    entry: Stream,
    health: Arc<health::Health>,
    state: &mut State,
) -> Result<Option<u64>> {
    let group = entry.group;
    let mut last = None;
    if entry.outgoing {
        // Both reads are independent. A position is only a service hint; the
        // endpoint still verifies receipts and refuses positions ahead of history.
        let (received, mut next) =
            tokio::try_join!(relay.checkpoint(&group), relay.position(&group))?;
        let g = group.clone();
        let confirmed = local(store.clone(), move |store| {
            store.transport_confirm(&g, entry.configuration, received.as_ref())
        })
        .await?;
        if let Some(receipt) = confirmed {
            // Only verified receiver evidence permits retirement. Restore it
            // before preparing packets so full queues can recover.
            let restore = next <= receipt.sequence();
            state.publish(&relay, &receipt, true, restore).await?;
            if restore {
                next = receipt
                    .sequence()
                    .checked_add(1)
                    .context("relay position overflow")?;
            }
        }
        let deadline = Instant::now() + TIME_SLICE;
        for _ in 0..PACKETS {
            let g = group.clone();
            let packet = local(store.clone(), move |store| {
                // Drain already encrypted history before allocating more. A
                // failing relay must not keep growing the encrypted outbox.
                let existing = if entry.configuration {
                    store.sync_outgoing(&g, next)?
                } else {
                    store.data_outgoing(&g, next)?
                };
                if existing.is_some() {
                    return Ok(existing);
                }
                if entry.configuration {
                    store.sync_prepare(&g)?;
                    store.sync_outgoing(&g, next)
                } else {
                    store.data_prepare(&g)?;
                    store.data_outgoing(&g, next)
                }
            })
            .await?;
            let Some(packet) = packet else {
                health.idle(&group);
                break;
            };
            ensure!(
                packet.sequence() == next,
                "relay position has no retained packet"
            );
            relay.put(&packet).await?;
            health.progress(&group, true, crate::store::now());
            last = Some(next);
            next = next.checked_add(1).context("relay position overflow")?;
            if Instant::now() >= deadline {
                break;
            }
        }
    } else {
        let g = group.clone();
        let (mut next, receipt) = local(store.clone(), move |store| {
            let next = if entry.configuration {
                store.sync_next(&g)?
            } else {
                store.data_next(&g)?
            };
            Ok((next, store.transport_receipt(&g, entry.configuration)?))
        })
        .await?;
        state.publish(&relay, &receipt, false, false).await?;
        let mut latest = None;
        let deadline = Instant::now() + TIME_SLICE;
        // Commit each packet separately. On a later failure, publish the last
        // accepted checkpoint before returning the error; never skip a gap.
        let result: Result<()> = async {
            for _ in 0..PACKETS {
                let Some(packet) = relay.get(&group, next).await? else {
                    health.idle(&group);
                    break;
                };
                let g = group.clone();
                let receipt = local(store.clone(), move |store| {
                    if entry.configuration {
                        store.sync_receive(&packet)?;
                    } else {
                        store.data_receive(&packet)?;
                    }
                    store.transport_receipt(&g, entry.configuration)
                })
                .await?;
                ensure!(
                    receipt.sequence() >= next,
                    "received packet did not advance the stream"
                );
                let accepted = receipt.sequence();
                latest = Some(receipt);
                health.progress(&group, false, crate::store::now());
                last = Some(accepted);
                next = accepted.checked_add(1).context("relay position overflow")?;
                if Instant::now() >= deadline {
                    break;
                }
            }
            Ok(())
        }
        .await;
        if let Some(receipt) = latest {
            state.publish(&relay, &receipt, false, false).await?;
        }
        result?;
    }
    Ok(last)
}
