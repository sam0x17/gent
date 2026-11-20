//! Bounded ordered bursts amortize relay bookkeeping without starving peers.
use super::*;
mod checkpoints;
pub(super) mod outgoing;
pub(super) use checkpoints::State;
pub(crate) use outgoing::Prepared;

const TIME_SLICE: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub(super) struct Peers {
    pub(super) direct: Option<Arc<direct::Direct>>,
    pub(super) wss: notifications::wss::Wss,
}

impl Peers {
    pub(super) async fn transfer(
        &self,
        store: &SharedStore,
        relay: &Relay,
        entry: &Stream,
        health: &health::Health,
        prepared: &mut Prepared,
        state: &mut State,
    ) -> Option<Result<Option<u64>>> {
        let direct = match &self.direct {
            Some(direct) => {
                direct
                    .transfer(store.clone(), entry, health, prepared)
                    .await
            }
            None => None,
        };
        let result = match direct {
            Some(result) => result,
            None => self.wss.transfer(store, entry, health, prepared).await?,
        };
        Some(result.map(|delivery| {
            delivery.map(|confirmed| {
                state.retire_direct(relay, &confirmed.receipt);
                confirmed.last
            })
        }))
    }
}

pub(super) async fn run(
    store: SharedStore,
    relay: Relay,
    entry: Stream,
    health: Arc<health::Health>,
    prepared: &mut Prepared,
    state: &mut State,
) -> Result<Option<u64>> {
    let group = entry.group;
    let mut last = None;
    if entry.outgoing {
        let mut remote = relay.state(&group).await?;
        let received = remote.receipt.take();
        let relay_next = remote.next;
        let g = group.clone();
        let (confirmed, first) = local(store.clone(), move |store| {
            let confirmed = store.transport_confirm(&g, entry.configuration, received.as_ref())?;
            let floor = confirmed.as_ref().map_or(0, |r| r.sequence() + 1);
            let first = store.relay_upload_start(&g, relay_next, floor)?;
            Ok((confirmed, first))
        })
        .await?;
        if let Some(receipt) = confirmed {
            // Only verified receiver evidence permits retirement. Restore it
            // before preparing packets so full queues can recover.
            let restore = remote.restore_floor(&receipt);
            state.publish(&relay, &receipt, true, restore).await?;
        }
        return outgoing::run(
            store,
            &relay,
            &group,
            entry.configuration,
            first,
            &health,
            prepared,
        )
        .await;
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
        let was_published = state.matches(&receipt);
        state.publish(&relay, &receipt, false, false).await?;
        let mut latest = None;
        let deadline = Instant::now() + TIME_SLICE;
        // Commit each packet separately. On a later failure, publish the last
        // accepted checkpoint before returning the error; never skip a gap.
        let result: Result<()> = async {
            let packets = relay.get_batch(&group, next).await?;
            if packets.is_empty() {
                health.idle(&group);
                // Bulk sweeps skip current streams before reaching this path.
                // A legacy relay or a single idle stream still needs to detect
                // loss of just the checkpoint, with no new packets or hints.
                if was_published && relay.checkpoint(&group).await?.as_ref() != Some(&receipt) {
                    state.publish(&relay, &receipt, false, true).await?;
                }
            }
            for packet in packets {
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
