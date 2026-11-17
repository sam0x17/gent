//! Direct encrypted peer setup shares the existing authenticated relay. A
//! stored receiver receipt acknowledges durable local admission, not a hint.
use super::*;

pub(super) async fn sync(store: SharedStore, relay: &Relay) -> Result<bool> {
    let mut progressed = false;
    let outgoing = local(store.clone(), |s| s.direct_mesh_outgoing()).await?;
    for packet in outgoing {
        if let Some(receipt) = relay.checkpoint(packet.group()).await? {
            let saved = receipt.clone();
            local(store.clone(), move |s| s.direct_mesh_confirm(&saved)).await?;
            relay.put_checkpoint(&receipt, true).await?;
            local(store.clone(), move |s| s.direct_mesh_finished(&receipt)).await?;
            progressed = true;
        } else {
            relay.put(&packet).await?;
        }
    }
    let incoming = local(store.clone(), |s| s.direct_mesh_incoming()).await?;
    for (peer, group) in incoming {
        let id = group.clone();
        let receipt = local(store.clone(), move |s| s.direct_mesh_receipt(&id)).await?;
        let receipt = if let Some(receipt) = receipt {
            receipt
        } else if let Some(packet) = relay.get(&group, 0).await? {
            progressed = true;
            local(store.clone(), move |s| {
                s.receive_direct_mesh(&peer, &packet)
            })
            .await?
        } else {
            continue;
        };
        relay.put_checkpoint(&receipt, false).await?;
        local(store.clone(), move |s| {
            s.direct_mesh_receipt_published(&group)
        })
        .await?;
    }
    Ok(progressed)
}
