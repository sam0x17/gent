//! The negotiated payload carried by QUIC and relayed WSS. A request contains a
//! bounded batch of compact signed packets. Its response is one compact signed
//! receipt for the committed head. Carriers supply routing and correlation.
use super::*;

pub(crate) const VERSION: u8 = 2;
const MAGIC: &[u8; 4] = b"GNTS";
const HEADER: usize = 7;
pub(crate) const MAX_FRAME_BYTES: usize = HEADER + 256 + gent_protocol::transport_batch::MAX_BYTES;

pub(crate) enum Peer {
    Endpoint(EndpointId),
    Node(String),
}

pub(crate) fn request_group(frame: &[u8]) -> Result<&[u8]> {
    ensure!(
        (HEADER..=MAX_FRAME_BYTES).contains(&frame.len())
            && &frame[..4] == MAGIC
            && frame[4] == VERSION,
        "invalid session header"
    );
    let len = usize::from(u16::from_be_bytes([frame[5], frame[6]]));
    ensure!((1..=256).contains(&len), "invalid session group length");
    frame
        .get(HEADER..HEADER + len)
        .context("truncated session group")
}

fn encode(group: &[u8], batch: &Batch) -> Result<Vec<u8>> {
    ensure!((1..=256).contains(&group.len()), "invalid session group");
    let mut compact = Batch::default();
    for bytes in batch.packets() {
        ensure!(
            compact.push(Packet::decode(bytes)?.encode_compact()?)?,
            "compact batch exceeds session limit"
        );
    }
    ensure!(!compact.packets().is_empty(), "empty session batch");
    let encoded = compact.encode();
    let mut out = Vec::with_capacity(HEADER + group.len() + encoded.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&(group.len() as u16).to_be_bytes());
    out.extend_from_slice(group);
    out.extend_from_slice(&encoded);
    Ok(out)
}

fn decode(frame: &[u8]) -> Result<(&[u8], Vec<Packet>)> {
    let group = request_group(frame)?;
    let batch = Batch::decode(&frame[HEADER + group.len()..])?;
    ensure!(!batch.packets().is_empty(), "empty session batch");
    let mut packets = Vec::with_capacity(batch.packets().len());
    let mut next = None;
    for bytes in batch.packets() {
        let packet = Packet::decode_compact(bytes)?;
        ensure!(packet.group() == group, "session group mismatch");
        ensure!(
            next.is_none_or(|n| n == packet.sequence()),
            "noncontiguous session batch"
        );
        next = Some(packet.sequence() + 1);
        packets.push(packet);
    }
    Ok((group, packets))
}

pub(crate) async fn accept(store: SharedStore, peer: Peer, frame: &[u8]) -> Result<Vec<u8>> {
    let (group, packets) = decode(frame)?;
    receive(store, peer, group.to_vec(), packets)
        .await?
        .encode_compact()
}

pub(super) async fn receive(
    store: SharedStore,
    peer: Peer,
    group: Vec<u8>,
    packets: Vec<Packet>,
) -> Result<Receipt> {
    local(store, move |s| {
        let count = packets.len();
        let receipt = match peer {
            Peer::Endpoint(id) => s.direct_receive(id, &group, packets)?,
            Peer::Node(id) => s.node_session_receive(&id, &group, packets)?,
        };
        for _ in 0..count {
            s.sync_health.progress(&group, false, crate::store::now());
        }
        Ok(receipt)
    })
    .await
}

pub(super) struct Pending {
    pub(super) batch: Batch,
    last: u64,
}

impl Pending {
    pub(super) async fn prepare(
        store: SharedStore,
        group: &[u8],
        wakeup: Arc<Notify>,
    ) -> Result<Option<Self>> {
        let g = group.to_vec();
        let first = local(store.clone(), move |s| {
            let Some(receipt) = s.transport_confirm(&g, false, None)? else {
                return Ok(0);
            };
            ensure!(
                receipt.group() == g,
                "saved receipt belongs to another stream"
            );
            Ok(receipt.sequence() + 1)
        })
        .await?;
        let batch =
            crate::sync::transfer::outgoing::prepare(store, group, false, first, wakeup).await?;
        if batch.packets().is_empty() {
            return Ok(None);
        }
        let last = first + batch.packets().len() as u64 - 1;
        Ok(Some(Self { batch, last }))
    }

    pub(super) async fn exchange<F, Fut>(
        &self,
        store: SharedStore,
        group: &[u8],
        exchange: F,
    ) -> Result<u64>
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: Future<Output = Result<Vec<u8>>>,
    {
        let bytes = exchange(encode(group, &self.batch)?).await?;
        self.confirm(store, group, Receipt::decode_compact(&bytes)?)
            .await
    }

    pub(super) async fn confirm(
        &self,
        store: SharedStore,
        group: &[u8],
        receipt: Receipt,
    ) -> Result<u64> {
        ensure!(
            receipt.sequence() >= self.last,
            "receiver did not commit session batch"
        );
        let group = group.to_vec();
        let count = self.batch.packets().len();
        local(store, move |s| {
            s.transport_confirm(&group, false, Some(&receipt))?;
            for _ in 0..count {
                s.sync_health.progress(&group, true, crate::store::now());
            }
            Ok(())
        })
        .await?;
        Ok(self.last)
    }
}

pub(crate) async fn push<F, Fut>(
    store: SharedStore,
    group: &[u8],
    wakeup: Arc<Notify>,
    exchange: F,
) -> Result<Option<u64>>
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: Future<Output = Result<Vec<u8>>>,
{
    let Some(pending) = Pending::prepare(store.clone(), group, wakeup).await? else {
        return Ok(None);
    };
    pending.exchange(store, group, exchange).await.map(Some)
}

#[cfg(test)]
mod tests;
