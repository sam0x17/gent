//! The negotiated payload carried by QUIC and relayed WSS. A request contains a
//! bounded batch of compact signed packets. Its response is one compact signed
//! receipt for the committed head. Carriers supply routing and correlation.
use super::*;
pub(crate) use crate::sync::transfer::Prepared;
use crate::sync::transfer::outgoing::Pending;

pub(crate) const VERSION: u8 = 2;
const MAGIC: &[u8; 4] = b"GNTS";
const HEADER: usize = 7;
pub(crate) const MAX_FRAME_BYTES: usize = HEADER + 256 + gent_protocol::transport_batch::MAX_BYTES;

pub(crate) enum Peer {
    ObservedEndpoint(EndpointId, health::TransportPath),
    Helper(EndpointId, health::TransportPath, Arc<HelperPeer>),
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
        let last = packets.last().map(Packet::sequence);
        let (receipt, path) = match peer {
            Peer::ObservedEndpoint(id, path) => (s.direct_receive(id, &group, packets)?, path),
            Peer::Helper(id, path, pin) => {
                let receipt =
                    if path == health::TransportPath::DirectQuic && s.direct_allowed(id).is_ok() {
                        s.direct_receive(id, &group, packets)?
                    } else {
                        s.helper_receive(&pin, &group, packets)?
                    };
                (receipt, path)
            }
            Peer::Node(id) => (
                s.node_session_receive(&id, &group, packets)?,
                health::TransportPath::RelayWss,
            ),
        };
        if let Some(last) = last {
            s.sync_health.record_transport(
                &group,
                path,
                health::TransportEvidence::ReceivedPacket,
                last,
            );
        }
        for _ in 0..count {
            s.sync_health.progress(&group, false, crate::store::now());
        }
        Ok(receipt)
    })
    .await
}

pub(crate) struct Confirmed {
    pub(crate) last: u64,
    pub(in crate::sync) receipt: Receipt,
}

impl Pending {
    pub(super) async fn exchange<F, Fut>(
        &self,
        store: SharedStore,
        group: &[u8],
        exchange: F,
    ) -> Result<Confirmed>
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
    ) -> Result<Confirmed> {
        ensure!(
            receipt.sequence() >= self.last(),
            "receiver did not commit session batch"
        );
        let group = group.to_vec();
        let count = self.batch.packets().len();
        let receipt = local(store, move |s| {
            let confirmed = s
                .transport_confirm(&group, false, Some(&receipt))?
                .context("missing committed receipt")?;
            for _ in 0..count {
                s.sync_health.progress(&group, true, crate::store::now());
            }
            Ok(confirmed)
        })
        .await?;
        Ok(Confirmed {
            last: self.last(),
            receipt,
        })
    }
}

pub(crate) async fn push<F, Fut>(
    store: SharedStore,
    group: &[u8],
    prepared: &mut Prepared,
    exchange: F,
) -> Result<Option<Confirmed>>
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: Future<Output = Result<Vec<u8>>>,
{
    let Some(pending) = prepared.peer(store.clone(), group).await? else {
        return Ok(None);
    };
    local(store.clone(), |s| s.require_node_delivery()).await?;
    pending.exchange(store, group, exchange).await.map(Some)
}

#[cfg(test)]
mod tests;
