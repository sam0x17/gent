use super::*;
use gent_protocol::transport_batch::{Batch, MAX_PACKETS};

pub(super) fn handle(
    data: &mut BTreeMap<String, Vec<Vec<u8>>>,
    parts: &[&str],
    method: &str,
    body: &[u8],
    mode: usize,
) -> (u16, Vec<u8>) {
    if mode == 7 {
        return (404, vec![]);
    }
    let first: usize = parts[5].parse().unwrap();
    let queue = data.entry(parts[3].into()).or_default();
    if method == "PUT" {
        let batch = Batch::decode(body).unwrap();
        let mut next = queue.clone();
        for (index, packet) in batch.packets().iter().enumerate() {
            let position = first + index;
            if position == next.len() {
                next.push(packet.clone());
            }
            if next.get(position) != Some(packet) {
                return (409, vec![]);
            }
        }
        *queue = next;
        (
            200,
            serde_json::to_vec(
                &json!({"stored": true, "next": first + batch.packets().len(),
            "count": batch.packets().len()}),
            )
            .unwrap(),
        )
    } else {
        let mut batch = Batch::default();
        for packet in queue.iter().skip(first).take(MAX_PACKETS) {
            if packet.is_empty() {
                break;
            }
            let mut packet = packet.clone();
            if mode == 2 {
                *packet.last_mut().unwrap() ^= 1;
            }
            if !batch.push(packet).unwrap() {
                break;
            }
        }
        (200, batch.encode())
    }
}
