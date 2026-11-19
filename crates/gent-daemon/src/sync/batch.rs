//! HTTP batching leaves individual authenticated packets and retry identities intact.
use super::*;
use gent_protocol::transport_batch::{Batch, MAX_BYTES};

#[derive(Default)]
pub(super) struct Support(Mutex<Option<Instant>>);
impl Support {
    pub(super) fn enabled(&self) -> bool {
        self.0
            .lock()
            .expect("batch support lock poisoned")
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(300))
    }
    pub(super) fn unavailable(&self) {
        *self.0.lock().expect("batch support lock poisoned") = Some(Instant::now());
    }
}

impl Relay {
    fn batch_route(&self, group: &[u8], first: u64) -> Result<Url> {
        Ok(self.origin.join(&format!(
            "v1/mailboxes/{}/batch/{first}",
            URL_SAFE_NO_PAD.encode(group)
        ))?)
    }
    pub(super) async fn get_batch(&self, group: &[u8], first: u64) -> Result<Vec<Packet>> {
        if self.batches.enabled() {
            let response = self
                .mailbox("GET", self.batch_route(group, first)?, vec![])
                .await?;
            if response.status() == StatusCode::NOT_FOUND {
                // Old relays lack this route. A current relay represents an
                // empty mailbox with a successful empty envelope, never 404.
                self.batches.unavailable();
            } else {
                ensure!(
                    response.status() == StatusCode::OK,
                    "relay batch fetch failed ({})",
                    response.status()
                );
                let batch = Batch::decode(&response.bytes(MAX_BYTES)?)?;
                return batch
                    .packets()
                    .iter()
                    .enumerate()
                    .map(|(index, bytes)| {
                        let packet = Packet::decode(bytes)?;
                        ensure!(
                            packet.group() == group && packet.sequence() == first + index as u64,
                            "relay returned another stream position"
                        );
                        Ok(packet)
                    })
                    .collect();
            }
        }
        Ok(self.get(group, first).await?.into_iter().collect())
    }
    pub(super) async fn put_batch(&self, group: &[u8], first: u64, batch: &Batch) -> Result<usize> {
        ensure!(!batch.packets().is_empty(), "cannot publish an empty batch");
        if self.batches.enabled() {
            let response = self
                .mailbox("PUT", self.batch_route(group, first)?, batch.encode())
                .await?;
            if response.status() == StatusCode::NOT_FOUND {
                self.batches.unavailable();
            } else {
                ensure!(
                    response.status() == StatusCode::OK,
                    "relay batch storage failed ({})",
                    response.status()
                );
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct StoredBatch {
                    stored: bool,
                    next: u64,
                    count: usize,
                }
                let stored: StoredBatch = serde_json::from_slice(&response.bytes(1024)?)?;
                ensure!(
                    stored.stored
                        && stored.count == batch.packets().len()
                        && stored.next == first + stored.count as u64,
                    "invalid batch storage acknowledgment"
                );
                return Ok(stored.count);
            }
        }
        // Preserve bounded fairness on old servers too. Unsent ciphertext is
        // already durable and will resume from the relay's next position.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut count = 0;
        for bytes in batch.packets() {
            self.put(&Packet::decode(bytes)?).await?;
            count += 1;
            if Instant::now() >= deadline {
                break;
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests;
