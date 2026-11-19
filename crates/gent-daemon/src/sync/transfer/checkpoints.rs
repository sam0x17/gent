//! Avoid uploading the same signed checkpoint on every reconciliation pass.
//! This is disposable transport bookkeeping, never receipt or key authority.
use super::*;

const REFRESH: Duration = Duration::from_secs(30);

#[derive(Default)]
pub(in crate::sync) struct State {
    published: Option<(u64, gent_crypto::Digest, Instant)>,
    direct_retired: Option<(Instant, JoinHandle<Result<()>>)>,
}

impl State {
    pub(super) fn retire_direct(&mut self, relay: &Relay, receipt: &Receipt) {
        // Direct traffic does not need a cloud write per batch. Periodically
        // retire old cloud packets; lost writes remain retryable and cannot
        // invalidate a verified direct delivery.
        if self
            .direct_retired
            .as_ref()
            .is_none_or(|(at, task)| task.is_finished() && at.elapsed() >= Duration::from_secs(300))
        {
            let relay = relay.clone();
            let receipt = receipt.clone();
            self.direct_retired = Some((
                Instant::now(),
                tokio::spawn(async move { relay.put_checkpoint(&receipt, true).await }),
            ));
        }
    }
    fn due(&self, receipt: &Receipt, now: Instant) -> bool {
        self.published
            .as_ref()
            .is_none_or(|(sequence, digest, at)| {
                *sequence != receipt.sequence()
                    || *digest != receipt.digest()
                    || now.duration_since(*at) >= REFRESH
            })
    }

    pub(super) async fn publish(
        &mut self,
        relay: &Relay,
        receipt: &Receipt,
        retire: bool,
        force: bool,
    ) -> Result<()> {
        if force || self.due(receipt, Instant::now()) {
            relay.put_checkpoint(receipt, retire).await?;
            // A failure, including a lost response, never suppresses a retry.
            self.published = Some((receipt.sequence(), receipt.digest(), Instant::now()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn failures_retry_and_relay_loss_forces_a_cached_receipt_back_to_storage() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut paths = Vec::new();
            for status in [503, 204, 204, 204] {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = BufReader::new(socket);
                let mut line = String::new();
                socket.read_line(&mut line).await.unwrap();
                paths.push(line);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    socket.read_line(&mut line).await.unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                assert!(length <= MAX_RECEIPT_BYTES);
                let mut body = vec![0; length];
                socket.read_exact(&mut body).await.unwrap();
                Receipt::decode(&body).unwrap();
                socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            }
            paths
        });
        let relay = Relay {
            client: Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            origin: format!("http://{address}/").parse().unwrap(),
            authorization: header::HeaderValue::from_static("Bearer test"),
            batches: Arc::default(),
            states: Arc::default(),
            exchange: None,
            cluster: None,
        };
        let node = gent_crypto::NodeIdentity::generate().unwrap();
        let receipt = node.sign_stream_receipt(b"stream", 1, [1; 32]).unwrap();
        let mut state = State::default();
        assert!(state.publish(&relay, &receipt, true, false).await.is_err());
        assert!(state.published.is_none());
        state.publish(&relay, &receipt, true, false).await.unwrap();
        // The third call skips HTTP; a reported storage rollback forces it.
        state.publish(&relay, &receipt, true, false).await.unwrap();
        state.publish(&relay, &receipt, true, true).await.unwrap();
        let changed = node.sign_stream_receipt(b"stream", 2, [2; 32]).unwrap();
        state.publish(&relay, &changed, true, false).await.unwrap();
        let paths = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(paths.len(), 4);
        assert!(
            paths
                .iter()
                .all(|p| p.starts_with("PUT /v1/mailboxes/") && p.contains("/retire "))
        );
    }

    #[test]
    fn unchanged_receipts_refresh_periodically_and_changes_publish_immediately() {
        let node = gent_crypto::NodeIdentity::generate().unwrap();
        let receipt = node.sign_stream_receipt(b"stream", 1, [1; 32]).unwrap();
        let now = Instant::now();
        let mut state = State::default();
        assert!(state.due(&receipt, now));
        state.published = Some((receipt.sequence(), receipt.digest(), now));
        assert!(!state.due(&receipt, now + Duration::from_secs(29)));
        assert!(state.due(&receipt, now + REFRESH));
        let changed = node.sign_stream_receipt(b"stream", 2, [2; 32]).unwrap();
        assert!(state.due(&changed, now));
        // Even an unexpected digest change at the same sequence must go to
        // the relay's conflict check, not disappear behind this optimization.
        let conflicting = node.sign_stream_receipt(b"stream", 1, [3; 32]).unwrap();
        assert!(state.due(&conflicting, now));
    }
}
