//! Avoid uploading the same signed checkpoint on every reconciliation pass.
//! This is disposable transport bookkeeping, never receipt or key authority.
use super::*;

const DELETE_LIMIT: u64 = 256;
// The relay enforces this packet quota across all mailboxes in one realm.
const MAX_RELAY_ROWS: u64 = 65_536;
const LEGACY_RECHECK: Duration = Duration::from_secs(30);
const DIRECT_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Default)]
pub(in crate::sync) struct State {
    published: Option<(u64, gent_crypto::Digest)>,
    covered_next: u64,
    more: bool,
    legacy_recheck: Option<Instant>,
    direct_after: Option<Instant>,
    direct_retired: Option<(Receipt, JoinHandle<Result<Retirement>>)>,
}

impl State {
    pub(in crate::sync) fn forget_publication(&mut self) {
        self.published = None;
    }

    pub(in crate::sync) fn more(&self) -> bool {
        self.more
    }

    pub(super) fn matches(&self, receipt: &Receipt) -> bool {
        self.published == Some((receipt.sequence(), receipt.digest()))
    }

    pub(super) fn retire_direct(&mut self, relay: &Relay, receipt: &Receipt) {
        if (self.matches(receipt) && !self.more)
            || self.direct_retired.is_some()
            || self.direct_after.is_some_and(|at| Instant::now() < at)
        {
            return;
        }
        let relay = relay.clone();
        let signed = receipt.clone();
        self.direct_after = Some(Instant::now() + DIRECT_INTERVAL);
        self.direct_retired = Some((
            receipt.clone(),
            tokio::spawn(async move { relay.put_checkpoint(&signed, true).await }),
        ));
    }

    pub(in crate::sync) async fn collect_direct(&mut self) {
        if self
            .direct_retired
            .as_ref()
            .is_some_and(|(_, task)| task.is_finished())
            && let Some((receipt, task)) = self.direct_retired.take()
            && let Ok(Ok(progress)) = task.await
            && self
                .published
                .is_none_or(|(seq, _)| seq <= receipt.sequence())
        {
            self.retired(&receipt, progress);
        }
    }

    fn retired(&mut self, receipt: &Receipt, progress: Retirement) {
        let next = receipt.sequence() + 1;
        self.published = Some((receipt.sequence(), receipt.digest()));
        self.more = matches!(progress, Retirement::More);
        if self.more {
            self.direct_after = Some(Instant::now() + Duration::from_secs(1));
        }
        self.legacy_recheck = None;
        match progress {
            Retirement::Drained => self.covered_next = next,
            Retirement::More | Retirement::Legacy => {
                // A legacy 204 completes at least one bounded deletion pass.
                // Pace ambiguous follow-ups on safety sweeps. A long-lived
                // sequence number alone cannot imply more than the realm quota.
                self.covered_next = (self.covered_next.max(next.saturating_sub(MAX_RELAY_ROWS))
                    + DELETE_LIMIT)
                    .min(next);
                if matches!(progress, Retirement::Legacy) && self.covered_next < next {
                    self.legacy_recheck = Some(Instant::now() + LEGACY_RECHECK);
                }
            }
        }
    }

    pub(super) async fn publish(
        &mut self,
        relay: &Relay,
        receipt: &Receipt,
        retire: bool,
        force: bool,
    ) -> Result<()> {
        if force {
            self.forget_publication();
            self.covered_next = 0;
        }
        if self.matches(receipt)
            && !self.more
            && self.legacy_recheck.is_none_or(|at| Instant::now() < at)
        {
            return Ok(());
        }
        if retire && let Some((_, task)) = self.direct_retired.take() {
            // The foreground pass supersedes this job. Its older response
            // must not mark a subsequently restored mailbox as drained.
            task.abort();
        }
        let progress = relay.put_checkpoint(receipt, retire).await?;
        if retire {
            self.retired(receipt, progress);
        } else {
            self.published = Some((receipt.sequence(), receipt.digest()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::test_http::server;

    #[tokio::test]
    async fn lost_checkpoint_responses_retry_identical_receipts_and_only_changes_publish() {
        let (relay, requests) = server(vec![
            (0, vec![]),
            (204, vec![]),
            (204, vec![]),
            (204, vec![]),
        ])
        .await;
        let node = gent_crypto::NodeIdentity::generate().unwrap();
        let receipt = node.sign_stream_receipt(b"stream", 1, [1; 32]).unwrap();
        let mut state = State::default();
        assert!(state.publish(&relay, &receipt, false, false).await.is_err());
        assert!(!state.matches(&receipt));
        state.publish(&relay, &receipt, false, false).await.unwrap();
        state.publish(&relay, &receipt, false, false).await.unwrap();
        state.publish(&relay, &receipt, false, true).await.unwrap();
        let changed = node.sign_stream_receipt(b"stream", 2, [2; 32]).unwrap();
        state.publish(&relay, &changed, false, false).await.unwrap();
        let requests = requests.await.unwrap();
        assert_eq!(requests[0], requests[1]);
        assert_eq!(requests[1], requests[2]);
        assert_eq!(requests[2].1, receipt.encode().unwrap());
        assert_eq!(requests[3].1, changed.encode().unwrap());
    }

    #[tokio::test]
    async fn a_missing_retirement_floor_restores_even_when_the_packet_cursor_is_current() {
        let (relay, requests) = server(vec![
            (200, br#"{"more":false}"#.to_vec()),
            (
                200,
                br#"{"next":5,"checkpoint":null,"retired_sequence":-1}"#.to_vec(),
            ),
            (200, br#"{"more":false}"#.to_vec()),
            (
                200,
                br#"{"next":5,"checkpoint":null,"retired_sequence":3}"#.to_vec(),
            ),
            (200, br#"{"next":5,"checkpoint":null}"#.to_vec()),
            (200, br#"{"next":3,"checkpoint":null}"#.to_vec()),
            (
                200,
                br#"{"next":5,"checkpoint":null,"retired_sequence":5}"#.to_vec(),
            ),
        ])
        .await;
        let node = gent_crypto::NodeIdentity::generate().unwrap();
        let receipt = node.sign_stream_receipt(b"stream", 3, [1; 32]).unwrap();
        let mut state = State::default();
        state.publish(&relay, &receipt, true, false).await.unwrap();
        let remote = relay.state(b"stream").await.unwrap();
        assert!(remote.restore_floor(&receipt));
        state
            .publish(&relay, &receipt, true, remote.restore_floor(&receipt))
            .await
            .unwrap();
        assert!(
            !relay
                .state(b"stream")
                .await
                .unwrap()
                .restore_floor(&receipt)
        );
        assert!(
            !relay
                .state(b"stream")
                .await
                .unwrap()
                .restore_floor(&receipt)
        );
        assert!(
            relay
                .state(b"stream")
                .await
                .unwrap()
                .restore_floor(&receipt)
        );
        assert!(relay.state(b"stream").await.is_err());
        let requests = requests.await.unwrap();
        assert_eq!(requests[0], requests[2]);
        assert!(requests[0].0.contains("/retire "));
    }

    #[tokio::test]
    async fn retirement_continues_across_failed_passes_until_explicitly_drained() {
        let (relay, requests) = server(vec![
            (200, br#"{"more":true}"#.to_vec()),
            (503, vec![]),
            (200, br#"{"more":false}"#.to_vec()),
        ])
        .await;
        let node = gent_crypto::NodeIdentity::generate().unwrap();
        let receipt = node
            .sign_stream_receipt(b"stream", 1_000_000, [1; 32])
            .unwrap();
        let mut state = State::default();
        state.publish(&relay, &receipt, true, false).await.unwrap();
        assert!(state.more());
        assert!(state.publish(&relay, &receipt, true, false).await.is_err());
        assert!(state.more());
        state.publish(&relay, &receipt, true, false).await.unwrap();
        assert!(!state.more());
        assert!(state.legacy_recheck.is_none());
        state.publish(&relay, &receipt, true, false).await.unwrap();
        assert!(
            requests
                .await
                .unwrap()
                .iter()
                .all(|(path, _)| path.contains("/retire "))
        );
    }

    #[test]
    fn legacy_retirement_bounds_cleanup_and_preserves_a_safety_recheck() {
        let node = gent_crypto::NodeIdentity::generate().unwrap();
        let receipt = node
            .sign_stream_receipt(b"stream", 1_000_000, [1; 32])
            .unwrap();
        let mut state = State::default();
        for pass in 1..=MAX_RELAY_ROWS / DELETE_LIMIT {
            state.retired(&receipt, Retirement::Legacy);
            assert!(!state.more());
            assert_eq!(
                state.legacy_recheck.is_some(),
                pass * DELETE_LIMIT < MAX_RELAY_ROWS
            );
        }
        assert_eq!(state.covered_next, receipt.sequence() + 1);
    }

    #[tokio::test]
    async fn empty_legacy_ack_waits_for_the_next_cleanup_interval() {
        let (relay, requests) = server(vec![(204, vec![]), (204, vec![])]).await;
        let node = gent_crypto::NodeIdentity::generate().unwrap();
        let receipt = node
            .sign_stream_receipt(b"stream", DELETE_LIMIT, [1; 32])
            .unwrap();
        let mut state = State::default();
        state.publish(&relay, &receipt, true, false).await.unwrap();
        assert!(state.legacy_recheck.is_some());
        state.publish(&relay, &receipt, true, false).await.unwrap();
        assert!(!state.more());
        state.legacy_recheck = Some(Instant::now());
        state.publish(&relay, &receipt, true, false).await.unwrap();
        assert!(state.legacy_recheck.is_none());
        let requests = requests.await.unwrap();
        assert_eq!(requests[0], requests[1]);
    }
}
