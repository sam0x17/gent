use super::*;
use futures_util::FutureExt;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

#[tokio::test(start_paused = true)]
async fn arrivals_share_a_fixed_half_second_bucket_without_sliding_the_deadline() {
    let available = Arc::new(AtomicU64::new(1));
    let wakeup = Arc::new(Notify::new());
    let started = Instant::now();
    let mut prepared = Prepared::new(wakeup.clone());
    let collected = prepared.collect_with(0, |next| {
        let available = available.clone();
        async move { Ok((next < available.load(Ordering::SeqCst)).then(|| vec![next as u8])) }
    });
    let arrivals = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        available.store(2, Ordering::SeqCst);
        wakeup.notify_one();
        tokio::time::sleep(Duration::from_millis(350)).await;
        available.store(3, Ordering::SeqCst);
        wakeup.notify_one();
    };
    let (batch, ()) = tokio::join!(collected, arrivals);
    assert_eq!(batch.unwrap().packets(), &[vec![0], vec![1], vec![2]]);
    assert_eq!(started.elapsed(), WINDOW);
}

#[tokio::test(start_paused = true)]
async fn full_bursts_flush_early_and_byte_limited_suffixes_resume_at_the_same_position() {
    let started = Instant::now();
    let batch = Prepared::new(Arc::default())
        .collect_with(0, |next| async move { Ok(Some(vec![next as u8])) })
        .await
        .unwrap();
    assert_eq!(batch.packets().len(), MAX_PACKETS);
    assert_eq!(started.elapsed(), Duration::ZERO);
    let large = Prepared::new(Arc::default())
        .collect_with(7, |next| async move {
            Ok(Some(vec![
                next as u8;
                gent_protocol::transport_batch::MAX_PACKET_BYTES
            ]))
        })
        .await
        .unwrap();
    assert_eq!(large.packets().len(), 1);
    assert_eq!(large.packets()[0][0], 7);
    let suffix = Prepared::new(Arc::default())
        .collect_with(8, |next| async move {
            Ok(Some(vec![
                next as u8;
                gent_protocol::transport_batch::MAX_PACKET_BYTES
            ]))
        })
        .await
        .unwrap();
    assert_eq!(suffix.packets()[0][0], 8);
    assert_eq!(started.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn idle_streams_do_not_wait_and_preparation_failure_does_not_return_a_partial_batch() {
    let started = Instant::now();
    assert!(
        Prepared::new(Arc::default())
            .collect_with(0, |_| async { Ok(None) })
            .await
            .unwrap()
            .packets()
            .is_empty()
    );
    assert!(
        Prepared::new(Arc::default())
            .collect_with(0, |next| async move {
                ensure!(next == 0, "injected preparation failure");
                Ok(Some(vec![1]))
            })
            .await
            .is_err()
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
}

#[tokio::test]
async fn same_cursor_peer_and_mailbox_fallback_reuse_the_prepared_bytes() {
    // This store has no such stream. Any attempt to reload the checkpoint or
    // outbox will fail, even if the second coalescing window was suppressed.
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    config::initialize(home.path(), "coalescing-test").unwrap();
    let store = Arc::new(Mutex::new(Store::open(home.path()).unwrap()));
    let group = b"test-stream";
    let mut prepared = Prepared::new(Arc::default());
    for packets in [vec![vec![43], vec![44]], vec![]] {
        let mut batch = Batch::default();
        for bytes in &packets {
            assert!(batch.push(bytes.clone()).unwrap());
        }
        prepared.pending = Some(Pending {
            group: group.to_vec(),
            first: 43,
            batch,
        });
        prepared.coalesced = true;
        let retry = prepared
            .peer(store.clone(), group)
            .now_or_never()
            .unwrap()
            .unwrap();
        assert_eq!(
            retry.map(|pending| pending.batch.packets()),
            (!packets.is_empty()).then_some(packets.as_slice())
        );
        let fallback = prepared
            .mailbox(store.clone(), group, false, 43)
            .now_or_never()
            .unwrap()
            .unwrap();
        assert_eq!(fallback.packets(), packets);
    }
}

#[tokio::test(start_paused = true)]
async fn changed_cursor_reads_the_new_suffix_without_a_second_window() {
    let mut prepared = Prepared::new(Arc::default());
    let started = Instant::now();
    let read = |next| async move { Ok((next <= 45).then(|| vec![next as u8])) };
    let peer = prepared.collect_with(43, read).await.unwrap();
    assert_eq!(peer.packets(), &[vec![43], vec![44], vec![45]]);
    assert_eq!(started.elapsed(), WINDOW);
    let relay = prepared.collect_with(45, read).await.unwrap();
    assert_eq!(relay.packets(), &[vec![45]]);
    assert_eq!(started.elapsed(), WINDOW);
}
