use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

#[tokio::test(start_paused = true)]
async fn arrivals_share_a_fixed_half_second_bucket_without_sliding_the_deadline() {
    let available = Arc::new(AtomicU64::new(1));
    let wakeup = Arc::new(Notify::new());
    let started = Instant::now();
    let collected = collect(0, wakeup.clone(), |next| {
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
    let batch = collect(0, Arc::default(), |next| async move {
        Ok(Some(vec![next as u8]))
    })
    .await
    .unwrap();
    assert_eq!(batch.packets().len(), MAX_PACKETS);
    assert_eq!(started.elapsed(), Duration::ZERO);
    let large = collect(7, Arc::default(), |next| async move {
        Ok(Some(vec![
            next as u8;
            gent_protocol::transport_batch::MAX_PACKET_BYTES
        ]))
    })
    .await
    .unwrap();
    assert_eq!(large.packets().len(), 1);
    assert_eq!(large.packets()[0][0], 7);
    let suffix = collect(8, Arc::default(), |next| async move {
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
        collect(0, Arc::default(), |_| async { Ok(None) })
            .await
            .unwrap()
            .packets()
            .is_empty()
    );
    assert!(
        collect(0, Arc::default(), |next| async move {
            ensure!(next == 0, "injected preparation failure");
            Ok(Some(vec![1]))
        })
        .await
        .is_err()
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
}
