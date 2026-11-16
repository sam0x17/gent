//! Serialize local transactions without keeping timed-out work in the queue.
use anyhow::{Result, ensure};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

struct Cancellation(Arc<AtomicBool>);
impl Drop for Cancellation {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub(crate) async fn run<S: Send + 'static, T: Send + 'static>(
    store: Arc<Mutex<S>>,
    label: &'static str,
    operation: impl FnOnce(&mut S) -> Result<T> + Send + 'static,
) -> Result<T> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let _cancel = Cancellation(cancelled.clone());
    let active = Arc::new(AtomicBool::new(false));
    let running = active.clone();
    let queued = Instant::now();
    let mut task = tokio::task::spawn_blocking(move || {
        let mut store = store
            .lock()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
        ensure!(
            !cancelled.load(Ordering::Acquire),
            "local operation cancelled before execution"
        );
        running.store(true, Ordering::Release);
        let started = Instant::now();
        let result = operation(&mut store);
        let elapsed = started.elapsed();
        if queued.elapsed() >= Duration::from_secs(2) {
            eprintln!(
                "Gent {label}: queued {} ms, storage {} ms",
                started.duration_since(queued).as_millis(),
                elapsed.as_millis()
            );
        }
        result
    });
    tokio::select! {
        result = &mut task => result?,
        _ = tokio::time::sleep(Duration::from_secs(2)) => {
            let phase = if active.load(Ordering::Acquire) { "storage operation" } else { "storage queue" };
            eprintln!("Gent {label}: waiting for {phase}");
            task.await?
        }
    }
}

#[cfg(test)]
mod tests;
