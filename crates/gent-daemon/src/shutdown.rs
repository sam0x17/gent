//! Register process signals at the supervisor that owns shutdown ordering.
use std::{future::Future, io};
use tokio::signal::unix::{SignalKind, signal};

/// Register both signals before starting services, then wait for a signal or
/// the caller's cooperative shutdown. Registration errors fail startup.
pub fn with_signals(shutdown: impl Future<Output = ()>) -> io::Result<impl Future<Output = ()>> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = shutdown => {},
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
    })
}
