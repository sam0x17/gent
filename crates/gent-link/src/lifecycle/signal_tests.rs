use super::*;
use gent_daemon::{DaemonLock, config, request};
use gent_protocol::{OwnerOp, Request};
use rustix::process::{Signal, getpid, kill_process};
use std::{future::pending, os::unix::fs::PermissionsExt, process::Stdio, time::Duration};

#[tokio::test]
async fn signals_drain_native_after_dependents() {
    const MODE: &str = "GENT_LIFECYCLE_SIGNAL_TEST";
    let Ok(mode) = std::env::var(MODE) else {
        // Signals are process-wide. Only disposable child test processes receive
        // them, so other parallel tests and the developer's daemon are untouched.
        for mode in ["outer-int", "outer-term", "default-int", "default-term"] {
            let mut child = tokio::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "lifecycle::signal_tests::signals_drain_native_after_dependents",
                    "--nocapture",
                ])
                .env(MODE, mode)
                .stdin(Stdio::null())
                .kill_on_drop(true);
            let status = tokio::time::timeout(Duration::from_secs(20), child.status())
                .await
                .expect("signal subprocess timed out")
                .unwrap();
            assert!(status.success(), "signal subprocess failed: {mode}");
        }
        return;
    };
    let signal = if mode.ends_with("-int") {
        Signal::INT
    } else {
        Signal::TERM
    };
    let home = tempfile::Builder::new()
        .prefix("gent-signal-")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    config::initialize(home.path(), "signal-drain").unwrap();
    let credential = config::read_private(&home.path().join("owner.key")).unwrap();
    let lock = DaemonLock::acquire(home.path()).unwrap();
    let status = || Request::Owner {
        credential: credential.clone(),
        action: OwnerOp::Status,
    };
    let send_signal = async {
        // The server is ready before the signal is sent. Waiting for a response
        // also forces the enclosing supervisor to keep polling native RPC.
        while request(home.path(), status()).await.is_err() {
            tokio::task::yield_now().await;
        }
        kill_process(getpid(), signal).unwrap();
    };
    if mode.starts_with("default-") {
        let (result, ()) = tokio::join!(gent_daemon::run_locked(lock, pending()), send_signal);
        result.unwrap();
    } else {
        let native_stop = CancellationToken::new();
        let web_stop = CancellationToken::new();
        let shutdown = gent_daemon::shutdown::with_signals(pending()).unwrap();
        let web = async {
            send_signal.await;
            web_stop.cancelled().await;
            assert!(!native_stop.is_cancelled());
            // An accepted gateway request still needs an RPC during drain.
            request(home.path(), status()).await.unwrap();
            assert!(!native_stop.is_cancelled());
            assert!(DaemonLock::acquire(home.path()).is_err());
            Ok(())
        };
        run(
            gent_daemon::run_locked_until(lock, native_stop.clone().cancelled_owned()),
            web,
            pending(),
            shutdown,
            native_stop.clone(),
            web_stop.clone(),
        )
        .await
        .unwrap();
        assert!(native_stop.is_cancelled());
    }
    assert!(!home.path().join("daemon.sock").exists());
    DaemonLock::acquire(home.path()).unwrap();
}
