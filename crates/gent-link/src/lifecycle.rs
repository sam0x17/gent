//! Drain a dependent service while continuing to poll the service it uses.
use anyhow::Result;
use std::future::Future;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
mod signal_tests;

enum Exit {
    Service(Result<()>),
    Dependent(Result<()>),
    Stop(Result<()>),
}

pub(crate) async fn run(
    service: impl Future<Output = Result<()>>,
    dependent: impl Future<Output = Result<()>>,
    maintenance: impl Future<Output = Result<()>>,
    shutdown: impl Future<Output = ()>,
    service_stop: CancellationToken,
    dependent_stop: CancellationToken,
) -> Result<()> {
    // Dropping this future also cancels supervised work. All service futures
    // remain owned here; none are detached into background tasks.
    let _service_guard = service_stop.clone().drop_guard();
    let _dependent_guard = dependent_stop.clone().drop_guard();
    tokio::pin!(service, dependent);
    let exit = {
        tokio::pin!(maintenance, shutdown);
        tokio::select! {
            biased;
            // Startup errors must win before maintenance starts.
            result = &mut service => Exit::Service(result),
            _ = &mut shutdown => Exit::Stop(Ok(())),
            result = &mut maintenance => Exit::Stop(result),
            result = &mut dependent => Exit::Dependent(result),
        }
        // Drop maintenance here to cancel its network waits before draining.
    };
    dependent_stop.cancel();
    let result = match exit {
        Exit::Service(result) => return result.and(dependent.await),
        Exit::Dependent(result) => result,
        Exit::Stop(result) => {
            // RPC services are ordinary futures, so they must keep being
            // polled while their dependents finish accepted requests.
            tokio::select! {
                biased;
                service_result = &mut service => {
                    return result.and(service_result).and(dependent.await);
                }
                dependent_result = &mut dependent => result.and(dependent_result),
            }
        }
    };
    service_stop.cancel();
    result.and(service.await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::{pending, ready},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::{mpsc, oneshot};

    struct Dropped(Arc<AtomicBool>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn cooperative_shutdown_and_maintenance_failure_drain_web_rpc_first() {
        for maintenance_fails in [false, true] {
            let native_stop = CancellationToken::new();
            let web_stop = CancellationToken::new();
            let events = Mutex::new(Vec::new());
            let (rpc_tx, mut rpc_rx) = mpsc::unbounded_channel::<oneshot::Sender<()>>();
            let maintenance_dropped = Arc::new(AtomicBool::new(false));
            let guard = Dropped(maintenance_dropped.clone());
            let maintenance = async move {
                let _guard = guard;
                if maintenance_fails {
                    anyhow::bail!("maintenance failed");
                }
                pending().await
            };
            let daemon = async {
                events.lock().unwrap().push("native started");
                loop {
                    tokio::select! {
                        _ = native_stop.cancelled() => break,
                        Some(reply) = rpc_rx.recv() => {
                            assert!(!native_stop.is_cancelled());
                            events.lock().unwrap().push("RPC served");
                            reply.send(()).unwrap();
                        }
                    }
                }
                events.lock().unwrap().push("native stopped");
                Ok(())
            };
            let web = async {
                web_stop.cancelled().await;
                assert!(maintenance_dropped.load(Ordering::SeqCst));
                assert!(!native_stop.is_cancelled());
                events.lock().unwrap().push("web draining");
                let (reply_tx, reply_rx) = oneshot::channel();
                rpc_tx.send(reply_tx).unwrap();
                reply_rx.await.unwrap();
                assert!(!native_stop.is_cancelled());
                events.lock().unwrap().push("web stopped");
                Ok(())
            };
            let shutdown = async {
                if maintenance_fails {
                    pending::<()>().await;
                }
            };
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                run(
                    daemon,
                    web,
                    maintenance,
                    shutdown,
                    native_stop.clone(),
                    web_stop.clone(),
                ),
            )
            .await
            .expect("shutdown must keep polling native RPC");
            if maintenance_fails {
                assert_eq!(result.unwrap_err().to_string(), "maintenance failed");
            } else {
                result.unwrap();
            }
            assert_eq!(
                *events.lock().unwrap(),
                [
                    "native started",
                    "web draining",
                    "RPC served",
                    "web stopped",
                    "native stopped"
                ]
            );
        }
    }

    #[tokio::test]
    async fn native_startup_failure_cancels_web_before_polling_it() {
        let native_stop = CancellationToken::new();
        let web_stop = CancellationToken::new();
        let web = async {
            assert!(web_stop.is_cancelled());
            Ok(())
        };
        let maintenance = async { panic!("maintenance must not start after native failure") };
        let result = run(
            ready(Err(anyhow::anyhow!("native startup failed"))),
            web,
            maintenance,
            pending(),
            native_stop.clone(),
            web_stop.clone(),
        )
        .await;
        assert_eq!(result.unwrap_err().to_string(), "native startup failed");
        assert!(native_stop.is_cancelled());
    }

    #[tokio::test]
    async fn native_failure_during_drain_preserves_error_and_finishes_web() {
        let native_stop = CancellationToken::new();
        let web_stop = CancellationToken::new();
        let (fail_tx, fail_rx) = oneshot::channel();
        let (failed_tx, failed_rx) = oneshot::channel();
        let web_finished = AtomicBool::new(false);
        let daemon = async {
            fail_rx.await.unwrap();
            failed_tx.send(()).unwrap();
            anyhow::bail!("native failed during drain")
        };
        let web = async {
            web_stop.cancelled().await;
            fail_tx.send(()).unwrap();
            failed_rx.await.unwrap();
            web_finished.store(true, Ordering::SeqCst);
            Ok(())
        };
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run(
                daemon,
                web,
                pending(),
                ready(()),
                native_stop,
                web_stop.clone(),
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            result.unwrap_err().to_string(),
            "native failed during drain"
        );
        assert!(web_finished.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn dependent_exit_waits_for_service_shutdown() {
        for fails in [false, true] {
            let service_stop = CancellationToken::new();
            let dependent_stop = CancellationToken::new();
            let service_finished = AtomicBool::new(false);
            let service = async {
                service_stop.cancelled().await;
                service_finished.store(true, Ordering::SeqCst);
                Ok(())
            };
            let dependent = async {
                anyhow::ensure!(!fails, "dependent failed");
                Ok(())
            };
            let result = run(
                service,
                dependent,
                pending(),
                pending(),
                service_stop.clone(),
                dependent_stop.clone(),
            )
            .await;
            if fails {
                assert_eq!(result.unwrap_err().to_string(), "dependent failed");
            } else {
                result.unwrap();
            }
            assert!(service_finished.load(Ordering::SeqCst));
            assert!(dependent_stop.is_cancelled());
        }
    }

    #[tokio::test]
    async fn nested_shutdown_drains_gateway_through_proxy_and_native() {
        let native_stop = CancellationToken::new();
        let web_stop = CancellationToken::new();
        let proxy_stop = CancellationToken::new();
        let gateway_stop = CancellationToken::new();
        let events = Mutex::new(Vec::new());
        let (native_tx, mut native_rx) = mpsc::unbounded_channel::<oneshot::Sender<()>>();
        let (proxy_tx, mut proxy_rx) = mpsc::unbounded_channel::<oneshot::Sender<()>>();
        let (started_tx, started_rx) = oneshot::channel();
        let native = async {
            loop {
                tokio::select! {
                    _ = native_stop.cancelled() => break,
                    Some(reply) = native_rx.recv() => {
                        assert!(!native_stop.is_cancelled());
                        events.lock().unwrap().push("native replied");
                        reply.send(()).unwrap();
                    }
                }
            }
            events.lock().unwrap().push("native stopped");
            Ok(())
        };
        let proxy = async {
            loop {
                tokio::select! {
                    _ = proxy_stop.cancelled() => break,
                    Some(reply) = proxy_rx.recv() => {
                        assert!(!proxy_stop.is_cancelled());
                        let (forward_tx, forward_rx) = oneshot::channel();
                        native_tx.send(forward_tx).unwrap();
                        forward_rx.await.unwrap();
                        events.lock().unwrap().push("proxy replied");
                        reply.send(()).unwrap();
                    }
                }
            }
            assert!(!native_stop.is_cancelled());
            events.lock().unwrap().push("proxy stopped");
            Ok(())
        };
        let gateway = async {
            // Model a request accepted before shutdown which still needs RPC.
            started_tx.send(()).unwrap();
            gateway_stop.cancelled().await;
            events.lock().unwrap().push("gateway draining");
            let (reply_tx, reply_rx) = oneshot::channel();
            proxy_tx.send(reply_tx).unwrap();
            reply_rx.await.unwrap();
            assert!(!native_stop.is_cancelled());
            assert!(!proxy_stop.is_cancelled());
            events.lock().unwrap().push("gateway stopped");
            Ok(())
        };
        let web = run(
            proxy,
            gateway,
            pending(),
            web_stop.cancelled(),
            proxy_stop.clone(),
            gateway_stop.clone(),
        );
        tokio::time::timeout(
            Duration::from_secs(2),
            run(
                native,
                web,
                pending(),
                async { started_rx.await.unwrap() },
                native_stop.clone(),
                web_stop.clone(),
            ),
        )
        .await
        .expect("both RPC services must be polled during gateway drain")
        .unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            [
                "gateway draining",
                "native replied",
                "proxy replied",
                "gateway stopped",
                "proxy stopped",
                "native stopped",
            ]
        );
    }

    #[tokio::test]
    async fn dropping_supervisor_cancels_tokens_and_drops_owned_futures() {
        let native_stop = CancellationToken::new();
        let web_stop = CancellationToken::new();
        let native_dropped = Arc::new(AtomicBool::new(false));
        let web_dropped = Arc::new(AtomicBool::new(false));
        let native_guard = Dropped(native_dropped.clone());
        let web_guard = Dropped(web_dropped.clone());
        let daemon = async move {
            let _guard = native_guard;
            pending().await
        };
        let web = async move {
            let _guard = web_guard;
            pending().await
        };
        let mut supervisor = Box::pin(run(
            daemon,
            web,
            pending(),
            pending(),
            native_stop.clone(),
            web_stop.clone(),
        ));
        assert!(futures_util::poll!(&mut supervisor).is_pending());
        drop(supervisor);
        assert!(native_stop.is_cancelled());
        assert!(web_stop.is_cancelled());
        assert!(native_dropped.load(Ordering::SeqCst));
        assert!(web_dropped.load(Ordering::SeqCst));
    }
}
