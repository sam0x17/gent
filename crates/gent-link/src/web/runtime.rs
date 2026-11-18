use super::*;
use std::collections::BTreeMap;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub(super) async fn ready(home: &Path) -> bool {
    tokio::time::timeout(Duration::from_secs(2), async {
        let gateway = gateway::control::probe(home).await?;
        let daemon = owner(home, OwnerOp::Status).await?;
        Ok::<_, anyhow::Error>(gateway["connected"] == true && daemon["remote_ready"] == true)
    })
    .await
    .is_ok_and(|r| r.unwrap_or(false))
}

async fn run(home: &Path, stop: CancellationToken) -> Result<()> {
    let daemon_stop = CancellationToken::new();
    let gateway_stop = CancellationToken::new();
    let lock = gent_daemon::DaemonLock::acquire(home)?
        .with_build_info(serde_json::to_value(crate::build_info::current())?);
    let daemon = gent_daemon::run_locked(lock, daemon_stop.cancelled());
    let gateway = gateway::run_web(home.to_owned(), gateway_stop.clone());
    tokio::pin!(daemon, gateway);
    let result = tokio::select! {
        result = &mut daemon => {
            gateway_stop.cancel();
            let _ = gateway.await;
            return result;
        },
        result = &mut gateway => result,
        _ = stop.cancelled() => {
            // Drain HTTP requests while the node daemon still accepts their
            // RPCs, then let the daemon commit and drain its own requests.
            gateway_stop.cancel();
            gateway.await
        },
    };
    daemon_stop.cancel();
    daemon.await?;
    result
}

/// The parent alone renews the account session, extending all child transport
/// leases. Children have no GitHub credentials, updater, or host integrations.
pub(crate) async fn maintain(parent: &Path, stop: CancellationToken) {
    let mut tasks = JoinSet::new();
    let mut active = BTreeMap::<PathBuf, CancellationToken>::new();
    let mut retry = BTreeMap::new();
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_error = None;
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Ok(home) = result {
                    active.remove(&home);
                    retry.insert(home, tokio::time::Instant::now() + Duration::from_secs(15));
                } else {
                    // An unexpected panic must not strand a permanent active
                    // entry. Restart the supervisor with all children drained.
                    break;
                }
            },
            _ = interval.tick() => {
                match storage::list(parent) {
                    Ok(records) => {
                        last_error = None;
                        let desired: std::collections::BTreeSet<_> = records.into_iter()
                            .filter(|(_, r)| r.node.is_some() && !r.revoked)
                            .map(|(home, _)| home).collect();
                        for (home, token) in &active {
                            if !desired.contains(home) { token.cancel(); }
                        }
                        for home in desired {
                            if active.contains_key(&home) || retry.get(&home)
                                .is_some_and(|when| *when > tokio::time::Instant::now()) { continue; }
                            let token = stop.child_token();
                            active.insert(home.clone(), token.clone());
                            tasks.spawn(async move {
                                // HTTP errors can contain credentials. Keep
                                // supervisor diagnostics independent of them.
                                if run(&home, token).await.is_err() {
                                    eprintln!("Gent web node stopped; retrying its saved runtime.");
                                }
                                home
                            });
                        }
                    },
                    Err(error) => {
                        let error = error.to_string();
                        if last_error.as_ref() != Some(&error) {
                            eprintln!("Gent web nodes pending: {error}");
                            last_error = Some(error);
                        }
                    }
                }
            },
        }
    }
    for token in active.values() {
        token.cancel();
    }
    while tasks.join_next().await.is_some() {}
}
