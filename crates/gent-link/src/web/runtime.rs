use super::*;
use std::collections::BTreeMap;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub(super) async fn ready(home: &Path) -> bool {
    tokio::time::timeout(Duration::from_secs(2), async {
        let gateway = gateway::control::probe(home).await?;
        let daemon = owner(home, OwnerOp::Status).await?;
        Ok::<_, anyhow::Error>(gateway["connected"] == true && daemon["hosted_by"].is_string())
    })
    .await
    .is_ok_and(|r| r.unwrap_or(false))
}

async fn run(
    parent: &Path,
    home: &Path,
    stop: CancellationToken,
    budget: gent_daemon::hosted::ConnectionBudget,
) -> Result<()> {
    let child = node_home::inspect(home)?;
    let host = node_home::inspect(parent)?;
    if host.service.is_some() && child.hosted_parent()?.is_some() {
        let nodes = owner(parent, OwnerOp::Nodes).await?;
        let create = nodes.as_array().is_some_and(|nodes| {
            nodes
                .iter()
                .any(|n| n["id"] == child.node.id && n["hosted_by"] == host.node.id)
        });
        return super::failover::run(
            parent,
            home,
            &child.node.id,
            &child.node.name,
            create,
            stop,
            budget,
        )
        .await;
    }
    owner(
        parent,
        OwnerOp::PrepareHostedNode {
            node_id: child.node.id.clone(),
            home: home.into(),
        },
    )
    .await?;
    let id = gent_crypto::scoped_id(
        b"gent/hosted-node-activation/v1\0",
        &[host.node.id.as_bytes(), child.node.id.as_bytes()],
    )
    .to_string();
    let result = owner(
        parent,
        OwnerOp::Configure {
            request_id: id.clone(),
            edit: gent_protocol::ConfigurationEdit::HostNode {
                node_id: child.node.id.clone(),
                parent: host.node.id,
            },
        },
    )
    .await?;
    ensure!(
        result["state"] != "rejected",
        "hosting configuration was rejected"
    );
    let key = config::read_private(&home.join("owner.key"))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        if gent_daemon::request(
            parent,
            gent_protocol::Request::HostedStatus {
                node_id: child.node.id.clone(),
                gateway_credential: key.clone(),
            },
        )
        .await
        .is_ok()
        {
            break;
        }
        let status = owner(
            parent,
            OwnerOp::ConfigurationRequests {
                request_id: Some(id.clone()),
            },
        )
        .await?;
        ensure!(
            status["state"] != "rejected",
            "hosting configuration was rejected"
        );
        tokio::select! {
            _=stop.cancelled()=>return Ok(()),
            _=tokio::time::sleep_until(deadline)=>anyhow::bail!("hosting activation is pending; retrying the saved request"),
            _=tokio::time::sleep(Duration::from_secs(1))=>{},
        }
    }
    let daemon_stop = CancellationToken::new();
    let gateway_stop = CancellationToken::new();
    if host.service.is_some() {
        return super::failover::run(
            parent,
            home,
            &child.node.id,
            &child.node.name,
            true,
            stop,
            budget,
        )
        .await;
    }
    crate::lifecycle::run(
        gent_daemon::hosted::run_with_budget(home, daemon_stop.clone().cancelled_owned(), budget),
        gateway::run_web(home.to_owned(), gateway_stop.clone(), None),
        std::future::pending(),
        stop.cancelled(),
        daemon_stop,
        gateway_stop,
    )
    .await
}

/// The parent alone renews the account session, extending all child transport
/// leases. Children have no GitHub credentials, updater, or host integrations.
pub(crate) async fn maintain(parent: &Path, stop: CancellationToken) {
    let budget = gent_daemon::hosted::ConnectionBudget::default();
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
                        let revoked:std::collections::BTreeSet<_>=records.iter().filter(|(_,r)|r.revoked)
                            .filter_map(|(_,r)|r.node.clone()).collect();
                        let known:std::collections::BTreeSet<_>=records.iter().filter_map(|(_,r)|r.node.clone()).collect();
                        let mut desired: BTreeMap<PathBuf,Option<(String,String)>> = records.into_iter()
                            .filter(|(_, r)| r.node.is_some() && !r.revoked)
                            .map(|(home, _)| (home,None)).collect();
                        if let Ok(cfg)=node_home::inspect(parent)
                            && cfg.service.is_some()
                            && let Ok(nodes)=owner(parent,OwnerOp::Nodes).await
                            && let Some(nodes)=nodes.as_array()
                            && nodes.iter().any(|n|n["id"]==cfg.node.id && n["can_configure"]==true) {
                            for node in nodes.iter().filter(|n|n["hosted_by"].is_string()) {
                                let (Some(id),Some(name))=(node["id"].as_str(),node["name"].as_str()) else {continue;};
                                if revoked.contains(id) || known.contains(id) {continue;}
                                if desired.len()>=storage::MAX_NODES {break;}
                                let home=storage::portable_home(parent,id);
                                desired.entry(home).or_insert_with(||Some((id.into(),name.into())));
                            }
                        }
                        for (home, token) in &active {
                            if !desired.contains_key(home) { token.cancel(); }
                        }
                        for (home,discovered) in desired {
                            if active.contains_key(&home) || retry.get(&home)
                                .is_some_and(|when| *when > tokio::time::Instant::now()) { continue; }
                            let token = stop.child_token();
                            active.insert(home.clone(), token.clone());
                            let parent=parent.to_owned();
                            let budget=budget.clone();
                            tasks.spawn(async move {
                                // HTTP errors can contain credentials. Keep
                                // supervisor diagnostics independent of them.
                                let result=if let Some((node,name))=discovered {
                                    super::failover::run(&parent,&home,&node,&name,false,token,budget).await
                                } else {run(&parent,&home,token,budget).await};
                                if result.is_err() {
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
