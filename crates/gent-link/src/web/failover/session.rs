use super::*;
use gent_protocol::web_failover::Checkpoint;
use std::pin::Pin;
use tokio::sync::Mutex;
use tokio::time::{Instant, timeout_at};

pub(crate) struct Session {
    pub(super) client: Arc<Client>,
    home: PathBuf,
    pub(crate) epoch: u64,
    pub(crate) passive: bool,
    pub(super) lost: CancellationToken,
    grant: Mutex<Option<Grant>>,
    pub(crate) files: Arc<std::fs::File>,
    checkpoint: Mutex<Publication>,
    management: std::sync::RwLock<Option<String>>,
}

#[derive(Default)]
struct Publication {
    checkpoint: Option<Checkpoint>,
    synchronized: bool,
    committed: Option<(u64, String)>,
}

#[derive(Clone, Copy)]
struct Grant {
    until: Instant,
    expires_at: u64,
}

impl Grant {
    fn reusable(self, refreshing: Option<Instant>, now: Instant, wall: u64) -> bool {
        self.until > now + Duration::from_secs(5)
            && self.expires_at > wall.saturating_add(5)
            && refreshing.is_none_or(|previous| self.until > previous)
    }
}

impl Session {
    pub(super) fn new(
        client: Arc<Client>,
        home: PathBuf,
        lease: &Lease,
        passive: bool,
        files: Arc<std::fs::File>,
    ) -> Self {
        Self {
            client,
            home,
            epoch: lease.epoch,
            passive,
            lost: CancellationToken::new(),
            grant: Mutex::new(None),
            files,
            checkpoint: Mutex::new(Publication {
                checkpoint: lease.checkpoint.clone(),
                ..Publication::default()
            }),
            management: std::sync::RwLock::new(None),
        }
    }
    pub(crate) async fn connector(
        &self,
        action: gent_protocol::hosted_mcp::ConnectorAction,
    ) -> Result<String> {
        let cfg = node_home::inspect(&self.home)?;
        let base = gent_protocol::hosted_mcp::node_base(&cfg.cluster.id, &cfg.node.id)
            .context("invalid web node identity")?;
        let result = gateway::registry::capability::manage(
            &self.home,
            &format!("{}{base}", origin(&self.home)?),
            &action,
        )?;
        self.flush().await?;
        Ok(result)
    }

    pub(crate) fn credential(&self) -> Result<String> {
        self.client.credential()
    }
    pub(crate) fn management(&self) -> Option<String> {
        self.management.read().ok().and_then(|g| g.clone())
    }

    pub(crate) fn disconnected(&self) {
        self.lost.cancel();
    }

    // A quiet passive socket conveys reachability only. Obtain a signed
    // epoch grant before dispatch, then keep it live only while work is pending.
    pub(crate) async fn work<T>(
        &self,
        operation: Pin<Box<impl Future<Output = Result<T>>>>,
    ) -> Result<T> {
        if !self.passive {
            return operation.await;
        }
        let grants = async {
            let until = self.grant(None).await.inspect_err(|_| self.lost.cancel())?;
            // Management can mutate the registry before making a hosted-agent
            // RPC. Recheck the local route and epoch before entering it.
            timeout_at(until, self.current()).await??;
            self.while_granted(until, operation).await
        };
        tokio::select! {
            biased;
            _ = self.lost.cancelled() => anyhow::bail!("web carrier grant lost"),
            result = grants => result,
        }
    }

    pub(super) async fn while_granted<T>(
        &self,
        mut until: Instant,
        operation: Pin<Box<impl Future<Output = Result<T>>>>,
    ) -> Result<T> {
        let refresh = async {
            loop {
                // A legacy carrier keeps its existing five-second heartbeat.
                let pause = if self.passive { 10 } else { 5 };
                let next = (Instant::now() + Duration::from_secs(pause))
                    .min(until - Duration::from_secs(2));
                tokio::time::sleep_until(next).await;
                match timeout_at(until, self.grant(Some(until))).await {
                    Ok(Ok(next)) => until = next,
                    Ok(Err(_))
                        if !self.passive && Instant::now() + Duration::from_secs(2) < until =>
                    {
                        continue;
                    }
                    Ok(Err(error)) => return error,
                    Err(_) => return anyhow::anyhow!("web work grant expired"),
                }
            }
        };
        let result = tokio::select! {
            biased;
            error = refresh => { self.lost.cancel(); Err(error) },
            result = operation => result,
        };
        let value = result?;
        ensure!(
            Instant::now() < until && !self.lost.is_cancelled(),
            "web carrier grant expired"
        );
        Ok(value)
    }

    async fn grant(&self, refreshing: Option<Instant>) -> Result<Instant> {
        let mut cached = self.grant.lock().await;
        ensure!(!self.lost.is_cancelled(), "web carrier grant lost");
        let started = crate::auth::now()?;
        if let Some(grant) = *cached
            && grant.reusable(refreshing, Instant::now(), started)
        {
            return Ok(grant.until);
        }
        let lease: Lease = self
            .client
            .required(&Control::Renew { epoch: self.epoch })
            .await?;
        let grant = self.install(&lease, started).await?;
        *cached = Some(grant);
        Ok(grant.until)
    }

    pub(super) async fn acquired(&self, lease: &Lease, started: u64) -> Result<Instant> {
        let grant = self.install(lease, started).await?;
        *self.grant.lock().await = Some(grant);
        Ok(grant.until)
    }

    async fn install(&self, lease: &Lease, started: u64) -> Result<Grant> {
        ensure!(
            !lease.revoked
                && lease.epoch == self.epoch
                && lease.owner == node_home::inspect(&self.client.parent)?.node.id,
            "web carrier grant changed"
        );
        let expires_at = lease.expires_at.min(started.saturating_add(20));
        let remaining = expires_at.saturating_sub(crate::auth::now()?);
        ensure!(remaining > 3, "web carrier grant expired");
        // Reserve one second for the Unix clock's fractional part.
        let until = Instant::now() + Duration::from_secs(remaining - 1);
        timeout_at(
            until,
            owner(
                &self.client.parent,
                OwnerOp::WebGrant {
                    node_id: self.client.node.clone(),
                    epoch: self.epoch,
                    expires_at,
                },
            ),
        )
        .await??;
        ensure!(
            expires_at > crate::auth::now()? && until > Instant::now(),
            "local web grant expired"
        );
        Ok(Grant { until, expires_at })
    }

    async fn current(&self) -> Result<Value> {
        let state = owner(
            &self.client.parent,
            OwnerOp::WebCheckpoint {
                node_id: self.client.node.clone(),
            },
        )
        .await?;
        ensure!(
            state["hosting_here"] == true
                && state["epoch"].as_u64() == Some(self.epoch)
                && state["lease_until"]
                    .as_u64()
                    .is_some_and(|until| until > crate::auth::now().unwrap_or(u64::MAX)),
            "web carrier lease changed"
        );
        Ok(state)
    }

    pub(crate) async fn flush(&self) -> Result<()> {
        let mut previous = self.checkpoint.lock().await;
        let state = self.current().await?;
        let revision = state["revision"].as_u64().context("web revision missing")?;
        let home = self.home.clone();
        let files = self.files.clone();
        let registry_hash = tokio::task::spawn_blocking(move || {
            let _guard = files;
            gateway::registry::portable::capture(&home)?.change_hash()
        })
        .await??;
        if previous.synchronized
            && previous.committed.as_ref() == Some(&(revision, registry_hash))
            && state["durable"]
                .as_u64()
                .is_some_and(|durable| durable >= revision)
        {
            return Ok(());
        }
        if !previous.synchronized {
            // Inspect only after acquisition or an uncertain publication. An
            // identical retry can recover a commit whose response was lost.
            let current: Lease = self.client.required(&Control::Inspect).await?;
            ensure!(
                current.epoch == self.epoch
                    && current.owner == node_home::inspect(&self.client.parent)?.node.id
                    && !current.revoked,
                "web carrier lease changed"
            );
            previous.checkpoint = current.checkpoint;
            previous.synchronized = true;
        }
        let parent = self.client.parent.clone();
        let home = self.home.clone();
        let node = self.client.node.clone();
        let epoch = self.epoch;
        let files = self.files.clone();
        let (bytes, revision, management, registry_hash) =
            tokio::task::spawn_blocking(move || -> Result<_> {
                let _guard = files;
                // Registry bindings precede daemon registration. Capture the store
                // first and the registry second so every stored chat has its handle.
                let snapshot = gent_daemon::hosted::checkpoint_for_epoch(&parent, &node, epoch)?;
                let revision = snapshot.revision;
                let registry = gateway::registry::portable::capture(&home)?;
                let management = registry.management.clone();
                let registry_hash = registry.change_hash()?;
                let bytes = serde_json::to_vec(&Bundle {
                    version: 1,
                    snapshot,
                    registry,
                })?;
                ensure!(
                    bytes.len() <= CHUNK_BYTES * MAX_CHUNKS,
                    "web checkpoint capacity reached"
                );
                Ok((bytes, revision, management, registry_hash))
            })
            .await??;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        if !previous
            .checkpoint
            .as_ref()
            .is_some_and(|c| c.sha256 == sha256)
        {
            let checkpoint = Checkpoint {
                generation: previous.checkpoint.as_ref().map_or(1, |c| c.generation + 1),
                chunks: bytes.len().div_ceil(CHUNK_BYTES),
                bytes: bytes.len(),
                sha256,
            };
            // Mark uncertainty before sending: cancellation after cloud commit
            // must force an Inspect on the next attempt.
            previous.synchronized = false;
            let lease: Lease = if checkpoint.chunks <= MAX_BATCH {
                self.client
                    .required(&Control::Publish {
                        epoch: self.epoch,
                        checkpoint: checkpoint.clone(),
                        chunks: bytes
                            .chunks(CHUNK_BYTES)
                            .map(|p| STANDARD.encode(p))
                            .collect(),
                    })
                    .await?
            } else {
                for (batch, parts) in bytes.chunks(CHUNK_BYTES * MAX_BATCH).enumerate() {
                    let (status, _) = self
                        .client
                        .call(&Control::Stage {
                            epoch: self.epoch,
                            generation: checkpoint.generation,
                            start: batch * MAX_BATCH,
                            chunks: parts
                                .chunks(CHUNK_BYTES)
                                .map(|p| STANDARD.encode(p))
                                .collect(),
                        })
                        .await?;
                    ensure!(status == 200, "web checkpoint staging failed ({status})");
                }
                self.client
                    .required(&Control::Commit {
                        epoch: self.epoch,
                        checkpoint: checkpoint.clone(),
                    })
                    .await?
            };
            ensure!(
                lease.checkpoint.as_ref() == Some(&checkpoint),
                "web checkpoint commit changed"
            );
            previous.checkpoint = Some(checkpoint);
            previous.synchronized = true;
        }
        owner(
            &self.client.parent,
            OwnerOp::WebCommit {
                epoch: Some(self.epoch),
                node_id: self.client.node.clone(),
                revision,
            },
        )
        .await?;
        previous.committed = Some((revision, registry_hash));
        *self
            .management
            .write()
            .map_err(|_| anyhow::anyhow!("web checkpoint state unavailable"))? = management;
        Ok(())
    }

    pub(super) async fn maintain(&self, stop: CancellationToken) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {_=stop.cancelled()=>return Ok(()),_=interval.tick()=>{}}
            let state = owner(
                &self.client.parent,
                OwnerOp::WebCheckpoint {
                    node_id: self.client.node.clone(),
                },
            )
            .await?;
            // A delayed configuration proposal can arrive after takeover.
            // Reacquire a new epoch and republish the route with a fresh retry
            // identity instead of keeping a live lease on an unusable carrier.
            ensure!(
                state["hosting_here"] == true && state["epoch"].as_u64() == Some(self.epoch),
                "web hosting route changed; reacquiring carrier lease"
            );
            if state["revision"] != state["durable"]
                || gateway::registry::portable::management(&self.home)? != self.management()
            {
                // A pending encrypted file upload is retryable. The local lease
                // continues independently while publication remains gated.
                let _ = self.work(Box::pin(self.flush())).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use gent_protocol::hosted_mcp::PASSIVE_HEADER;

    #[test]
    fn passive_mode_requires_one_exact_echo() {
        let mut headers = HeaderMap::new();
        assert!(!passive_echo(&headers).unwrap());
        headers.insert(PASSIVE_HEADER, "0".parse().unwrap());
        assert!(passive_echo(&headers).is_err());
        headers.insert(PASSIVE_HEADER, "1".parse().unwrap());
        assert!(passive_echo(&headers).unwrap());
        headers.append(PASSIVE_HEADER, "1".parse().unwrap());
        assert!(passive_echo(&headers).is_err());
    }

    #[test]
    fn concurrent_work_shares_only_a_fresh_unexpired_grant() {
        let now = Instant::now();
        let grant = Grant {
            until: now + Duration::from_secs(19),
            expires_at: 120,
        };
        assert!(grant.reusable(None, now, 100));
        // The first long-running call must renew. Its siblings can share the extension.
        assert!(!grant.reusable(Some(grant.until), now, 100));
        assert!(grant.reusable(Some(now + Duration::from_secs(9)), now, 100));
        assert!(!grant.reusable(None, now + Duration::from_secs(15), 100));
        assert!(!grant.reusable(None, now, 120));
    }
}
