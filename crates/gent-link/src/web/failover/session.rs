use super::*;
use gent_protocol::web_failover::Checkpoint;
use tokio::sync::Mutex;

pub(crate) struct Session {
    pub(super) client: Arc<Client>,
    home: PathBuf,
    pub(crate) epoch: u64,
    checkpoint: Mutex<Publication>,
    management: std::sync::RwLock<Option<String>>,
}

#[derive(Default)]
struct Publication {
    checkpoint: Option<Checkpoint>,
    synchronized: bool,
    committed: Option<(u64, String)>,
}

impl Session {
    pub(super) fn new(client: Arc<Client>, home: PathBuf, lease: &Lease) -> Self {
        Self {
            client,
            home,
            epoch: lease.epoch,
            checkpoint: Mutex::new(Publication {
                checkpoint: lease.checkpoint.clone(),
                ..Publication::default()
            }),
            management: std::sync::RwLock::new(None),
        }
    }
    pub(crate) fn credential(&self) -> Result<String> {
        self.client.credential()
    }
    pub(crate) fn management(&self) -> Option<String> {
        self.management.read().ok().and_then(|g| g.clone())
    }

    pub(crate) async fn flush(&self) -> Result<()> {
        let mut previous = self.checkpoint.lock().await;
        let state = owner(
            &self.client.parent,
            OwnerOp::WebCheckpoint {
                node_id: self.client.node.clone(),
            },
        )
        .await?;
        ensure!(
            state["hosting_here"] == true
                && state["lease_until"]
                    .as_u64()
                    .is_some_and(|until| until > crate::auth::now().unwrap_or(u64::MAX)),
            "web carrier lease changed"
        );
        let revision = state["revision"].as_u64().context("web revision missing")?;
        let home = self.home.clone();
        let registry_hash = tokio::task::spawn_blocking(move || {
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
        let (bytes, revision, management, registry_hash) =
            tokio::task::spawn_blocking(move || -> Result<_> {
                // Registry bindings precede daemon registration. Capture the store
                // first and the registry second so every stored chat has its handle.
                let snapshot = gent_daemon::hosted::checkpoint(&parent, &node)?;
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

    pub(super) async fn heartbeat(&self, stop: CancellationToken) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut renewed = tokio::time::Instant::now();
        loop {
            tokio::select! {_=stop.cancelled()=>return Ok(()),_=interval.tick()=>{}}
            let started = tokio::time::Instant::now();
            if self
                .client
                .required::<Lease>(&Control::Renew { epoch: self.epoch })
                .await
                .is_err()
            {
                ensure!(
                    renewed.elapsed() < Duration::from_secs(20),
                    "web carrier lease renewal failed"
                );
                continue;
            }
            let seconds = 20u64.saturating_sub(started.elapsed().as_secs());
            ensure!(seconds > 0, "web lease renewal took too long");
            owner(
                &self.client.parent,
                OwnerOp::WebLease {
                    node_id: self.client.node.clone(),
                    seconds,
                },
            )
            .await?;
            renewed = started;
        }
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
                state["hosting_here"] == true,
                "web hosting route changed; reacquiring carrier lease"
            );
            if state["revision"] != state["durable"]
                || gateway::registry::portable::management(&self.home)? != self.management()
            {
                // A pending encrypted file upload is retryable. The local lease
                // continues independently while publication remains gated.
                let _ = self.flush().await;
            }
        }
    }
}
