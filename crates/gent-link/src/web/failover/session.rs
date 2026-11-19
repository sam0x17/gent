use super::*;
use gent_protocol::web_failover::Checkpoint;
use tokio::sync::Mutex;

pub(crate) struct Session {
    pub(super) client: Arc<Client>,
    home: PathBuf,
    pub(crate) epoch: u64,
    checkpoint: Mutex<Option<Checkpoint>>,
    management: std::sync::RwLock<Option<String>>,
}

impl Session {
    pub(super) fn new(client: Arc<Client>, home: PathBuf, lease: &Lease) -> Self {
        Self {
            client,
            home,
            epoch: lease.epoch,
            checkpoint: Mutex::new(lease.checkpoint.clone()),
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
        // A lost commit response must not strand the uploader on an already
        // published generation. Recover the service pointer before retrying.
        let current: Lease = self.client.required(&Control::Inspect).await?;
        ensure!(
            current.epoch == self.epoch
                && current.owner == node_home::inspect(&self.client.parent)?.node.id
                && !current.revoked,
            "web carrier lease changed"
        );
        *previous = current.checkpoint;
        let parent = self.client.parent.clone();
        let home = self.home.clone();
        let node = self.client.node.clone();
        let (bytes, revision, management) = tokio::task::spawn_blocking(move || -> Result<_> {
            // Registry bindings precede daemon registration. Capture the store
            // first and the registry second so every stored chat has its handle.
            let snapshot = gent_daemon::hosted::checkpoint(&parent, &node)?;
            let revision = snapshot.revision;
            let registry = gateway::registry::portable::capture(&home)?;
            let management = registry.management.clone();
            let bytes = serde_json::to_vec(&Bundle {
                version: 1,
                snapshot,
                registry,
            })?;
            ensure!(
                bytes.len() <= CHUNK_BYTES * MAX_CHUNKS,
                "web checkpoint capacity reached"
            );
            Ok((bytes, revision, management))
        })
        .await??;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        if !previous.as_ref().is_some_and(|c| c.sha256 == sha256) {
            let checkpoint = Checkpoint {
                generation: previous.as_ref().map_or(1, |c| c.generation + 1),
                chunks: bytes.len().div_ceil(CHUNK_BYTES),
                bytes: bytes.len(),
                sha256,
            };
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
            let lease: Lease = self
                .client
                .required(&Control::Commit {
                    epoch: self.epoch,
                    checkpoint: checkpoint.clone(),
                })
                .await?;
            ensure!(
                lease.checkpoint.as_ref() == Some(&checkpoint),
                "web checkpoint commit changed"
            );
            *previous = Some(checkpoint);
        }
        owner(
            &self.client.parent,
            OwnerOp::WebCommit {
                node_id: self.client.node.clone(),
                revision,
            },
        )
        .await?;
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
