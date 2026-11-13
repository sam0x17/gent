//! One ciphertext chunk per object per pass; all local work rechecks authority.
use super::*;
use crate::file_transport::FileRelay;

pub(super) struct Scheduler {
    relay: FileRelay,
    retries: BTreeMap<String, Retry>,
    cursor: usize,
}
pub(super) struct Worker(JoinHandle<()>);
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl Scheduler {
    pub fn start(mut self, store: SharedStore) -> Worker {
        Worker(tokio::spawn(async move {
            loop {
                // This worker never consumes configuration wake-ups. Check for
                // new file jobs at least once per second while otherwise idle.
                let progressed = self.tick(store.clone()).await.unwrap_or(false);
                let mut pause = if progressed {
                    Duration::from_millis(10)
                } else {
                    Duration::from_secs(1)
                };
                if let Some(delay) = self.delay() {
                    pause = pause.min(delay);
                }
                tokio::time::sleep(pause).await;
            }
        }))
    }

    pub fn new(relay: FileRelay) -> Self {
        Self {
            relay,
            retries: BTreeMap::new(),
            cursor: 0,
        }
    }
    pub fn delay(&self) -> Option<Duration> {
        self.retries
            .values()
            .map(|r| r.at.saturating_duration_since(Instant::now()))
            .min()
    }
    pub async fn tick(&mut self, store: SharedStore) -> Result<bool> {
        let jobs = local(store.clone(), |s| s.file_jobs()).await?;
        self.retries.retain(|id, _| jobs.contains(id));
        let begin = self.cursor.min(jobs.len());
        let end = (begin + 16).min(jobs.len());
        let selected: Vec<_> = jobs[begin..end]
            .iter()
            .filter(|id| self.retries.get(*id).is_none_or(|r| r.at <= Instant::now()))
            .cloned()
            .collect();
        self.cursor = if end == jobs.len() { 0 } else { end };
        let mut progressed = self.cursor != 0;
        let mut work = stream::iter(selected)
            .map(|id| {
                let store = store.clone();
                let relay = self.relay.clone();
                async move {
                    let result = transfer_file(store, relay, &id).await;
                    (id, result)
                }
            })
            .buffer_unordered(4);
        while let Some((id, result)) = work.next().await {
            let delay = match result {
                Ok(true) => {
                    progressed = true;
                    self.retries.remove(&id);
                    continue;
                }
                Ok(false) => Duration::from_secs(30),
                Err(_) => self.retries.get(&id).map_or(Duration::from_secs(1), |r| {
                    (r.delay * 2).min(Duration::from_secs(30))
                }),
            };
            // No IDs, metadata, paths, keys, or value-bearing transport errors in logs.
            self.retries.insert(
                id,
                Retry {
                    at: Instant::now() + delay,
                    delay,
                },
            );
        }
        Ok(progressed)
    }
}
async fn transfer_file(store: SharedStore, relay: FileRelay, id: &str) -> Result<bool> {
    let object = id.to_owned();
    let Some(job) = local(store.clone(), move |s| s.file_transfer(&object)).await? else {
        return Ok(false);
    };
    if job.upload {
        let mut snapshot = relay.reserve(id, &job.manifest).await?;
        let missing =
            (0..job.manifest.chunks.len() as u32).find(|i| !snapshot.uploaded.contains(i));
        if let Some(index) = missing {
            let object = job.id.clone();
            let bytes = local(store.clone(), move |s| s.file_upload(&object, index)).await?;
            relay.put(id, &job.manifest, index, &bytes).await?;
            snapshot.uploaded.push(index);
            snapshot.uploaded.sort_unstable();
        }
        let changed = local(store, move |s| s.file_uploaded(&job.id, &snapshot.uploaded)).await?;
        Ok(missing.is_some() || changed)
    } else if let Some(&index) = job.missing.first() {
        let Some(bytes) = relay.get(id, &job.manifest, index).await? else {
            anyhow::bail!("file chunk awaiting relay recovery");
        };
        local(store, move |s| s.file_received(&job.id, index, &bytes)).await?;
        Ok(true)
    } else {
        anyhow::bail!("incomplete file without missing chunks")
    }
}
