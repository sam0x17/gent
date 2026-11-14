//! Opt-in CIMD for an exact owner-selected set of existing host namespaces.
//! A request may select one of those identities, never an arbitrary fetch URL.
use super::*;
use crate::gateway::Registry;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::Instant,
};
use tokio::sync::{Mutex, Semaphore};

const RETRY_DELAY: Duration = Duration::from_secs(5);
const ATTEMPT_WINDOW: Duration = Duration::from_secs(1);

#[derive(Default)]
struct Cache {
    fresh: Option<(Instant, u64)>,
    retry: Option<Instant>,
    attempts: VecDeque<Instant>,
}

struct Entry {
    local: String,
    cache: Mutex<Cache>,
}

pub(crate) struct Runtime {
    registry: Registry,
    resource: String,
    clients: BTreeMap<String, Entry>,
    fetches: Semaphore,
    #[cfg(test)]
    pub(crate) fetcher: Option<TestFetcher>,
}

#[cfg(test)]
pub(crate) type TestFetcher = Arc<
    dyn Fn(
            Registration,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(Policy, Duration)>> + Send>,
        > + Send
        + Sync,
>;

impl Runtime {
    pub(crate) async fn new(
        registry: Registry,
        resource: String,
        clients: &[String],
    ) -> Result<Arc<Self>> {
        ensure!(clients.len() <= 32, "select at most 32 metadata clients");
        let mut selected = BTreeMap::new();
        for id in clients {
            let snapshot = registry
                .metadata_snapshot(id.clone(), resource.clone())
                .await?;
            let external = &snapshot.registration.assertion.as_ref().unwrap().client_id;
            endpoint(external)?;
            ensure!(
                selected
                    .insert(
                        external.clone(),
                        Entry {
                            local: id.clone(),
                            cache: Mutex::new(Cache::default())
                        }
                    )
                    .is_none(),
                "duplicate metadata client"
            );
        }
        Ok(Arc::new(Self {
            registry,
            resource,
            clients: selected,
            fetches: Semaphore::new(4),
            #[cfg(test)]
            fetcher: None,
        }))
    }

    pub(crate) fn enabled(&self) -> bool {
        !self.clients.is_empty()
    }

    #[cfg(test)]
    pub(crate) async fn expire_for_test(&self, id: &str) {
        let mut cache = self.clients[id].cache.lock().await;
        if let Some((until, _)) = &mut cache.fresh {
            *until = Instant::now();
        }
        cache.retry = None;
        cache.attempts.clear();
    }

    pub(crate) async fn prepare(&self, id: &str, callback: Option<&str>) -> Result<()> {
        #[cfg(test)]
        if let Some(fetcher) = &self.fetcher {
            return self
                .prepare_using(id, callback, |registration| fetcher(registration))
                .await;
        }
        self.prepare_using(id, callback, |registration| async move {
            import_fresh(
                &registration.assertion.as_ref().unwrap().client_id,
                &registration.resource,
                &registration.redirect_uris,
            )
            .await
        })
        .await
    }

    async fn prepare_using<F, Fut>(
        &self,
        id: &str,
        callback: Option<&str>,
        fetcher: F,
    ) -> Result<()>
    where
        F: FnOnce(Registration) -> Fut,
        Fut: std::future::Future<Output = Result<(Policy, Duration)>>,
    {
        // Unselected IDs retain the preregistration path, which rejects unknown
        // clients locally. Neither their URLs nor assertion headers are fetched.
        let Some(entry) = self.clients.get(id) else {
            return Ok(());
        };
        let mut cache = entry
            .cache
            .try_lock()
            .map_err(|_| crate::gateway::registry::Busy)?;
        let snapshot = self
            .registry
            .metadata_snapshot(entry.local.clone(), self.resource.clone())
            .await?;
        ensure!(
            snapshot.registration.assertion.as_ref().unwrap().client_id == id,
            "metadata identity changed"
        );
        ensure!(
            callback.is_none_or(|c| snapshot.registration.redirect_uris.iter().any(|r| r == c)),
            "unapproved metadata callback"
        );
        let now = Instant::now();
        if !snapshot.pending
            && cache
                .fresh
                .is_some_and(|(until, revision)| now < until && revision == snapshot.revision)
        {
            return Ok(());
        }
        if cache.retry.is_some_and(|until| now < until) {
            return Err(crate::gateway::registry::Busy.into());
        }
        while cache
            .attempts
            .front()
            .is_some_and(|time| now.duration_since(*time) >= ATTEMPT_WINDOW)
        {
            cache.attempts.pop_front();
        }
        ensure!(cache.attempts.len() < 2, crate::gateway::registry::Busy);
        let _permit = self
            .fetches
            .try_acquire()
            .map_err(|_| crate::gateway::registry::Busy)?;
        cache.fresh = None;
        cache.attempts.push_back(now);
        // Set backoff before awaiting: cancellation must not permit repeated
        // new fetches or reuse metadata whose validation did not complete.
        cache.retry = Some(now + RETRY_DELAY);
        let (policy, ttl) = fetcher(snapshot.registration)
            .await
            .map_err(|_| crate::gateway::registry::Busy)?;
        let revision = self
            .registry
            .apply_metadata_keys(entry.local.clone(), policy, snapshot.revision)
            .await
            .map_err(|_| crate::gateway::registry::Busy)?;
        cache.fresh = Some((now + ttl.min(CACHE_TTL), revision));
        cache.retry = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
