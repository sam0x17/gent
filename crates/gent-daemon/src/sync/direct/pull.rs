//! Separate bounded connection pools for authenticated, read-only QUIC protocols.
use super::*;

#[derive(Default)]
pub(super) struct Pool {
    links: Mutex<BTreeMap<EndpointId, Connection>>,
    failed: Mutex<BTreeMap<EndpointId, Instant>>,
}

impl Direct {
    pub(super) async fn primary_pull_connection(
        &self,
        cache: &Pool,
        address: EndpointAddr,
        alpn: &[u8],
        max_links: usize,
    ) -> Option<Connection> {
        let id = address.id;
        {
            let mut links = cache.links.lock().expect("pull links poisoned");
            links.retain(|_, link| link.close_reason().is_none());
            if let Some(link) = links.get(&id) {
                return Some(link.clone());
            }
            if links.len() >= max_links {
                return None;
            }
        }
        let address = self.primary_address(address);
        let cooling = cache
            .failed
            .lock()
            .expect("pull backoff poisoned")
            .get(&id)
            .is_some_and(|at| at.elapsed() < BACKOFF);
        if cooling || address.addrs.is_empty() {
            return None;
        }
        let link = match tokio::time::timeout(DIAL, self.endpoint.connect(address, alpn)).await {
            Ok(Ok(conn)) => conn,
            _ => {
                cache.backoff(id);
                return None;
            }
        };
        let mut links = cache.links.lock().expect("pull links poisoned");
        if !links.contains_key(&id) && links.len() >= max_links {
            return None;
        }
        Some(links.entry(id).or_insert(link).clone())
    }
}

impl Pool {
    pub(super) fn backoff(&self, id: EndpointId) {
        let mut failed = self.failed.lock().expect("pull backoff poisoned");
        failed.retain(|_, at| at.elapsed() < BACKOFF);
        failed.insert(id, Instant::now());
    }
}
