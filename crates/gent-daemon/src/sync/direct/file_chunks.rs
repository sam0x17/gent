//! Pull ciphertext already identified by an authorized message's file manifest.
//! Files have separate QUIC connections so backpressure cannot occupy a chat stream.
use super::*;
use gent_protocol::file_objects::{MAX_CHUNKS, Manifest};
use uuid::Uuid;

pub(super) const ALPN: &[u8] = b"gent/file-chunks/1";
const LINKS: usize = 2;
const IDLE: Duration = Duration::from_secs(15);

#[derive(Default)]
pub(super) struct Client {
    links: Mutex<BTreeMap<EndpointId, Connection>>,
    failed: Mutex<BTreeMap<EndpointId, Instant>>,
}

impl Direct {
    async fn primary_file_connection(&self, address: EndpointAddr) -> Option<Connection> {
        let id = address.id;
        {
            let mut links = self.files.links.lock().expect("file links poisoned");
            links.retain(|_, link| link.close_reason().is_none());
            if let Some(link) = links.get(&id) {
                return Some(link.clone());
            }
            if links.len() >= LINKS {
                return None;
            }
        }
        let address = self.primary_address(address);
        let cooling = self
            .files
            .failed
            .lock()
            .expect("file backoff poisoned")
            .get(&id)
            .is_some_and(|at| at.elapsed() < BACKOFF);
        if cooling || address.addrs.is_empty() {
            return None;
        }
        let link = match tokio::time::timeout(DIAL, self.endpoint.connect(address, ALPN)).await {
            Ok(Ok(conn)) => conn,
            _ => {
                self.files.backoff(id);
                return None;
            }
        };
        let mut links = self.files.links.lock().expect("file links poisoned");
        if !links.contains_key(&id) && links.len() >= LINKS {
            return None;
        }
        Some(links.entry(id).or_insert(link).clone())
    }

    pub(crate) async fn file_chunk(
        &self,
        store: SharedStore,
        peer: &str,
        object: &str,
        manifest: &Manifest,
        index: u32,
    ) -> Option<Vec<u8>> {
        let peer = peer.to_owned();
        let address = local(store.clone(), move |s| s.peer_file_source(&peer))
            .await
            .ok()??;
        let id = address.id;
        let length = manifest.chunks.get(index as usize)?.bytes as usize;
        let object = Uuid::parse_str(object).ok()?;
        let deadline = Instant::now() + OPERATION;
        let mut request = [0; 17];
        request[..16].copy_from_slice(object.as_bytes());
        request[16] = u8::try_from(index).ok()?;
        let fetch = async |link: &Connection| {
            let (mut send, mut recv) = link.open_bi().await?;
            send.write_all(&request).await?;
            send.finish()?;
            let bytes = recv.read_to_end(length).await?;
            crate::file_transport::verify_chunk(manifest, index, &bytes)?;
            self.metrics
                .file_received
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            Ok::<_, anyhow::Error>(bytes)
        };
        if let Some(link) = self.primary_file_connection(address).await {
            if let Ok(Ok(bytes)) = tokio::time::timeout_at(deadline, fetch(&link)).await {
                return Some(bytes);
            }
            link.close(1u32.into(), b"file request failed");
            self.files.backoff(id);
        }
        let helper = async {
            let candidates = local(store, move |s| s.helper_candidates(id)).await.ok()?;
            self.routes.file(id, &candidates).await
        };
        let link = tokio::time::timeout_at(deadline, helper).await.ok()??;
        if let Ok(Ok(bytes)) = tokio::time::timeout_at(deadline, fetch(&link)).await {
            return Some(bytes);
        }
        link.close(1u32.into(), b"file request failed");
        None
    }
}

impl Client {
    fn backoff(&self, id: EndpointId) {
        let mut failed = self.failed.lock().expect("file backoff poisoned");
        failed.retain(|_, at| at.elapsed() < BACKOFF);
        failed.insert(id, Instant::now());
    }
}

pub(super) async fn serve(conn: &Connection, store: SharedStore, metrics: &Metrics) -> Result<()> {
    loop {
        let (mut send, mut recv) = tokio::time::timeout(IDLE, conn.accept_bi()).await??;
        tokio::time::timeout(OPERATION, async {
            let request = recv.read_to_end(17).await?;
            ensure!(request.len() == 17, "invalid file chunk request");
            let object = Uuid::from_slice(&request[..16])?.to_string();
            let index = u32::from(request[16]);
            ensure!(index < MAX_CHUNKS, "invalid file chunk index");
            let endpoint = conn.remote_id();
            let bytes = local(store.clone(), move |s| {
                s.peer_file_chunk(endpoint, &object, index)
            })
            .await?;
            send.write_all(&bytes).await?;
            send.finish()?;
            metrics
                .file_sent
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    }
}
