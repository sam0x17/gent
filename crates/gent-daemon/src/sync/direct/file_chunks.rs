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
    pub(crate) async fn file_chunk(
        &self,
        store: SharedStore,
        peer: &str,
        object: &str,
        manifest: &Manifest,
        index: u32,
    ) -> Option<Vec<u8>> {
        let peer = peer.to_owned();
        let address = local(store, move |s| s.peer_file_source(&peer))
            .await
            .ok()??;
        let endpoint = address.id;
        let length = manifest.chunks.get(index as usize)?.bytes as usize;
        let object = Uuid::parse_str(object).ok()?;
        let cached = {
            let mut links = self.files.links.lock().expect("file links poisoned");
            links.retain(|_, link| link.close_reason().is_none());
            if links.len() >= LINKS && !links.contains_key(&endpoint) {
                return None;
            }
            links.get(&endpoint).cloned()
        };
        if self
            .files
            .failed
            .lock()
            .expect("file backoff poisoned")
            .get(&endpoint)
            .is_some_and(|at| at.elapsed() < BACKOFF)
        {
            return None;
        }
        let fetch = async {
            let link = match cached {
                Some(link) => link,
                None => {
                    let opened =
                        tokio::time::timeout(DIAL, self.endpoint.connect(address, ALPN)).await??;
                    let mut links = self.files.links.lock().expect("file links poisoned");
                    ensure!(
                        links.contains_key(&endpoint) || links.len() < LINKS,
                        "file connections busy"
                    );
                    links.entry(endpoint).or_insert(opened).clone()
                }
            };
            let (mut send, mut recv) = link.open_bi().await?;
            let mut request = [0; 17];
            request[..16].copy_from_slice(object.as_bytes());
            request[16] = u8::try_from(index)?;
            send.write_all(&request).await?;
            send.finish()?;
            let bytes = recv.read_to_end(length).await?;
            crate::file_transport::verify_chunk(manifest, index, &bytes)?;
            Ok::<_, anyhow::Error>(bytes)
        };
        if let Ok(Ok(bytes)) = tokio::time::timeout(OPERATION, fetch).await {
            self.metrics
                .file_received
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            return Some(bytes);
        }
        self.files
            .links
            .lock()
            .expect("file links poisoned")
            .remove(&endpoint);
        let mut failed = self.files.failed.lock().expect("file backoff poisoned");
        failed.retain(|_, at| at.elapsed() < BACKOFF);
        failed.insert(endpoint, Instant::now());
        None
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
