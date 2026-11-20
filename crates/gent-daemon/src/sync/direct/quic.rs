//! One persistent request stream per direction on the same negotiated connection.
//! A direction has at most one outstanding batch, so responses need no request ID.
use super::*;
use iroh::endpoint::{ConnectOptions, RecvStream, SendStream};
use tokio::sync::{Mutex as AsyncMutex, MutexGuard};

pub(super) const ALPN: &[u8] = b"gent/mls-stream/2";
const IDLE: Duration = Duration::from_secs(60);
pub(super) const MAX_LINKS: usize = 16;

pub(super) async fn dial(endpoint: &Endpoint, addr: iroh::EndpointAddr) -> Result<Connection> {
    let options = ConnectOptions::new().with_additional_alpns(vec![legacy::ALPN.to_vec()]);
    let connecting = endpoint.connect_with_opts(addr, ALPN, options).await?;
    Ok(connecting.await?)
}

type Streams = (SendStream, RecvStream);

async fn write_frame(stream: &mut SendStream, bytes: &[u8]) -> Result<()> {
    stream
        .write_all(&u32::try_from(bytes.len())?.to_be_bytes())
        .await?;
    stream.write_all(bytes).await?;
    Ok(())
}

async fn read_frame(stream: &mut RecvStream, len: [u8; 4], limit: usize) -> Result<Vec<u8>> {
    let len = u32::from_be_bytes(len) as usize;
    ensure!(
        (1..=limit).contains(&len),
        "invalid QUIC session frame length"
    );
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn serve(
    conn: Connection,
    store: SharedStore,
    used: Arc<Mutex<Instant>>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    loop {
        // The first byte can wait while the peer has no work. Bound the rest
        // of the frame independently so a trickle cannot keep a link alive.
        let mut len = [0; 4];
        recv.read_exact(&mut len[..1]).await?;
        *used.lock().expect("QUIC activity poisoned") = Instant::now();
        tokio::time::timeout(Duration::from_secs(5), async {
            recv.read_exact(&mut len[1..]).await?;
            let bytes = read_frame(&mut recv, len, session::MAX_FRAME_BYTES).await?;
            let receipt = session::accept(
                store.clone(),
                session::Peer::Endpoint(conn.remote_id()),
                &bytes,
            )
            .await?;
            *used.lock().expect("QUIC activity poisoned") = Instant::now();
            metrics
                .received
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            write_frame(&mut send, &receipt).await
        })
        .await??;
    }
}

pub(super) struct Link {
    pub(super) conn: Connection,
    used: Arc<Mutex<Instant>>,
    outgoing: AsyncMutex<Option<Streams>>,
    dialed: bool,
    reader: Option<JoinHandle<()>>,
}
impl Link {
    pub(super) fn touch(&self) {
        *self.used.lock().expect("QUIC activity poisoned") = Instant::now();
    }

    pub(super) fn reserve(&self) -> Option<MutexGuard<'_, Option<Streams>>> {
        self.outgoing.try_lock().ok()
    }

    pub(super) async fn exchange(
        &self,
        mut saved: MutexGuard<'_, Option<Streams>>,
        bytes: Vec<u8>,
        metrics: &Metrics,
    ) -> Result<Vec<u8>> {
        // Take ownership through the exchange. On cancellation the streams are
        // dropped, so a late receipt cannot be paired with the following batch.
        let (mut send, mut recv) = match saved.take() {
            Some(pair) => pair,
            None => {
                let streams = self.conn.open_bi().await?;
                metrics.streams.fetch_add(1, Ordering::Relaxed);
                streams
            }
        };
        self.touch();
        let sent = bytes.len();
        write_frame(&mut send, &bytes).await?;
        metrics.sent.fetch_add(sent as u64, Ordering::Relaxed);
        let mut len = [0; 4];
        recv.read_exact(&mut len).await?;
        let receipt = read_frame(&mut recv, len, MAX_RECEIPT_BYTES).await?;
        self.touch();
        *saved = Some((send, recv));
        Ok(receipt)
    }
}
impl Drop for Link {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"session ended");
        if let Some(task) = &self.reader {
            task.abort();
        }
    }
}

#[derive(Default)]
pub(super) struct Pool(Mutex<BTreeMap<EndpointId, Arc<Link>>>);
impl Pool {
    pub(super) fn prune(&self) {
        self.0
            .lock()
            .expect("QUIC pool poisoned")
            .retain(|_, link| {
                link.conn.close_reason().is_none()
                    && link.used.lock().expect("QUIC activity poisoned").elapsed() < IDLE
            });
    }

    pub(super) fn get(&self, id: EndpointId) -> Option<Arc<Link>> {
        let saved = self.0.lock().expect("QUIC pool poisoned");
        let link = saved.get(&id)?;
        if link.conn.close_reason().is_some() {
            return None;
        }
        Some(link.clone())
    }

    pub(super) fn install(
        &self,
        local_id: EndpointId,
        conn: Connection,
        dialed: bool,
        store: SharedStore,
        metrics: Arc<Metrics>,
    ) -> Arc<Link> {
        let id = conn.remote_id();
        let mut saved = self.0.lock().expect("QUIC pool poisoned");
        // During simultaneous dialing both ends keep the connection initiated
        // by the smaller endpoint ID. A sole incoming link is always usable.
        if let Some(old) = saved.get(&id)
            && old.conn.close_reason().is_none()
            && (old.dialed == dialed || old.dialed == (local_id < id))
        {
            conn.close(0u32.into(), b"duplicate connection");
            return old.clone();
        }
        if !saved.contains_key(&id)
            && saved.len() >= MAX_LINKS
            && let Some(oldest) = saved
                .iter()
                .min_by_key(|(_, link)| *link.used.lock().expect("QUIC activity poisoned"))
                .map(|(id, _)| *id)
        {
            saved.remove(&oldest);
        }
        let used = Arc::new(Mutex::new(Instant::now()));
        let reader = (conn.alpn() == ALPN).then(|| {
            let conn = conn.clone();
            let used = used.clone();
            let metrics = metrics.clone();
            tokio::spawn(async move {
                let _ = serve(conn.clone(), store, used, metrics).await;
                conn.close(1u32.into(), b"session stream ended");
            })
        });
        let link = Arc::new(Link {
            conn,
            used,
            outgoing: AsyncMutex::new(None),
            dialed,
            reader,
        });
        saved.insert(id, link.clone());
        metrics.connections.fetch_add(1, Ordering::Relaxed);
        link
    }
}
