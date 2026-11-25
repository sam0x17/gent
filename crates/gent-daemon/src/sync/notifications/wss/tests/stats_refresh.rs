use super::*;
use gent_protocol::{AgentOp, OwnerOp, Request as Rpc, Response};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::Semaphore,
};

#[derive(Clone)]
struct Socket {
    store: SharedStore,
    requests: Arc<Semaphore>,
    waiters: Arc<Semaphore>,
}

impl Socket {
    async fn call(&self, request: Rpc) -> Result<serde_json::Value> {
        let (mut client, server) = UnixStream::pair()?;
        let permit = self.requests.clone().acquire_owned().await?;
        let serve = crate::serve(
            server,
            self.store.clone(),
            Arc::new(Semaphore::new(2)),
            permit,
            Arc::new(serde_json::Value::Null),
            self.waiters.clone(),
        );
        let read = async {
            let mut bytes = serde_json::to_vec(&request)?;
            bytes.push(b'\n');
            client.write_all(&bytes).await?;
            let mut response = Vec::new();
            BufReader::new(client)
                .read_until(b'\n', &mut response)
                .await?;
            match serde_json::from_slice(&response)? {
                Response::Ok(value) => Ok(value),
                Response::Error(error) => anyhow::bail!(error),
            }
        };
        Ok(tokio::try_join!(serve, read)?.1)
    }
}

pub(crate) async fn exercise_stats_refresh(
    stores: [SharedStore; 2],
    owner: String,
    agent: String,
) -> Result<()> {
    let [a, b] = stores;
    let id = |s: &SharedStore| Uuid::parse_str(s.lock().unwrap().local_node_id()).unwrap();
    let (aid, bid) = (id(&a), id(&b));
    let watch = |s: &SharedStore| Wss::new(s.lock().unwrap().sync_health.stats.clone());
    let (aw, bw) = (watch(&a), watch(&b));
    let (mut ac, mut bc) = (Connection::open(&aw), Connection::open(&bw));
    let socket = Socket {
        store: a.clone(),
        requests: Arc::new(Semaphore::new(2)),
        waiters: Arc::new(Semaphore::new(64)),
    };
    let refresh = |credential: String| Rpc::Owner {
        credential,
        action: OwnerOp::RefreshStats,
    };
    assert!(
        socket
            .call(refresh("invalid".into()))
            .await
            .unwrap_err()
            .to_string()
            .contains("unauthorized")
    );
    let mut readers = JoinSet::new();
    const READERS: usize = 40;
    for _ in 0..READERS {
        let socket = socket.clone();
        let request = refresh(owner.clone());
        readers.spawn(async move { socket.call(request).await });
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while socket.waiters.available_permits() != 64 - READERS {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(socket.requests.available_permits(), 2);
    let identity = socket
        .call(Rpc::Agent {
            credential: agent,
            action: AgentOp::Identity,
        })
        .await?;
    assert!(identity.is_object());
    let cached = socket
        .call(Rpc::Owner {
            credential: owner.clone(),
            action: OwnerOp::Stats,
        })
        .await?;
    assert!(cached.get("refresh").is_none());
    assert_eq!(cached["outbound"]["messages"], 0);

    let workers = [
        tokio::spawn(aw.stats_worker(a.clone())),
        tokio::spawn(bw.stats_worker(b.clone())),
    ];
    let mut pushes = [0, 0];
    let mut bytes = 0;
    let started = tokio::time::Instant::now();
    while !readers.is_empty() {
        tokio::select! {
            frame = ac.next_send() => {
                let wire = frame?;
                pushes[0] += usize::from(Frame::decode(&wire)?.kind==Kind::Push);
                bytes += wire.len();
                bc.received(&rewrite(&wire,aid), &b)?;
            }
            frame = bc.next_send() => {
                let wire = frame?;
                pushes[1] += usize::from(Frame::decode(&wire)?.kind==Kind::Push);
                bytes += wire.len();
                ac.received(&rewrite(&wire,bid), &a)?;
            }
            value = readers.join_next() => {
                let value = value.unwrap()??;
                assert_eq!(value["refresh"],serde_json::json!({"expected_nodes":2,"confirmed_nodes":2}));
                assert_eq!(value["outbound"]["messages"],600);
            }
        }
    }
    eprintln!(
        "{READERS} refresh callers, {pushes:?} pushes, {bytes} WSS frame bytes through response, {:?}",
        started.elapsed()
    );
    assert_eq!(pushes, [2, 3]); // Hello + Read and three pages
    let reused = socket.call(refresh(owner)).await?;
    assert_eq!(reused["refresh"]["confirmed_nodes"], 2);
    assert!(a.lock().unwrap().next_stats_send()?.is_none());
    for task in workers {
        task.abort();
        let _ = task.await;
    }
    Ok(())
}
