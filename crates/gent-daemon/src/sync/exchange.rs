//! Bounded mailbox calls share one authenticated HTTP exchange. Operation bytes
//! and ordering remain unchanged across legacy fallback and caller retries.
use super::*;
use base64::engine::general_purpose::STANDARD;
use gent_protocol::transport_exchange as wire;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{mpsc, oneshot};

pub(super) struct Reply {
    pub status: StatusCode,
    pub body: Vec<u8>,
}
impl Reply {
    pub(super) fn status(&self) -> StatusCode {
        self.status
    }
    pub(super) fn bytes(self, limit: usize) -> Result<Vec<u8>> {
        ensure!(self.body.len() <= limit, "relay response too large");
        Ok(self.body)
    }
}
struct Call {
    operation: wire::Operation,
    reply: oneshot::Sender<Result<Reply>>,
}
#[derive(Default)]
struct Metrics {
    requests: AtomicU64,
    operations: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
}
pub(super) struct Exchange {
    sender: mpsc::Sender<Call>,
    metrics: Arc<Metrics>,
}
impl Exchange {
    pub(super) fn start(client: Client, origin: Url) -> Arc<Self> {
        let (sender, mut receiver) = mpsc::channel::<Call>(64);
        let metrics = Arc::new(Metrics::default());
        let measured = metrics.clone();
        tokio::spawn(async move {
            let mut unsupported = None;
            let mut carry = None;
            loop {
                let first = match carry.take() {
                    Some(call) => call,
                    None => match receiver.recv().await {
                        Some(call) => call,
                        None => break,
                    },
                };
                let mut calls = vec![first];
                let mut size = calls[0].operation.body.len() + 1024;
                let deadline = Instant::now() + Duration::from_millis(25);
                while calls.len() < wire::MAX_OPERATIONS {
                    match tokio::time::timeout_at(deadline, receiver.recv()).await {
                        Ok(Some(call)) => {
                            let next = call.operation.body.len() + 1024;
                            if size + next > wire::MAX_BYTES {
                                carry = Some(call);
                                break;
                            }
                            size += next;
                            calls.push(call);
                        }
                        _ => break,
                    }
                }
                measured
                    .operations
                    .fetch_add(calls.len() as u64, Ordering::Relaxed);
                if unsupported.is_some_and(|at: Instant| at.elapsed() < Duration::from_secs(300)) {
                    legacy(&client, &origin, calls, &measured).await;
                    continue;
                }
                let operations = calls.iter().map(|c| c.operation.clone()).collect();
                let result = post(&client, &origin, operations, &measured).await;
                if matches!(&result, Ok(None)) {
                    unsupported = Some(Instant::now());
                    legacy(&client, &origin, calls, &measured).await;
                    continue;
                }
                match result {
                    Ok(Some(results)) if results.len() == calls.len() => {
                        for (call, result) in calls.into_iter().zip(results) {
                            if result.status == 413 {
                                legacy(&client, &origin, vec![call], &measured).await;
                                continue;
                            }
                            let result = (|| {
                                Ok(Reply {
                                    status: StatusCode::from_u16(result.status)?,
                                    body: STANDARD.decode(result.body)?,
                                })
                            })();
                            let _ = call.reply.send(result);
                        }
                    }
                    _ => {
                        for call in calls {
                            let _ = call.reply.send(Err(anyhow::anyhow!(
                                "relay exchange unavailable; retained operations will retry"
                            )));
                        }
                    }
                }
            }
        });
        Arc::new(Self { sender, metrics })
    }
    pub(super) async fn request(&self, operation: wire::Operation) -> Result<Reply> {
        ensure!(operation.valid(), "invalid mailbox operation");
        let (reply, response) = oneshot::channel();
        tokio::time::timeout(Duration::from_secs(35), async {
            self.sender
                .send(Call { operation, reply })
                .await
                .map_err(|_| anyhow::anyhow!("relay exchange stopped"))?;
            response.await.context("relay exchange stopped")?
        })
        .await
        .context("relay exchange deadline")?
    }
    pub(super) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"http_requests":self.metrics.requests.load(Ordering::Relaxed),"mailbox_operations":self.metrics.operations.load(Ordering::Relaxed),"request_body_bytes":self.metrics.sent.load(Ordering::Relaxed),"response_body_bytes":self.metrics.received.load(Ordering::Relaxed),"scope":"Mailbox exchanges and legacy fallback in this process; excludes HTTP framing, files, configuration, discovery and direct traffic."})
    }
}
async fn post(
    client: &Client,
    origin: &Url,
    operations: Vec<wire::Operation>,
    metrics: &Metrics,
) -> Result<Option<Vec<wire::ResultItem>>> {
    let bytes = serde_json::to_vec(&wire::Request {
        version: wire::VERSION,
        operations,
    })?;
    ensure!(
        bytes.len() <= wire::MAX_BYTES,
        "relay exchange exceeds limit"
    );
    metrics.requests.fetch_add(1, Ordering::Relaxed);
    metrics
        .sent
        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    let response = network_error::send(
        client
            .post(origin.join(wire::ROUTE)?)
            .header(header::CONTENT_TYPE, "application/json")
            .body(bytes),
    )
    .await?;
    if matches!(
        response.status(),
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    ) {
        return Ok(None);
    }
    ensure!(
        response.status() == StatusCode::OK,
        "relay exchange rejected"
    );
    let bytes = bounded(response, wire::MAX_BYTES).await?;
    metrics
        .received
        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    let response: wire::Response = serde_json::from_slice(&bytes)?;
    ensure!(
        response.version == wire::VERSION,
        "unsupported relay exchange"
    );
    Ok(Some(response.results))
}
async fn legacy(client: &Client, origin: &Url, calls: Vec<Call>, metrics: &Metrics) {
    let mut groups = BTreeMap::<String, Vec<Call>>::new();
    for call in calls {
        groups
            .entry(call.operation.path.split('/').nth(3).unwrap().to_owned())
            .or_default()
            .push(call);
    }
    stream::iter(groups.into_values())
        .for_each_concurrent(4, |calls| async move {
            for call in calls {
                let result = async {
                    let bytes = STANDARD.decode(&call.operation.body)?;
                    metrics.requests.fetch_add(1, Ordering::Relaxed);
                    metrics
                        .sent
                        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    let method = reqwest::Method::from_bytes(call.operation.method.as_bytes())?;
                    let response = network_error::send(
                        client
                            .request(method, origin.join(&call.operation.path)?)
                            .header(header::CONTENT_TYPE, "application/octet-stream")
                            .body(bytes),
                    )
                    .await?;
                    let status = response.status();
                    let body = bounded(response, wire::MAX_BYTES).await?;
                    metrics
                        .received
                        .fetch_add(body.len() as u64, Ordering::Relaxed);
                    Ok(Reply { status, body })
                }
                .await;
                let _ = call.reply.send(result);
            }
        })
        .await;
}

#[cfg(test)]
mod tests;
impl Relay {
    pub(super) async fn mailbox(&self, method: &str, url: Url, body: Vec<u8>) -> Result<Reply> {
        if let Some(exchange) = &self.exchange {
            return exchange
                .request(wire::Operation {
                    method: method.into(),
                    path: url.path().into(),
                    body: STANDARD.encode(body),
                })
                .await;
        }
        let response = network_error::send(
            self.client
                .request(reqwest::Method::from_bytes(method.as_bytes())?, url)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(body),
        )
        .await?;
        let status = response.status();
        let body = bounded(response, wire::MAX_BYTES).await?;
        Ok(Reply { status, body })
    }
}
