//! Bounded mailbox calls share one authenticated HTTP exchange. Operation bytes
//! and ordering remain unchanged across legacy fallback and caller retries.
use super::*;
use base64::engine::general_purpose::STANDARD;
use gent_crypto::stream::mailbox;
use gent_protocol::transport_exchange::{self as wire, binary};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{mpsc, oneshot};
mod counters;

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
    operation: binary::Operation,
    reply: oneshot::Sender<Result<Reply>>,
}
#[derive(Default)]
struct Metrics {
    binary_requests: AtomicU64,
    binary_sent: AtomicU64,
    binary_received: AtomicU64,
    by_operation: Mutex<counters::Operations>,
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
            let mut binary = false;
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
                let mut size = estimate(&calls[0].operation, binary);
                let deadline = Instant::now() + Duration::from_millis(25);
                while calls.len() < wire::MAX_OPERATIONS {
                    match tokio::time::timeout_at(deadline, receiver.recv()).await {
                        Ok(Some(call)) => {
                            let next = estimate(&call.operation, binary);
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
                let result = post(&client, &origin, &calls, &measured, &mut binary).await;
                if matches!(&result, Ok(None)) {
                    unsupported = Some(Instant::now());
                    legacy(&client, &origin, calls, &measured).await;
                    continue;
                }
                match result {
                    Ok(Some(results)) => {
                        for (call, result) in calls.into_iter().zip(results) {
                            if result.status == StatusCode::PAYLOAD_TOO_LARGE {
                                legacy(&client, &origin, vec![call], &measured).await;
                                continue;
                            }
                            let _ = call.reply.send(Ok(result));
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
    pub(super) async fn request(&self, operation: binary::Operation) -> Result<Reply> {
        ensure!(
            !operation.compact && operation.valid(),
            "invalid canonical mailbox operation"
        );
        let kind = counters::classify(&operation);
        let (reply, response) = oneshot::channel();
        let result = tokio::time::timeout(Duration::from_secs(35), async {
            self.sender
                .send(Call { operation, reply })
                .await
                .map_err(|_| anyhow::anyhow!("relay exchange stopped"))?;
            response.await.context("relay exchange stopped")?
        })
        .await
        .context("relay exchange deadline")
        .and_then(|reply| reply);
        self.metrics
            .by_operation
            .lock()
            .expect("mailbox counters poisoned")
            .observe(kind, result.as_ref().ok());
        result
    }
    pub(super) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "http_requests": self.metrics.requests.load(Ordering::Relaxed),
            "mailbox_operations": self.metrics.operations.load(Ordering::Relaxed),
            "by_operation": *self.metrics.by_operation.lock().expect("mailbox counters poisoned"),
            "request_body_bytes": self.metrics.sent.load(Ordering::Relaxed),
            "response_body_bytes": self.metrics.received.load(Ordering::Relaxed),
            "binary_http_requests": self.metrics.binary_requests.load(Ordering::Relaxed),
            "binary_request_body_bytes": self.metrics.binary_sent.load(Ordering::Relaxed),
            "binary_response_body_bytes": self.metrics.binary_received.load(Ordering::Relaxed),
            "scope": "Mailbox exchanges and legacy fallback in this process; excludes HTTP framing, files, configuration, discovery and direct traffic."
        })
    }
}
fn estimate(op: &binary::Operation, binary: bool) -> usize {
    let len = op.body.len();
    1024 + if binary { len } else { 4 * len.div_ceil(3) }
}

async fn post(
    client: &Client,
    origin: &Url,
    calls: &[Call],
    metrics: &Metrics,
    binary: &mut bool,
) -> Result<Option<Vec<Reply>>> {
    let using_binary = *binary;
    let (content_type, bytes) = if using_binary {
        let ops: Vec<_> = calls
            .iter()
            .map(|call| {
                let mut op = call.operation.clone();
                (op.compact, op.body) = mailbox::pack(&op.method, &op.path, None, op.body);
                op
            })
            .collect();
        (binary::MEDIA_TYPE, binary::encode_request(&ops)?)
    } else {
        let operations = calls
            .iter()
            .map(|call| {
                let op = &call.operation;
                wire::Operation {
                    method: op.method.clone(),
                    path: op.path.clone(),
                    body: STANDARD.encode(&op.body),
                }
            })
            .collect();
        (
            "application/json",
            serde_json::to_vec(&wire::Request {
                version: wire::VERSION,
                operations,
            })?,
        )
    };
    ensure!(
        bytes.len() <= wire::MAX_BYTES,
        "relay exchange exceeds limit"
    );
    if using_binary {
        metrics.binary_requests.fetch_add(1, Ordering::Relaxed);
        metrics
            .binary_sent
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    }
    metrics.requests.fetch_add(1, Ordering::Relaxed);
    metrics
        .sent
        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    let mut request = client
        .post(origin.join(wire::ROUTE)?)
        .header(header::CONTENT_TYPE, content_type);
    if using_binary && calls.iter().any(|c| c.operation.path.ends_with("/state")) {
        request = request.header(binary::STATE_RETIREMENT_HEADER, "1");
    }
    let response = network_error::send(request.body(bytes)).await?;
    if matches!(
        response.status(),
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    ) {
        *binary = false;
        return Ok(None);
    }
    if using_binary
        && matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::UNSUPPORTED_MEDIA_TYPE
        )
    {
        // An older deployment may have replaced the advertising worker. Let
        // the caller retry retained work using JSON; don't replay on this error.
        *binary = false;
    }
    ensure!(
        response.status() == StatusCode::OK,
        "relay exchange rejected"
    );
    let advertised = response
        .headers()
        .get(binary::SUPPORT_HEADER)
        .is_some_and(|v| v.as_bytes() == binary::SUPPORT_VALUE.as_bytes());
    let bytes = bounded(response, wire::MAX_BYTES).await?;
    metrics
        .received
        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    let results = if using_binary {
        metrics
            .binary_received
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        binary::decode_response(&bytes)?
    } else {
        let response: wire::Response = serde_json::from_slice(&bytes)?;
        ensure!(
            response.version == wire::VERSION && response.results.len() == calls.len(),
            "invalid relay exchange response"
        );
        response
            .results
            .into_iter()
            .map(|r| {
                Ok(binary::Item {
                    status: r.status,
                    compact: false,
                    body: STANDARD.decode(r.body)?,
                })
            })
            .collect::<Result<Vec<_>>>()?
    };
    ensure!(
        results.len() == calls.len(),
        "relay exchange result count mismatch"
    );
    let replies = results
        .into_iter()
        .zip(calls)
        .map(|(item, call)| {
            let body = if item.compact {
                mailbox::unpack(
                    &call.operation.method,
                    &call.operation.path,
                    Some(item.status),
                    &item.body,
                )?
            } else {
                item.body
            };
            Ok(Reply {
                status: StatusCode::from_u16(item.status)?,
                body,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    *binary = advertised;
    Ok(Some(replies))
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
                    let bytes = call.operation.body;
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
                .request(binary::Operation {
                    method: method.into(),
                    path: url.path().into(),
                    compact: false,
                    body,
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
