use super::Endpoint;
use anyhow::{Context, Result, ensure};
use axum::{Router, body::Body, http::Request};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use gent_protocol::hosted_mcp::{self as protocol, Frame, HttpRequest, HttpResponse};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::mpsc,
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, client::IntoClientRequest, protocol::WebSocketConfig},
};
use tower::ServiceExt;

pub(super) async fn run(
    endpoint: &Endpoint,
    token: String,
    app: Router,
    connected: Arc<AtomicBool>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let mut request = endpoint.socket.clone().into_client_request()?;
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse()?);
    let config = WebSocketConfig::default()
        .max_message_size(Some(protocol::MAX_WIRE_BYTES))
        .max_frame_size(Some(protocol::MAX_WIRE_BYTES));
    let (mut socket, _) = timeout(
        Duration::from_secs(10),
        connect_async_with_config(request, Some(config), true),
    )
    .await
    .context("hosted MCP connection timed out")??;
    let ready = timeout(Duration::from_secs(10), socket.next())
        .await?
        .context("hosted MCP handshake ended")??;
    ensure!(
        matches!(
            parse(ready)?,
            Frame::Ready {
                version: protocol::VERSION
            }
        ),
        "unsupported hosted MCP protocol"
    );
    connected.store(true, Ordering::Release);
    let (mut writer, mut reader) = socket.split();
    let (responses, mut completed) = mpsc::channel(protocol::MAX_IN_FLIGHT);
    let mut tasks = JoinSet::new();
    let mut seen = BTreeSet::new();
    let mut draining = false;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_received = Instant::now();
    loop {
        // Rotate bounded duplicate tracking only after every accepted response
        // has reached the socket. Discovery traffic cannot abort an active turn.
        if draining && tasks.is_empty() && completed.is_empty() {
            writer.close().await?;
            return Ok(());
        }
        tokio::select! {
            _ = shutdown.cancelled(), if !draining => { draining = true; },
            message=reader.next()=> {
                let message=message.context("hosted MCP connection ended")??;
                last_received=Instant::now();
                match &message {
                    Message::Text(text) if text.as_str()==protocol::PONG=>continue,
                    Message::Ping(_)|Message::Pong(_)=>continue,
                    Message::Close(_)=>return Ok(()),
                    _=>{},
                }
                let Frame::Request(request)=parse(message)? else {anyhow::bail!("unexpected hosted frame");};
                ensure!(request.valid(),"invalid hosted request");
                ensure!(!seen.contains(&request.id),"repeated hosted request ID");
                if draining || tasks.len()>=protocol::MAX_IN_FLIGHT {
                    let response=failure(request.id,503,"Gent gateway is busy; retry identical tool arguments");
                    writer.send(Message::Text(serde_json::to_string(&Frame::Response(response))?.into())).await?;
                    continue;
                }
                seen.insert(request.id.clone());
                draining=seen.len()>=4096;
                let app=app.clone();
                let host=endpoint.host.clone();
                let sender=responses.clone();
                tasks.spawn(async move {
                    let id=request.id.clone();
                    let response=match timeout(Duration::from_secs(protocol::REQUEST_SECONDS-2),dispatch(app,&host,request)).await {
                        Ok(Ok(response))=>response,
                        _=>failure(id,502,"Gent could not return this result; retain the original request ID and check status before repeating work"),
                    };
                    let _=sender.send(response).await;
                });
            },
            Some(response)=completed.recv()=>writer.send(Message::Text(serde_json::to_string(&Frame::Response(response))?.into())).await?,
            Some(_)=tasks.join_next(), if !tasks.is_empty()=>{},
            _=heartbeat.tick()=> {
                ensure!(last_received.elapsed()<Duration::from_secs(60),"hosted MCP heartbeat timed out");
                writer.send(Message::Text(protocol::PING.into())).await?;
            },
        }
    }
}

fn parse(message: Message) -> Result<Frame> {
    match message {
        Message::Text(text) => serde_json::from_str(&text),
        Message::Binary(bytes) => serde_json::from_slice(&bytes),
        _ => anyhow::bail!("invalid hosted frame"),
    }
    .map_err(|_| anyhow::anyhow!("invalid hosted frame"))
}

fn failure(id: String, status: u16, message: &str) -> HttpResponse {
    HttpResponse {
        id,
        status,
        headers: vec![
            ("content-type".into(), "text/plain; charset=utf-8".into()),
            ("cache-control".into(), "no-store".into()),
        ],
        body_base64: STANDARD.encode(message),
    }
}

async fn dispatch(app: Router, host: &str, input: HttpRequest) -> Result<HttpResponse> {
    ensure!(input.valid(), "invalid hosted request");
    let bytes = STANDARD
        .decode(&input.body_base64)
        .context("invalid hosted body")?;
    ensure!(
        bytes.len() <= protocol::MAX_BODY_BYTES,
        "hosted body too large"
    );
    let mut request = Request::builder()
        .method(input.method.as_str())
        .uri(&input.path)
        .header("host", host);
    for (key, value) in input.headers {
        request = request.header(key, value);
    }
    let response = app.oneshot(request.body(Body::from(bytes))?).await?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter(|(key, _)| protocol::response_header(key.as_str()))
        .map(|(k, v)| Ok((k.as_str().to_owned(), v.to_str()?.to_owned())))
        .collect::<Result<Vec<_>>>()?;
    let bytes = axum::body::to_bytes(response.into_body(), protocol::MAX_BODY_BYTES).await?;
    let response = HttpResponse {
        id: input.id,
        status,
        headers,
        body_base64: STANDARD.encode(bytes),
    };
    ensure!(response.valid(), "invalid hosted response");
    Ok(response)
}
