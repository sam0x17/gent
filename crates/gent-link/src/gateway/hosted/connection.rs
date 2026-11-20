use super::Endpoint;
use anyhow::{Context, Result, ensure};
use axum::{Router, body::Body, http::Request};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{Sink, SinkExt, StreamExt};
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
    session: Option<Arc<crate::web::failover::Session>>,
) -> Result<()> {
    let mut request = endpoint.socket.clone().into_client_request()?;
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse()?);
    if let Some(session) = &session {
        request
            .headers_mut()
            .insert("x-gent-web-management", "1".parse()?);
        request
            .headers_mut()
            .insert("x-gent-web-epoch", session.epoch.to_string().parse()?);
        if session.passive {
            request
                .headers_mut()
                .insert(protocol::PASSIVE_HEADER, "1".parse()?);
        }
    }
    let config = WebSocketConfig::default()
        .max_message_size(Some(protocol::MAX_WIRE_BYTES))
        .max_frame_size(Some(protocol::MAX_WIRE_BYTES));
    let (mut socket, response) = timeout(
        Duration::from_secs(10),
        connect_async_with_config(request, Some(config), true),
    )
    .await
    .context("hosted MCP connection timed out")??;
    let passive = session.as_ref().is_some_and(|s| s.passive);
    ensure!(
        passive == crate::web::failover::passive_echo(response.headers())?,
        "bridge did not confirm passive web carrier"
    );
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
    serve(socket, &endpoint.host, app, shutdown, session, passive).await
}

async fn serve(
    socket: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    host: &str,
    app: Router,
    shutdown: tokio_util::sync::CancellationToken,
    session: Option<Arc<crate::web::failover::Session>>,
    passive: bool,
) -> Result<()> {
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
            timeout(Duration::from_secs(5), writer.close()).await??;
            return Ok(());
        }
        tokio::select! {
            _ = shutdown.cancelled(), if !draining => { draining = true; },
            message=reader.next()=> {
                let message=message.context("hosted MCP connection ended")??;
                last_received=Instant::now();
                match &message {
                    Message::Text(text) if passive && text.as_str()==protocol::PROBE=>{
                        write(&mut writer, protocol::ALIVE.into(), passive).await?;
                        continue;
                    }
                    Message::Text(text) if text.as_str()==protocol::PONG=>continue,
                    Message::Ping(_)|Message::Pong(_)=>continue,
                    Message::Close(_)=>return Ok(()),
                    _=>{},
                }
                let frame = parse(message)?;
                let id = match &frame {
                    Frame::Request(request) if request.valid() => request.id.clone(),
                    Frame::Manage { id, action } if session.is_some() && protocol::valid_id(id) && action.valid() => id.clone(),
                    _ => anyhow::bail!("invalid hosted request"),
                };
                ensure!(!seen.contains(&id),"repeated hosted request ID");
                if draining || tasks.len()>=protocol::MAX_IN_FLIGHT {
                    let response=failure(id,503,"Gent gateway is busy; retry identical tool arguments");
                    write(&mut writer, serde_json::to_string(&Frame::Response(response))?.into(), passive).await?;
                    continue;
                }
                seen.insert(id.clone());
                draining=seen.len()>=4096;
                let app=app.clone();
                let host=host.to_owned();
                let sender=responses.clone();
                let session=session.clone();
                tasks.spawn(async move {
                    let operation=Box::pin(async {
                        if let Frame::Manage { action, .. } = frame {
                            let session = session.as_ref().context("portable carrier required")?;
                            let result = session.connector(action).await;
                            return Ok(match result {
                                Ok(value) => HttpResponse {
                                    id: id.clone(), status: 200,
                                    headers: vec![("content-type".into(), "application/json".into()), ("cache-control".into(),"no-store".into())],
                                    body_base64: STANDARD.encode(serde_json::to_vec(&value)?),
                                },
                                Err(error) if error.to_string().contains("connector URL expired") => failure(id.clone(),422,"connector URL expired"),
                                Err(_) => failure(id.clone(),503,"connector management pending"),
                            });
                        }
                        let Frame::Request(request) = frame else { anyhow::bail!("invalid hosted request") };

                        let response=dispatch(app,&host,request).await?;
                        if let Some(session)=&session { session.flush().await?; }
                        Ok::<_,anyhow::Error>(response)
                    });
                    let serving=async {
                        match &session {
                            Some(session)=>session.work(operation).await,
                            None=>operation.await,
                        }
                    };
                    let response=match timeout(Duration::from_secs(protocol::REQUEST_SECONDS-2),serving).await {
                        Ok(Ok(response))=>response,
                        _=>failure(id,502,"Gent could not return this result; retain the original request ID and check status before repeating work"),
                    };
                    let _=sender.send(response).await;
                });
            },
            Some(response)=completed.recv()=>write(&mut writer, serde_json::to_string(&Frame::Response(response))?.into(), passive).await?,
            Some(_)=tasks.join_next(), if !tasks.is_empty()=>{},
            _=heartbeat.tick(), if !passive=> {
                ensure!(last_received.elapsed()<Duration::from_secs(60),"hosted MCP heartbeat timed out");
                writer.send(Message::Text(protocol::PING.into())).await?;
            },
        }
    }
}

// A stalled downstream write cannot hold the socket reader past the bridge's
// liveness probe. Failing the connection lets the bridge invite a standby.
async fn write(
    writer: &mut (impl Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    text: tokio_tungstenite::tungstenite::Utf8Bytes,
    passive: bool,
) -> Result<()> {
    let sending = writer.send(Message::Text(text));
    if passive {
        timeout(Duration::from_secs(1), sending).await??;
    } else {
        sending.await?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use tokio::{net::TcpListener, sync::Notify};
    use tokio_tungstenite::{accept_async, connect_async};

    #[tokio::test]
    async fn passive_reader_answers_probes_while_a_hosted_call_waits() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let app = Router::new().route(
            "/mcp",
            post({
                let entered = entered.clone();
                let release = release.clone();
                move || async move {
                    entered.notify_one();
                    release.notified().await;
                    "response"
                }
            }),
        );
        let bridge = async {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            let request = Frame::Request(HttpRequest {
                id: id.clone(),
                method: "POST".into(),
                path: "/mcp".into(),
                headers: vec![],
                body_base64: String::new(),
            });
            socket
                .send(Message::Text(
                    serde_json::to_string(&request).unwrap().into(),
                ))
                .await
                .unwrap();
            entered.notified().await;
            for _ in 0..2 {
                socket
                    .send(Message::Text(protocol::PROBE.into()))
                    .await
                    .unwrap();
                assert_eq!(
                    socket.next().await.unwrap().unwrap(),
                    Message::Text(protocol::ALIVE.into())
                );
            }
            release.notify_one();
            let Frame::Response(response) = parse(socket.next().await.unwrap().unwrap()).unwrap()
            else {
                panic!("missing hosted response")
            };
            assert_eq!(response.id, id);
            assert_eq!(response.status, 200);
            socket.close(None).await.unwrap();
        };
        let native = async {
            let (socket, _) = connect_async(url).await.unwrap();
            serve(socket, "localhost", app, Default::default(), None, true)
                .await
                .unwrap();
        };
        timeout(Duration::from_secs(3), async {
            tokio::join!(bridge, native)
        })
        .await
        .unwrap();
    }
}
