//! A parked carrier only contacts the bridge for an invitation or native delivery demand.
use super::*;
use futures_util::{SinkExt, StreamExt};
use gent_protocol::hosted_mcp::{AVAILABLE, ConnectorAction, PASSIVE_HEADER, STANDBY_HEADER};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_with_config,
    tungstenite::{Message, client::IntoClientRequest, protocol::WebSocketConfig},
};

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(base: &str, token: &str) -> Result<Socket> {
    let mut url = url::Url::parse(&format!("{base}/connect"))?;
    let scheme = match (url.scheme(), url.host_str()) {
        ("https", _) => "wss",
        ("http", Some("127.0.0.1" | "[::1]")) => "ws",
        _ => anyhow::bail!("invalid web standby origin"),
    };
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("invalid web standby URL"))?;
    let mut request = url.as_str().into_client_request()?;
    let headers = request.headers_mut();
    headers.insert("authorization", format!("Bearer {token}").parse()?);
    headers.insert(STANDBY_HEADER, "1".parse()?);
    headers.insert(PASSIVE_HEADER, "1".parse()?);
    let config = WebSocketConfig::default()
        .max_message_size(Some(256))
        .max_frame_size(Some(256));
    let (socket, response) = tokio::time::timeout(
        Duration::from_secs(10),
        connect_async_with_config(request, Some(config), true),
    )
    .await??;
    ensure!(
        passive_echo(response.headers())?,
        "bridge did not confirm passive standby"
    );
    Ok(socket)
}

async fn demand(client: &Client) -> Result<Option<String>> {
    let state = owner(
        &client.parent,
        OwnerOp::WebDeliveryDemand {
            node_id: client.node.clone(),
        },
    )
    .await?;
    let id = state
        .get("message_id")
        .context("missing web delivery demand")?;
    if id.is_null() {
        return Ok(None);
    }
    Ok(Some(
        id.as_str()
            .filter(|id| gent_protocol::hosted_mcp::valid_id(id))
            .context("invalid web delivery demand")?
            .into(),
    ))
}

async fn check_carrier(client: &Client, id: &str) -> Result<()> {
    ensure!(
        client.manage(&ConnectorAction::Status).await? == "ready",
        "web carrier unavailable"
    );
    owner(
        &client.parent,
        OwnerOp::WebDeliveryChecked {
            node_id: client.node.clone(),
            message_id: id.into(),
        },
    )
    .await?;
    Ok(())
}

async fn monitor_demand(client: &Client) {
    let poll = Duration::from_secs(3);
    let mut ticks = tokio::time::interval(poll);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut retry = tokio::time::Instant::now();
    let mut backoff = poll;
    loop {
        ticks.tick().await;
        match tokio::time::timeout(poll, demand(client)).await {
            Ok(Ok(None)) => {
                retry = tokio::time::Instant::now();
                backoff = poll;
            }
            Ok(Ok(Some(id))) if tokio::time::Instant::now() >= retry => {
                if matches!(
                    tokio::time::timeout(Duration::from_secs(45), check_carrier(client, &id)).await,
                    Ok(Ok(()))
                ) {
                    backoff = poll;
                } else {
                    retry = tokio::time::Instant::now() + backoff;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
            _ => {}
        }
    }
}

async fn wait(mut socket: Socket, monitor: impl Future<Output = ()>) -> Result<Socket> {
    tokio::pin!(monitor);
    loop {
        tokio::select! {
            message = socket.next() => match message.context("web standby disconnected")?? {
                Message::Text(text) if text.as_str() == AVAILABLE => return Ok(socket),
                Message::Ping(_) => tokio::time::timeout(Duration::from_secs(1), socket.flush()).await??,
                Message::Pong(_) => {},
                _ => anyhow::bail!("unexpected web standby response"),
            },
            _ = &mut monitor => anyhow::bail!("web standby demand monitor stopped"),
        }
    }
}

pub(super) async fn invited(client: &Client) -> Result<Socket> {
    let socket = connect(&client.url, &client.credential()?).await?;
    wait(socket, monitor_demand(client)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::handshake::server::{Callback, ErrorResponse, Request, Response},
    };

    struct StandbyHandshake;

    impl Callback for StandbyHandshake {
        fn on_request(
            self,
            req: &Request,
            mut res: Response,
        ) -> std::result::Result<Response, ErrorResponse> {
            assert_eq!(req.method().as_str(), "GET");
            assert_eq!(req.uri().path(), "/clusters/cluster/nodes/web/connect");
            assert_eq!(req.headers()[PASSIVE_HEADER], "1");
            assert_eq!(req.headers()[STANDBY_HEADER], "1");
            assert_eq!(req.headers()["authorization"], "Bearer test");
            assert!(!req.headers().contains_key("x-gent-web-epoch"));
            res.headers_mut()
                .insert(PASSIVE_HEADER, "1".parse().unwrap());
            Ok(res)
        }
    }

    #[tokio::test]
    async fn parked_socket_only_accepts_text_invitation_while_demand_is_pending() {
        for (frame, invited) in [
            (Message::Text(AVAILABLE.into()), true),
            (Message::Binary(AVAILABLE.as_bytes().to_vec().into()), false),
            (
                Message::Text(gent_protocol::hosted_mcp::PROBE.into()),
                false,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!(
                "http://{}/clusters/cluster/nodes/web",
                listener.local_addr().unwrap()
            );
            let (pending, started) = tokio::sync::oneshot::channel();
            let bridge = async {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = accept_hdr_async(stream, StandbyHandshake).await.unwrap();
                started.await.unwrap();
                // A standby sends no application traffic just for parking.
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), socket.next())
                        .await
                        .is_err()
                );
                socket.send(frame).await.unwrap();
            };
            let waiting = async {
                let socket = connect(&base, "test").await.unwrap();
                wait(socket, async {
                    pending.send(()).unwrap();
                    std::future::pending().await
                })
                .await
            };
            let ((), result) = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(bridge, waiting)
            })
            .await
            .unwrap();
            assert_eq!(result.is_ok(), invited);
        }
    }
}
