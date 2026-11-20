//! Negotiate peer delivery on the node's watch. Older relays can reject a
//! duplicate peer offer with 409 while still admitting a V2 hint subscription.
use super::Relay;
use anyhow::{Context, Result};
use gent_protocol::{transport_watch, transport_wss as wire};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_with_config,
    tungstenite::{Error, client::IntoClientRequest, protocol::WebSocketConfig},
};

pub(super) async fn connect(
    relay: &Relay,
    url: &str,
    mut offer: bool,
    take_over: bool,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, bool)> {
    loop {
        // Each attempt generates a fresh upgrade key and uses the same trusted
        // origin, TLS settings and bearer. The connector never follows redirects.
        let mut request = url.into_client_request()?;
        let headers = request.headers_mut();
        if let Some(cluster) = &relay.cluster {
            headers.insert("X-Gent-Cluster", cluster.parse()?);
        }
        headers.insert("X-Gent-Watch", "2".parse()?);
        headers.insert("X-Gent-Authority", "3".parse()?);
        headers.insert("Authorization", relay.authorization.clone());
        if offer {
            headers.insert(wire::HEADER, wire::OFFER.parse()?);
            if take_over {
                headers.insert(wire::HANDOFF, "1".parse()?);
            }
        }
        let limit = if offer {
            wire::MAX_FRAME
        } else {
            transport_watch::MAX_BYTES
        };
        let config = WebSocketConfig::default()
            .read_buffer_size(4096)
            .write_buffer_size(0)
            .max_write_buffer_size(limit * 2)
            .max_message_size(Some(limit))
            .max_frame_size(Some(limit));
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            connect_async_with_config(request, Some(config), true),
        )
        .await
        .context("push connection timed out")?;
        match result {
            Err(Error::Http(response)) if offer && response.status().as_u16() == 409 => {
                offer = false
            }
            result => {
                let (socket, response) = result?;
                let negotiated = offer
                    && response
                        .headers()
                        .get(wire::HEADER)
                        .is_some_and(|value| value == wire::OFFER);
                return Ok((socket, negotiated));
            }
        }
    }
}

#[cfg(test)]
mod tests;
