//! Compatibility with peers that select only the original JSON ALPN.
use super::*;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

pub(super) const ALPN: &[u8] = b"gent/mls-stream/1";
const LIMIT: usize = 3 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    group: String,
    batch: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u8,
    receipt: String,
}
pub(super) async fn request(conn: &Connection, group: &[u8], batch: &Batch) -> Result<Receipt> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let body = serde_json::to_vec(&Request {
        version: 1,
        group: URL_SAFE_NO_PAD.encode(group),
        batch: STANDARD.encode(batch.encode()),
    })?;
    ensure!(body.len() <= LIMIT, "direct batch too large");
    send.write_all(&body).await?;
    send.finish()?;
    let response: Response = serde_json::from_slice(&recv.read_to_end(8192).await?)?;
    ensure!(response.version == 1, "unsupported direct response");
    Receipt::decode(&STANDARD.decode(response.receipt)?)
}
pub(super) async fn serve(
    conn: &Connection,
    store: SharedStore,
    metrics: Arc<Metrics>,
) -> Result<()> {
    loop {
        let before = path::Frames::read(conn);
        let (mut send, mut recv) =
            tokio::time::timeout(Duration::from_secs(60), conn.accept_bi()).await??;
        tokio::time::timeout(Duration::from_secs(5), async {
            let body = recv.read_to_end(LIMIT).await?;
            let request: Request = serde_json::from_slice(&body)?;
            ensure!(
                request.version == 1 && request.group.len() <= 384,
                "invalid direct request"
            );
            let group = URL_SAFE_NO_PAD.decode(request.group)?;
            let batch = Batch::decode(&STANDARD.decode(request.batch)?)?;
            let bytes = batch.packets().iter().map(Vec::len).sum::<usize>();
            let packets = batch
                .packets()
                .iter()
                .map(|b| Packet::decode(b))
                .collect::<Result<Vec<_>>>()?;
            let receipt = session::receive(
                store.clone(),
                session::Peer::ObservedEndpoint(
                    conn.remote_id(),
                    path::Frames::read(conn).received(before, None),
                ),
                group,
                packets,
            )
            .await?;
            metrics.received.fetch_add(bytes as u64, Ordering::Relaxed);
            let bytes = serde_json::to_vec(&Response {
                version: 1,
                receipt: STANDARD.encode(receipt.encode()?),
            })?;
            send.write_all(&bytes).await?;
            send.finish()?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gent_crypto::NodeIdentity;

    #[tokio::test]
    async fn binary_client_negotiates_old_server_and_uses_its_json_wire() {
        let server = Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let addr = server.addr();
        let reader = NodeIdentity::generate().unwrap();
        let receipt = reader.sign_stream_receipt(b"group", 0, [9; 32]).unwrap();
        let response = receipt.clone();
        let task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            assert_eq!(conn.alpn(), ALPN);
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let body = recv.read_to_end(LIMIT).await.unwrap();
            let request: Request = serde_json::from_slice(&body).unwrap();
            assert_eq!(request.version, 1);
            assert_eq!(URL_SAFE_NO_PAD.decode(request.group).unwrap(), b"group");
            let batch = Batch::decode(&STANDARD.decode(request.batch).unwrap()).unwrap();
            assert_eq!(Packet::decode(&batch.packets()[0]).unwrap().sequence(), 0);
            let json = serde_json::to_vec(&Response {
                version: 1,
                receipt: STANDARD.encode(response.encode().unwrap()),
            })
            .unwrap();
            send.write_all(&json).await.unwrap();
            send.finish().unwrap();
            send.stopped().await.unwrap();
        });
        let conn = quic::dial(&client, addr).await.unwrap();
        assert_eq!(conn.alpn(), ALPN);
        let writer = NodeIdentity::generate().unwrap();
        let packet = writer
            .sign_stream_packet(b"group", 0, [0; 32], b"origin")
            .unwrap();
        let mut batch = Batch::default();
        assert!(batch.push(packet.encode().unwrap()).unwrap());
        assert_eq!(request(&conn, b"group", &batch).await.unwrap(), receipt);
        task.await.unwrap();
    }
}
