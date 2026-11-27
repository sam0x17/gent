//! Live board-scoped projection. Neither a file ID nor a decryption grant is on this protocol.
use super::*;
use gent_protocol::dashboard::{HTML_BATCH, HtmlProbe, HtmlProjection, MAX_HTML_BYTES};
use sha2::{Digest, Sha256};

pub(super) const ALPN: &[u8] = b"gent/dashboard-html/1";
const MAX_REQUEST: usize = 2048;
const MAX_REPLY: usize = HTML_BATCH * (MAX_HTML_BYTES * 6 + 256) + 2;

fn validate(probes: &[HtmlProbe]) -> Result<()> {
    ensure!(
        (1..=HTML_BATCH).contains(&probes.len()),
        "invalid board count"
    );
    let mut seen = std::collections::BTreeSet::new();
    for p in probes {
        ensure!(
            p.revision > 0
                && seen.insert(p.agent)
                && p.known_sha256.as_ref().is_none_or(
                    |hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
                ),
            "invalid board query"
        );
    }
    Ok(())
}

pub(super) async fn serve(conn: &Connection, store: SharedStore) -> Result<()> {
    loop {
        let (mut send, mut recv) =
            tokio::time::timeout(Duration::from_secs(30), conn.accept_bi()).await??;
        tokio::time::timeout(OPERATION, async {
            let input = recv.read_to_end(MAX_REQUEST).await?;
            let (checkpoint, json) = input
                .split_first_chunk::<32>()
                .context("missing authority checkpoint")?;
            let checkpoint = *checkpoint;
            let probes: Vec<HtmlProbe> = serde_json::from_slice(json)?;
            validate(&probes)?;
            let endpoint = conn.remote_id();
            let rows = local(store.clone(), move |s| {
                s.serve_board_html(endpoint, checkpoint, &probes)
            })
            .await?;
            send.write_all(&serde_json::to_vec(&rows)?).await?;
            send.finish()?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    }
}

pub(crate) async fn read(
    store: SharedStore,
    credential: String,
    probes: Vec<HtmlProbe>,
) -> Result<Vec<HtmlProjection>> {
    validate(&probes)?;
    let initial = probes.clone();
    let owner = credential.clone();
    let (direct, (address, checkpoint)) = local(store.clone(), move |s| {
        let addr = s.board_target(&owner, &initial)?;
        Ok((
            s.board_transport
                .upgrade()
                .context("board transport unavailable")?,
            addr,
        ))
    })
    .await?;
    let endpoint = address.id;
    let rows: Vec<HtmlProjection> = tokio::time::timeout(OPERATION, async {
        let conn = direct
            .primary_pull_connection(&direct.boards, address, ALPN, 32)
            .await
            .context("board carrier unavailable")?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let mut input = checkpoint.to_vec();
        serde_json::to_writer(&mut input, &probes)?;
        send.write_all(&input).await?;
        send.finish()?;
        Ok::<_, anyhow::Error>(serde_json::from_slice(&recv.read_to_end(MAX_REPLY).await?)?)
    })
    .await??;
    ensure!(rows.len() <= probes.len(), "invalid board reply");
    let mut seen = std::collections::BTreeSet::new();
    for row in &rows {
        let probe = probes
            .iter()
            .find(|p| p.agent == row.agent && p.revision == row.revision)
            .context("unexpected board")?;
        ensure!(
            seen.insert(row.agent) && row.expires_at > crate::store::now() as u64,
            "duplicate or expired board"
        );
        ensure!(
            match &row.static_html {
                Some(html) =>
                    (1..=MAX_HTML_BYTES).contains(&html.len())
                        && format!("{:x}", Sha256::digest(html.as_bytes())) == row.sha256,
                None => probe.known_sha256.as_ref() == Some(&row.sha256),
            },
            "invalid board content digest"
        );
    }
    local(store, move |s| {
        let (current, head) = s.board_target(&credential, &probes)?;
        ensure!(
            current.id == endpoint && head == checkpoint,
            "board carrier changed"
        );
        Ok(rows)
    })
    .await
}
