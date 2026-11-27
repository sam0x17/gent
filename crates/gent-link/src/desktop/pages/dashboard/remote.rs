//! Fetch from the current carrier only while Desktop reads the gallery.
//! A fresh digest confirmation permits reuse of an already visible document.
use super::*;
use futures_util::{StreamExt, stream};
use gent_protocol::dashboard::{HTML_BATCH, HtmlProbe, HtmlProjection};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) async fn project(
    home: &Path,
    page: &mut BoardPage,
    previous: Option<&View>,
    hidden: &Hidden,
) {
    let mut cached = BTreeMap::new();
    let mut batches = Vec::new();
    for ids in page.remote_html_candidates.values() {
        let mut probes = Vec::new();
        for id in ids {
            let Some(row) = page.rows.iter().find(|row| row.agent == *id) else {
                continue;
            };
            if hidden.contains_key(id) {
                continue;
            }
            let known_sha256 = previous
                .and_then(|view| {
                    view.rows
                        .iter()
                        .find(|old| old.agent == *id && old.revision == row.revision)
                })
                .and_then(|old| old.board.extra.get("static_html")?.as_str())
                .map(|html| {
                    let digest = format!("{:x}", Sha256::digest(html.as_bytes()));
                    cached.insert(*id, (digest.clone(), html));
                    digest
                });
            probes.push(HtmlProbe {
                agent: *id,
                revision: row.revision,
                known_sha256,
            });
        }
        batches.extend(probes.chunks(HTML_BATCH).map(<[_]>::to_vec));
    }
    let mut reads = stream::iter(batches)
        .map(|boards| async move {
            let value = owner(home, OwnerOp::DashboardRemoteHtml { boards })
                .await
                .ok()?;
            serde_json::from_value::<Vec<HtmlProjection>>(value).ok()
        })
        .buffer_unordered(4);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
    while let Ok(Some(batch)) = tokio::time::timeout_at(deadline, reads.next()).await {
        for projection in batch.into_iter().flatten() {
            let Some(row) = page
                .rows
                .iter_mut()
                .find(|r| r.agent == projection.agent && r.revision == projection.revision)
            else {
                continue;
            };
            let html = projection.static_html.or_else(|| {
                let (sha, text) = cached.get(&row.agent)?;
                (sha == &projection.sha256).then(|| (*text).into())
            });
            if let Some(html) = html {
                row.board
                    .extra
                    .insert("static_html".into(), Value::String(html));
            }
        }
    }
}
