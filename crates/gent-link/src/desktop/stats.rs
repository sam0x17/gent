//! Read the CLI’s local owner snapshot and format it once for both native views.
use crate::{display::visible, owner};
use gent_protocol::{OwnerOp, stats::Stats};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Stats,
}

fn count(number: u64) -> String {
    let mut text = number.to_string();
    let mut index = text.len();
    while index > 3 {
        index -= 3;
        text.insert(index, ',');
    }
    text
}

fn timestamp(seconds: Option<i64>) -> String {
    seconds
        .and_then(|time| chrono::DateTime::from_timestamp(time, 0))
        .map(|time| time.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "—".into())
}

fn label(name: &str, id: &str) -> String {
    visible(if name.trim().is_empty() { id } else { name })
}

fn view(snapshot: Stats) -> Value {
    let coverage = &snapshot.coverage;
    let summary = format!(
        "{} of {} cluster nodes reporting · {} fresh. {} Hosted chats count under their physical node.",
        coverage.reporting_nodes,
        coverage.expected_nodes,
        coverage.fresh_nodes,
        if coverage.complete {
            "Showing the latest reports on this node."
        } else {
            "Partial coverage. Totals include the latest available reports."
        }
    );
    let traffic = snapshot.outbound;
    let recoveries = snapshot.babysitter;
    let (outbound, babysitter) = if coverage.reporting_nodes == 0 {
        (
            "Awaiting node reports.".into(),
            "Awaiting node reports.".into(),
        )
    } else {
        (
            format!(
                "Accepted sends: {}   ·   Payload bytes: {}\nUTF-8 text: {} bytes   ·   Original attachments: {} bytes\nEach accepted send counts once. Retries add nothing.",
                count(traffic.messages),
                count(traffic.bytes),
                count(traffic.text_bytes),
                count(traffic.attachment_bytes)
            ),
            format!(
                "Ordinary chat continuations: {}   ·   Goal resumes: {}\nCounts confirmed submissions to the chat host. Goal tracking starts on each reporting node’s tracking date.",
                count(recoveries.ordinary_submitted),
                count(recoveries.goal_submitted),
            ),
        )
    };
    let rows: Vec<_> = snapshot
        .top_senders
        .into_iter()
        .map(|sender| {
            json!({
                "chat_id": visible(&sender.chat_id),
                "name": label(&sender.name, &sender.chat_id),
                "messages": count(sender.traffic.messages),
                "bytes": count(sender.traffic.bytes),
            })
        })
        .collect();
    let optional_count = |n: Option<u64>| n.map(count).unwrap_or_else(|| "—".into());
    let nodes: Vec<_> = snapshot.nodes.into_iter().map(|entry| {
        let traffic = entry.outbound.as_ref();
        let babysitter = entry.babysitter.as_ref();
        let tracking = entry.coverage.as_ref();
        json!({
            "name": label(&entry.node.name, &entry.node.id),
            "status": visible(&entry.status),
            "messages": optional_count(traffic.map(|t| t.messages)),
            "bytes": optional_count(traffic.map(|t| t.bytes)),
            "ordinary": optional_count(babysitter.map(|b| b.ordinary_submitted)),
            "goals": optional_count(babysitter.map(|b| b.goal_submitted)),
            "as_of": timestamp(entry.as_of),
            "started": timestamp(tracking.map(|t| t.tracking_started_at)),
            "backfill": tracking.map(|t| visible(&t.backfill).replace('_', " ")).unwrap_or_else(|| "—".into()),
            "older_daemon": tracking.map(|t| visible(&t.older_daemon_activity).replace('_', " ")).unwrap_or_else(|| "—".into()),
            "id": visible(&entry.node.id),
        })
    }).collect();
    json!({"page":"stats", "coverage":summary, "outbound":outbound, "babysitter":babysitter,
        "rows":rows, "nodes":nodes})
}

pub(super) async fn read(home: &Path) -> Value {
    let notice = match owner(home, OwnerOp::Stats).await {
        Ok(value) => match serde_json::from_value::<Stats>(value) {
            Ok(snapshot) if snapshot.scope == "cluster" => return view(snapshot),
            Ok(_) => "The daemon returned an unsupported Stats scope. Update Gent, then refresh.",
            Err(_) => {
                "The daemon returned an unreadable Stats snapshot. Update Gent, then refresh."
            }
        },
        Err(error) if error.to_string() == "invalid request" => {
            "This daemon does not support Stats. Update the daemon, then refresh."
        }
        Err(_) if !home.join("config.toml").is_file() => {
            "Set up this node in Status to view cluster stats."
        }
        Err(error) if error.to_string().starts_with("daemon unavailable;") => {
            "Stats unavailable. Start the local Gent daemon, then refresh."
        }
        Err(_) => "Stats unavailable. Check the local daemon and owner access, then refresh.",
    };
    json!({"page":"stats", "error":notice})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_older_daemon_or_incomplete_snapshot_is_unavailable() {
        use gent_protocol::Response;
        use tokio::{
            io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
            net::UnixListener,
        };

        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("fixture");
        gent_daemon::config::initialize(&home, "stats").unwrap();
        let listener = UnixListener::bind(home.join("daemon.sock")).unwrap();
        for (response, expected) in [
            (
                Response::Error("invalid request".into()),
                "does not support Stats",
            ),
            (Response::Ok(json!({})), "unreadable Stats snapshot"),
        ] {
            let server = async {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut frame = String::new();
                stream.read_line(&mut frame).await.unwrap();
                assert!(matches!(
                    serde_json::from_str(&frame),
                    Ok(gent_protocol::Request::Owner {
                        action: OwnerOp::Stats,
                        ..
                    })
                ));
                let mut bytes = serde_json::to_vec(&response).unwrap();
                bytes.push(b'\n');
                stream.get_mut().write_all(&bytes).await.unwrap();
            };
            let (page, ()) = tokio::join!(read(&home), server);
            assert_eq!(page["page"], "stats");
            assert!(page["error"].as_str().unwrap().contains(expected));
            assert!(page.get("outbound").is_none() && page.get("nodes").is_none());
        }
    }

    #[test]
    fn counts_preserve_exact_bytes_and_group_large_values() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1_000), "1,000");
        assert_eq!(count(u64::MAX), "18,446,744,073,709,551,615");
    }
}
