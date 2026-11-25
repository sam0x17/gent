use super::*;
use gent_protocol::stats::Stats;

pub(super) fn render(output: &mut String, value: &Value) -> Result<()> {
    let stats: Stats =
        serde_json::from_value(value.clone()).context("invalid Gent stats response")?;
    anyhow::ensure!(stats.scope == "cluster", "unsupported Gent stats scope");
    header(output, "Stats")?;
    let coverage = &stats.coverage;
    row(
        output,
        "Cluster coverage",
        &format!(
            "{} of {} nodes reporting, {} fresh{}",
            coverage.reporting_nodes,
            coverage.expected_nodes,
            coverage.fresh_nodes,
            if coverage.complete {
                ""
            } else {
                " (partial coverage)"
            }
        ),
    )?;
    if coverage.reporting_nodes == 0 {
        writeln!(output, "  Awaiting node reports.")?;
    } else {
        row(
            output,
            "Messages sent",
            &stats.outbound.messages.to_string(),
        )?;
        row(
            output,
            "Bytes sent",
            &format!(
                "{} ({} text, {} attachments)",
                stats.outbound.bytes, stats.outbound.text_bytes, stats.outbound.attachment_bytes
            ),
        )?;
        writeln!(output, "\nBabysitter")?;
        row(
            output,
            "Chat continuations",
            &stats.babysitter.ordinary_submitted.to_string(),
        )?;
        row(
            output,
            "Goal resumes",
            &stats.babysitter.goal_submitted.to_string(),
        )?;
        writeln!(output, "\nTop sending chats")?;
        if stats.top_senders.is_empty() {
            writeln!(output, "  No Gent messages recorded.")?;
        } else {
            let rows = stats
                .top_senders
                .into_iter()
                .map(|sender| {
                    vec![
                        sender.name,
                        sender.traffic.messages.to_string(),
                        sender.traffic.bytes.to_string(),
                        sender.chat_id,
                    ]
                })
                .collect::<Vec<_>>();
            output.push_str(&table(&["Chat", "Messages", "Bytes", "Chat ID"], &rows));
        }
    }
    writeln!(output, "\nPer node")?;
    for node in &stats.nodes {
        writeln!(
            output,
            "  {} ({})",
            visible(&node.node.name),
            visible(&node.status)
        )?;
        if let (Some(send), Some(babysitter)) = (&node.outbound, &node.babysitter) {
            writeln!(
                output,
                "    {} messages, {} bytes, {} chat continuations, {} goal resumes",
                send.messages, send.bytes, babysitter.ordinary_submitted, babysitter.goal_submitted
            )?;
        }
        if let Some(as_of) = node.as_of.and_then(|s| u64::try_from(s).ok()) {
            writeln!(output, "    As of {}", date(as_of))?;
        }
        if let Some(start) = node
            .coverage
            .as_ref()
            .and_then(|c| u64::try_from(c.tracking_started_at).ok())
        {
            writeln!(output, "    Tracking since {}", date(start))?;
        }
    }
    writeln!(
        output,
        "\nEarlier totals include retained native sends and confirmed chat continuations where available. Goal resume counts start when tracking begins."
    )?;
    Ok(())
}
