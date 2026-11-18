//! Cluster inventory grouped by stable node identity, including empty nodes.
use super::*;
use gent_protocol::directory::Entry;

struct Group {
    name: String,
    status: String,
    agents: Vec<Entry>,
}

pub(super) fn render(output: &mut String, value: &Value) -> Result<()> {
    let agents: Vec<Entry> =
        serde_json::from_value(value["agents"].clone()).context("invalid chat list response")?;
    let nodes: Vec<NodeStatus> =
        serde_json::from_value(value["nodes"].clone()).context("invalid node list response")?;
    let retired = agents
        .iter()
        .filter(|entry| entry.retired || entry.agent.revoked)
        .count();
    let count = agents.len() - retired;
    let mut groups: BTreeMap<_, _> = nodes
        .into_iter()
        .map(|node| {
            (
                node.id,
                Group {
                    name: node.name,
                    status: node.status,
                    agents: Vec::new(),
                },
            )
        })
        .collect();
    for agent in agents
        .into_iter()
        .filter(|entry| !entry.retired && !entry.agent.revoked)
    {
        groups
            .entry(agent.agent.node_id.clone())
            .or_insert_with(|| Group {
                name: "Unknown or removed node".into(),
                status: "not enrolled".into(),
                agents: Vec::new(),
            })
            .agents
            .push(agent);
    }
    let mut groups: Vec<_> = groups.into_iter().collect();
    groups.sort_by_cached_key(|(id, group)| (group.name.to_lowercase(), id.clone()));
    header(output, &format!("Chats ({count})"))?;
    super::sync::summary(output, &value["sync"])?;
    for (id, mut group) in groups {
        writeln!(
            output,
            "\n{}  {}  ({} {})",
            crate::ui::paint(&visible(&group.name), "1"),
            crate::ui::state(&visible(&group.status)),
            group.agents.len(),
            if group.agents.len() == 1 {
                "chat"
            } else {
                "chats"
            }
        )?;
        writeln!(output, "  Node ID: {}", visible(&id))?;
        group.agents.sort_by_cached_key(|entry| {
            (
                entry.agent.name.to_lowercase(),
                std::cmp::Reverse(entry.last_activity_at),
                entry.agent.id.clone(),
            )
        });
        if group.agents.is_empty() {
            writeln!(output, "  No known chats.")?;
            continue;
        }
        let rows = group
            .agents
            .into_iter()
            .map(|entry| {
                vec![
                    entry.agent.name,
                    entry.agent.provider,
                    entry
                        .last_activity_at
                        .map(|time| date(time as u64))
                        .unwrap_or_else(|| "unknown".into()),
                    entry.agent.id,
                ]
            })
            .collect::<Vec<_>>();
        output.push_str(&table(&["CHAT", "PROVIDER", "LAST ACTIVE", "ID"], &rows));
    }
    if retired > 0 {
        writeln!(
            output,
            "\n  ({retired} conversations from removed nodes or revoked registrations; use --verbose to show)"
        )?;
    }
    if count == 0 {
        writeln!(
            output,
            "\nRegister chats through Gent MCP or enable gent node discovery on each node."
        )?;
    }
    writeln!(
        output,
        "\nKnown registrations include offline nodes. Node connectivity does not prove a chat can receive a turn."
    )?;
    Ok(())
}

pub(super) fn resolution(output: &mut String, value: &Value) -> Result<()> {
    header(output, "Chat resolution")?;
    row(
        output,
        "Status",
        value["status"].as_str().unwrap_or("unknown"),
    )?;
    if !value["selected"].is_null() {
        let selected: Entry = serde_json::from_value(value["selected"].clone())?;
        for (label, text) in [
            ("Chat", selected.agent.name),
            ("Node", selected.node_name.unwrap_or(selected.agent.node_id)),
            ("Provider", selected.agent.provider),
            (
                "Last active",
                selected
                    .last_activity_at
                    .map(|t| date(t as u64))
                    .unwrap_or_else(|| "unknown".into()),
            ),
            ("Chat ID", selected.agent.id),
        ] {
            row(output, label, &text)?;
        }
    } else if value["status"] == "ambiguous" {
        let entries: Vec<Entry> = serde_json::from_value(value["candidates"].clone())?;
        let rows = entries
            .into_iter()
            .map(|entry| {
                vec![
                    entry.agent.name,
                    entry.node_name.unwrap_or(entry.agent.node_id),
                    entry.agent.provider,
                    entry
                        .last_activity_at
                        .map(|t| date(t as u64))
                        .unwrap_or_else(|| "unknown".into()),
                    entry.agent.id,
                ]
            })
            .collect::<Vec<_>>();
        output.push_str(&table(
            &["CHAT", "NODE", "PROVIDER", "LAST ACTIVE", "ID"],
            &rows,
        ));
        writeln!(
            output,
            "\nActivity is missing or tied. Choose a node/provider or use the full chat ID."
        )?;
    } else {
        writeln!(output, "  No matching active conversation.")?;
    }
    Ok(())
}
