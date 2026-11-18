//! Cluster inventory grouped by stable node identity, including empty nodes.
use super::*;

struct Group {
    name: String,
    status: String,
    agents: Vec<Agent>,
}

pub(super) fn render(output: &mut String, value: &Value) -> Result<()> {
    let agents: Vec<Agent> =
        serde_json::from_value(value["agents"].clone()).context("invalid agent list response")?;
    let nodes: Vec<NodeStatus> =
        serde_json::from_value(value["nodes"].clone()).context("invalid node list response")?;
    let count = agents.len();
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
    for agent in agents {
        groups
            .entry(agent.node_id.clone())
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
    header(output, &format!("Agents ({count})"))?;
    for (id, mut group) in groups {
        writeln!(
            output,
            "\n{}  {}  ({} {})",
            crate::ui::paint(&visible(&group.name), "1"),
            crate::ui::state(&visible(&group.status)),
            group.agents.len(),
            if group.agents.len() == 1 {
                "agent"
            } else {
                "agents"
            }
        )?;
        writeln!(output, "  Node ID: {}", visible(&id))?;
        group
            .agents
            .sort_by_cached_key(|agent| (agent.name.to_lowercase(), agent.id.clone()));
        if group.agents.is_empty() {
            writeln!(output, "  No known agents.")?;
            continue;
        }
        let rows = group
            .agents
            .into_iter()
            .map(|agent| {
                vec![
                    agent.name,
                    agent.provider,
                    if agent.revoked { "revoked" } else { "active" }.into(),
                    agent.id,
                ]
            })
            .collect::<Vec<_>>();
        output.push_str(&table(&["AGENT", "PROVIDER", "REGISTRATION", "ID"], &rows));
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
