//! Human views of existing responses. Rendering performs no I/O or RPC calls;
//! JSON callers retain the original response and its complete field set.
mod agents;
mod stats;
mod sync;

use anyhow::{Context, Result};
use gent_daemon::config::{ClusterConfig, NodeConfig};
use gent_protocol::Agent;
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, fmt::Write, time::Duration};

#[derive(Clone, Copy)]
pub(crate) enum View {
    Cluster,
    Node,
    Nodes,
    Agent,
    Agents,
    Resolution,
    Stats,
    Sync,
    Providers,
}

#[derive(Deserialize)]
struct ClusterStatus {
    process_id: u32,
    node: NodeConfig,
    cluster: ClusterConfig,
    remote_ready: bool,
    authority: Authority,
    config_saved: bool,
    #[serde(default)]
    sync: Value,
}

#[derive(Deserialize)]
struct Authority {
    #[serde(default)]
    mode: String,
    revision: u64,
    expires_at: u64,
    fresh: bool,
}

#[derive(Deserialize)]
struct NodeStatus {
    id: String,
    name: String,
    status: String,
    data_link: bool,
    can_configure: bool,
    #[serde(default)]
    is_owner: Option<bool>,
    #[serde(default)]
    transport: Value,
}

// Labels can contain Unicode formatting characters even when configuration
// validation rejects control characters. Escape both before terminal output.
pub(crate) fn visible(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for c in value.chars() {
        let formatting = matches!(
            c,
            '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        );
        if c.is_control() || formatting {
            output.extend(c.escape_unicode());
        } else {
            output.push(c);
        }
    }
    output
}

fn date(seconds: u64) -> String {
    // httpdate supports years through 9999. Unexpected values must not panic
    // or turn into plausible dates in a status report.
    if seconds > 253_402_300_799 {
        return "outside supported date range".into();
    }
    httpdate::fmt_http_date(std::time::UNIX_EPOCH + Duration::from_secs(seconds))
}

fn agent(output: &mut String, value: &Agent) -> std::fmt::Result {
    writeln!(
        output,
        "{} ({})",
        visible(&value.name),
        visible(&value.provider)
    )?;
    writeln!(output, "  Chat ID: {}", visible(&value.id))?;
    writeln!(output, "  Node ID: {}", visible(&value.node_id))?;
    writeln!(
        output,
        "  Registration: {}",
        if value.revoked { "revoked" } else { "active" }
    )?;
    let activity = match u64::try_from(value.last_seen) {
        Ok(0) | Err(_) => "not recorded".into(),
        Ok(seconds) => date(seconds),
    };
    writeln!(output, "  Last recorded activity: {activity}")
}

pub(crate) fn render(view: View, value: &Value) -> Result<String> {
    let mut output = String::new();
    match view {
        View::Cluster => {
            let value: ClusterStatus =
                serde_json::from_value(value.clone()).context("invalid cluster status response")?;
            header(&mut output, "Cluster")?;
            for (label, text) in [
                ("Cluster", value.cluster.name),
                ("Cluster ID", value.cluster.id),
                ("Node", value.node.name),
                ("Node ID", value.node.id),
                (
                    "Type",
                    if value.cluster.local_only {
                        "development"
                    } else {
                        "service"
                    }
                    .into(),
                ),
                ("Daemon", format!("responding (PID {})", value.process_id)),
                (
                    "Configuration",
                    format!(
                        "{} ({} {})",
                        if value.authority.fresh {
                            "current"
                        } else {
                            "stale"
                        },
                        if value.authority.mode == "peers" {
                            "sequence"
                        } else {
                            "revision"
                        },
                        value.authority.revision
                    ),
                ),
                ("Lease expires", date(value.authority.expires_at)),
                (
                    "Local config",
                    if value.config_saved {
                        "saved"
                    } else {
                        "write pending"
                    }
                    .into(),
                ),
                (
                    "Remote transport",
                    if value.remote_ready {
                        "configured; connectivity not checked"
                    } else {
                        "not ready"
                    }
                    .into(),
                ),
            ] {
                row(&mut output, label, &text)?;
            }
            sync::summary(&mut output, &value.sync)?;
            writeln!(
                output,
                "\n  Use gent doctor to check service, account and relay health."
            )?;
        }
        View::Node => {
            let value: NodeConfig =
                serde_json::from_value(value.clone()).context("invalid node configuration")?;
            header(&mut output, "Node")?;
            row(&mut output, "Name", &value.name)?;
            row(&mut output, "ID", &value.id)?;
            row(&mut output, "Source", "local configuration")?;
        }
        View::Nodes => {
            let nodes: Vec<NodeStatus> =
                serde_json::from_value(value.clone()).context("invalid node list response")?;
            let names: BTreeMap<_, _> = nodes
                .iter()
                .map(|n| (n.id.as_str(), n.name.as_str()))
                .collect();
            writeln!(
                output,
                "{}  {}",
                crate::ui::paint("gent", "1;36"),
                crate::ui::paint(&format!("Nodes ({})", nodes.len()), "1")
            )?;
            let rows = nodes
                .iter()
                .map(|node| {
                    let mut transport = if node.status == "local" || node.status == "hosted" {
                        "local".to_owned()
                    } else {
                        sync::transport(&node.transport["last"])
                    };
                    if let Some(carrier) = node.transport["carrier_id"].as_str()
                        && carrier != node.id
                    {
                        transport = format!(
                            "{transport} (via {})",
                            names.get(carrier).copied().unwrap_or(carrier)
                        );
                    }
                    vec![
                        node.name.clone(),
                        node.status.clone(),
                        if node.status == "local" {
                            "local"
                        } else if node.data_link {
                            "paired"
                        } else {
                            "not paired"
                        }
                        .into(),
                        transport,
                        if node.is_owner == Some(true) {
                            "owner"
                        } else if node.can_configure {
                            "yes"
                        } else {
                            "no"
                        }
                        .into(),
                        node.id.clone(),
                    ]
                })
                .collect::<Vec<_>>();
            output.push_str(&table(
                &[
                    "NODE",
                    "STATUS",
                    "ENCRYPTED LINK",
                    "LAST TRANSPORT",
                    "ADMIN",
                    "ID",
                ],
                &rows,
            ));
            if nodes.is_empty() {
                writeln!(output, "  No enrolled nodes.")?;
            }
            writeln!(
                output,
                "\n  Last transport shows evidence from this daemon session. Mailbox upload confirms relay storage. Use --verbose for timestamps, signed receipts and carrier IDs."
            )?;
        }
        View::Agents => agents::render(&mut output, value)?,
        View::Sync => sync::render(&mut output, value)?,
        View::Stats => stats::render(&mut output, value)?,
        View::Resolution => agents::resolution(&mut output, value)?,
        View::Agent => {
            let details: Agent =
                serde_json::from_value(value.clone()).context("invalid chat response")?;
            header(&mut output, "Chats (1)")?;
            writeln!(output)?;
            agent(&mut output, &details)?;
            if let Some(generation) = value["registration_generation"].as_u64() {
                writeln!(output, "  Registration generation: {generation}")?;
            }
            writeln!(
                output,
                "\nActivity is the daemon's recorded contact time. Live host availability is unknown."
            )?;
        }
        View::Providers => {
            let providers: BTreeMap<String, Vec<Agent>> =
                serde_json::from_value(value.clone()).context("invalid provider list response")?;
            writeln!(output, "Providers ({})", providers.len())?;
            for (name, agents) in &providers {
                writeln!(
                    output,
                    "\n{}: {} registered chat{}",
                    visible(name),
                    agents.len(),
                    if agents.len() == 1 { "" } else { "s" }
                )?;
            }
            if providers.is_empty() {
                writeln!(
                    output,
                    "\nProvider labels appear when chats register through Gent MCP."
                )?;
            } else {
                writeln!(
                    output,
                    "\nLabels come from chat registrations. Use gent chats for details."
                )?;
            }
        }
    }
    Ok(output)
}

fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let rows: Vec<Vec<_>> = rows
        .iter()
        .map(|row| row.iter().map(|cell| visible(cell)).collect())
        .collect();
    let widths: Vec<_> = headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            rows.iter()
                .map(|row| row[index].chars().count())
                .max()
                .unwrap_or(0)
                .max(header.len())
        })
        .collect();
    let mut output = String::new();
    for (number, row) in std::iter::once(headers.iter().map(|v| v.to_string()).collect::<Vec<_>>())
        .chain(rows)
        .enumerate()
    {
        output.push_str("  ");
        for (index, cell) in row.iter().enumerate() {
            output.push_str(&if number == 0 {
                crate::ui::paint(cell, "2")
            } else {
                cell.clone()
            });
            if index + 1 < row.len() {
                output.push_str(&" ".repeat(widths[index] - cell.chars().count() + 2));
            }
        }
        output.push('\n');
    }
    output
}

fn header(output: &mut String, title: &str) -> std::fmt::Result {
    writeln!(
        output,
        "{}  {}",
        crate::ui::paint("gent", "1;36"),
        crate::ui::paint(title, "1")
    )
}

fn row(output: &mut String, label: &str, value: &str) -> std::fmt::Result {
    writeln!(
        output,
        "  {}  {}",
        crate::ui::paint(&format!("{label:<18}"), "2"),
        visible(value)
    )
}
