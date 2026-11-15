//! Human views of existing responses. Rendering performs no I/O or RPC calls;
//! JSON callers retain the original response and its complete field set.
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
}

#[derive(Deserialize)]
struct Authority {
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
    revision: u64,
    #[serde(default)]
    last_seen: Option<i64>,
    #[serde(default)]
    presence: Option<Presence>,
}

#[derive(Deserialize)]
struct Presence {
    reason: String,
    observed_at: i64,
    response_window_seconds: u64,
}

// Labels can contain Unicode formatting characters even when configuration
// validation rejects control characters. Escape both before terminal output.
fn visible(value: &str) -> String {
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
    writeln!(output, "  Agent ID: {}", visible(&value.id))?;
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
            writeln!(output, "Cluster: {}", visible(&value.cluster.name))?;
            writeln!(output, "Cluster ID: {}", visible(&value.cluster.id))?;
            writeln!(
                output,
                "Type: {}",
                if value.cluster.local_only {
                    "development"
                } else {
                    "service"
                }
            )?;
            writeln!(output, "Node: {}", visible(&value.node.name))?;
            writeln!(output, "Node ID: {}", visible(&value.node.id))?;
            writeln!(output, "Daemon: responding (PID {})", value.process_id)?;
            writeln!(
                output,
                "Signed configuration: {} (revision {})",
                if value.authority.fresh {
                    "current"
                } else {
                    "stale"
                },
                value.authority.revision
            )?;
            writeln!(
                output,
                "Configuration lease expires: {}",
                date(value.authority.expires_at)
            )?;
            writeln!(
                output,
                "Local configuration: {}",
                if value.config_saved {
                    "saved"
                } else {
                    "write pending"
                }
            )?;
            writeln!(
                output,
                "Remote transport: {}",
                if value.remote_ready {
                    "configured; connectivity not checked"
                } else {
                    "not ready"
                }
            )?;
            writeln!(
                output,
                "\nUse gent doctor to check service, account and relay health."
            )?;
        }
        View::Node => {
            let value: NodeConfig =
                serde_json::from_value(value.clone()).context("invalid node configuration")?;
            writeln!(output, "Node: {}", visible(&value.name))?;
            writeln!(output, "Node ID: {}", visible(&value.id))?;
            writeln!(output, "Source: local configuration")?;
        }
        View::Nodes => {
            let nodes: Vec<NodeStatus> =
                serde_json::from_value(value.clone()).context("invalid node list response")?;
            writeln!(output, "Nodes ({})", nodes.len())?;
            for node in &nodes {
                writeln!(
                    output,
                    "\n{} [{}]",
                    visible(&node.name),
                    visible(&node.status)
                )?;
                writeln!(output, "  Node ID: {}", visible(&node.id))?;
                writeln!(
                    output,
                    "  Encrypted link: {}",
                    if node.status == "local" {
                        "local node"
                    } else if node.data_link {
                        "paired"
                    } else {
                        "not paired"
                    }
                )?;
                writeln!(
                    output,
                    "  Configuration admin: {}",
                    if node.can_configure { "yes" } else { "no" }
                )?;
                writeln!(output, "  Configuration revision: {}", node.revision)?;
                if node.status != "local" {
                    let verified = node.last_seen.and_then(|at| u64::try_from(at).ok());
                    writeln!(
                        output,
                        "  Last verified round trip: {}",
                        verified.map(date).unwrap_or_else(|| "not recorded".into())
                    )?;
                    if let Some(presence) = &node.presence {
                        if let Some(age) = node
                            .last_seen
                            .and_then(|at| presence.observed_at.checked_sub(at))
                            .filter(|age| *age >= 0)
                        {
                            writeln!(output, "  Evidence age: {age} seconds")?;
                        }
                        let reason = match presence.reason.as_str() {
                            "not_paired" => "waiting for encrypted pairing".into(),
                            "stale_authority" => "signed configuration is stale".into(),
                            "local_node_not_enrolled" => "this node is no longer enrolled".into(),
                            "relay_not_configured" => "relay is not configured".into(),
                            "recent_encrypted_round_trip" => "verified encrypted round trip".into(),
                            "probe_timed_out" => format!(
                                "latest probe exceeded {} seconds",
                                presence.response_window_seconds
                            ),
                            "no_recent_encrypted_round_trip" => {
                                "no recent encrypted round trip".into()
                            }
                            "awaiting_first_round_trip" => {
                                "waiting for the first verified round trip".into()
                            }
                            other => visible(other),
                        };
                        writeln!(output, "  Check: {reason}")?;
                    } else {
                        writeln!(output, "  Check: not measured by this daemon")?;
                    }
                }
            }
            if nodes.iter().any(|node| node.status != "local") {
                writeln!(
                    output,
                    "\nPresence describes recent daemon communication. Agent activity is tracked separately."
                )?;
            }
        }
        View::Agent | View::Agents => {
            let agents: Vec<Agent> = if matches!(view, View::Agent) {
                vec![serde_json::from_value(value.clone()).context("invalid agent response")?]
            } else {
                serde_json::from_value(value.clone()).context("invalid agent list response")?
            };
            writeln!(output, "Agents ({})", agents.len())?;
            for value in &agents {
                writeln!(output)?;
                agent(&mut output, value)?;
            }
            if agents.is_empty() {
                writeln!(
                    output,
                    "\nRegister an existing chat through its Gent MCP connection."
                )?;
            } else {
                writeln!(
                    output,
                    "\nActivity is the daemon's recorded contact time. Live host availability is unknown."
                )?;
            }
        }
        View::Providers => {
            let providers: BTreeMap<String, Vec<Agent>> =
                serde_json::from_value(value.clone()).context("invalid provider list response")?;
            writeln!(output, "Providers ({})", providers.len())?;
            for (name, agents) in &providers {
                writeln!(
                    output,
                    "\n{}: {} registered agent{}",
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
                    "\nLabels come from agent registrations. Use gent agents for details."
                )?;
            }
        }
    }
    Ok(output)
}
