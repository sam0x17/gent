use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use gent_protocol::{OwnerOp, owner_transfer::OwnerTransferOp};
use serde_json::Value;
use std::path::Path;

#[derive(Subcommand)]
pub enum Command {
    /// Show the signing owner and local transfers, or inspect one transfer.
    Status { request: Option<String> },
    /// Prepare an enrolled successor by node ID or unique name; keep signing active.
    Prepare { node: String },
    /// Permanently stop the old signer and authorize the prepared successor.
    /// The daemon resumes delivery and activation after reconnects or restarts.
    Commit { request: String },
    /// Retry preparation or finish an already committed transfer; never commits a new one.
    Resume { request: String },
}

fn resolve_node(nodes: &Value, requested: &str) -> Result<String> {
    let nodes = nodes.as_array().context("invalid node list")?;
    if let Some(node) = nodes.iter().find(|node| node["id"] == requested) {
        return Ok(node["id"].as_str().context("missing node ID")?.into());
    }
    let matches: Vec<_> = nodes
        .iter()
        .filter(|node| node["name"] == requested)
        .collect();
    ensure!(
        matches.len() == 1,
        "node name is missing or ambiguous; use an ID from gent nodes"
    );
    Ok(matches[0]["id"].as_str().context("missing node ID")?.into())
}

pub async fn execute(home: &Path, request_id: &str, command: Option<Command>) -> Result<Value> {
    let action = match command.unwrap_or(Command::Status { request: None }) {
        Command::Status { request } => OwnerTransferOp::Status {
            request_id: request,
        },
        Command::Prepare { node } => OwnerTransferOp::Prepare {
            request_id: request_id.into(),
            node_id: resolve_node(&crate::owner(home, OwnerOp::Nodes).await?, &node)?,
        },
        Command::Commit { request } => OwnerTransferOp::Commit {
            request_id: request,
        },
        Command::Resume { request } => OwnerTransferOp::Resume {
            request_id: request,
        },
    };
    crate::owner(home, OwnerOp::OwnerTransfer { action }).await
}

pub fn print(value: &Value) {
    let text = |name| value[name].as_str().unwrap_or("unknown");
    if let Some(transfers) = value["transfers"].as_array() {
        println!(
            "Signing owner: {} (epoch {})",
            text("owner_node"),
            value["owner_epoch"]
        );
        if transfers.is_empty() {
            println!("No transfers recorded on this node.");
        }
        for transfer in transfers {
            println!(
                "{}  {}  {} to {}",
                transfer["id"].as_str().unwrap_or("unknown"),
                transfer["state"].as_str().unwrap_or("unknown"),
                transfer["source_name"]
                    .as_str()
                    .or(transfer["source"].as_str())
                    .unwrap_or("unknown"),
                transfer["successor_name"]
                    .as_str()
                    .or(transfer["successor"].as_str())
                    .unwrap_or("unknown")
            );
        }
        return;
    }
    let id = text("id");
    println!("Transfer {id}: {}", text("state"));
    println!("Source: {} ({})", text("source_name"), text("source"));
    println!(
        "Successor: {} ({})",
        text("successor_name"),
        text("successor")
    );
    if let Some(error) = value["error"].as_str() {
        println!("Pending: {error}");
    }
    if let Some(errors) = value["preparation_errors"].as_array() {
        for error in errors {
            if let Some(error) = error["error"].as_str() {
                println!("Preparation: {error}");
            }
        }
    }
    if value["committed"] == true && value["role"] == "source" {
        println!("The source signer is permanently stopped for this transfer.");
    }
    if value["auto_activate"] == false {
        println!("This older plan requires manual activation through its original workflow.");
    } else {
        match text("state") {
            "prepared" if value["role"] == "source" => println!(
                "Ready. To permanently stop the source signer and transfer authority: gent cluster owner commit {id}"
            ),
            "preparing" => {
                println!("Preparation is running. Check: gent cluster owner status {id}")
            }
            "stale" => println!("Prepare a new transfer using the current cluster configuration."),
            "complete" => (),
            _ => println!(
                "The daemon will continue automatically. Retry progress: gent cluster owner resume {id}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn owner_transfer_requires_an_exact_id_or_unique_node_name() {
        let nodes = json!([
            {"id":"a", "name":"shared"},
            {"id":"b", "name":"shared"},
            {"id":"c", "name":"studio"},
            {"id":"d", "name":"a"}
        ]);
        assert!(resolve_node(&nodes, "shared").is_err());
        assert!(resolve_node(&nodes, "missing").is_err());
        assert_eq!(resolve_node(&nodes, "studio").unwrap(), "c");
        // An ID wins even if another node has that name.
        assert_eq!(resolve_node(&nodes, "a").unwrap(), "a");
    }
}
