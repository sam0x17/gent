//! Named hosted nodes belong to the machine's one cluster. Their private
//! runtimes are supervised by its daemon; they are never selectable profiles.
mod runtime;
mod storage;
use crate::{auth, gateway, managed_file, node_home, owner};
use anyhow::{Context, Result, ensure};
use gent_daemon::{
    config,
    pairing::{self, Peer, ServiceRelay},
};
use gent_protocol::{OwnerOp, PairingOp};
pub(crate) use runtime::maintain;
use serde_json::{Value, json};
use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
    time::Duration,
};
use storage::Record;

const ORIGIN: &str = "https://mcp.gent.link";

#[derive(clap::Subcommand)]
pub(crate) enum Command {
    /// Show web nodes hosted by this machine, without revealing their URLs.
    List,
    /// Display this web node's private connector URL.
    Url(Output),
    /// Replace its URL immediately, keeping this node and its existing chats.
    Rotate(Output),
    /// Disable this web node's connector and stop its hosted runtime.
    Revoke { name: String },
}

#[derive(clap::Args)]
pub(crate) struct Output {
    name: String,
    /// Save the URL in a private file instead of displaying it.
    #[arg(long)]
    out: Option<PathBuf>,
}

struct LocalPeer<'a> {
    parent: &'a Path,
    cluster: String,
    service: Option<auth::Service>,
}

impl Peer for LocalPeer<'_> {
    async fn call(&mut self, action: PairingOp) -> Result<Value> {
        owner(
            self.parent,
            OwnerOp::Pair {
                cluster_id: self.cluster.clone(),
                action,
            },
        )
        .await
    }
    async fn prepare_service(&mut self, relay: &ServiceRelay) -> Result<()> {
        let cfg = node_home::inspect(self.parent)?;
        ensure!(
            cfg.cluster.id == self.cluster && cfg.service.as_ref() == Some(&relay.account),
            "web node enrollment changed account or cluster"
        );
        self.service = Some(auth::Service::open_pinned(self.parent, Some(&relay.account)).await?);
        Ok(())
    }
    async fn provision_service(
        &mut self,
        runtime: &Path,
        home: &Path,
        relay: &ServiceRelay,
    ) -> Result<()> {
        crate::cluster::provision_joined(
            runtime,
            home,
            self.service
                .as_ref()
                .context("web node service login is missing")?,
            relay,
        )
        .await
    }
}

fn output_allowed(out: Option<&Path>) -> Result<()> {
    ensure!(
        out.is_some() || std::io::stdout().is_terminal(),
        "display connector URLs in a terminal, or use --out PRIVATE_FILE (--code-out for node add)"
    );
    Ok(())
}

fn connection(home: &Path, cfg: &config::Config, rotate: bool) -> Result<String> {
    let base = gent_protocol::hosted_mcp::node_base(&cfg.cluster.id, &cfg.node.id)
        .context("invalid web node identity")?;
    gateway::registry::capability::url(home, &format!("{ORIGIN}{base}"), rotate)
}

fn output_url(mut value: Value, url: &str, out: Option<&Path>) -> Result<Value> {
    if let Some(path) = out {
        let path = managed_file::normalize(path)?;
        let snapshot = managed_file::Snapshot::read(&path)?;
        snapshot.private()?;
        snapshot.write(&format!("{url}\n"))?;
        value["url_file"] = json!(path);
    } else {
        value["url"] = json!(url);
    }
    value["security"] = gateway::access::AccessRoute::Hosted.summary();
    value["web_node"] = json!(true);
    Ok(value)
}

pub(crate) async fn add(parent: &Path, name: &str, out: Option<&Path>) -> Result<Value> {
    output_allowed(out)?;
    config::label(name)?;
    let cfg = node_home::inspect(parent)?;
    ensure!(
        cfg.service.is_some(),
        "web nodes need a Gent service cluster"
    );
    let directory = storage::directory(parent)?;
    let lock = managed_file::lock(&directory.join("setup.lock"))?;
    let home = storage::home(parent, name);
    ensure!(
        home.join("gateway/control.sock").as_os_str().len() < 104,
        "Gent state path is too long for hosted node sockets; use a shorter state directory"
    );
    let mut record = match storage::read(parent, &home)? {
        Some(record) => {
            ensure!(
                record.name == name,
                "web node name conflicts with saved state"
            );
            ensure!(!record.revoked, "web node was revoked; choose a new name");
            record
        }
        None => {
            ensure!(
                storage::list(parent)?.len() < storage::MAX_NODES,
                "this machine has reached its web node limit"
            );
            config::private_dir(&home)?;
            let record = Record {
                version: 1,
                cluster: cfg.cluster.id.clone(),
                parent: cfg.node.id.clone(),
                name: name.into(),
                node: None,
                revoked: false,
            };
            storage::save(&home, &record)?;
            record
        }
    };
    if record.node.is_none() {
        let _progress = crate::ui::Progress::start("Creating web node");
        pairing::join(
            &home,
            pairing::Options {
                cluster: &cfg.cluster.id,
                name,
                relay_endpoint: None,
                replace_node: None,
            },
            &mut LocalPeer {
                parent,
                cluster: cfg.cluster.id.clone(),
                service: None,
            },
        )
        .await?;
        gateway::registry::capability::create(&home)?;
        record.node = Some(node_home::inspect(&home)?.node.id);
        storage::save(&home, &record)?;
    }
    drop(lock);
    let cfg = node_home::inspect(&home)?;
    let url = connection(&home, &cfg, false)?;
    // Setup is committed before readiness. An old/stopped parent daemon cannot
    // turn a successful enrollment into another pending join.
    let _progress = crate::ui::Progress::start("Connecting web node");
    let mut ready = false;
    for _ in 0..60 {
        if runtime::ready(&home).await {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    output_url(
        json!({"name":name, "node_id":cfg.node.id, "cluster":cfg.cluster.name,
        "ready":ready, "next":if ready {
            "Add a custom MCP connector using this private URL and select No authentication."
        } else {
            "Node saved. Keep this machine's updated Gent daemon running; check gent node web list."
        }}),
        &url,
        out,
    )
}

pub(crate) async fn execute(parent: &Path, command: Command) -> Result<Value> {
    if let Command::List = command {
        let parent_config = node_home::inspect(parent)?;
        let mut nodes = Vec::new();
        for (home, record) in storage::list(parent)? {
            nodes.push(json!({"name":record.name,"node_id":record.node,
                "host_node_id":parent_config.node.id,"host_node_name":parent_config.node.name,
                "revoked":record.revoked,"ready":!record.revoked && runtime::ready(&home).await}));
        }
        return Ok(json!({"web_nodes":nodes}));
    }
    let (name, out, rotate, revoke) = match command {
        Command::Url(output) => (output.name, output.out, false, false),
        Command::Rotate(output) => (output.name, output.out, true, false),
        Command::Revoke { name } => (name, None, false, true),
        Command::List => unreachable!(),
    };
    if !revoke {
        output_allowed(out.as_deref())?;
    }
    let directory = storage::directory(parent)?;
    let _lock = managed_file::lock(&directory.join("setup.lock"))?;
    let home = storage::home(parent, &name);
    let mut record = storage::read(parent, &home)?.context("unknown web node name")?;
    ensure!(
        record.name == name && record.node.is_some(),
        "web node setup is incomplete; repeat node add"
    );
    if revoke {
        gateway::registry::capability::revoke(&home)?;
        record.revoked = true;
        storage::save(&home, &record)?;
        return Ok(json!({"web_node":true,"name":name,"revoked":true}));
    }
    ensure!(!record.revoked, "web node is revoked");
    let cfg = node_home::inspect(&home)?;
    let url = connection(&home, &cfg, rotate)?;
    output_url(
        json!({"name":name,"node_id":cfg.node.id,"rotated":rotate}),
        &url,
        out.as_deref(),
    )
}

pub(crate) fn print(value: &Value) {
    if let Some(nodes) = value["web_nodes"].as_array() {
        println!("gent  Web nodes");
        for node in nodes {
            println!(
                "  {}  {}  via {}",
                crate::display::visible(node["name"].as_str().unwrap_or("")),
                if node["revoked"] == true {
                    "revoked"
                } else if node["ready"] == true {
                    "connected"
                } else {
                    "offline"
                },
                crate::display::visible(node["host_node_name"].as_str().unwrap_or("this machine"))
            );
        }
        return;
    }
    println!(
        "gent  Web node {}",
        crate::display::visible(value["name"].as_str().unwrap_or(""))
    );
    if value["revoked"] == true {
        println!("  Connector revoked. Existing messages are retained.");
        return;
    }
    if let Some(url) = value["url"].as_str() {
        println!("\n{url}\n");
    }
    if let Some(path) = value["url_file"].as_str() {
        println!("  Private URL saved to {}", crate::display::visible(path));
    }
    if let Some(next) = value["next"].as_str() {
        println!("  {next}");
    }
    if value["rotated"] == true {
        println!("  Previous URL revoked. Update the connector URL; existing chats are retained.");
    }
    println!("  Keep this URL private. Anyone with it can use this web node.");
    println!("  {}", gateway::access::AccessRoute::Hosted.disclosure());
}
