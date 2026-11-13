mod mcp;
mod pairing;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use gent_daemon::{config, request};
use gent_protocol::{Effect, OwnerOp, Permission, Request, Rule, Selector};
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "gent",
    version,
    about = "Permissioned communication between agents",
    after_help = "Local proof setup: gent cluster new demo --local\nStart the daemon: gent daemon run\nConnect a host: gent mcp serve --binding /private/path/to/chat.key"
)]
struct Cli {
    /// State directory (default: ~/.gent). Use a separate directory for experiments.
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Create or inspect the cluster. Hosted enrollment is not available in this proof.
    Cluster {
        #[command(subcommand)]
        command: Option<ClusterCommand>,
    },
    /// Run or inspect the local daemon.
    Daemon {
        #[command(subcommand)]
        command: Option<DaemonCommand>,
    },
    /// Expose Gent to an MCP host.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// List host labels announced by registered agents.
    Providers {
        #[command(subcommand)]
        command: Option<ListCommand>,
    },
    /// List registered agents as the local owner.
    Agents,
    /// List enrolled nodes; remote presence is currently unknown.
    Nodes,
    /// Inspect or revoke a registration.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Inspect or rename this node.
    Node {
        #[command(subcommand)]
        command: Option<NodeCommand>,
    },
    /// Inspect, validate, or apply TOML configuration.
    Config {
        #[command(subcommand)]
        command: Option<ConfigCommand>,
    },
    /// Change communication permissions as the local owner.
    Permission {
        #[command(subcommand)]
        command: PermissionCommand,
    },
}
#[derive(Subcommand)]
enum ClusterCommand {
    New {
        name: String,
        #[arg(long)]
        local: bool,
    },
    Status,
    /// Renew the locally held owner-signed configuration lease.
    Renew,
    /// Join through an SSH-authenticated owner node; keys stay on their own machines.
    Join(pairing::JoinArgs),
    /// Private stdio protocol used by cluster join over SSH.
    #[command(hide = true)]
    PairingServe,
}
#[derive(Subcommand)]
enum DaemonCommand {
    Run,
    Status,
}
#[derive(Subcommand)]
enum McpCommand {
    Serve {
        /// Owner/host-selected private credential file, unique per conversation.
        #[arg(long)]
        binding: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
enum ListCommand {
    List,
}
#[derive(Subcommand)]
enum AgentCommand {
    Show { agent: String },
    Revoke { agent: String },
}
#[derive(Subcommand)]
enum NodeCommand {
    Name {
        #[command(subcommand)]
        command: Option<NodeNameCommand>,
    },
}
#[derive(Subcommand)]
enum NodeNameCommand {
    Set { name: String },
}
#[derive(Subcommand)]
enum ConfigCommand {
    Path,
    Validate,
    Apply,
}
#[derive(Clone, Copy, ValueEnum)]
enum PermissionName {
    Enumerate,
    Receive,
    Send,
}
#[derive(Subcommand)]
enum PermissionCommand {
    /// Add grants. Selectors: agent UUID, *, same-node, node:UUID, group:NAME.
    Allow {
        actor: String,
        peer: String,
        #[arg(long,value_enum,num_args=1..,required=true)]
        permission: Vec<PermissionName>,
    },
    /// Add explicit denials, overriding matching grants.
    Deny {
        actor: String,
        peer: String,
        #[arg(long,value_enum,num_args=1..,required=true)]
        permission: Vec<PermissionName>,
    },
}

async fn owner(home: &std::path::Path, action: OwnerOp) -> Result<Value> {
    request(
        home,
        Request::Owner {
            credential: config::read_private(&home.join("owner.key"))?,
            action,
        },
    )
    .await
}
fn selector(value: String) -> Result<Selector> {
    Ok(match value.as_str() {
        "*" => Selector::All,
        "same-node" => Selector::SameNode,
        value if value.starts_with("node:") => Selector::Node(value[5..].into()),
        value if value.starts_with("group:") => Selector::Group(value[6..].into()),
        _ => Selector::Agent(value),
    })
}

#[tokio::main]
async fn main() {
    if let Err(error) = execute(Cli::parse()).await {
        eprintln!("gent: {error:#}");
        std::process::exit(1);
    }
}

async fn execute(cli: Cli) -> Result<()> {
    let home = cli
        .home
        .or_else(|| std::env::var_os("GENT_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".gent")))
        .context("cannot locate home; pass --home")?;
    let output = match cli.command {
        None => owner(&home, OwnerOp::Status).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::New { name, local }),
        }) => {
            ensure!(
                local,
                "hosted enrollment is not implemented; --local creates an isolated development cluster"
            );
            json!(config::initialize(&home, &name)?)
        }
        Some(Command::Cluster {
            command: Some(ClusterCommand::Renew),
        }) => owner(&home, OwnerOp::Renew).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::Join(args)),
        }) => pairing::join(&home, args).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::PairingServe),
        }) => {
            pairing::serve(&home).await?;
            return Ok(());
        }
        Some(Command::Cluster { .. }) => owner(&home, OwnerOp::Status).await?,
        Some(Command::Daemon {
            command: Some(DaemonCommand::Run),
        }) => {
            gent_daemon::run(&home).await?;
            return Ok(());
        }
        Some(Command::Daemon { .. }) => owner(&home, OwnerOp::Status).await?,
        Some(Command::Mcp {
            command: McpCommand::Serve { binding },
        }) => {
            mcp::run(home, binding).await?;
            return Ok(());
        }
        Some(Command::Providers { .. }) => owner(&home, OwnerOp::Providers).await?,
        Some(Command::Agents) => owner(&home, OwnerOp::Agents).await?,
        Some(Command::Nodes) => owner(&home, OwnerOp::Nodes).await?,
        Some(Command::Agent {
            command: AgentCommand::Revoke { agent },
        }) => owner(&home, OwnerOp::Revoke { agent_id: agent }).await?,
        Some(Command::Agent {
            command: AgentCommand::Show { agent },
        }) => {
            let agents = owner(&home, OwnerOp::Agents).await?;
            agents
                .as_array()
                .context("invalid agent list")?
                .iter()
                .find(|a| a["id"] == agent)
                .cloned()
                .context("unknown agent ID")?
        }
        Some(Command::Node {
            command:
                Some(NodeCommand::Name {
                    command: Some(NodeNameCommand::Set { name }),
                }),
        }) => owner(&home, OwnerOp::RenameNode { name }).await?,
        Some(Command::Node {
            command: Some(NodeCommand::Name { command: None }),
        }) => {
            let name = config::load(&home)?.node.name;
            if cli.json {
                json!(name)
            } else {
                println!("{name}");
                return Ok(());
            }
        }
        Some(Command::Node { command: None }) => json!(config::load(&home)?.node),
        Some(Command::Config {
            command: Some(ConfigCommand::Path),
        }) => {
            let path = std::path::absolute(config::path(&home))?;
            if cli.json {
                json!(path)
            } else {
                println!("{}", path.display());
                return Ok(());
            }
        }
        Some(Command::Config {
            command: Some(ConfigCommand::Validate),
        }) => {
            config::load(&home)?;
            json!({"valid":true})
        }
        Some(Command::Config {
            command: Some(ConfigCommand::Apply),
        }) => {
            owner(
                &home,
                OwnerOp::SetPolicy {
                    policy: config::load(&home)?.policy,
                },
            )
            .await?
        }
        Some(Command::Config { command: None }) => json!(config::load(&home)?),
        Some(Command::Permission { command }) => {
            let (actor, peer, permissions, effect) = match command {
                PermissionCommand::Allow {
                    actor,
                    peer,
                    permission,
                } => (actor, peer, permission, Effect::Allow),
                PermissionCommand::Deny {
                    actor,
                    peer,
                    permission,
                } => (actor, peer, permission, Effect::Deny),
            };
            let mut config = config::load(&home)?;
            let actor = selector(actor)?;
            let peer = selector(peer)?;
            for permission in permissions {
                let permission = match permission {
                    PermissionName::Enumerate => Permission::Enumerate,
                    PermissionName::Receive => Permission::Receive,
                    PermissionName::Send => Permission::Send,
                };
                let rule = Rule {
                    actor: actor.clone(),
                    peer: peer.clone(),
                    permission,
                    effect,
                };
                if !config.policy.rules.contains(&rule) {
                    config.policy.rules.push(rule);
                }
            }
            owner(
                &home,
                OwnerOp::SetPolicy {
                    policy: config.policy,
                },
            )
            .await?
        }
    };
    if cli.json {
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&output)?);
    }
    Ok(())
}
