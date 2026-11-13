mod auth;
mod cluster;
mod files;
mod hooks;
mod integration;
mod invitations;
mod managed_file;
mod mcp;
mod pairing;
mod service;

use anyhow::{Context, Result, ensure};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use gent_daemon::{config, request};
use gent_protocol::{ConfigurationEdit, Effect, OwnerOp, Permission, Request, Rule, Selector};
use serde_json::{Value, json};
use std::{io::Write, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "gent",
    version,
    about = "Permissioned communication between agents",
    after_help = "Service setup: gent auth login && gent cluster new demo && gent daemon install\nLocal development: gent daemon install --local demo\nConnect a host: gent mcp serve --binding /private/path/to/chat.key"
)]
struct Cli {
    /// State directory (default: ~/.gent). Use a separate directory for experiments.
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    /// Stable UUID for retrying a policy edit, config apply, rename, or renewal.
    #[arg(long, global = true)]
    request_id: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Sign in to Gent's service, inspect the account session, or sign out.
    Auth {
        #[command(subcommand)]
        command: Option<auth::Command>,
    },
    /// Create, join, or inspect a cluster.
    Cluster {
        #[command(subcommand)]
        command: Option<ClusterCommand>,
    },
    /// Install, control, or inspect the local daemon.
    Daemon {
        #[command(subcommand)]
        command: Option<DaemonCommand>,
    },
    /// Expose Gent to an MCP host.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Configure a host's MCP connection and conversation binding.
    Integration {
        #[command(subcommand)]
        command: integration::Command,
    },
    /// Show user-scope Gent installation for supported hosts.
    Integrations,
    /// Manage Gent's PATH and completion setup in an interactive shell.
    Hooks {
        #[command(subcommand)]
        command: Option<hooks::Command>,
    },
    /// Print a completion script; does not read Gent state or start the daemon.
    Completions { shell: hooks::Shell },
    /// List host labels announced by registered agents.
    Providers {
        #[command(subcommand)]
        command: Option<ListCommand>,
    },
    /// List registered agents as the local owner.
    Agents,
    /// List enrolled nodes; remote presence is currently unknown.
    Nodes,
    /// Inspect local file storage and clean expired handoff copies.
    Files {
        #[command(subcommand)]
        command: Option<FilesCommand>,
    },
    /// Inspect or prune local Gent message and agent retry history.
    History {
        #[command(subcommand)]
        command: Option<HistoryCommand>,
    },
    /// Inspect encrypted transport storage and compact redundant records.
    Transport {
        #[command(subcommand)]
        command: Option<TransportCommand>,
    },
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
    /// Manage time-limited relay grants and inspect stored local attachments.
    Relay {
        #[command(subcommand)]
        command: Option<RelayCommand>,
    },
}
#[derive(Subcommand)]
enum FilesCommand {
    Status,
    /// Clean one bounded batch of expired, unchanged handoff copies and encrypted objects.
    Clean {
        /// Preview the batch without removing files or storage records.
        #[arg(long)]
        dry_run: bool,
    },
}
#[derive(Subcommand)]
enum HistoryCommand {
    Status,
    /// Retire a bounded batch of expired exchanges and inadmissible retry IDs.
    Clean {
        #[arg(long)]
        dry_run: bool,
    },
}
#[derive(Subcommand)]
enum TransportCommand {
    Status,
    /// Compact duplicate ciphertext copies and old replay evidence; retain packets for offline peers.
    Clean {
        #[arg(long)]
        dry_run: bool,
    },
}
#[derive(Subcommand)]
enum RelayCommand {
    Grants,
    /// Authorize one intermediary to select one target; messaging permissions still apply.
    Grant {
        intermediary: String,
        target: String,
        #[arg(long, default_value_t=86400, value_parser=clap::value_parser!(u64).range(1..=gent_protocol::MAX_RELAY_GRANT_LIFETIME))]
        ttl_seconds: u64,
    },
    /// Permanently retire a grant ID. Reauthorization uses a new grant.
    Revoke {
        grant: String,
    },
    /// List up to 100 recent attachments stored on this node.
    Attachments,
}
#[derive(Subcommand)]
enum ClusterCommand {
    /// Create a service cluster after gent auth login, or a local development cluster.
    New {
        name: String,
        #[arg(long)]
        local: bool,
    },
    /// Resume service setup or refresh this node's revoked/expired credential.
    /// Stop the daemon first; sign into the original account with gent auth login.
    Connect,
    Status,
    /// Renew the locally held owner-signed configuration lease.
    Renew,
    /// Join with a private invitation file or through a trusted SSH owner node.
    Join(pairing::JoinArgs),
    /// Create a private invitation for one new node; the owner daemon must be online.
    Invite(invitations::InviteArgs),
    /// List or revoke this owner's invitations.
    Invitations {
        #[command(subcommand)]
        command: Option<invitations::Command>,
    },
    /// Private stdio protocol used by cluster join over SSH.
    #[command(hide = true)]
    PairingServe,
}
#[derive(Subcommand)]
enum DaemonCommand {
    /// Run in the foreground; stop with Ctrl-C or SIGTERM.
    Run,
    Status,
    /// Register and start a systemd user service or macOS LaunchAgent.
    Install {
        /// Initialize an unconfigured local development cluster (default name: default).
        #[arg(long, num_args=0..=1, default_missing_value="default")]
        local: Option<String>,
    },
    /// Stop and remove the service, retaining all Gent state and credentials.
    #[command(alias = "remove")]
    Uninstall,
    Start,
    Stop,
    Restart,
    /// Show recent daemon diagnostics.
    Logs {
        #[arg(long, default_value_t=100, value_parser=clap::value_parser!(u32).range(1..=10000))]
        lines: u32,
    },
}
#[derive(Subcommand)]
enum McpCommand {
    Serve {
        /// Owner/host-selected private credential file, unique per conversation.
        #[arg(long)]
        binding: Option<PathBuf>,
        /// Select credentials using host-supplied conversation metadata.
        #[arg(long, value_enum, conflicts_with = "binding")]
        host: Option<integration::Host>,
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
    /// Grant or revoke configuration management on an enrolled node (owner only).
    Admin {
        #[command(subcommand)]
        command: NodeAdminCommand,
    },
    Name {
        #[command(subcommand)]
        command: Option<NodeNameCommand>,
    },
}
#[derive(Subcommand)]
enum NodeAdminCommand {
    Grant { node: String },
    Revoke { node: String },
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
    /// List the latest 100 local configuration requests, including offline edits.
    Requests,
    /// Inspect an accepted, rejected, or pending configuration request.
    Request {
        id: String,
    },
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
async fn configure(home: &std::path::Path, id: &str, edit: ConfigurationEdit) -> Result<Value> {
    let mut value = owner(
        home,
        OwnerOp::Configure {
            request_id: id.into(),
            edit,
        },
    )
    .await?;
    let until = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while value["state"] == "queued" && tokio::time::Instant::now() < until {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        match owner(
            home,
            OwnerOp::ConfigurationRequests {
                request_id: Some(id.into()),
            },
        )
        .await
        {
            Ok(status) => value = status,
            Err(_) => break, // The durable request remains inspectable after restart.
        }
    }
    ensure!(
        value["state"] != "rejected",
        "configuration request {id} rejected: {}",
        value["reason"].as_str().unwrap_or("unknown reason")
    );
    Ok(value)
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
    if let Some(Command::Completions { shell }) = cli.command {
        let mut script = Vec::new();
        clap_complete::generate(shell.generator(), &mut Cli::command(), "gent", &mut script);
        if let Err(error) = std::io::stdout().lock().write_all(&script)
            && error.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(error.into());
        }
        return Ok(());
    }
    if let Some(Command::Hooks { command }) = cli.command {
        let value = hooks::execute(command.unwrap_or_default())?;
        println!(
            "{}",
            if cli.json {
                serde_json::to_string(&value)?
            } else {
                serde_json::to_string_pretty(&value)?
            }
        );
        return Ok(());
    }
    let request_id = cli
        .request_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let home = cli
        .home
        .or_else(|| std::env::var_os("GENT_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".gent")))
        .context("cannot locate home; pass --home")?;
    if let Some(Command::Auth { command }) = cli.command {
        let status_only = matches!(command, None | Some(auth::Command::Status));
        let output = auth::execute(&home, command.unwrap_or(auth::Command::Status)).await?;
        if cli.json {
            println!("{}", serde_json::to_string(&output)?);
        } else {
            auth::print(&output);
        }
        if (status_only && output["status"] != "active") || output["status"] == "revocation_pending"
        {
            std::process::exit(3);
        }
        return Ok(());
    }
    if let Some(Command::Daemon { command }) = cli.command {
        if matches!(command, Some(DaemonCommand::Run)) {
            gent_daemon::run(&home).await?;
            return Ok(());
        }
        let status_only = matches!(command, None | Some(DaemonCommand::Status));
        let output = service::execute(&home, command.unwrap_or(DaemonCommand::Status)).await?;
        if cli.json {
            println!("{}", serde_json::to_string(&output)?);
        } else {
            service::print(&output);
        }
        if status_only && output["daemon"]["running"] != true {
            std::process::exit(3);
        }
        return Ok(());
    }
    let files_output = matches!(&cli.command, Some(Command::Files { .. }));
    let history_output = matches!(&cli.command, Some(Command::History { .. }));
    let transport_output = matches!(&cli.command, Some(Command::Transport { .. }));
    let cluster_setup_output = matches!(
        &cli.command,
        Some(Command::Cluster {
            command: Some(ClusterCommand::New { local: false, .. } | ClusterCommand::Connect)
        })
    );
    let output = match cli.command {
        None => owner(&home, OwnerOp::Status).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::New { name, local }),
        }) => {
            if local {
                json!(cluster::local(&home, &name)?)
            } else {
                cluster::connect(&home, Some(&name)).await?
            }
        }
        Some(Command::Cluster {
            command: Some(ClusterCommand::Connect),
        }) => cluster::connect(&home, None).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::Renew),
        }) => configure(&home, &request_id, ConfigurationEdit::Renew).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::Join(args)),
        }) => pairing::join(&home, args).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::Invite(args)),
        }) => invitations::create(&home, args).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::Invitations { command }),
        }) => invitations::execute(&home, command.unwrap_or(invitations::Command::List)).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::PairingServe),
        }) => {
            pairing::serve(&home).await?;
            return Ok(());
        }
        Some(Command::Cluster { .. }) => owner(&home, OwnerOp::Status).await?,
        Some(Command::Daemon { .. } | Command::Auth { .. }) => unreachable!(),
        Some(Command::Hooks { .. } | Command::Completions { .. }) => unreachable!(),
        Some(Command::Mcp {
            command: McpCommand::Serve { binding, host },
        }) => {
            mcp::run(home, binding, host).await?;
            return Ok(());
        }
        Some(Command::Integration { command }) => integration::execute(&home, command)?,
        Some(Command::Integrations) => integration::execute(
            &home,
            integration::Command::Status {
                host: None,
                config_dir: None,
            },
        )?,
        Some(Command::Providers { .. }) => owner(&home, OwnerOp::Providers).await?,
        Some(Command::Agents) => owner(&home, OwnerOp::Agents).await?,
        Some(Command::Nodes) => owner(&home, OwnerOp::Nodes).await?,
        Some(Command::Files { command }) => {
            let action = match command.unwrap_or(FilesCommand::Status) {
                FilesCommand::Status => OwnerOp::FilesStatus,
                FilesCommand::Clean { dry_run } => OwnerOp::FilesClean { dry_run },
            };
            owner(&home, action).await?
        }
        Some(Command::History { command }) => {
            owner(
                &home,
                match command.unwrap_or(HistoryCommand::Status) {
                    HistoryCommand::Status => OwnerOp::HistoryStatus,
                    HistoryCommand::Clean { dry_run } => OwnerOp::HistoryClean { dry_run },
                },
            )
            .await?
        }
        Some(Command::Transport { command }) => {
            owner(
                &home,
                match command.unwrap_or(TransportCommand::Status) {
                    TransportCommand::Status => OwnerOp::TransportStatus,
                    TransportCommand::Clean { dry_run } => OwnerOp::TransportClean { dry_run },
                },
            )
            .await?
        }
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
        }) => configure(&home, &request_id, ConfigurationEdit::RenameNode { name }).await?,
        Some(Command::Node {
            command: Some(NodeCommand::Admin { command }),
        }) => {
            let (node_id, allow) = match command {
                NodeAdminCommand::Grant { node } => (node, true),
                NodeAdminCommand::Revoke { node } => (node, false),
            };
            owner(&home, OwnerOp::DelegateConfiguration { node_id, allow }).await?
        }
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
            let proposed = config::load(&home)?;
            configure(
                &home,
                &request_id,
                ConfigurationEdit::Replace {
                    cluster_name: proposed.cluster.name,
                    node_name: proposed.node.name,
                    policy: proposed.policy,
                },
            )
            .await?
        }
        Some(Command::Config {
            command: Some(ConfigCommand::Requests),
        }) => owner(&home, OwnerOp::ConfigurationRequests { request_id: None }).await?,
        Some(Command::Config {
            command: Some(ConfigCommand::Request { id }),
        }) => {
            owner(
                &home,
                OwnerOp::ConfigurationRequests {
                    request_id: Some(id),
                },
            )
            .await?
        }
        Some(Command::Config { command: None }) => json!(config::load(&home)?),
        Some(Command::Relay { command }) => match command.unwrap_or(RelayCommand::Grants) {
            RelayCommand::Grants => owner(&home, OwnerOp::RelayGrants).await?,
            RelayCommand::Attachments => owner(&home, OwnerOp::RelayAttachments).await?,
            RelayCommand::Grant {
                intermediary,
                target,
                ttl_seconds,
            } => {
                configure(
                    &home,
                    &request_id,
                    ConfigurationEdit::GrantRelay {
                        grant_id: request_id.clone(),
                        intermediary,
                        target,
                        lifetime_seconds: ttl_seconds,
                    },
                )
                .await?
            }
            RelayCommand::Revoke { grant } => {
                configure(
                    &home,
                    &request_id,
                    ConfigurationEdit::RevokeRelay { grant_id: grant },
                )
                .await?
            }
        },
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
            configure(
                &home,
                &request_id,
                ConfigurationEdit::Policy {
                    policy: config.policy,
                },
            )
            .await?
        }
    };
    if cli.json {
        println!("{}", serde_json::to_string(&output)?);
    } else if cluster_setup_output {
        println!(
            "Cluster {} configured on node {}.",
            output["cluster"]["name"].as_str().unwrap_or(""),
            output["node"]["name"].as_str().unwrap_or("")
        );
        println!(
            "Cluster ID: {}",
            output["cluster"]["id"].as_str().unwrap_or("")
        );
        println!("Start the daemon with gent daemon install.");
    } else if files_output {
        files::print_report(&output);
    } else if history_output {
        files::print_history(&output);
    } else if transport_output {
        files::print_transport(&output);
    } else {
        println!("{}", serde_json::to_string_pretty(&output)?);
    }
    Ok(())
}
