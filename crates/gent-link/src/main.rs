mod agent;
mod agent_recovery;
mod auth;
mod backup;
mod build_info;
mod chats;
mod cluster;
mod config_editor;
mod display;
mod doctor;
mod enrollment;
mod files;
mod gateway;
mod groups;
mod hooks;
mod integration;
mod invitations;
mod managed_file;
mod mcp;
mod node;
mod node_home;
mod owner_recovery;
mod owner_transfer;
mod pairing;
mod peer_configuration;
mod permission_admin;
mod service;
mod setup;
mod ui;
mod update;
mod wake;
mod web;
mod work;

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
    about = "Permissioned communication between chats",
    after_help = "Guided setup: gent setup\nScripted setup: gent auth login && gent setup --new demo --no-input\nLocal development: gent setup --local demo\nConnect a host: gent mcp serve --binding /private/path/to/chat.key"
)]
struct Cli {
    /// Isolated state directory for development (default: ~/.gent).
    #[arg(long, global = true, hide = true)]
    home: Option<PathBuf>,
    /// Assert this node belongs to this cluster; never select another directory.
    #[arg(long = "cluster", global = true, hide = true)]
    context: Option<String>,
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    /// Show the complete response as formatted JSON; suppress animation.
    #[arg(long, short, global = true)]
    verbose: bool,
    /// Stable UUID for retrying an edit, renewal, or owner-transfer preparation.
    #[arg(long, global = true)]
    request_id: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Guided cluster enrollment, daemon startup and host integration setup.
    Setup {
        /// Initialize a local development cluster without signing in.
        #[arg(long, num_args=0..=1, default_missing_value="default")]
        local: Option<String>,
        #[command(flatten)]
        setup: setup::Options,
    },
    /// Show the exact build revision used for update comparisons.
    Version,
    /// Install the blessed stable release or inspect automatic updates.
    Update {
        #[command(subcommand)]
        command: Option<update::Command>,
    },
    /// Collect and inspect private recovery evidence; does not replace an owner.
    Recovery {
        #[command(subcommand)]
        command: owner_recovery::Command,
    },
    /// Inspect local work reports and reconcile interrupted attempts.
    Work {
        #[command(subcommand)]
        command: Option<work::Command>,
    },
    /// Create, verify or extract encrypted offline node backups.
    Backup {
        #[command(subcommand)]
        command: backup::Command,
    },
    /// Manage permission groups and separately delegated membership editing.
    #[command(alias = "groups")]
    Group {
        #[command(subcommand)]
        command: Option<groups::Command>,
    },
    /// Diagnose local setup without repairing state or running a model.
    Doctor(doctor::Options),
    /// Show current relay synchronization progress and queued records.
    Sync {
        #[command(subcommand)]
        command: Option<SyncCommand>,
    },
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
    /// Inspect host-input dispatch evidence; separate from message delivery and work.
    Wake {
        #[command(subcommand)]
        command: Option<wake::Command>,
    },
    /// Serve authenticated remote MCP directly on a user-controlled node.
    Gateway {
        #[command(subcommand)]
        command: Option<gateway::Command>,
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
    /// List host labels announced by registered chats.
    Providers {
        #[command(subcommand)]
        command: Option<ListCommand>,
    },
    /// List known chats across the cluster, grouped by node.
    #[command(name = "chats", alias = "agents", visible_aliases = ["ls", "list"])]
    Agents {
        #[command(subcommand)]
        command: Option<AgentsCommand>,
    },
    /// Resolve an exact chat name, defaulting to its most recent conversation activity.
    Resolve {
        name: String,
        #[arg(long)]
        node: Option<String>,
        #[arg(long)]
        provider: Option<String>,
    },
    /// List enrolled nodes and recent encrypted connectivity checks.
    Nodes,
    /// Inspect local file storage and clean expired handoff copies.
    Files {
        #[command(subcommand)]
        command: Option<FilesCommand>,
    },
    /// Inspect retained messages, recover archived history, or clean expired records.
    History {
        #[command(subcommand)]
        command: Option<HistoryCommand>,
    },
    /// Inspect encrypted transport storage and compact redundant records.
    Transport {
        #[command(subcommand)]
        command: Option<TransportCommand>,
    },
    /// Inspect, rename, recover or revoke a registration.
    #[command(name = "chat", alias = "agent")]
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
    /// Inspect saved relay selections. Relay uses ordinary messaging permissions.
    Relay {
        #[command(subcommand)]
        command: Option<RelayCommand>,
    },
}
#[derive(Subcommand)]
enum SyncCommand {
    Status,
}
#[derive(Subcommand)]
enum AgentsCommand {
    /// Clear retired registrations from this node's directory; preserve chat history.
    Clear {
        #[arg(long)]
        dry_run: bool,
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
    /// List historical imports, their recipients, and access revisions.
    Imports,
    /// Recover one archived chat's exchanges for one current local chat.
    Import {
        archive: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[command(flatten)]
        selection: backup::HistorySelection,
        #[arg(long = "chat", alias = "agent", value_name = "CHAT_ID")]
        agent: String,
        /// Explicitly restore a removed import at its last observed revision.
        #[arg(long)]
        restore_revision: Option<u64>,
    },
    /// Remove an import's records and access. Keep its revision for safe retries.
    Remove {
        import_id: String,
        #[arg(long)]
        expect_revision: u64,
    },
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
    #[command(hide = true)]
    Grants,
    /// Legacy compatibility only; new relay selections need no grant.
    #[command(hide = true)]
    Grant {
        intermediary: String,
        target: String,
        #[arg(long, default_value_t=86400, value_parser=clap::value_parser!(u64).range(1..=gent_protocol::MAX_RELAY_GRANT_LIFETIME))]
        ttl_seconds: u64,
    },
    /// Retire a legacy grant without affecting new permission-based selections.
    #[command(hide = true)]
    Revoke { grant: String },
    /// List up to 100 recent attachments stored on this node.
    Attachments,
}
#[derive(Subcommand)]
enum ClusterCommand {
    /// Enable equal node administration and ordered encrypted configuration.
    Upgrade,
    /// Prepare, commit, inspect or resume a signing-owner transfer.
    #[command(hide = true)]
    Owner {
        #[command(subcommand)]
        command: Option<owner_transfer::Command>,
    },
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
    /// Join through Gent with a pairing code, a private invitation, or trusted SSH.
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
        #[command(flatten)]
        setup: setup::Options,
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
        /// Opt into queued Codex wake through an existing local app-server socket.
        #[arg(long, requires = "host")]
        wake_socket: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
enum ListCommand {
    List,
}
#[derive(Subcommand)]
enum AgentCommand {
    Show {
        #[arg(value_name = "CHAT_ID")]
        agent: String,
    },
    Revoke {
        #[arg(value_name = "CHAT_ID")]
        agent: String,
    },
    /// Rename a chat on this node without changing its identity or permissions.
    Rename {
        #[arg(value_name = "CHAT_ID")]
        agent: String,
        name: String,
        /// Compare with a previously observed generation; do not overwrite a later rename.
        #[arg(long)]
        expect_generation: Option<u64>,
    },
    /// Create a fresh conversation binding and assign selected archived history.
    Recover(Box<agent_recovery::Args>),
}
#[derive(Subcommand)]
enum NodeCommand {
    /// Configure automatic discovery and waking of supported native chats.
    Discovery {
        #[command(subcommand)]
        command: Option<integration::discovery::Command>,
    },
    /// Stop local services and archive this node for fresh enrollment; keep GitHub login.
    Reset,
    /// Add a named node through a one-time invitation, or host one with --web.
    Add(enrollment::AddArgs),
    /// Manage named web/mobile connectors hosted by this machine.
    Web {
        #[command(subcommand)]
        command: web::Command,
    },
    /// Remove another node from membership and revoke its service access.
    Remove { node: String },
    /// List durable removal progress. Confirmation refers to service access, not peer sync.
    Removals {
        #[arg(long)]
        after: Option<String>,
        #[arg(long)]
        pending: bool,
    },
    /// Grant or revoke cluster administration on an enrolled node.
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
    /// Edit a private draft and save validated changes without publishing them.
    Edit(config_editor::Options),
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
    /// Delegate bounded permission editing to a chat, or revoke a delegation.
    Admin {
        #[command(subcommand)]
        command: permission_admin::Command,
    },
    /// Explain effective policy between two registered chat IDs, including matching rules.
    Explain { actor: String, peer: String },
    /// Add grants. Selectors: chat UUID, *, same-node, node:UUID, group:NAME.
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
    /// Remove exact-selector overrides and inherit the remaining cluster rules.
    Inherit {
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
    let chat_output = matches!(
        &cli.command,
        Some(Command::Agent { .. } | Command::Agents { .. } | Command::Resolve { .. })
    );
    let output_format = ui::Output::for_cli(&cli);
    ui::configure(output_format.raw());
    if matches!(cli.command, Some(Command::Version)) {
        let build = build_info::current();
        if output_format.raw() {
            output_format.print(&serde_json::to_value(&build)?)?;
        } else {
            println!(
                "gent {} ({}{})",
                build.version,
                build.commit,
                if build.dirty { ", modified source" } else { "" }
            );
        }
        return Ok(());
    }
    if let Some(Command::Backup { command }) = cli.command {
        let progress = ui::Progress::start("Processing encrypted backup");
        let value = backup::execute(command, cli.home.as_deref(), cli.context.as_deref())?;
        drop(progress);
        output_format.print(&value)?;
        return Ok(());
    }
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
    if let Some(Command::Recovery {
        command:
            owner_recovery::Command::Inspect {
                ref challenge,
                ref reports,
            },
    }) = cli.command
    {
        ensure!(
            cli.context.is_none(),
            "offline recovery inspection does not select a live cluster"
        );
        let value = owner_recovery::inspect(challenge, reports)?;
        output_format.print(&value)?;
        return Ok(());
    }
    if let Some(Command::Hooks { command }) = cli.command {
        let value = hooks::execute(command.unwrap_or_default())?;
        output_format.print(&value)?;
        return Ok(());
    }
    let request_id = cli
        .request_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let explicit_binding_scope = cli.home.is_some() || cli.context.is_some();
    let root = cli
        .home
        .or_else(|| std::env::var_os("GENT_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".gent")))
        .context("cannot locate home; pass --home")?;
    // A retained host guard must pass unrelated human input even after Gent
    // is removed or archived. Its notification path still checks all scope
    // and recovery guards; errors become a blocking hook response.
    if let Some(Command::Integration {
        command: integration::Command::ClaudeWakeGuard { ref config_dir },
    }) = cli.command
    {
        let value = integration::claude_wake::guard_execute(&root, config_dir).await;
        println!("{}", serde_json::to_string(&value)?);
        return Ok(());
    }
    if matches!(
        cli.command,
        Some(Command::Node {
            command: Some(NodeCommand::Reset)
        })
    ) {
        let output = node_home::reset::execute(&root).await?;
        output_format.print(&output)?;
        return Ok(());
    }
    // Archived state must never redirect a command to live state.
    gent_daemon::recovery::ensure_active(&root)?;
    if let Some(Command::Doctor(options)) = cli.command {
        let progress = ui::Progress::start("Checking this node");
        let report = doctor::run(&root, cli.context.as_deref(), options).await;
        drop(progress);
        if output_format.raw() {
            output_format.print(&serde_json::to_value(&report)?)?;
        } else {
            report.print();
        }
        if report.exit_code() != 0 {
            std::process::exit(report.exit_code());
        }
        return Ok(());
    }
    if let Some(Command::Config {
        command: Some(ConfigCommand::Edit(options)),
    }) = cli.command
    {
        config_editor::execute(&root, cli.context.as_deref(), options, cli.json).await?;
        return Ok(());
    }
    let home = node_home::resolve(&root, cli.context.as_deref())?;
    gent_daemon::recovery::ensure_active(&home)?;
    if let Some(Command::Setup { local, setup }) = cli.command {
        let output =
            node_home::provision::install(&home, local, setup, !output_format.raw()).await?;
        if output_format.raw() {
            output_format.print(&output)?;
        } else {
            service::print(&output);
        }
        if output["setup_complete"] == false {
            std::process::exit(3);
        }
        return Ok(());
    }
    if let Some(Command::Update { command }) = cli.command {
        let value = update::execute(&home, command.unwrap_or(update::Command::Install)).await?;
        output_format.print(&value)?;
        return Ok(());
    }
    if let Some(Command::Integration {
        command: integration::Command::CodexWrapper(args),
    }) = cli.command
    {
        integration::vscode::wrapped::execute(&home, args).await?;
        std::process::exit(0);
    }
    if let Some(Command::Integration {
        command: integration::Command::CodexIde(args),
    }) = cli.command
    {
        integration::vscode::execute(&home, args).await?;
        // Tokio's stdin may have an outstanding blocking read when the native
        // server disconnects. Stdout has been flushed; do not wait for that read
        // at runtime shutdown or leave the extension's child process hanging.
        std::process::exit(0);
    }
    if let Some(Command::Auth { command }) = cli.command {
        let status_only = matches!(command, None | Some(auth::Command::Status));
        let output = auth::execute(&home, command.unwrap_or(auth::Command::Status)).await?;
        if output_format.raw() {
            output_format.print(&output)?;
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
            update::run_daemon(&home).await?;
            return Ok(());
        }
        let status_only = matches!(command, None | Some(DaemonCommand::Status));
        let output = match command.unwrap_or(DaemonCommand::Status) {
            DaemonCommand::Install { local, setup } => {
                node_home::provision::install(&home, local, setup, !output_format.raw()).await?
            }
            action => service::execute(&home, action).await?,
        };
        if output_format.raw() {
            output_format.print(&output)?;
        } else {
            service::print(&output);
        }
        if (status_only && output["daemon"]["running"] != true) || output["setup_complete"] == false
        {
            std::process::exit(3);
        }
        return Ok(());
    }
    if let Some(Command::Gateway {
        command: Some(gateway::Command::Service { command }),
    }) = cli.command
    {
        let status_only = matches!(command, None | Some(service::GatewayCommand::Status));
        let output = gateway::execute(&home, gateway::Command::Service { command })
            .await?
            .context("missing gateway service result")?;
        if output_format.raw() {
            output_format.print(&output)?;
        } else {
            service::print(&output);
        }
        if status_only && output["gateway"]["running"] != true {
            std::process::exit(3);
        }
        return Ok(());
    }
    let files_output = matches!(&cli.command, Some(Command::Files { .. }));
    if let Some(Command::Node {
        command: Some(NodeCommand::Remove { node }),
    }) = cli.command
    {
        let output = node::remove(&home, node).await?;
        output_format.print(&output)?;
        if output["service_status"] == "pending" {
            std::process::exit(3);
        }
        return Ok(());
    }
    let history_output = matches!(&cli.command, Some(Command::History { .. }));
    let transport_output = matches!(&cli.command, Some(Command::Transport { .. }));
    let cluster_setup_output = matches!(
        &cli.command,
        Some(Command::Cluster {
            command: Some(ClusterCommand::New { local: false, .. } | ClusterCommand::Connect)
        })
    );
    let owner_transfer_output = matches!(
        &cli.command,
        Some(Command::Cluster {
            command: Some(ClusterCommand::Owner { .. })
        })
    );
    let display = match &cli.command {
        None
        | Some(Command::Cluster {
            command: None | Some(ClusterCommand::Status),
        }) => Some(display::View::Cluster),
        Some(Command::Node { command: None }) => Some(display::View::Node),
        Some(Command::Nodes) => Some(display::View::Nodes),
        Some(Command::Sync { .. }) => Some(display::View::Sync),
        Some(Command::Agents { command: None }) => Some(display::View::Agents),
        Some(Command::Resolve { .. }) => Some(display::View::Resolution),
        Some(Command::Agent {
            command: AgentCommand::Show { .. } | AgentCommand::Rename { .. },
        }) => Some(display::View::Agent),
        Some(Command::Providers { .. }) => Some(display::View::Providers),
        _ => None,
    };
    let progress = match &cli.command {
        Some(Command::Nodes) => Some(ui::Progress::start("Checking node connections")),
        Some(Command::Integration {
            command:
                integration::Command::Install(_)
                | integration::Command::Uninstall(_)
                | integration::Command::Status { .. },
        }) => Some(ui::Progress::start("Configuring host integration")),
        Some(Command::Config {
            command: Some(ConfigCommand::Apply),
        }) => Some(ui::Progress::start("Publishing cluster configuration")),
        _ => None,
    };
    let output = match cli.command {
        Some(Command::Version | Command::Update { .. } | Command::Setup { .. }) => unreachable!(),
        Some(Command::Node {
            command: Some(NodeCommand::Reset),
        }) => unreachable!(),
        Some(Command::Recovery { command }) => owner_recovery::execute(&home, command).await?,
        Some(Command::Work { command }) => work::execute(&home, command).await?,
        Some(Command::Wake { command }) => wake::execute(&home, command).await?,
        Some(Command::Doctor(_) | Command::Backup { .. }) => unreachable!(),
        None => owner(&home, OwnerOp::Status).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::New { name, local }),
        }) => node_home::provision::create(&home, name, local).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::Connect),
        }) => cluster::connect(&home, None).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::Renew),
        }) => configure(&home, &request_id, ConfigurationEdit::Renew).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::Upgrade),
        }) => peer_configuration::upgrade(&home).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::Owner { command }),
        }) => owner_transfer::execute(&home, &request_id, command).await?,
        Some(Command::Cluster {
            command: Some(ClusterCommand::Join(args)),
        }) => enrollment::join(&home, args).await?,
        Some(Command::Node {
            command: Some(NodeCommand::Add(args)),
        }) => enrollment::add(&home, args).await?,
        Some(Command::Node {
            command: Some(NodeCommand::Web { command }),
        }) => web::execute(&home, command).await?,
        Some(Command::Node {
            command: Some(NodeCommand::Discovery { command }),
        }) => {
            integration::discovery::execute(
                &home,
                command.unwrap_or(integration::discovery::Command::Status),
            )
            .await?
        }
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
            command:
                McpCommand::Serve {
                    binding,
                    host,
                    wake_socket,
                },
        }) => {
            mcp::run(home, binding, host, wake_socket, explicit_binding_scope).await?;
            return Ok(());
        }
        Some(Command::Gateway { command }) => {
            let Some(value) =
                gateway::execute(&home, command.unwrap_or(gateway::Command::Status)).await?
            else {
                return Ok(());
            };
            value
        }
        Some(Command::Integration {
            command: integration::Command::ClaudeWake { config_dir },
        }) => integration::claude_wake::execute(&home, &config_dir).await?,
        Some(Command::Integration {
            command: integration::Command::Start(args),
        }) => integration::runtime::start(&home, args).await?,
        Some(Command::Integration {
            command: integration::Command::Recovery { command },
        }) => integration::recovery::execute(&home, command).await?,
        Some(Command::Integration {
            command:
                integration::Command::Status {
                    host,
                    config_dir,
                    live: true,
                    host_binary,
                },
        }) => {
            integration::runtime::status(
                &home,
                host.context("--live requires a host")?,
                config_dir,
                host_binary.as_deref(),
            )
            .await?
        }
        Some(Command::Integration { command }) => integration::execute(&home, command)?,
        Some(Command::Integrations) => integration::execute(
            &home,
            integration::Command::Status {
                host: None,
                config_dir: None,
                live: false,
                host_binary: None,
            },
        )?,
        Some(Command::Providers { .. }) => owner(&home, OwnerOp::Providers).await?,
        Some(Command::Resolve {
            name,
            node,
            provider,
        }) => {
            owner(
                &home,
                OwnerOp::Resolve {
                    name,
                    node,
                    provider,
                },
            )
            .await?
        }
        Some(Command::Agents {
            command: Some(AgentsCommand::Clear { dry_run }),
        }) => owner(&home, OwnerOp::ClearRetiredAgents { dry_run }).await?,
        Some(Command::Agents { command: None }) => {
            let agents = owner(&home, OwnerOp::Agents).await?;
            if output_format.raw() {
                agents
            } else {
                let nodes = owner(&home, OwnerOp::Nodes).await?;
                let status = owner(&home, OwnerOp::Status).await?;
                json!({"agents":agents,"nodes":nodes,"sync":status["sync"]})
            }
        }
        Some(Command::Sync { .. }) => owner(&home, OwnerOp::Status)
            .await?
            .get("sync")
            .cloned()
            .context(
                "this daemon does not report sync progress; update Gent and restart its daemon",
            )?,
        Some(Command::Nodes) => owner(&home, OwnerOp::Nodes).await?,
        Some(Command::Files { command }) => {
            let action = match command.unwrap_or(FilesCommand::Status) {
                FilesCommand::Status => OwnerOp::FilesStatus,
                FilesCommand::Clean { dry_run } => OwnerOp::FilesClean { dry_run },
            };
            owner(&home, action).await?
        }
        Some(Command::History { command }) => match command.unwrap_or(HistoryCommand::Status) {
            HistoryCommand::Status => owner(&home, OwnerOp::HistoryStatus).await?,
            HistoryCommand::Clean { dry_run } => {
                owner(&home, OwnerOp::HistoryClean { dry_run }).await?
            }
            HistoryCommand::Imports => owner(&home, OwnerOp::HistoryImports).await?,
            HistoryCommand::Remove {
                import_id,
                expect_revision,
            } => {
                owner(
                    &home,
                    OwnerOp::HistoryRemove {
                        import_id,
                        expected_revision: expect_revision,
                    },
                )
                .await?
            }
            HistoryCommand::Import {
                archive,
                identity,
                selection,
                agent,
                restore_revision,
            } => {
                backup::import_history(
                    &home,
                    &archive,
                    &identity,
                    selection,
                    agent,
                    restore_revision,
                )
                .await?
            }
        },
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
            command: AgentCommand::Recover(args),
        }) => agent_recovery::execute(&home, *args).await?,
        Some(Command::Agent {
            command: AgentCommand::Show { agent },
        }) => agent::show(&home, agent).await?,
        Some(Command::Agent {
            command:
                AgentCommand::Rename {
                    agent,
                    name,
                    expect_generation,
                },
        }) => agent::rename(&home, agent, name, expect_generation).await?,
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
            command: Some(NodeCommand::Removals { after, pending }),
        }) => {
            owner(
                &home,
                OwnerOp::NodeRemovals {
                    after,
                    pending_only: pending,
                },
            )
            .await?
        }
        Some(Command::Node {
            command: Some(NodeCommand::Remove { .. }),
        }) => unreachable!(),
        Some(Command::Node {
            command: Some(NodeCommand::Name { command: None }),
        }) => {
            let name = config::load(&home)?.node.name;
            if output_format.raw() {
                json!(name)
            } else {
                println!("{}", display::visible(&name));
                return Ok(());
            }
        }
        Some(Command::Node { command: None }) => json!(config::load(&home)?.node),
        Some(Command::Config {
            command: Some(ConfigCommand::Path),
        }) => {
            let path = std::path::absolute(config::path(&home))?;
            if output_format.raw() {
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
            command: Some(ConfigCommand::Edit(_)),
        }) => unreachable!("editor dispatched before ordinary command output"),
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
        Some(Command::Relay { command }) => match command.unwrap_or(RelayCommand::Attachments) {
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
        Some(Command::Group { command }) => groups::run(&home, &request_id, command).await?,
        Some(Command::Permission {
            command: PermissionCommand::Explain { actor, peer },
        }) => owner(&home, OwnerOp::PermissionExplain { actor, peer }).await?,
        Some(Command::Permission {
            command: PermissionCommand::Admin { command },
        }) => permission_admin::run(&home, &request_id, command).await?,
        Some(Command::Permission { command }) => {
            let (actor, peer, permissions, effect) = match command {
                PermissionCommand::Explain { .. } | PermissionCommand::Admin { .. } => {
                    unreachable!()
                }
                PermissionCommand::Allow {
                    actor,
                    peer,
                    permission,
                } => (actor, peer, permission, Some(Effect::Allow)),
                PermissionCommand::Deny {
                    actor,
                    peer,
                    permission,
                } => (actor, peer, permission, Some(Effect::Deny)),
                PermissionCommand::Inherit {
                    actor,
                    peer,
                    permission,
                } => (actor, peer, permission, None),
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
                if let Some(effect) = effect {
                    let rule = Rule {
                        actor: actor.clone(),
                        peer: peer.clone(),
                        permission,
                        effect,
                    };
                    if !config.policy.rules.contains(&rule) {
                        config.policy.rules.push(rule);
                    }
                } else {
                    config.policy.rules.retain(|rule| {
                        rule.actor != actor || rule.peer != peer || rule.permission != permission
                    });
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
    let mut output = output;
    if chat_output {
        chats::expose(&mut output);
    }
    drop(progress);
    if output_format.raw() {
        output_format.print(&output)?;
    } else if output["web_node"] == true || output["web_nodes"].is_array() {
        web::print(&output);
    } else if output["chat_discovery"] == true {
        integration::discovery::print(&output);
    } else if let Some(view) = display {
        print!("{}", display::render(view, &output)?);
    } else if owner_transfer_output {
        owner_transfer::print(&output);
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
        if let Some(target) = output["replaced_node"].as_str() {
            println!("Replaced node {target}. Old chats and history were not imported.");
        }
        println!("Start the daemon with gent daemon install.");
    } else if files_output {
        files::print_report(&output);
    } else if history_output {
        files::print_history(&output);
    } else if transport_output {
        files::print_transport(&output);
    } else {
        output_format.print(&output)?;
    }
    if output["setup_complete"] == false {
        std::process::exit(3);
    }
    Ok(())
}
