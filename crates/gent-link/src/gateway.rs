//! User-controlled remote MCP. The HTTP credential authenticates a trusted host
//! namespace; every agent call also needs that host's conversation metadata.
mod registry;
mod server;
use crate::{contexts, managed_file};
use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
pub(crate) use registry::{Permit, Registry};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Subcommand)]
pub enum Command {
    /// Show local gateway configuration and limits; does not probe a running listener.
    Status,
    /// Run a user-controlled Streamable HTTP MCP endpoint in the foreground.
    Run(Run),
    /// Grant or revoke a trusted remote host's conversation namespace.
    Clients {
        #[command(subcommand)]
        command: Option<ClientCommand>,
    },
}

#[derive(Subcommand)]
pub enum ClientCommand {
    List,
    /// Issue a private host credential. Transfer it to the host outside model prompts.
    Add {
        name: String,
        /// Host-owned per-call MCP metadata field, e.g. gent/conversation.
        /// Provider support and metadata provenance must be verified separately.
        #[arg(long)]
        conversation_key: String,
        /// Private credential export; an identical retry preserves its token.
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t=720, value_parser=clap::value_parser!(u64).range(1..=8760))]
        ttl_hours: u64,
    },
    /// Reject future requests from this host, retaining agent identities and messages.
    Revoke {
        client: String,
    },
}

#[derive(Args)]
pub struct Run {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,
    /// Exact external HTTPS origin when serving TLS directly.
    #[arg(long, requires = "tls_cert")]
    origin: Option<String>,
    /// PEM certificate chain for direct TLS on this trusted node.
    #[arg(long, requires_all=["tls_key","origin"])]
    tls_cert: Option<PathBuf>,
    /// Private PEM key (mode 0600); never sent to Gent's relay.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
}

pub async fn execute(home: &Path, command: Command, explicit: bool) -> Result<Option<Value>> {
    let home = managed_file::normalize(home)?;
    match command {
        Command::Run(options) => {
            ensure!(
                explicit,
                "gateway run requires a pinned --home or --cluster"
            );
            server::run(home, options).await?;
            Ok(None)
        }
        Command::Status
        | Command::Clients {
            command: None | Some(ClientCommand::List),
        } => {
            let cfg = contexts::inspect(&home)?;
            if cfg.gateway_registry()?.is_none() {
                return Ok(Some(
                    json!({"configured":false,"clients":[],"running":"not_probed"}),
                ));
            }
            Ok(Some(Registry::open(&home)?.listing()?))
        }
        Command::Clients {
            command:
                Some(ClientCommand::Add {
                    name,
                    conversation_key,
                    out,
                    ttl_hours,
                }),
        } => Ok(Some(registry::add(
            &home,
            &name,
            &conversation_key,
            &out,
            ttl_hours,
        )?)),
        Command::Clients {
            command: Some(ClientCommand::Revoke { client }),
        } => Ok(Some(Registry::open(&home)?.revoke(&client)?)),
    }
}
