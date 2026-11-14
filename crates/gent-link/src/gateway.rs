//! User-controlled remote MCP. The HTTP credential authenticates a trusted host
//! namespace; every agent call also needs that host's conversation metadata.
mod assertion;
mod metadata;
mod mtls;
pub(crate) mod registry;
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
    /// Inspect and authorize OAuth connection requests on this node.
    Oauth {
        #[command(subcommand)]
        command: Option<OAuthCommand>,
    },
}

#[derive(Subcommand)]
pub enum OAuthCommand {
    Requests,
    /// Approve the exact request shown in your browser after checking its client and callback.
    Approve {
        request: String,
    },
    Deny {
        request: String,
    },
}

#[derive(Subcommand)]
pub enum ClientCommand {
    List,
    /// Inspect or replace an existing signed client's pinned public keys.
    Keys {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Register a trusted host and write its private connection configuration.
    Add {
        name: String,
        /// Host-owned per-call MCP metadata field, e.g. gent/conversation or Codex threadId.
        /// Provider support and metadata provenance must be verified separately.
        #[arg(long)]
        conversation_key: String,
        /// Private registration export; an identical retry preserves its identity and credentials.
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t=720, value_parser=clap::value_parser!(u64).range(1..=8760))]
        ttl_hours: u64,
        /// Pin this OAuth client's exact MCP resource URL. The export token becomes its client secret.
        #[arg(long, requires = "redirect_uri")]
        oauth_resource: Option<String>,
        /// Exact OAuth callback URL; repeat for additional callbacks. No wildcards.
        #[arg(long, requires = "oauth_resource")]
        redirect_uri: Vec<String>,
        /// Exact HTTPS OAuth client identifier for private_key_jwt authentication.
        #[arg(long, requires_all = ["oauth_resource", "oauth_jwks"])]
        oauth_client_id: Option<String>,
        /// Pin a local public RSA JWKS (RS256). Gent never fetches keys from request headers.
        #[arg(long, requires = "oauth_client_id")]
        oauth_jwks: Option<PathBuf>,
        /// Fetch this HTTPS client metadata document and its same-origin public JWKS.
        /// Only the explicitly selected callbacks are registered.
        #[arg(long, requires = "oauth_resource", conflicts_with_all = ["oauth_client_id", "oauth_jwks"])]
        oauth_metadata: Option<String>,
        /// Pin one client CA certificate. The peer must also have the exact --tls-client-name DNS SAN.
        #[arg(long, requires = "tls_client_name")]
        tls_client_ca: Option<PathBuf>,
        /// Exact lowercase DNS SAN in the client certificate; no wildcards or CN fallback.
        #[arg(long, requires = "tls_client_ca")]
        tls_client_name: Option<String>,
    },
    /// Reject future requests from this host, retaining agent identities and messages.
    Revoke {
        client: String,
    },
}

#[derive(Subcommand)]
pub enum KeyCommand {
    Show {
        client: String,
    },
    /// Replace the complete key set while preserving the client and its agents.
    Set {
        client: String,
        #[arg(long)]
        jwks: PathBuf,
        /// Revision from keys show; prevents a stale update from replacing newer keys.
        #[arg(long)]
        expect_revision: u64,
    },
    /// Fetch this client's metadata/JWKS again and replace keys after checking its existing callbacks.
    Refresh {
        client: String,
        #[arg(long)]
        expect_revision: u64,
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
    /// Enable CIMD and bounded metadata/key refresh for this existing signed client UUID. Repeat for more hosts.
    #[arg(long)]
    client_metadata: Vec<String>,
}

pub async fn execute(home: &Path, command: Command, explicit: bool) -> Result<Option<Value>> {
    let home = managed_file::normalize(home)?;
    match command {
        Command::Oauth { command } => {
            let registry = Registry::open(&home)?;
            Ok(Some(match command.unwrap_or(OAuthCommand::Requests) {
                OAuthCommand::Requests => registry.oauth_requests()?,
                OAuthCommand::Approve { request } => registry.oauth_decide(&request, true)?,
                OAuthCommand::Deny { request } => registry.oauth_decide(&request, false)?,
            }))
        }
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
                    oauth_resource,
                    redirect_uri,
                    oauth_client_id,
                    oauth_jwks,
                    oauth_metadata,
                    tls_client_ca,
                    tls_client_name,
                }),
        } => {
            let imported = if let Some(id) = oauth_metadata {
                Some(
                    metadata::import(
                        &id,
                        oauth_resource.as_deref().expect("clap requires resource"),
                        &redirect_uri,
                    )
                    .await?,
                )
            } else {
                None
            };
            Ok(Some(registry::add_client(
                &home,
                &name,
                &conversation_key,
                &out,
                ttl_hours,
                oauth_resource
                    .map(|resource| -> Result<_> {
                        Ok(registry::oauth::Registration {
                            resource,
                            redirect_uris: redirect_uri,
                            assertion: imported.or(oauth_jwks
                                .map(|path| {
                                    assertion::Policy::load(
                                        &path,
                                        oauth_client_id
                                            .as_deref()
                                            .expect("clap requires client ID"),
                                    )
                                })
                                .transpose()?),
                        })
                    })
                    .transpose()?,
                tls_client_ca
                    .map(|path| {
                        mtls::Policy::load(
                            &path,
                            tls_client_name
                                .as_deref()
                                .expect("clap requires client name"),
                        )
                    })
                    .transpose()?,
            )?))
        }
        Command::Clients {
            command: Some(ClientCommand::Keys { command }),
        } => {
            let registry = Registry::open(&home)?;
            Ok(Some(match command {
                KeyCommand::Show { client } => registry.signing_keys(&client)?,
                KeyCommand::Set {
                    client,
                    jwks,
                    expect_revision,
                } => registry.set_signing_keys(&client, &jwks, expect_revision)?,
                KeyCommand::Refresh {
                    client,
                    expect_revision,
                } => {
                    let registration = registry.signing_registration(&client)?;
                    let policy = metadata::import(
                        &registration.assertion.as_ref().unwrap().client_id,
                        &registration.resource,
                        &registration.redirect_uris,
                    )
                    .await?;
                    registry.set_verified_signing_keys(&client, policy, expect_revision)?
                }
            }))
        }
        Command::Clients {
            command: Some(ClientCommand::Revoke { client }),
        } => Ok(Some(Registry::open(&home)?.revoke(&client)?)),
    }
}
