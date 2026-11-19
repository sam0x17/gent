//! User-controlled remote MCP. The HTTP credential authenticates a trusted host
//! namespace; every agent call also needs that host's conversation metadata.
pub(crate) mod access;
mod assertion;
pub(crate) mod control;
pub(crate) mod downloads;
pub(crate) mod files;
mod hosted;
mod metadata;
mod mtls;
pub(crate) mod registry;
mod server;
mod service_options;
use crate::{managed_file, node_home};
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
    /// Manage this node's persistent gateway listener independently of its daemon.
    Service {
        #[command(subcommand)]
        command: Option<crate::service::GatewayCommand>,
    },
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
    Add(Box<ClientAdd>),
    /// Reject future requests from this host, retaining chat identities and messages.
    Revoke {
        client: String,
    },
}

#[derive(Args)]
pub struct ClientAdd {
    name: String,
    /// Host-owned per-call MCP metadata field, e.g. gent/conversation or Codex threadId.
    /// Provider support and metadata provenance must be verified separately.
    #[arg(
        long,
        required_unless_present = "conversation_handles",
        conflicts_with = "conversation_handles"
    )]
    conversation_key: Option<String>,
    /// Issue chat-retained conversation handles for a host without stable chat metadata.
    #[arg(long, conflicts_with = "subject_key")]
    conversation_handles: bool,
    /// Stable host-owned user metadata field. Requires OAuth and pins each grant to its first reported user.
    #[arg(long, requires = "oauth_resource")]
    subject_key: Option<String>,
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
}

#[derive(Subcommand)]
pub enum KeyCommand {
    Show {
        client: String,
    },
    /// Replace the complete key set while preserving the client and its chats.
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

#[derive(Args, Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,
    /// Publish through Gent's web bridge using an outbound connection. This route is not E2EE.
    #[arg(long, num_args=0..=1, default_missing_value="https://mcp.gent.link", conflicts_with_all=["origin","tls_cert","tls_key"])]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hosted: Option<String>,
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
    /// Allow file imports for CLIENT_UUID=https://exact-download-host. Repeat for additional origins; no wildcards.
    #[arg(long)]
    file_origin: Vec<String>,
    /// Allow this host UUID to issue five-minute bearer download links. Anyone with a link can fetch its file without host credentials or mTLS.
    #[arg(long)]
    file_downloads: Vec<String>,
}

pub(crate) async fn run_web(
    home: PathBuf,
    stop: tokio_util::sync::CancellationToken,
    session: Option<std::sync::Arc<crate::web::failover::Session>>,
) -> Result<()> {
    let options = Run {
        listen: "127.0.0.1:8787".parse().unwrap(),
        hosted: Some("https://mcp.gent.link".into()),
        origin: None,
        tls_cert: None,
        tls_key: None,
        client_metadata: Vec::new(),
        file_origin: Vec::new(),
        file_downloads: Vec::new(),
    };
    hosted::run_portable(home, options, stop, session).await
}

pub async fn execute(home: &Path, command: Command) -> Result<Option<Value>> {
    let home = managed_file::normalize(home)?;
    match command {
        Command::Service { command } => {
            let command = command.unwrap_or(crate::service::GatewayCommand::Status);
            Ok(Some(crate::service::gateway(&home, command).await?))
        }
        Command::Oauth { command } => {
            let registry = Registry::open(&home)?;
            Ok(Some(match command.unwrap_or(OAuthCommand::Requests) {
                OAuthCommand::Requests => registry.oauth_requests()?,
                OAuthCommand::Approve { request } => registry.oauth_decide(&request, true)?,
                OAuthCommand::Deny { request } => registry.oauth_decide(&request, false)?,
            }))
        }
        Command::Run(options) => {
            server::run(home, options).await?;
            Ok(None)
        }
        Command::Status
        | Command::Clients {
            command: None | Some(ClientCommand::List),
        } => {
            let cfg = node_home::inspect(&home)?;
            if cfg.gateway_registry()?.is_none() {
                return Ok(Some(
                    json!({"configured":false,"clients":[],"running":"not_probed"}),
                ));
            }
            Ok(Some(Registry::open(&home)?.listing()?))
        }
        Command::Clients {
            command: Some(ClientCommand::Add(options)),
        } => {
            let ClientAdd {
                name,
                conversation_key,
                conversation_handles,
                subject_key,
                out,
                ttl_hours,
                oauth_resource,
                redirect_uri,
                oauth_client_id,
                oauth_jwks,
                oauth_metadata,
                tls_client_ca,
                tls_client_name,
            } = *options;
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
                registry::BindingKeys {
                    conversation: if conversation_handles {
                        registry::conversations::KEY.into()
                    } else {
                        conversation_key.expect("clap requires a conversation policy")
                    },
                    subject: subject_key,
                },
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

/// Inspect existing pins/state without creating a registry lock or listener.
pub(crate) fn diagnose(home: &Path) -> Result<Value> {
    registry::diagnose(home)
}
