//! Outbound publication of the native gateway through Gent's disclosed web
//! bridge. The bridge can read HTTP content; daemon encryption is unchanged.
mod connection;
use super::{Registry, Run, access::AccessRoute};
use crate::{managed_file, node_home};
use anyhow::{Context, Result, ensure};
use axum::Router;
use gent_daemon::config;
use gent_protocol::hosted_mcp as protocol;
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub(super) struct Endpoint {
    pub origin: String,
    pub host: String,
    pub base: String,
    pub socket: String,
}

fn endpoint(home: &Path, options: &Run) -> Result<Endpoint> {
    ensure!(
        options.tls_cert.is_none() && options.tls_key.is_none() && options.origin.is_none(),
        "hosted publication cannot use direct TLS options"
    );
    ensure!(
        options.file_downloads.is_empty(),
        "hosted download URLs are not supported yet; use the remote file read/view tools"
    );
    let raw = options
        .hosted
        .as_deref()
        .context("hosted endpoint is missing")?;
    let url = url::Url::parse(raw).context("invalid hosted origin")?;
    ensure!(
        url.origin().ascii_serialization() == raw
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && (url.scheme() == "https"
                || (url.scheme() == "http"
                    && matches!(url.host_str(), Some("127.0.0.1" | "[::1]")))),
        "hosted origin must be canonical HTTPS or loopback HTTP without a path"
    );
    let cfg = node_home::inspect(home)?;
    let prefix =
        protocol::node_base(&cfg.cluster.id, &cfg.node.id).context("invalid node identity")?;
    let base = format!("{raw}{prefix}");
    let mut socket = url::Url::parse(&format!("{base}/connect"))?;
    socket
        .set_scheme(if url.scheme() == "https" { "wss" } else { "ws" })
        .map_err(|_| anyhow::anyhow!("invalid hosted scheme"))?;
    Ok(Endpoint {
        origin: raw.into(),
        host: url[url::Position::BeforeHost..url::Position::AfterPort].into(),
        base,
        socket: socket.into(),
    })
}

fn credential(home: &Path) -> Result<String> {
    let cfg = config::load(home)?;
    let relay = cfg
        .relay
        .context("configure this node's encrypted relay before publishing MCP")?;
    let token = config::read_relay_credential(&home.join(relay.credential_file))?;
    ensure!(
        gent_protocol::service::transport_created_at(&token).is_some(),
        "hosted MCP requires this node's service credential"
    );
    Ok(token)
}

async fn app(
    home: &Path,
    options: &Run,
    endpoint: &Endpoint,
    stop: CancellationToken,
) -> Result<Router> {
    let mut registry = Registry::open(home)?.with_file_origins(&options.file_origin)?;
    ensure!(
        registry.tls_policies()?.is_empty(),
        "hosted MCP cannot authenticate direct client TLS certificates; use a separate gateway registration"
    );
    registry.access = AccessRoute::Hosted;
    let metadata = super::metadata::runtime::Runtime::new(
        registry.clone(),
        format!("{}/mcp", endpoint.base),
        &options.client_metadata,
    )
    .await?;
    Ok(super::server::router(
        home.into(),
        registry,
        endpoint.host.clone(),
        endpoint.base.clone(),
        stop,
        metadata,
    ))
}

pub(super) async fn validate(home: &Path, options: &Run) -> Result<()> {
    let endpoint = endpoint(home, options)?;
    credential(home)?;
    let _app = app(home, options, &endpoint, CancellationToken::new()).await?;
    Ok(())
}

pub(super) async fn run(home: PathBuf, options: Run) -> Result<()> {
    run_until(home, options, CancellationToken::new()).await
}

pub(super) async fn run_until(
    home: PathBuf,
    options: Run,
    shutdown: CancellationToken,
) -> Result<()> {
    let endpoint = endpoint(&home, &options)?;
    credential(&home)?;
    let _lock = managed_file::lock(&home.join("gateway/runtime.lock"))?;
    let stop = CancellationToken::new();
    let app = app(&home, &options, &endpoint, stop.clone()).await?;
    let control = super::control::Server::bind(&home)?;
    let connected = Arc::new(AtomicBool::new(false));
    eprintln!(
        "Gent hosted MCP: {}/mcp\n{}",
        endpoint.base,
        AccessRoute::Hosted.disclosure()
    );
    let publish = async {
        let mut delay = 1;
        loop {
            if shutdown.is_cancelled() {
                return Ok::<_, anyhow::Error>(());
            }
            // Reload after every disconnect: account renewal can replace the
            // node's transport credential while this process remains alive.
            if let Ok(token) = credential(&home) {
                let began = tokio::time::Instant::now();
                let _ = connection::run(
                    &endpoint,
                    token,
                    app.clone(),
                    connected.clone(),
                    shutdown.clone(),
                )
                .await;
                if began.elapsed() > Duration::from_secs(60) {
                    delay = 1;
                }
            }
            connected.store(false, Ordering::Release);
            if shutdown.is_cancelled() {
                return Ok(());
            }
            eprintln!(
                "Gent hosted MCP disconnected; reconnecting in {delay}s. Accepted tool calls are not replayed."
            );
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(delay)) => {},
                _ = shutdown.cancelled() => return Ok(()),
            }
            delay = (delay * 2).min(30);
        }
    };
    tokio::pin!(publish);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let result = tokio::select! {
        result=&mut publish=>result,
        result=control.serve_status(||json!({"version":1,"process_id":std::process::id(),"listen":null,
            "origin":endpoint.origin,"endpoint":format!("{}/mcp",endpoint.base),"transport":"hosted_bridge",
            "connected":connected.load(Ordering::Acquire)}))=>result,
        result=tokio::signal::ctrl_c()=>{
            shutdown.cancel();
            publish.await?;
            result.map_err(Into::into)
        },
        _=terminate.recv()=>{
            shutdown.cancel();
            publish.await
        },
    };
    stop.cancel();
    result
}
