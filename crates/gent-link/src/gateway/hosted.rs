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
    route: gent_daemon::backend::TransportRoute,
    connect_path: String,
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
    let route = crate::web::bridge_route(home, &cfg, url)?;
    let public = route.identity();
    let origin = public.origin().ascii_serialization();
    let base = format!("{origin}{prefix}");
    Ok(Endpoint {
        origin,
        host: public[url::Position::BeforeHost..url::Position::AfterPort].into(),
        base,
        route,
        connect_path: format!("{prefix}/connect"),
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
    carrier_lock: Option<Arc<std::fs::File>>,
) -> Result<Router> {
    let mut registry = Registry::open(home)?.with_file_origins(&options.file_origin)?;
    ensure!(
        registry.tls_policies()?.is_empty(),
        "hosted MCP cannot authenticate direct client TLS certificates; use a separate gateway registration"
    );
    registry.access = AccessRoute::Hosted;
    registry.carrier_lock = carrier_lock;
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
    endpoint.route.destination()?;
    credential(home)?;
    let _app = app(home, options, &endpoint, CancellationToken::new(), None).await?;
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
    run_portable(home, options, shutdown, None).await
}

pub(super) async fn run_portable(
    home: PathBuf,
    options: Run,
    shutdown: CancellationToken,
    session: Option<Arc<crate::web::failover::Session>>,
) -> Result<()> {
    let endpoint = endpoint(&home, &options)?;
    if let Some(session) = &session {
        session.credential()?;
    } else {
        credential(&home)?;
    }
    let _lock = managed_file::lock(&home.join("gateway/runtime.lock"))?;
    let stop = CancellationToken::new();
    let _guard = stop.clone().drop_guard();
    let app = app(
        &home,
        &options,
        &endpoint,
        stop.clone(),
        session.as_ref().map(|s| s.files.clone()),
    )
    .await?;
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
            let token = session
                .as_ref()
                .map_or_else(|| credential(&home), |s| s.credential());
            if token.is_err() && session.as_ref().is_some_and(|s| s.passive) {
                anyhow::bail!("passive web carrier credential unavailable");
            }
            if let Ok(token) = token {
                let began = tokio::time::Instant::now();
                let result = connection::run(
                    &endpoint,
                    token,
                    app.clone(),
                    connected.clone(),
                    shutdown.clone(),
                    session.clone(),
                )
                .await;
                if let Some(session) = session.as_ref().filter(|s| s.passive) {
                    // Re-enter signed admission after a lost passive socket.
                    connected.store(false, Ordering::Release);
                    if !shutdown.is_cancelled() {
                        session.disconnected();
                    }
                    return result;
                }
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
            "connected":connected.load(Ordering::Acquire),
            "carrier_epoch":session.as_ref().map(|s|s.epoch),
            "checkpoint_management":session.as_ref().and_then(|s|s.management())}))=>result,
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

#[cfg(test)]
mod tests {
    use super::*;
    use gent_daemon::{
        backend::{ACCOUNT, MCP, RELAY},
        store::Store,
    };
    use gent_protocol::{ConfigurationEdit, OwnerOp, ReleaseChannel, Request, Response};

    #[test]
    fn portable_web_uses_carrier_channel_and_retains_its_public_issuer() -> Result<()> {
        let root = tempfile::tempdir()?;
        let parent = root.path().join("parent");
        config::initialize(&parent, "gateway")?;
        let mut store = Store::open(&parent)?;
        let request = Request::Owner {
            credential: config::read_private(&parent.join("owner.key"))?,
            action: OwnerOp::Configure {
                request_id: uuid::Uuid::new_v4().to_string(),
                edit: ConfigurationEdit::SetReleaseChannel {
                    channel: ReleaseChannel::Beta,
                },
            },
        };
        assert!(matches!(store.handle(request), Response::Ok(_)));
        drop(store);

        let mut host = config::load(&parent)?;
        host.cluster.local_only = false;
        host.service = Some(config::ServiceConfig {
            origin: ACCOUNT.stable.into(),
            account_id: uuid::Uuid::new_v4().to_string(),
        });
        host.relay = Some(config::RelayConfig {
            endpoint: RELAY.stable.into(),
            credential_file: parent.join("relay.key"),
        });
        config::save(&parent, &host)?;
        let home = root.path().join("child");
        config::private_dir(&home)?;
        let mut child = host.clone();
        child.service = None;
        child.node.id = uuid::Uuid::new_v4().to_string();
        child.set_hosted_parent(config::HostedParent {
            home: parent.clone(),
            node_id: host.node.id.clone(),
        })?;
        config::save(&home, &child)?;

        let mut options = Run {
            listen: "127.0.0.1:8787".parse()?,
            hosted: Some(MCP.beta.into()),
            origin: None,
            tls_cert: None,
            tls_key: None,
            client_metadata: vec![],
            file_origin: vec![],
            file_downloads: vec![],
        };
        let bridge = endpoint(&home, &options)?;
        let prefix = protocol::node_base(&host.cluster.id, &child.node.id).unwrap();
        assert_eq!(bridge.origin, MCP.stable);
        assert_eq!(bridge.host, "mcp.gent.link");
        assert_eq!(bridge.base, format!("{}{prefix}", MCP.stable));
        assert_eq!(
            bridge.route.destination()?.origin().ascii_serialization(),
            MCP.beta
        );
        assert_eq!(bridge.connect_path, format!("{prefix}/connect"));
        options.hosted = Some("https://bridge.example".into());
        let custom = endpoint(&home, &options)?;
        assert_eq!(custom.host, "bridge.example");
        assert_eq!(
            custom.route.destination()?.host_str(),
            Some("bridge.example")
        );
        Ok(())
    }
}
