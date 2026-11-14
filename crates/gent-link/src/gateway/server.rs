//! Direct TLS termination on the owner's node. No forwarded-header trust and
//! no request logging: even metadata and tool arguments can be private.
use super::{Registry, Run};
use crate::{managed_file, mcp::GentMcp};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::any_service,
};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    task::JoinSet,
};
use tokio_rustls::{TlsAcceptor, rustls};
use tokio_util::sync::CancellationToken;

const MAX_CONNECTIONS: usize = 64;
const REQUEST_TIME: Duration = Duration::from_secs(30);
const CONNECTION_TIME: Duration = Duration::from_secs(60);
mod oauth;

#[cfg(test)]
mod tests;

#[derive(Clone)]
struct Boundary {
    registry: Registry,
    host: String,
    origin: String,
}

fn one<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(first)
    }
}

impl Boundary {
    fn validate(&self, request: &Request<Body>) -> Result<()> {
        ensure!(
            (request.uri().query().is_none()
                || matches!(request.uri().path(), "/oauth/authorize" | "/oauth/continue"))
                && request.uri().scheme().is_none()
                && request.uri().authority().is_none(),
            "invalid request target"
        );
        let headers = request.headers();
        ensure!(
            one(headers, "host") == Some(self.host.as_str()),
            "invalid host"
        );
        ensure!(
            !headers.contains_key("origin") || one(headers, "origin") == Some(self.origin.as_str()),
            "invalid origin"
        );
        ensure!(
            !headers.keys().any(|h| h == "forwarded"
                || h.as_str().starts_with("x-forwarded-")
                || h == "x-real-ip"),
            "forwarded requests are unsupported"
        );
        Ok(())
    }
}

async fn guard(
    State(boundary): State<Boundary>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let response = async {
        if boundary.validate(&request).is_err() {
            return StatusCode::FORBIDDEN.into_response();
        }
        if request.uri().path() != "/mcp" {
            return oauth::handle(&boundary, request).await;
        }
        let token = one(request.headers(), "authorization")
            .and_then(|s| s.strip_prefix("Bearer "))
            .filter(|s| s.len() <= 128)
            .map(str::to_owned);
        // The SDK sees the authorization decision, never the raw bearer.
        request.headers_mut().remove(header::AUTHORIZATION);
        let Some(token) = token else {
            return oauth::challenge(&boundary.origin);
        };
        let permit = boundary
            .registry
            .authenticate_remote(token, format!("{}/mcp", boundary.origin))
            .await;
        let permit = match permit {
            Ok(permit) => permit,
            Err(error) if error.is::<super::registry::Busy>() => return oauth::busy(),
            Err(_) => return oauth::challenge(&boundary.origin),
        };
        request.extensions_mut().insert(permit);
        next.run(request).await
    };
    let mut response = tokio::time::timeout(REQUEST_TIME, response)
        .await
        .unwrap_or_else(|_| StatusCode::REQUEST_TIMEOUT.into_response());
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("referrer-policy", "no-referrer".parse().unwrap());
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    response.headers_mut().insert(
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            .parse()
            .unwrap(),
    );
    response
}

fn origin(options: &Run, bound: SocketAddr) -> Result<(String, String)> {
    ensure!(
        options.tls_cert.is_some() == options.tls_key.is_some()
            && options.tls_cert.is_some() == options.origin.is_some(),
        "direct TLS needs --tls-cert, --tls-key and --origin"
    );
    if let Some(origin) = &options.origin {
        let url = url::Url::parse(origin).context("invalid gateway HTTPS origin")?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "gateway origin must be an HTTPS origin without credentials, path, query or fragment"
        );
        let canonical = url.origin().ascii_serialization();
        ensure!(
            *origin == canonical,
            "use the canonical HTTPS origin without a trailing slash"
        );
        Ok((
            url[url::Position::BeforeHost..url::Position::AfterPort].to_string(),
            canonical,
        ))
    } else {
        ensure!(
            bound.ip().is_loopback(),
            "non-loopback listeners require direct TLS"
        );
        Ok((bound.to_string(), format!("http://{bound}")))
    }
}

fn tls(options: &Run) -> Result<Option<TlsAcceptor>> {
    let (Some(cert), Some(key)) = (&options.tls_cert, &options.tls_key) else {
        return Ok(None);
    };
    let cert = managed_file::Snapshot::read(cert)?;
    let key = managed_file::Snapshot::read(key)?;
    key.private()?;
    let cert_text = cert
        .text
        .as_deref()
        .context("TLS certificate file is missing")?;
    let key_text = key.text.as_deref().context("TLS key file is missing")?;
    ensure!(
        cert_text.len() <= 64 * 1024 && key_text.len() <= 64 * 1024,
        "TLS PEM file is too large"
    );
    let certs =
        rustls_pemfile::certs(&mut cert_text.as_bytes()).collect::<std::io::Result<Vec<_>>>()?;
    let key_der = rustls_pemfile::private_key(&mut key_text.as_bytes())?
        .context("missing TLS private key")?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certs, key_der)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    cert.verify()?;
    key.verify()?;
    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

fn router(
    home: PathBuf,
    registry: Registry,
    host: String,
    origin: String,
    stop: CancellationToken,
) -> Router {
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_max_request_body_bytes(gent_protocol::MAX_FRAME_BYTES)
        .with_allowed_hosts([host.clone()])
        .with_allowed_origins([origin.clone()])
        .enforce_origin_validation()
        .with_cancellation_token(stop);
    let binding = registry.clone();
    let service = StreamableHttpService::new(
        move || Ok(GentMcp::remote(home.clone(), binding.clone())),
        Arc::new(NeverSessionManager::default()),
        config,
    );
    Router::new()
        .route_service("/mcp", any_service(service))
        .layer(middleware::from_fn_with_state(
            Boundary {
                registry,
                host,
                origin,
            },
            guard,
        ))
}

async fn connection<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: T, app: Router) {
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_headers(64)
        .max_buf_size(16 * 1024);
    // Connection failures carry no useful user action and may include private
    // request data; deliberately do not print errors from peers.
    let _ = builder
        .serve_connection(TokioIo::new(io), TowerToHyperService::new(app))
        .await;
}

async fn serve(
    listener: TcpListener,
    app: Router,
    tls: Option<TlsAcceptor>,
    stop: CancellationToken,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            Some(_)=tasks.join_next(), if !tasks.is_empty()=>{},
            accepted=listener.accept()=> {
                let (socket,_)=accepted?;
                if tasks.len()>=MAX_CONNECTIONS {continue;}
                let app=app.clone();
                let tls=tls.clone();
                tasks.spawn(async move {
                    let _=tokio::time::timeout(CONNECTION_TIME,async move {
                        if let Some(tls)=tls {
                            if let Ok(Ok(stream))=tokio::time::timeout(Duration::from_secs(10),tls.accept(socket)).await {
                                connection(stream,app).await;
                            }
                        } else {connection(socket,app).await;}
                    }).await;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

pub(super) async fn run(home: PathBuf, options: Run) -> Result<()> {
    let registry = Registry::open(&home)?;
    let _lock = managed_file::lock(&home.join("gateway/runtime.lock"))?;
    // Validate exposure before binding any non-loopback socket.
    origin(&options, options.listen)?;
    let tls = tls(&options)?;
    let listener = TcpListener::bind(options.listen).await?;
    let address = listener.local_addr()?;
    let (host, origin) = origin(&options, address)?;
    let stop = CancellationToken::new();
    let app = router(home, registry, host, origin.clone(), stop.clone());
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    eprintln!("Gent gateway: {origin}/mcp (user-controlled endpoint, listening on {address})");
    let result = tokio::select! {
        result=serve(listener,app,tls,stop.clone())=>result,
        result=tokio::signal::ctrl_c()=>result.map_err(Into::into),
        _=terminate.recv()=>Ok(()),
    };
    stop.cancel();
    result
}
