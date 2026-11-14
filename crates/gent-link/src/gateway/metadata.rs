//! Client metadata retrieval. Only owner-selected URLs can be fetched, and
//! every fetch pins validated DNS answers before TLS connection.
use super::{assertion::Policy, registry::oauth::Registration};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use url::{Host, Url};

const MAX_BYTES: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);
const CACHE_TTL: Duration = Duration::from_secs(60);

pub(crate) mod runtime;

#[cfg(test)]
pub(crate) mod tests;

#[derive(Deserialize)]
struct Document {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    jwks_uri: String,
    jwks: Option<serde_json::Value>,
    token_endpoint_auth_method: Option<String>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    token_endpoint_auth_signing_alg: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
}

fn endpoint(raw: &str) -> Result<Url> {
    ensure!(raw.len() <= 2048, "metadata URL is too long");
    let url = Url::parse(raw).context("invalid client metadata URL")?;
    ensure!(
        url.as_str() == raw
            && url.scheme() == "https"
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() != "/",
        "metadata URL must be canonical HTTPS on port 443 with a path and no credentials, query or fragment"
    );
    let Some(Host::Domain(host)) = url.host() else {
        anyhow::bail!("metadata URL must use a public DNS name");
    };
    ensure!(
        host.len() <= 253
            && host.contains('.')
            && host.split('.').all(|label| !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "invalid metadata DNS name"
    );
    Ok(url)
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !matches!(a, 0 | 10 | 127 | 224..=255)
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 169 && b == 254)
                && !(a == 172 && (16..=31).contains(&b))
                && !(a == 192
                    && (b == 168 || (b == 0 && matches!(c, 0 | 2)) || (b == 88 && c == 99)))
                && !(a == 198 && (matches!(b, 18 | 19) || (b == 51 && c == 100)))
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            (0x2000..0x4000).contains(&a)
                && !(a == 0x2001 && (b < 0x200 || b == 0xdb8))
                && a != 0x2002
                && a != 0x3fff
        }
    }
}

pub(super) fn destinations(addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>> {
    ensure!(
        !addresses.is_empty()
            && addresses.len() <= 32
            && addresses
                .iter()
                .all(|a| a.port() == 443 && public_ip(a.ip())),
        "metadata DNS must resolve only to public unicast addresses (at most 32)"
    );
    Ok(addresses
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

pub(super) fn client(url: &Url, addresses: &[SocketAddr]) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .resolve_to_addrs(
            url.host_str().expect("validated metadata hostname"),
            addresses,
        )
}

struct Fetched {
    bytes: Vec<u8>,
    ttl: Duration,
}

// Cap publisher freshness at one minute. Invalid or revalidation-required
// directives disable reuse; failed requests never extend an existing cache.
fn freshness(headers: &reqwest::header::HeaderMap) -> Duration {
    let mut ttl = CACHE_TTL.as_secs();
    let mut max_age_seen = false;
    for value in headers.get_all("cache-control") {
        let Ok(value) = value.to_str() else {
            return Duration::ZERO;
        };
        for directive in value.split(',') {
            let (name, argument) = directive
                .trim()
                .split_once('=')
                .map_or((directive.trim(), None), |(n, v)| {
                    (n.trim(), Some(v.trim()))
                });
            if ["no-store", "no-cache"]
                .iter()
                .any(|v| name.eq_ignore_ascii_case(v))
            {
                return Duration::ZERO;
            }
            if name.eq_ignore_ascii_case("max-age") {
                if max_age_seen {
                    return Duration::ZERO;
                }
                max_age_seen = true;
                let Some(age) = argument.and_then(|v| {
                    let value = if v.starts_with('"') {
                        v.strip_prefix('"')?.strip_suffix('"')?
                    } else {
                        v
                    };
                    decimal(value)
                }) else {
                    return Duration::ZERO;
                };
                ttl = age;
            }
        }
    }
    let mut apparent_age = Duration::ZERO;
    let mut dates = headers.get_all("date").iter();
    if let Some(date) = dates.next() {
        let Some(date) = date
            .to_str()
            .ok()
            .and_then(|v| httpdate::parse_http_date(v).ok())
        else {
            return Duration::ZERO;
        };
        if dates.next().is_some() {
            return Duration::ZERO;
        }
        apparent_age = std::time::SystemTime::now()
            .duration_since(date)
            .unwrap_or_default();
    }
    let mut ages = headers.get_all("age").iter();
    if let Some(age) = ages.next() {
        let Some(age) = age.to_str().ok().and_then(decimal) else {
            return Duration::ZERO;
        };
        if ages.next().is_some() {
            return Duration::ZERO;
        }
        apparent_age = apparent_age.max(Duration::from_secs(age));
    }
    // Without max-age, an Expires header may prohibit reuse; avoid interpreting
    // remote wall clocks and conservatively revalidate such responses.
    if !max_age_seen && headers.contains_key("expires") {
        return Duration::ZERO;
    }
    Duration::from_secs(ttl)
        .saturating_sub(apparent_age)
        .min(CACHE_TTL)
}

fn decimal(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

async fn fetch_response(client: &reqwest::Client, url: &Url) -> Result<Fetched> {
    let started = std::time::Instant::now();
    let mut response = client
        .get(url.clone())
        .header("accept", "application/json, application/jwk-set+json")
        .send()
        .await
        .context("client metadata fetch failed")?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "metadata endpoint must return HTTP 200 without redirects"
    );
    let types: Vec<_> = response.headers().get_all("content-type").iter().collect();
    ensure!(
        types.len() == 1
            && types[0].to_str().ok().is_some_and(|v| matches!(
                v.split(';').next().unwrap_or("").trim(),
                "application/json" | "application/jwk-set+json"
            )),
        "metadata must be served as JSON"
    );
    ensure!(
        !response.headers().contains_key("content-encoding"),
        "encoded metadata responses are unsupported"
    );
    let ttl = freshness(response.headers());
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= MAX_BYTES as u64),
        "metadata response is too large"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("metadata body read failed")?
    {
        ensure!(
            chunk.len() <= MAX_BYTES - bytes.len(),
            "metadata response is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(Fetched {
        bytes,
        ttl: ttl.saturating_sub(started.elapsed()),
    })
}

#[cfg(test)]
async fn response(client: &reqwest::Client, url: &Url) -> Result<Vec<u8>> {
    Ok(fetch_response(client, url).await?.bytes)
}

async fn fetch(url: &Url) -> Result<Fetched> {
    tokio::time::timeout(TIMEOUT, async {
        let addresses = tokio::net::lookup_host((url.host_str().unwrap(), 443))
            .await
            .context("client metadata DNS lookup failed")?
            .take(33)
            .collect();
        let addresses = destinations(addresses)?;
        fetch_response(&client(url, &addresses).build()?, url).await
    })
    .await
    .context("client metadata fetch timed out")?
}

fn entries(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= 16
        && values.iter().all(|v| {
            !v.is_empty() && v.len() <= 128 && v.bytes().all(|b| (0x21..=0x7e).contains(&b))
        })
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn document(bytes: &[u8], id: &Url, resource: &str, callbacks: &[String]) -> Result<Url> {
    ensure!(
        bytes.len() <= MAX_BYTES,
        "client metadata document is too large"
    );
    let doc: Document =
        serde_json::from_slice(bytes).context("invalid client metadata document")?;
    ensure!(
        doc.client_id == id.as_str(),
        "metadata client ID does not match its exact URL"
    );
    ensure!(
        !doc.client_name.trim().is_empty()
            && doc.client_name.len() <= 200
            && !doc.client_name.chars().any(char::is_control),
        "invalid published client name"
    );
    let supported = match &doc.token_endpoint_auth_methods_supported {
        Some(methods) => entries(methods) && methods.iter().any(|m| m == "private_key_jwt"),
        None => doc.token_endpoint_auth_method.as_deref() == Some("private_key_jwt"),
    };
    ensure!(
        supported
            && doc
                .token_endpoint_auth_signing_alg
                .as_deref()
                .is_none_or(|a| a == "RS256"),
        "client metadata must support RS256 private_key_jwt"
    );
    ensure!(
        doc.grant_types.as_ref().is_none_or(|g| entries(g)
            && ["authorization_code", "refresh_token"]
                .iter()
                .all(|v| g.iter().any(|s| s == v)))
            && doc
                .response_types
                .as_ref()
                .is_none_or(|r| entries(r) && r.iter().any(|v| v == "code")),
        "metadata does not permit the code and refresh flow"
    );
    Registration {
        resource: resource.into(),
        redirect_uris: doc.redirect_uris.clone(),
        assertion: None,
    }
    .validate()?;
    Registration {
        resource: resource.into(),
        redirect_uris: callbacks.to_vec(),
        assertion: None,
    }
    .validate()?;
    ensure!(
        callbacks.iter().all(|c| doc.redirect_uris.contains(c)),
        "requested callback is absent from published metadata"
    );
    ensure!(doc.jwks.is_none(), "inline JWKS cannot accompany jwks_uri");
    let keys = endpoint(&doc.jwks_uri)?;
    ensure!(
        keys.origin() == id.origin(),
        "client JWKS must use the metadata document's HTTPS origin"
    );
    Ok(keys)
}

pub(crate) async fn import(id: &str, resource: &str, callbacks: &[String]) -> Result<Policy> {
    Ok(import_fresh(id, resource, callbacks).await?.0)
}

async fn import_fresh(
    id: &str,
    resource: &str,
    callbacks: &[String],
) -> Result<(Policy, Duration)> {
    import_fresh_using(
        id,
        resource,
        callbacks,
        |url| async move { fetch(&url).await },
    )
    .await
}

async fn import_fresh_using<F, Fut>(
    id: &str,
    resource: &str,
    callbacks: &[String],
    fetcher: F,
) -> Result<(Policy, Duration)>
where
    F: Fn(Url) -> Fut,
    Fut: std::future::Future<Output = Result<Fetched>>,
{
    let started = std::time::Instant::now();
    let id = endpoint(id)?;
    let doc = fetcher(id.clone()).await?;
    let keys = document(&doc.bytes, &id, resource, callbacks)?;
    let keys = fetcher(keys).await?;
    let ttl = doc.ttl.min(keys.ttl).saturating_sub(started.elapsed());
    Ok((Policy::from_jwks(&keys.bytes, id.as_str())?, ttl))
}

#[cfg(test)]
async fn import_using<F, Fut>(
    id: &str,
    resource: &str,
    callbacks: &[String],
    fetcher: F,
) -> Result<Policy>
where
    F: Fn(Url) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let id = endpoint(id)?;
    let keys = document(&fetcher(id.clone()).await?, &id, resource, callbacks)?;
    Policy::from_jwks(&fetcher(keys).await?, id.as_str())
}
