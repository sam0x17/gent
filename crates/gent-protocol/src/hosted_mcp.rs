//! Bounded HTTP messages for an outbound hosted MCP connection. This transport
//! carries plaintext at the hosted endpoint; it is not the encrypted node relay.
use serde::{Deserialize, Serialize};

pub const VERSION: u8 = 1;
pub const MAX_BODY_BYTES: usize = crate::MAX_FRAME_BYTES;
pub const MAX_ENCODED_BYTES: usize = MAX_BODY_BYTES.div_ceil(3) * 4;
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_WIRE_BYTES: usize = MAX_ENCODED_BYTES + MAX_HEADER_BYTES + 16 * 1024;
pub const MAX_IN_FLIGHT: usize = 4;
pub const REQUEST_SECONDS: u64 = 30;
pub const PING: &str = "gent-mcp-ping-v1";
pub const PONG: &str = "gent-mcp-pong-v1";

// Never derive Debug: headers and bodies may contain OAuth credentials or chat
// content. Logs should report only generic failures and request counts.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frame {
    Ready { version: u8 },
    Request(HttpRequest),
    Response(HttpResponse),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequest {
    pub id: String,
    pub method: String,
    /// Native gateway route, with OAuth query parameters if applicable.
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body_base64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpResponse {
    pub id: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_base64: String,
}

pub fn valid_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

pub fn node_base(cluster: &str, node: &str) -> Option<String> {
    (valid_id(cluster) && valid_id(node)).then(|| format!("/clusters/{cluster}/nodes/{node}"))
}

/// Routes both canonical endpoint URLs and RFC 8414/9728 discovery suffixes.
/// No arbitrary paths or encoded path separators are forwarded to the node.
pub fn route(path: &str) -> Option<(&str, &str, String)> {
    fn scope(rest: &str) -> Option<(&str, &str, &str)> {
        if rest.ends_with('/') {
            return None;
        }
        let (cluster, rest) = rest.split_once("/nodes/")?;
        let (node, suffix) = rest.split_once('/').unwrap_or((rest, ""));
        (valid_id(cluster) && valid_id(node)).then_some((cluster, node, suffix))
    }
    if let Some(rest) = path.strip_prefix("/clusters/") {
        let (cluster, node, suffix) = scope(rest)?;
        let native = format!("/{suffix}");
        return (native == "/connect" || valid_path(&native)).then_some((cluster, node, native));
    }
    for (public, native, suffix) in [
        (
            "/.well-known/oauth-authorization-server/clusters/",
            "/.well-known/oauth-authorization-server",
            "",
        ),
        (
            "/.well-known/oauth-protected-resource/clusters/",
            "/.well-known/oauth-protected-resource/mcp",
            "mcp",
        ),
    ] {
        if let Some(rest) = path.strip_prefix(public) {
            let (cluster, node, tail) = scope(rest)?;
            return (tail == suffix).then_some((cluster, node, native.into()));
        }
    }
    None
}

pub fn valid_path(path: &str) -> bool {
    if path.len() > 8192 || path.contains('#') || path.chars().any(char::is_control) {
        return false;
    }
    let (path, query) = path
        .split_once('?')
        .map_or((path, false), |(p, _)| (p, true));
    if query && !matches!(path, "/oauth/authorize" | "/oauth/continue") {
        return false;
    }
    matches!(
        path,
        "/mcp"
            | "/.well-known/oauth-protected-resource"
            | "/.well-known/oauth-protected-resource/mcp"
            | "/.well-known/oauth-authorization-server"
            | "/oauth/authorize"
            | "/oauth/continue"
            | "/oauth/token"
    )
}

pub fn request_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "content-type"
            | "accept"
            | "origin"
            | "mcp-protocol-version"
            | "mcp-session-id"
            | "last-event-id"
            | "mcp-method"
            | "mcp-name"
    ) || name.strip_prefix("mcp-param-").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
    })
}

pub fn response_header(name: &str) -> bool {
    matches!(
        name,
        "content-type"
            | "location"
            | "www-authenticate"
            | "retry-after"
            | "cache-control"
            | "referrer-policy"
            | "x-content-type-options"
            | "content-security-policy"
            | "mcp-protocol-version"
            | "mcp-session-id"
            | "allow"
    )
}

fn valid_headers(headers: &[(String, String)], allowed: fn(&str) -> bool) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    headers.len() <= 24
        && headers
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
            <= MAX_HEADER_BYTES
        && headers.iter().all(|(k, v)| {
            allowed(k)
                && seen.insert(k)
                && v.is_ascii()
                && !v.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        })
}

impl HttpRequest {
    pub fn valid(&self) -> bool {
        valid_id(&self.id)
            && matches!(
                self.method.as_str(),
                "GET" | "POST" | "DELETE" | "HEAD" | "OPTIONS"
            )
            && valid_path(&self.path)
            && valid_headers(&self.headers, request_header)
            && self.body_base64.len() <= MAX_ENCODED_BYTES
    }
}

impl HttpResponse {
    pub fn valid(&self) -> bool {
        valid_id(&self.id)
            && (200..=599).contains(&self.status)
            && valid_headers(&self.headers, response_header)
            && self.body_base64.len() <= MAX_ENCODED_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NODE: &str = "f84ce64e-2200-40b0-bc1d-cd64295d9c85";
    const CLUSTER: &str = "629ec806-dc35-4c93-a174-38133d5b99f7";

    #[test]
    fn discovery_and_mcp_routes_keep_the_exact_node() {
        for (public, expected) in [
            (format!("/clusters/{CLUSTER}/nodes/{NODE}/mcp"), "/mcp"),
            (
                format!("/clusters/{CLUSTER}/nodes/{NODE}/oauth/token"),
                "/oauth/token",
            ),
            (
                format!("/clusters/{CLUSTER}/nodes/{NODE}/connect"),
                "/connect",
            ),
            (
                format!("/.well-known/oauth-authorization-server/clusters/{CLUSTER}/nodes/{NODE}"),
                "/.well-known/oauth-authorization-server",
            ),
            (
                format!(
                    "/.well-known/oauth-protected-resource/clusters/{CLUSTER}/nodes/{NODE}/mcp"
                ),
                "/.well-known/oauth-protected-resource/mcp",
            ),
        ] {
            assert_eq!(
                route(&public),
                Some((CLUSTER, NODE, expected.into())),
                "{public}"
            );
        }
        for path in [
            format!("/clusters/{CLUSTER}/nodes/{NODE}/../../oauth/token"),
            format!("/clusters/{CLUSTER}/nodes/{NODE}/%6dcp"),
            format!("/clusters/{CLUSTER}/nodes/{NODE}/mcp/"),
            format!(
                "/.well-known/oauth-authorization-server/clusters/{CLUSTER}/nodes/{NODE}/other"
            ),
            "/nodes/00000000-0000-0000-0000-000000000000/mcp".into(),
            "/nodes/not-a-node/mcp".into(),
        ] {
            assert!(route(&path).is_none(), "{path}");
        }
    }

    #[test]
    fn wire_boundary_rejects_proxy_authority_header_injection_and_unbounded_bodies() {
        let mut request = HttpRequest {
            id: NODE.into(),
            method: "POST".into(),
            path: "/mcp".into(),
            headers: vec![("authorization".into(), "Bearer opaque".into())],
            body_base64: String::new(),
        };
        assert!(request.valid());
        request
            .headers
            .push(("authorization".into(), "Bearer other".into()));
        assert!(!request.valid());
        for (name, value) in [
            ("host", "evil.example"),
            ("forwarded", "host=evil.example"),
            ("authorization", "Bearer a\r\nx-injected:1"),
        ] {
            request.headers = vec![(name.into(), value.into())];
            assert!(!request.valid());
        }
        request.headers.clear();
        request.path = "/mcp?access_token=secret".into();
        assert!(!request.valid());
        request.path = "/oauth/authorize?client_id=host&state=opaque%2Fvalue".into();
        assert!(request.valid());
        request.body_base64 = "a".repeat(MAX_ENCODED_BYTES + 1);
        assert!(!request.valid());
    }
}
