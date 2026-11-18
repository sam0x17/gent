use super::*;
use crate::gateway::registry::oauth::{SCOPE, parameters};
use axum::{Json, response::Html};
use serde_json::json;

pub(super) fn challenge(origin: &str) -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(header::WWW_AUTHENTICATE,format!(
        "Bearer resource_metadata=\"{origin}/.well-known/oauth-protected-resource/mcp\", scope=\"{SCOPE}\""
    ).parse().expect("validated gateway origin"));
    response
}
fn error(code: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error":code}))).into_response()
}
pub(super) fn busy() -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error":"temporarily_unavailable"})),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, "1".parse().unwrap());
    response
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn page(body: &str) -> Response {
    Html(format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Connect Gent</title><body><h1>Connect Gent</h1>{body}</body></html>")).into_response()
}
pub(super) async fn handle(boundary: &Boundary, request: Request<Body>) -> Response {
    let origin = &boundary.origin;
    let resource = format!("{origin}/mcp");
    let path = request.uri().path();
    let method = request.method();
    if matches!(
        path,
        "/.well-known/oauth-protected-resource" | "/.well-known/oauth-protected-resource/mcp"
    ) && method == "GET"
    {
        return Json(json!({"resource":resource,"authorization_servers":[origin],"scopes_supported":[SCOPE],"bearer_methods_supported":["header"]})).into_response();
    }
    if path == "/.well-known/oauth-authorization-server" && method == "GET" {
        let mut metadata = json!({"issuer":origin,"authorization_endpoint":format!("{origin}/oauth/authorize"),
            "token_endpoint":format!("{origin}/oauth/token"),"response_types_supported":["code"],
            "grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],
            "token_endpoint_auth_methods_supported":["client_secret_post","private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported":["RS256"],"scopes_supported":[SCOPE],
            "authorization_response_iss_parameter_supported":true});
        if boundary.metadata.enabled() {
            metadata["client_id_metadata_document_supported"] = json!(true);
        }
        return Json(metadata).into_response();
    }
    if path == "/oauth/authorize" && method == "GET" {
        let Ok(fields) = parameters(request.uri().query().unwrap_or_default()) else {
            return error("invalid_request");
        };
        if fields.get("resource") != Some(&resource) {
            return error("invalid_request");
        }
        if let Err(failure) = boundary
            .metadata
            .prepare(
                fields.get("client_id").map_or("", String::as_str),
                fields.get("redirect_uri").map(String::as_str),
            )
            .await
        {
            return if failure.is::<crate::gateway::registry::Busy>() {
                busy()
            } else {
                error("invalid_request")
            };
        }
        return match boundary.registry.oauth_begin(fields, resource).await {
            Ok(value) => {
                let id = value["request"].as_str().unwrap();
                let disclosure = escape(boundary.registry.access.disclosure());
                page(&format!(
                    "<p>Allow <strong>{}</strong> to connect to your Gent agents?</p><p>Client: <code>{}</code></p><p>Callback: <code>{}</code></p><p>This grants a host namespace. Conversations use this connector's configured identity policy; existing messaging permissions still apply.</p><p>On your Gent node, inspect <code>gent gateway oauth requests</code>. Check this request ID and callback, then approve only if you started this connection:</p><pre>gent gateway oauth approve {id}</pre><p>Request: <code>{id}</code></p><p>{disclosure}</p><p><a href=\"{origin}/oauth/continue?request={id}\">Continue after approval</a></p>",
                    escape(value["name"].as_str().unwrap()),
                    escape(value["oauth_client_id"].as_str().unwrap()),
                    escape(value["redirect_uri"].as_str().unwrap())
                ))
            }
            Err(failure) if failure.is::<crate::gateway::registry::Busy>() => busy(),
            Err(_) => error("invalid_request"),
        };
    }
    if path == "/oauth/continue" && method == "GET" {
        let Ok(fields) = parameters(request.uri().query().unwrap_or_default()) else {
            return error("invalid_request");
        };
        let Some(id) = fields.get("request") else {
            return error("invalid_request");
        };
        return match boundary.registry.oauth_continue(id.clone(), resource).await {
            Ok(Some(redirect)) => {
                let mut response = StatusCode::SEE_OTHER.into_response();
                response.headers_mut().insert(
                    header::LOCATION,
                    redirect.parse().expect("validated redirect"),
                );
                response
            }
            Ok(None) => page(
                "<p>This connection is still waiting for approval on your Gent node. Return to the previous page to check the request.</p>",
            ),
            Err(failure) if failure.is::<crate::gateway::registry::Busy>() => busy(),
            Err(_) => error("invalid_request"),
        };
    }
    if path == "/oauth/token" && method == "POST" {
        if one(request.headers(), "content-type")
            .is_none_or(|t| t.split(';').next() != Some("application/x-www-form-urlencoded"))
            || request.headers().contains_key(header::AUTHORIZATION)
        {
            return error("invalid_request");
        }
        let peer = request
            .extensions()
            .get::<Peer>()
            .cloned()
            .unwrap_or_default();
        let Ok(bytes) = axum::body::to_bytes(request.into_body(), 8192).await else {
            return error("invalid_request");
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return error("invalid_request");
        };
        let Ok(fields) = parameters(text) else {
            return error("invalid_request");
        };
        if fields.get("resource") != Some(&resource) {
            return error("invalid_target");
        }
        if let Err(failure) = boundary
            .metadata
            .prepare(fields.get("client_id").map_or("", String::as_str), None)
            .await
        {
            return if failure.is::<crate::gateway::registry::Busy>() {
                busy()
            } else {
                error("invalid_client")
            };
        }
        return match boundary
            .registry
            .oauth_exchange(fields, resource, peer)
            .await
        {
            Ok(value) => Json(value).into_response(),
            Err(failure) if failure.is::<crate::gateway::registry::Busy>() => busy(),
            Err(failure) => {
                let code = failure
                    .downcast_ref::<crate::gateway::registry::oauth::Failure>()
                    .map_or("invalid_grant", |f| f.0);
                if code == "temporarily_unavailable" {
                    busy()
                } else {
                    error(code)
                }
            }
        };
    }
    StatusCode::NOT_FOUND.into_response()
}
