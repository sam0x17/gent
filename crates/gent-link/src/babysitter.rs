//! Classify provider-owned failures. Never feed chat or tool output to this matcher.
use gent_protocol::notifications::Failure;
use sha2::{Digest, Sha256};

pub(crate) fn fingerprint(parts: &[&str]) -> String {
    let mut hash = Sha256::new();
    for p in parts {
        hash.update((p.len() as u64).to_be_bytes());
        hash.update(p.as_bytes());
    }
    format!("{:x}", hash.finalize())
}
pub(crate) fn classify(code: &str, details: &str) -> Option<Failure> {
    let text = details.to_ascii_lowercase();
    match code {
        "rate_limit" | "rate_limit_error" | "usageLimitExceeded" | "rateLimitExceeded" => {
            Some(Failure::RateLimit)
        }
        "overloaded" | "overloaded_error" | "serverOverloaded" | "flexUnavailable" => {
            Some(Failure::Capacity)
        }
        "responseStreamDisconnected" | "responseStreamConnectionFailed" | "network_error" => {
            Some(Failure::Connection)
        }
        ""
        | "other"
        | "badRequest"
        | "invalid_request"
        | "invalid_request_error"
        | "api_error"
        | "unknown"
        | "server_error"
        | "internalServerError"
        | "responseTooManyFailedAttempts"
        | "httpConnectionFailed" => classify_details(&text).or_else(|| {
            if matches!(
                code,
                "badRequest" | "invalid_request" | "invalid_request_error"
            ) && text.trim() == "invalid request payload"
            {
                return Some(Failure::RequestPayload);
            }
            // Codex can wrap the provider's JSON error in an HTTP diagnostic.
            let body = text.get(text.find('{')?..=text.rfind('}')?)?;
            let envelope: serde_json::Value = serde_json::from_str(body).ok()?;
            let error = &envelope["error"];
            (error["type"] == "invalid_request_error"
                && error["message"] == "invalid request payload")
                .then_some(Failure::RequestPayload)
        }),
        _ => None,
    }
}
fn classify_details(text: &str) -> Option<Failure> {
    match () {
        _ if text.contains("at capacity")
            || text.contains("model is overloaded")
            || text.contains("model is currently overloaded") =>
        {
            Some(Failure::Capacity)
        }
        _ if [
            "rate limited",
            "rate limit exceeded",
            "rate limit reached",
            "too many requests",
            "rate_limit_exceeded",
        ]
        .iter()
        .any(|p| text.contains(p)) =>
        {
            Some(Failure::RateLimit)
        }
        _ if [
            "stream disconnected",
            "stream interrupted",
            "connection reset",
            "stream closed before",
            "disconnected before completion",
            "connection was closed",
        ]
        .iter()
        .any(|p| text.contains(p)) =>
        {
            Some(Failure::Connection)
        }
        _ if text.contains("invalid value")
            && text.contains("supported values")
            && text.contains("tools[")
            && text.contains("].type") =>
        {
            Some(Failure::ToolSchema)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_provider_failures_and_excludes_unrelated_invalid_requests() {
        assert_eq!(
            classify(
                "invalid_request",
                r#"Invalid value: 'message'. Supported values are: ... input[0].tools[1].type"#
            ),
            Some(Failure::ToolSchema)
        );
        assert_eq!(
            classify("invalid_request", "Invalid value: input[0].content"),
            None
        );
        let payload = r#"{"error":{"message":"Invalid request payload","type":"invalid_request_error","code":"invalid_request_error","param":"12345"}}"#;
        assert_eq!(classify("", payload), Some(Failure::RequestPayload));
        assert_eq!(classify("authentication_failed", payload), None);
        assert_eq!(
            classify("other", "The file contains an invalid request payload"),
            None
        );
        assert_eq!(
            classify("", "Model is at capacity"),
            Some(Failure::Capacity)
        );
        assert_eq!(classify("authentication_failed", "connection reset"), None);
        assert_eq!(
            classify("responseTooManyFailedAttempts", "credentials expired"),
            None
        );
        assert_eq!(
            classify("policyCapacityUnavailable", "model at capacity"),
            None
        );
    }
}
