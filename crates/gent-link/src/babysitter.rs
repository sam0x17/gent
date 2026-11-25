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
        | "httpConnectionFailed" => {
            if let Some(reason) = classify_details(&text) {
                return Some(reason);
            }
            // Codex can wrap a provider JSON envelope in an HTTP diagnostic.
            // The provider's parameter is a location hint, which may be absent.
            if let Some(error) = text
                .find('{')
                .zip(text.rfind('}'))
                .and_then(|(start, end)| text.get(start..=end))
                .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
                && error["error"]["type"] == "invalid_request_error"
            {
                let error = &error["error"];
                return validation_failure(
                    error["code"].as_str(),
                    error["message"].as_str()?,
                    error["param"].as_str(),
                );
            }
            match code {
                "badRequest" | "invalid_request" | "invalid_request_error" | "other" => {
                    validation_failure(None, text.trim(), None)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn validation_failure(code: Option<&str>, message: &str, param: Option<&str>) -> Option<Failure> {
    let validation = match code {
        Some(
            "unknown_parameter"
            | "unsupported_parameter"
            | "missing_required_parameter"
            | "invalid_parameter"
            | "invalid_value"
            | "unsupported_value"
            | "invalid_type"
            | "invalid_json"
            | "invalid_request_payload"
            | "invalid_json_schema"
            | "invalid_function_parameters",
        ) => true,
        None | Some("invalid_request_error" | "invalid_request") => {
            message == "invalid request payload"
                || [
                    "unknown parameter:",
                    "unsupported parameter:",
                    "missing required parameter:",
                    "invalid value:",
                    "unsupported value:",
                    "invalid type for ",
                ]
                .iter()
                .any(|prefix| message.starts_with(prefix))
        }
        _ => false,
    };
    if !validation || message.is_empty() {
        return None;
    }
    // Preserve the existing tool-schema diagnostic when the location identifies
    // a tools array. Eligibility itself is independent of the location.
    let location = param.unwrap_or(message);
    if location.starts_with("tools[") || location.contains(".tools[") {
        Some(Failure::ToolSchema)
    } else {
        Some(Failure::RequestPayload)
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
    fn provider_validation_accepts_any_parameter_location() {
        for (code, message, param, expected) in [
            (
                "invalid_request_error",
                "Invalid request payload",
                serde_json::json!("56959"),
                Failure::RequestPayload,
            ),
            (
                "invalid_request_error",
                "Invalid request payload",
                serde_json::json!(56959),
                Failure::RequestPayload,
            ),
            (
                "invalid_value",
                "Invalid value: ''. Supported values are: 'assistant', 'system', 'developer', and 'user'.",
                serde_json::json!("input[12]"),
                Failure::RequestPayload,
            ),
            (
                "invalid_value",
                "Invalid value: 'new'.",
                serde_json::json!("metadata.role"),
                Failure::RequestPayload,
            ),
            (
                "unknown_parameter",
                "Unknown parameter: 'seed'.",
                serde_json::Value::Null,
                Failure::RequestPayload,
            ),
            (
                "invalid_type",
                "Expected an object",
                serde_json::json!("response_format"),
                Failure::RequestPayload,
            ),
            (
                "unsupported_parameter",
                "Parameter is unsupported",
                serde_json::json!("input[3].content[2].name"),
                Failure::RequestPayload,
            ),
            (
                "unknown_parameter",
                "Unknown parameter: 'input[0].tools[0].role'.",
                serde_json::json!("input[0].tools[0].role"),
                Failure::ToolSchema,
            ),
        ] {
            let details = serde_json::json!({"error":{"type":"invalid_request_error","code":code,
                "message":message,"param":param}})
            .to_string();
            assert_eq!(classify("other", &format!("■ {details}")), Some(expected));
            assert_eq!(classify("authentication_failed", &details), None);
        }
        let omitted =
            r#"{"error":{"type":"invalid_request_error","message":"Invalid request payload"}}"#;
        assert_eq!(classify("other", omitted), Some(Failure::RequestPayload));
        assert_eq!(
            classify("other", "Invalid request payload"),
            Some(Failure::RequestPayload)
        );
    }

    #[test]
    fn other_provider_errors_keep_their_own_meaning() {
        for code in [
            "unauthorized",
            "invalid_api_key",
            "model_not_found",
            "context_length_exceeded",
            "content_policy_violation",
        ] {
            let details = serde_json::json!({"error":{"type":"invalid_request_error",
                "code":code,"message":"Invalid value: 'example'.","param":"input[0]"}})
            .to_string();
            assert_eq!(classify("other", &details), None, "{code}");
        }
        let wrong_type = r#"{"error":{"type":"permission_error","code":"invalid_value","message":"Invalid value: 'example'."}}"#;
        assert_eq!(classify("other", wrong_type), None);
    }

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
            Some(Failure::RequestPayload)
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
