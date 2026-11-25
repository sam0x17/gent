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
            if error["type"] != "invalid_request_error" {
                return None;
            }
            if error["message"] == "invalid request payload" {
                return Some(Failure::RequestPayload);
            }
            let path = error["param"].as_str()?;
            if error["code"] == "invalid_value"
                && error["message"] == "invalid value: ''. supported values are: 'assistant', 'system', 'developer', and 'user'."
                && indexed(path.strip_suffix(".role").unwrap_or(path), "input")
            {
                // The provider can point to the entire message instead of its role field.
                return Some(Failure::RequestPayload);
            }
            if error["code"] != "unknown_parameter" {
                return None;
            }
            if error["message"].as_str()? != format!("unknown parameter: '{path}'.") {
                return None;
            }
            unknown_input_role(path)
        }),
        _ => None,
    }
}

fn indexed(field: &str, name: &str) -> bool {
    field.split_once('[').is_some_and(|(key, index)| {
        key == name
            && index.strip_suffix(']').is_some_and(|digits| {
                !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
            })
    })
}

fn unknown_input_role(path: &str) -> Option<Failure> {
    let mut fields = path.strip_suffix(".role")?.split('.');
    if !indexed(fields.next()?, "input") {
        return None;
    }
    let first = fields.next()?;
    if indexed(first, "content") && fields.next().is_none() {
        return Some(Failure::RequestPayload);
    }
    (indexed(first, "tools") && fields.all(|f| indexed(f, "tools"))).then_some(Failure::ToolSchema)
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
    fn recognizes_empty_message_role_in_provider_input() {
        let message = "Invalid value: ''. Supported values are: 'assistant', 'system', 'developer', and 'user'.";
        let details = |param: &str, code: &str| {
            serde_json::json!({"error": {"type": "invalid_request_error", "code": code,
                "param": param, "message": message}})
            .to_string()
        };
        let role = details("input[12]", "invalid_value");
        assert_eq!(classify("other", &role), Some(Failure::RequestPayload));
        assert_eq!(
            classify("other", &details("input[0].role", "invalid_value")),
            Some(Failure::RequestPayload)
        );
        for path in [
            "metadata.role",
            "input[12].content",
            "input[0].tools[1].role",
            "input[-1]",
        ] {
            assert_eq!(
                classify("other", &details(path, "invalid_value")),
                None,
                "{path}"
            );
        }
        for other in [
            role.replace("assistant", "function"),
            role.replace("''", "'bogus'"),
            role.replace("invalid_request_error", "permission_error"),
        ] {
            assert_eq!(classify("other", &other), None);
        }
        assert_eq!(classify("other", message), None);
        assert_eq!(
            classify("other", &details("input[].role", "invalid_value")),
            None
        );
        assert_eq!(
            classify("other", &details("input[0].role", "unauthorized")),
            None
        );
        assert_eq!(classify("authentication_failed", &role), None);
    }

    #[test]
    fn matches_unknown_role_only_in_provider_input_content_or_tools() {
        fn failure(path: &str, message_path: &str) -> String {
            serde_json::json!({"error":{"message": format!("Unknown parameter: '{message_path}'."),
                "type": "invalid_request_error", "code":"unknown_parameter", "param":path}})
            .to_string()
        }
        for (path, expected) in [
            ("input[0].tools[0].tools[0].role", Some(Failure::ToolSchema)),
            ("input[12].tools[3].role", Some(Failure::ToolSchema)),
            ("input[1].content[0].role", Some(Failure::RequestPayload)),
            ("input[0].tools[].role", None),
            ("input[0].content[0].tools[0].role", None),
            ("input[x].tools[0].role", None),
            ("input[0].metadata[0].role", None),
            ("input[0].tools[0].name", None),
            ("role", None),
        ] {
            let details = format!("■ {}", failure(path, path));
            assert_eq!(classify("other", &details), expected, "{path}");
            assert_eq!(classify("authentication_failed", &details), None);
        }
        let path = "input[0].tools[0].tools[0].role";
        assert_eq!(classify("other", &failure(path, "other")), None);
        assert_eq!(
            classify(
                "other",
                &failure(path, path).replace("unknown_parameter", "unauthorized")
            ),
            None
        );
        assert_eq!(
            classify("other", &format!("Unknown parameter: '{path}'.")),
            None
        );
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
