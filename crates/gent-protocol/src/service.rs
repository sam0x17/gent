//! Account administration only. These records convey no cluster key authority.
use serde::{Deserialize, Serialize};

pub const SESSION_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const SESSION_CREATION_WINDOW_SECONDS: u64 = 15 * 60;
pub const CALLBACK_PATH: &str = "/gent/github/callback";

/// Client-generated 256-bit secrets include their creation time so deleting
/// expired verifier rows cannot make an old revoked credential usable again.
pub fn session_created_at(token: &str) -> Option<u64> {
    credential_created_at(token, "gent_s1")
}

pub fn transport_created_at(token: &str) -> Option<u64> {
    credential_created_at(token, "gent_t1")
}

fn credential_created_at(token: &str, prefix: &str) -> Option<u64> {
    let mut fields = token.split('.');
    if fields.next()? != prefix {
        return None;
    }
    let timestamp = fields.next()?;
    let created = timestamp.parse::<u64>().ok()?;
    let secret = fields.next()?;
    (created > 0
        && created.to_string() == timestamp
        && secret.len() == 64
        && secret
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && fields.next().is_none())
    .then_some(created)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub github_client_id: String,
    pub session_lifetime_seconds: u64,
}

// No Debug derives: requests carry provider and service credentials.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenExchange {
    pub github_access_token: String,
    pub session_token: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeExchange {
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub session_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSession {
    pub account_id: String,
    pub github_subject: String,
    pub github_login: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCluster {
    pub id: String,
    pub role: String,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportEnrollment {
    pub transport_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransportSession {
    pub cluster_id: String,
    pub node_id: String,
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportCheck {
    pub token_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_tokens_have_one_canonical_shape() {
        let token = format!("gent_s1.1794580000.{}", "ab".repeat(32));
        assert_eq!(session_created_at(&token), Some(1794580000));
        let transport = token.replace("gent_s1", "gent_t1");
        assert_eq!(transport_created_at(&transport), Some(1794580000));
        assert_eq!(session_created_at(&transport), None);
        assert_eq!(transport_created_at(&token), None);
        for invalid in [
            token.replace("1794580000", "01794580000"),
            token.replace("1794580000", "+1794580000"),
            token.replace("1794580000", "0"),
            token.to_uppercase(),
            token.clone() + ".extra",
            token[..token.len() - 1].into(),
            token.replace("ab", "gg"),
        ] {
            assert_eq!(session_created_at(&invalid), None);
        }
    }
}
