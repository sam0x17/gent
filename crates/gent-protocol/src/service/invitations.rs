//! Scoped invitation routing authority, independent of cryptographic admission.
use serde::{Deserialize, Serialize};
use uuid::{Uuid, Variant};

pub const LIFETIME_SECONDS: u64 = 900;
pub const MAX_WIRE_BYTES: usize = 6 * 1024 * 1024 + 4096;
pub const MAX_ATTEMPTS: usize = 64;
pub const MAX_MESSAGES_PER_SIDE: u64 = 4096;
pub const MAX_BYTES_PER_SIDE: u64 = 64 * 1024 * 1024;

pub fn valid_attempt(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| {
        id.to_string() == value && id.get_version_num() == 4 && id.get_variant() == Variant::RFC4122
    })
}

/// UUIDv7 fixes the admission deadline even after expired verifier cleanup.
/// Issue time uses whole seconds so the signed offer and service agree exactly.
pub fn issued_at(id: &str) -> Option<u64> {
    let value = Uuid::parse_str(id).ok()?;
    if value.to_string() != id
        || value.get_version_num() != 7
        || value.get_variant() != Variant::RFC4122
    {
        return None;
    }
    let (seconds, nanos) = value.get_timestamp()?.to_unix();
    (seconds > 0 && nanos == 0).then_some(seconds)
}

pub fn credential_created_at(token: &str) -> Option<u64> {
    super::credential_created_at(token, "gent_j1")
}

/// Registration contains a routing-secret digest, never a signed offer or PSK.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub owner_node_id: String,
    pub routing_hash: String,
    pub expires_at: u64,
}

/// Sent only to the independently pinned account origin under a service session.
/// The client persists the join bearer before exchange, just like normal login.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exchange {
    pub routing_secret: String,
    pub join_token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub id: String,
    pub cluster_id: String,
    pub owner_node_id: String,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Owner,
    Join,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub invitation_id: String,
    pub side: Side,
    pub token_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub invitation_id: String,
    pub cluster_id: String,
    pub owner_node_id: String,
    pub side: Side,
    pub deadline: u64,
    pub expires_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_ids_bind_an_exact_issue_time_and_join_tokens_have_a_distinct_type() {
        let id = Uuid::new_v7(uuid::Timestamp::from_unix(uuid::NoContext, 1794580000, 0));
        assert_eq!(issued_at(&id.to_string()), Some(1794580000));
        for invalid in [
            id.to_string().to_uppercase(),
            id.simple().to_string(),
            Uuid::new_v4().to_string(),
            Uuid::new_v7(uuid::Timestamp::from_unix(uuid::NoContext, 0, 0)).to_string(),
            Uuid::new_v7(uuid::Timestamp::from_unix(
                uuid::NoContext,
                1794580000,
                1_000_000,
            ))
            .to_string(),
        ] {
            assert_eq!(issued_at(&invalid), None);
        }
        let token = format!("gent_j1.1794580000.{}", "ab".repeat(32));
        assert_eq!(credential_created_at(&token), Some(1794580000));
        assert_eq!(super::super::transport_created_at(&token), None);
        assert_eq!(super::super::session_created_at(&token), None);
        assert_eq!(
            credential_created_at(&token.replace("gent_j1", "gent_t1")),
            None
        );
    }
}
