//! Opaque owner-issued enrollment codes. Native signatures authorize admission.
use serde::{Deserialize, Serialize};
pub const LIFETIME: u64 = 900;
pub const MAX_CAPSULE: usize = 256 * 1024;
pub const MAX_BODY: usize = MAX_CAPSULE + 4096;
pub fn valid_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub cluster_id: String,
    pub owner_node_id: String,
    pub invitation_id: String,
    pub created_at: u64,
    pub capsule: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub id: String,
    pub cluster_id: String,
    pub invitation_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub capsule: String,
}
