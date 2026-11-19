//! Availability hints only. Neither subscription nor notification proves receipt.
use serde::{Deserialize, Serialize};

pub const VERSION: u8 = 2;
pub const MAX_INTERESTS: usize = 256;
pub const MAX_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Interest {
    pub mailbox: String,
    /// Writers watch receiver checkpoints; readers watch new packets.
    pub outgoing: bool,
}
impl Interest {
    pub fn valid(&self) -> bool {
        !self.mailbox.is_empty()
            && self.mailbox.len() <= 384
            && self
                .mailbox
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subscription {
    pub version: u8,
    pub interests: Vec<Interest>,
}
impl Subscription {
    pub fn valid(&self) -> bool {
        self.version == VERSION
            && self.interests.len() <= MAX_INTERESTS
            && self.interests.iter().all(Interest::valid)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notice {
    pub version: u8,
    pub event: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub streams: Vec<Interest>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub all: bool,
}
