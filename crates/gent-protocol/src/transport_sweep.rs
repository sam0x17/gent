//! One conditional read for the incoming mailboxes selected by a repair sweep.
use serde::{Deserialize, Serialize};

pub const ROUTE: &str = "/v2/mailbox-sweep";
pub const LIMIT: usize = 32;
pub const MAX_BYTES: usize = 20 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub mailbox: String,
    pub next: u64,
    /// SHA-256 of the canonical signed receipt encoded in standard Base64.
    pub checkpoint_hash: String,
}

impl Cursor {
    pub fn valid(&self) -> bool {
        !self.mailbox.is_empty()
            && self.mailbox.len() <= 384
            && self
                .mailbox
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && self.next < 1 << 53
            && self.checkpoint_hash.len() == 64
            && self
                .checkpoint_hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }
}

/// A bit per request cursor, in the same order. The sender still needs a
/// verified signed receipt before it can retire any ciphertext.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Changes {
    pub packets: u32,
    pub checkpoints: u32,
}
