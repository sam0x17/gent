//! Public ordering metadata. Configuration, node permissions, and encryption
//! keys belong only inside `ciphertext`, never in this protocol's headers.
use serde::{Deserialize, Serialize};

pub const MAX_SEQUENCE: u64 = (1 << 53) - 1;
pub const MAX_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_COMMIT_BYTES: usize = MAX_CIPHERTEXT_BYTES * 4 / 3 + 8192;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub sequence: u64,
    pub digest: [u8; 32],
    /// An ephemeral admission key, rotated on every commit. Its private part
    /// is distributed inside encrypted envelopes to authorized nodes only.
    pub write_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: u8,
    pub cluster: String,
    pub origin: String,
    pub operation: String,
    /// A salted commitment to the requested operation; never a bare hash of
    /// guessable private configuration. Stable across conflict rebases.
    pub intent: [u8; 32],
    pub previous: Head,
    pub next_write_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub header: Header,
    /// Canonical standard base64, bounded before parsing at ingress.
    pub ciphertext: String,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub cluster: String,
    pub origin: String,
    pub operation: String,
    pub intent: [u8; 32],
    pub head: Head,
}

/// Provisioned once through the account control plane. A service bootstrap is
/// not endpoint trust: clients independently pin and verify the encrypted
/// migration from their existing authority checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub cluster: String,
    pub head: Head,
}

pub fn valid_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

impl Head {
    pub fn valid(&self) -> bool {
        self.sequence <= MAX_SEQUENCE && self.digest != [0; 32] && self.write_key != [0; 32]
    }
}

impl Header {
    pub fn valid(&self) -> bool {
        self.version == 1
            && valid_id(&self.cluster)
            && valid_id(&self.origin)
            && valid_id(&self.operation)
            && self.intent != [0; 32]
            && self.previous.valid()
            && self.previous.sequence < MAX_SEQUENCE
            && self.next_write_key != [0; 32]
            && self.next_write_key != self.previous.write_key
    }
}
