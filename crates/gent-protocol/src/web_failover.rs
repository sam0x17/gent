//! Native carrier admission and checkpoint transport for hosted web nodes.
//! Checkpoints contain web state only. They never contain native node keys.
use crate::configuration_log::Head;
use serde::{Deserialize, Serialize};

pub const VERSION: u8 = 1;
pub const LEASE_SECONDS: u64 = 30;
pub const CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_CHUNKS: usize = 1024;
pub const MAX_BATCH: usize = 8;
pub const MAX_CONTROL_BYTES: usize = CHUNK_BYTES * MAX_BATCH * 4 / 3 + 8192;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub version: u8,
    pub cluster: String,
    pub node: String,
    pub web: String,
    pub head: Head,
    pub expires_at: u64,
    pub body_hash: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub generation: u64,
    pub chunks: usize,
    pub bytes: usize,
    pub sha256: String,
}

impl Checkpoint {
    pub fn valid(&self) -> bool {
        self.generation > 0
            && self.generation < (1 << 53)
            && (1..=MAX_CHUNKS).contains(&self.chunks)
            && self.bytes > 0
            && self.bytes.div_ceil(CHUNK_BYTES) == self.chunks
            && self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Control {
    Inspect,
    Acquire {
        create: bool,
    },
    Renew {
        epoch: u64,
    },
    Read {
        generation: u64,
        start: usize,
    },
    Stage {
        epoch: u64,
        generation: u64,
        start: usize,
        chunks: Vec<String>,
    },
    Commit {
        epoch: u64,
        checkpoint: Checkpoint,
    },
    /// Publish a complete small checkpoint in one atomic storage operation.
    Publish {
        epoch: u64,
        checkpoint: Checkpoint,
        chunks: Vec<String>,
    },
    Release {
        epoch: u64,
    },
    Disable {
        epoch: u64,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub owner: String,
    pub epoch: u64,
    pub expires_at: u64,
    pub checkpoint: Option<Checkpoint>,
    #[serde(default)]
    pub revoked: bool,
}
