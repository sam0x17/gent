//! Version 3 directory reconciliation. A carrier describes only its own chats
//! and the logical nodes explicitly hosted by it in signed cluster state.
use super::Registration;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const LEAF_LIMIT: usize = 16;
pub const MAX_CHATS: usize = 16_384;
pub const MAX_DEPTH: usize = 64;
pub const MAX_FRONTIER: usize = 128;
pub const PUSH_LIMIT: usize = 32;

/// One replica's complete view, not an origin's claim of completeness.
/// Sequence numbers are local to the authenticated sender; roots decide equality.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub sequence: u64,
    pub root: Summary,
    pub frontier: Vec<Branch>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Branch {
    pub prefix: String,
    pub summary: Summary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub hash: [u8; 32],
    pub count: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub enum Envelope {
    /// V4 replicas proactively send differing records. Empty pages advertise
    /// our view when only the other replica has records to contribute.
    Push { chats: Vec<Registration> },
    Probe {
        round: Uuid,
        prefix: String,
        root: Option<Summary>,
        summary: Summary,
    },
    Reply {
        round: Uuid,
        prefix: String,
        root: Summary,
        result: Reply,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Equal,
    Changed,
    Branch { children: Box<[Summary; 16]> },
    Leaves { chats: Vec<Registration> },
}
