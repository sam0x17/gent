//! Version 3 directory reconciliation. A carrier describes only its own chats
//! and the logical nodes explicitly hosted by it in signed cluster state.
use super::Registration;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const LEAF_LIMIT: usize = 16;
pub const MAX_CHATS: usize = 16_384;
pub const MAX_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub hash: [u8; 32],
    pub count: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub enum Envelope {
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
