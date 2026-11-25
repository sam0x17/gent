//! Cumulative counters on a physical carrier. Names come from the local directory.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) const PAGE_ROWS: usize = 256;
pub(crate) const MAX_ROWS: usize = 65_536;

/// The random token also distinguishes revision numbers reused after restore.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mark(pub i64, pub String);

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finish {
    pub head: Mark,
    pub as_of: i64,
    pub started: i64,
    pub ordinary: u64,
    pub goals: u64,
}

/// [chat UUID, accepted sends, UTF-8 text bytes, attachment bytes].
#[derive(Debug, Serialize, Deserialize)]
pub struct Counts(pub Uuid, pub u64, pub u64, pub u64);

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Exchange {
    Hello,
    Read {
        round: Uuid,
        base: Option<Mark>,
    },
    Page {
        round: Uuid,
        page: usize,
        full: bool,
        rows: Vec<Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        finish: Option<Finish>,
    },
}
