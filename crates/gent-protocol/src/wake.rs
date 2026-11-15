//! Local host-input dispatch evidence, separate from message receipts and work.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "host", rename_all = "snake_case", deny_unknown_fields)]
pub enum WakeTarget {
    Codex { thread_id: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeState {
    /// Persisted before submission. A lost response never permits another send.
    Uncertain,
    /// The adapter reported host acceptance; this proves neither intake nor work.
    Submitted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeRecord {
    pub message_id: String,
    pub agent: String,
    pub attempt_id: String,
    pub target: WakeTarget,
    pub state: WakeState,
    pub submission_id: Option<String>,
    /// First ordinary inbox call that returned this message, regardless of why.
    pub inbox_seen_at: Option<i64>,
    pub claimed_at: i64,
    pub updated_at: i64,
}
