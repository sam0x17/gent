//! Host attribution for ordinary conversation recovery.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CHAT_FAILURE_MAX_AGE: i64 = 10 * 60;
pub const CHAT_CHAIN_MAX_AGE: i64 = 30 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChatOrigin {
    Operator {
        turn: Uuid,
        started_at: i64,
        client_id: Option<String>,
    },
    Continuation {
        attempt: Uuid,
    },
}
