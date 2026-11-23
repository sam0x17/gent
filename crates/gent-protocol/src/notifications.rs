//! Account-scoped events shared by desktop and future delivery clients.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub account: String,
    pub origin: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Notice {
    pub id: Uuid,
    pub created_at: i64,
    pub event: Event,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    GoalResumed {
        chat: Uuid,
        node: Uuid,
        reason: Failure,
    },
    UpdateInstalled {
        node: Uuid,
        commit: String,
    },
}
impl Notice {
    pub fn valid(&self, now: i64) -> bool {
        !self.id.is_nil()
            && (now.saturating_sub(7 * 86400)..=now.saturating_add(60)).contains(&self.created_at)
            && match &self.event {
                Event::GoalResumed { chat, node, .. } => !chat.is_nil() && !node.is_nil(),
                Event::UpdateInstalled { node, commit } => {
                    !node.is_nil()
                        && commit.len() == 40
                        && commit.bytes().all(|b| b.is_ascii_hexdigit())
                }
            }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Capacity,
    RateLimit,
    Connection,
    ToolSchema,
    RequestPayload,
}
impl Failure {
    pub fn label(self) -> &'static str {
        match self {
            Self::Capacity => "model capacity",
            Self::RateLimit => "a rate limit",
            Self::Connection => "a connection error",
            Self::ToolSchema => "a provider tool-schema error",
            Self::RequestPayload => "a provider request-format error",
        }
    }
}
