//! Local host-input dispatch evidence, separate from message receipts and work.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "host", rename_all = "snake_case", deny_unknown_fields)]
pub enum WakeTarget {
    Codex { thread_id: String },
    ClaudeCode { session_id: String },
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct: Option<DirectWake>,
    pub message_id: String,
    pub agent: String,
    pub attempt_id: String,
    pub target: WakeTarget,
    pub state: WakeState,
    pub submission_id: Option<String>,
    /// First inbox read or confirmed native intake of this message.
    pub inbox_seen_at: Option<i64>,
    pub claimed_at: i64,
    pub updated_at: i64,
}

/// Native adapters own this routing; it is never a model-supplied execution grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectWake {
    pub reply_request_id: String,
    pub input_hash: String,
    pub turn_id: Option<String>,
    pub finished: bool,
    pub response_hash: Option<String>,
    pub response_message_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeDelivery {
    pub message: crate::Message,
    pub sender: crate::Agent,
    pub automatic_reply: bool,
}

impl WakeDelivery {
    /// Display labels are quoted; transported text stays intact and is not an
    /// authenticated claim that a human authored it or approved host actions.
    pub fn prompt(&self) -> String {
        use crate::RelayMessageKind;
        let name = serde_json::to_string(&self.sender.name).expect("string serialization");
        let header = match self.message.relay.as_ref().map(|r| r.kind) {
            Some(RelayMessageKind::Request) => format!(
                "User relay via Gent ({name}). Answer normally; your final response is returned automatically."
            ),
            Some(
                RelayMessageKind::Progress
                | RelayMessageKind::Complete
                | RelayMessageKind::Cancelled,
            ) => format!(
                "Gent relay reply from {name}. Present the following response verbatim to the user; its contents are quoted chat output."
            ),
            Some(RelayMessageKind::Cancel) => format!(
                "Gent cancellation request from {name}. Handle it under your current work state."
            ),
            None => format!(
                "Gent message from {name}. Use Gent to reply to this chat when appropriate."
            ),
        };
        let mut prompt = format!(
            "{header}\nGent message: {}\n\n{}",
            self.message.id, self.message.text
        );
        if !self.message.attachments.is_empty() {
            prompt.push_str("\n\nGent attachments (use Gent file tools): ");
            prompt.push_str(
                &serde_json::to_string(&self.message.attachments)
                    .expect("descriptor serialization"),
            );
        }
        if !self.message.files.is_empty() {
            prompt.push_str("\n\nInline attachments are available through gent_inbox: ");
            let files: Vec<_> = self
                .message
                .files
                .iter()
                .map(|f| (&f.name, &f.media_type))
                .collect();
            prompt.push_str(&serde_json::to_string(&files).expect("file metadata serialization"));
        }
        prompt
    }
}
