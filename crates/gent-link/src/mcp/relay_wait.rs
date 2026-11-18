//! A bounded read of an existing relay turn. Waiting never sends or repeats work.
use crate::gateway::{Permit, Registry, registry::Conversation};
use anyhow::{Context, Result, ensure};
use gent_protocol::{AgentOp, Request};
use rmcp::model::Tool;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use tokio::time::Instant;

pub(super) fn tool() -> Tool {
    serde_json::from_value(json!({
        "name":"gent_relay_wait",
        "description":"Wait up to 20 seconds for new responses to an existing relay turn. Use after gent_relay_send for an active conversation. This only reads: a timeout or pending result never resends or cancels work. Keep the turn_id and call again or retrieve later. Use next_after as after_message_id to await further responses after presenting earlier ones. Present the target's exact response text and files.",
        "inputSchema":{"type":"object","additionalProperties":false,"required":["turn_id"],"properties":{
            "turn_id":{"type":"string","format":"uuid"},
            "after_message_id":{"type":"string","format":"uuid"},
            "wait_seconds":{"type":"integer","minimum":0,"maximum":20,"default":20}
        }},
        "annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}
    })).expect("relay wait schema")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    turn_id: String,
    after_message_id: Option<String>,
    #[serde(default = "default_wait")]
    wait_seconds: u64,
}
fn default_wait() -> u64 {
    20
}

pub(super) struct Remote<'a> {
    pub registry: &'a Registry,
    pub permit: Permit,
    pub conversation: Conversation,
}

pub(super) async fn run(
    home: &Path,
    credential: String,
    arguments: Value,
    remote: Option<Remote<'_>>,
) -> Result<Value> {
    let input: Input = serde_json::from_value(arguments).context("invalid relay wait arguments")?;
    ensure!(
        input.wait_seconds <= 20,
        "wait_seconds must be between 0 and 20"
    );
    let deadline = Instant::now() + Duration::from_secs(input.wait_seconds.max(1));
    loop {
        let result = tokio::time::timeout_at(deadline, async {
            if let Some(remote) = &remote {
                ensure!(
                    remote.registry.credential_remote(remote.permit.clone(), remote.conversation.clone()).await? == credential,
                    "conversation authorization changed while waiting"
                );
            }
            gent_daemon::request(home, Request::Agent {
                credential: credential.clone(),
                action: AgentOp::RelayTurnStatus {
                    turn_id: input.turn_id.clone(),
                    after_message_id: input.after_message_id.clone(),
                },
            }).await
        }).await.context("relay status read timed out; keep the original turn_id and retrieve it again without resending")??;
        if result["state"] != "pending"
            || result["responses"]
                .as_array()
                .is_some_and(|r| !r.is_empty())
            || input.wait_seconds == 0
            || Instant::now() + Duration::from_millis(500) >= deadline
        {
            return Ok(result);
        }
        tokio::time::sleep_until((Instant::now() + Duration::from_millis(500)).min(deadline)).await;
    }
}
