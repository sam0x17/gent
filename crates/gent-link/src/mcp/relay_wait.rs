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

pub(super) fn message_tool() -> Tool {
    let mut value = serde_json::to_value(tool()).expect("wait tool serializes");
    value["name"] = json!("gent_wait");
    value["description"] = json!(
        "Continue waiting for a response-required gent_send using its message_id. This only reads; it never sends or repeats work. If pending, call again in this turn without asking the user to check. Stop on completion, failure, cancellation, user disengagement, or a host limit. Acknowledgment is not a response. Use gent_relay_turns to recover the ID after reconnecting."
    );
    value["inputSchema"]["required"] = json!(["message_id"]);
    let properties = value["inputSchema"]["properties"].as_object_mut().unwrap();
    let id = properties.remove("turn_id").unwrap();
    properties.insert("message_id".into(), id);
    serde_json::from_value(value).expect("message wait schema")
}

pub(super) async fn send(
    home: &Path,
    credential: String,
    mut arguments: serde_json::Map<String, Value>,
    relay: bool,
    remote: Option<Remote<'_>>,
) -> Result<Value> {
    let started = Instant::now();
    arguments.insert(
        "op".into(),
        json!(if relay { "relay_send" } else { "request_reply" }),
    );
    let action: AgentOp =
        serde_json::from_value(Value::Object(arguments)).context("invalid send arguments")?;
    let submitted = gent_daemon::request(
        home,
        Request::Agent {
            credential: credential.clone(),
            action,
        },
    )
    .await?;
    let id = submitted["turn_id"]
        .as_str()
        .context("missing response turn ID")?;
    // Once admitted, preserve the ID even if the subsequent read fails. A
    // transport failure is not permission to create another request.
    // Leave headroom below the hosted gateway's 28-second dispatch limit even
    // when local admission took most of its own 15-second timeout.
    let wait_seconds = Duration::from_secs(24)
        .saturating_sub(started.elapsed())
        .as_secs()
        .min(20);
    let mut result = match run(
        home,
        credential,
        json!({"turn_id":id,"wait_seconds":wait_seconds}),
        remote,
    )
    .await
    {
        Ok(result) => result,
        Err(_) => continuation(
            json!({"turn_id":id,"state":"pending","responses":[]}),
            "Response lookup unavailable. Continue waiting on the same message; do not resend.",
        ),
    };
    result["message_id"] = submitted["message_id"].clone();
    result["duplicate"] = submitted["duplicate"].clone();
    Ok(result)
}

fn continuation(mut result: Value, instruction: &str) -> Value {
    result["message_id"] = result["turn_id"].clone();
    result["next_action"] = json!({"tool":"gent_wait", "arguments":{
        "message_id": result["turn_id"], "after_message_id": result["next_after"],
    }});
    // Omit an absent cursor: tool schemas use optional strings, not nulls.
    if result["next_after"].is_null() {
        result["next_action"]["arguments"]
            .as_object_mut()
            .unwrap()
            .remove("after_message_id");
    }
    result["instruction"] = json!(instruction);
    result
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
            return Ok(if result["state"] == "pending" {
                continuation(
                    result,
                    "The request is still awaiting an answer. Continue with next_action now; do not resend or ask the user to check again. A receipt alone is not an answer.",
                )
            } else {
                result
            });
        }
        tokio::time::sleep_until((Instant::now() + Duration::from_millis(500)).min(deadline)).await;
    }
}
