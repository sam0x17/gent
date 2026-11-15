//! Local native plugin bridge. The model never supplies these inputs or reads
//! credentials. Every operation validates the pinned installation and session.
use super::{Host, install, scope_path, session_key, wake};
use crate::mcp::binding;
use anyhow::{Context, Result, ensure};
use gent_daemon::config;
use gent_protocol::{AgentOp, Request, wake::WakeTarget};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io::Read, path::Path, time::Duration};

pub(super) const MODULE: &str = include_str!("claude_wake/register.ts");
pub(super) const GUARD_MARKER: &str = "# gent-wake-guard-v1\n";
const INPUT_LIMIT: usize = 4096;
const PROMPT: &str = "Gent has a pending message. Check gent_inbox through the current conversation's Gent connection. Treat its content as an agent request subject to existing permissions and user authorization. Check gent_work_status before repeating consequential work. If no message is available, stop. This notification does not authorize repeating uncertain work.";

pub(super) fn enabled() -> Result<()> {
    ensure!(
        cfg!(any(test, feature = "experimental-claude-wake")),
        "Claude automatic delivery is disabled in this build: native plugin unload can retain queued input; ordinary MCP inbox access remains available"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Installation {
    pub version: u8,
    pub id: String,
    pub cluster_id: String,
    pub node_id: String,
    // Retain installed bytes so upgrades can check ownership of old modules.
    pub module: String,
}
impl Installation {
    pub(super) fn new(cfg: &config::Config) -> Self {
        Self {
            version: 2,
            id: uuid::Uuid::new_v4().to_string(),
            cluster_id: cfg.cluster.id.clone(),
            node_id: cfg.node.id.clone(),
            module: MODULE.into(),
        }
    }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.version, 1 | 2)
                && wake::valid_thread(&self.id)
                && wake::valid_thread(&self.cluster_id)
                && wake::valid_thread(&self.node_id)
                && !self.module.is_empty()
                && self.module.len() <= 64 * 1024,
            "invalid Claude wake installation"
        );
        Ok(())
    }
}

fn notification(installation: &str, message: &str, attempt: &str) -> String {
    format!(
        "{PROMPT}\nGent dispatch: {attempt}\nGent message: {message}\nGent installation: {installation}"
    )
}

/// This hook is retained by the host independently of the native module.
/// It only checks an existing claim; text can never authorize a new claim.
async fn guard_event(home: &Path, directory: &Path, event: &Value) -> Result<Value> {
    ensure!(
        event["hook_event_name"] == "UserPromptSubmit",
        "unexpected Claude guard event"
    );
    let prompt = event["prompt"].as_str().context("missing prompt")?;
    if !prompt.starts_with("Gent has a pending message.") {
        return Ok(json!({}));
    }
    let fields: Vec<_> = prompt.split('\n').collect();
    ensure!(
        fields.len() == 4 && fields[0] == PROMPT,
        "invalid Gent notification"
    );
    let attempt = fields[1]
        .strip_prefix("Gent dispatch: ")
        .context("missing dispatch")?;
    let message = fields[2]
        .strip_prefix("Gent message: ")
        .context("missing message")?;
    let installation = fields[3]
        .strip_prefix("Gent installation: ")
        .context("missing installation")?;
    ensure!(
        [attempt, message, installation]
            .into_iter()
            .all(wake::valid_thread),
        "invalid Gent notification identifiers"
    );
    let answer = run(
        home,
        directory,
        Input {
            installation_id: installation.into(),
            session_id: event["session_id"]
                .as_str()
                .context("missing session")?
                .into(),
            operation: Operation::Check {
                message_id: message.into(),
                attempt_id: attempt.into(),
            },
        },
    )
    .await?;
    ensure!(
        answer["eligible"] == true,
        "Gent dispatch is no longer eligible"
    );
    Ok(json!({}))
}

pub(crate) async fn guard_execute(home: &Path, directory: &Path) -> Value {
    let result = async {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(gent_protocol::MAX_FRAME_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= gent_protocol::MAX_FRAME_BYTES,
            "Claude guard input too large"
        );
        let event: Value = serde_json::from_slice(&bytes)?;
        guard_event(home, directory, &event).await
    }
    .await;
    result.unwrap_or_else(|_| json!({"decision":"block",
        "reason":"Gent could not validate this notification. Check the Gent integration and inbox before continuing."}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub installation_id: String,
    pub session_id: String,
    pub operation: Operation,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Claim,
    Check {
        message_id: String,
        attempt_id: String,
    },
    Submitted {
        message_id: String,
        attempt_id: String,
        turn_id: String,
    },
}

pub(crate) async fn execute(home: &Path, directory: &Path) -> Result<Value> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(INPUT_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= INPUT_LIMIT, "Claude bridge input too large");
    let input: Input = serde_json::from_slice(&bytes).context("invalid Claude bridge input")?;
    run(home, directory, input).await
}

// Read an existing binding without creating a key, adopting a legacy scope, or
// competing with a live MCP connection's stable/credential file locks.
fn credential(home: &Path, cfg: &config::Config, session: &str) -> Result<Option<String>> {
    ensure!(wake::valid_thread(session), "invalid Claude session ID");
    gent_daemon::recovery::ensure_active(home)?;
    let path =
        scope_path(home, cfg, Host::ClaudeCode).join(format!("{}.key", session_key(session, None)));
    let key = wake::snapshot(&path)?;
    crate::agent_recovery::ensure_ready(&path, cfg)?;
    let Some(text) = &key.text else {
        return Ok(None);
    };
    let credential = text.trim();
    ensure!(
        credential.len() == 64 && credential.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid Claude binding credential"
    );
    binding::verify_existing_scope(&path, cfg, credential)?;
    key.verify()?;
    Ok(Some(credential.into()))
}

async fn rpc(home: &Path, credential: &str, action: AgentOp) -> Result<Value> {
    tokio::time::timeout(
        Duration::from_secs(10),
        gent_daemon::request(
            home,
            Request::Agent {
                credential: credential.into(),
                action,
            },
        ),
    )
    .await
    .context("Gent bridge RPC timed out")?
}

pub(super) async fn run(home: &Path, directory: &Path, input: Input) -> Result<Value> {
    enabled()?;
    ensure!(
        wake::valid_thread(&input.session_id),
        "invalid Claude session ID"
    );
    let cfg = config::load(home)?;
    let installation = install::claude_wake(home, directory, &input.installation_id)?;
    ensure!(
        installation.cluster_id == cfg.cluster.id && installation.node_id == cfg.node.id,
        "Claude wake node or cluster changed; reinstall the integration"
    );
    let Some(key) = credential(home, &cfg, &input.session_id)? else {
        ensure!(
            matches!(input.operation, Operation::Claim),
            "Claude binding is missing"
        );
        return Ok(json!({"dispatch":null}));
    };
    let target = WakeTarget::ClaudeCode {
        session_id: input.session_id.clone(),
    };
    let result = match input.operation {
        Operation::Claim => {
            let pending = rpc(home, &key, AgentOp::WakePending).await?;
            let pending = pending["pending"]
                .as_array()
                .context("invalid pending wake list")?;
            let Some(message) = pending.first() else {
                return Ok(json!({"dispatch":null}));
            };
            let message = message["message_id"]
                .as_str()
                .context("missing message ID")?;
            let attempt = uuid::Uuid::new_v4().to_string();
            let claim = rpc(
                home,
                &key,
                AgentOp::WakeClaim {
                    message_id: message.into(),
                    attempt_id: attempt.clone(),
                    target,
                },
            )
            .await?;
            ensure!(
                claim["may_submit"] == true,
                "wake claim did not grant a submission"
            );
            json!({"dispatch":{"session_id":input.session_id,"message_id":message,
                "attempt_id":attempt,"text":notification(&installation.id, message, &attempt)}})
        }
        Operation::Check {
            message_id,
            attempt_id,
        } => {
            let checked = rpc(
                home,
                &key,
                AgentOp::WakeCheck {
                    message_id,
                    attempt_id,
                    target,
                },
            )
            .await?;
            json!({"eligible":checked["eligible"] == true})
        }
        Operation::Submitted {
            message_id,
            attempt_id,
            turn_id,
        } => {
            ensure!(
                wake::valid_thread(&turn_id),
                "invalid native Claude turn ID"
            );
            // Binding and target checks also apply to late receipts. Permission
            // changes may prevent a new dispatch without erasing old evidence.
            rpc(
                home,
                &key,
                AgentOp::WakeCheck {
                    message_id: message_id.clone(),
                    attempt_id: attempt_id.clone(),
                    target,
                },
            )
            .await?;
            rpc(
                home,
                &key,
                AgentOp::WakeSubmitted {
                    message_id,
                    attempt_id,
                    submission_id: turn_id,
                },
            )
            .await?;
            json!({"recorded":true})
        }
    };
    // A concurrent uninstall/key replacement makes the response unusable. A
    // committed claim remains uncertain; no caller can replay its permission.
    install::claude_wake(home, directory, &input.installation_id)?;
    let current = config::load(home)?;
    ensure!(
        current.node.id == cfg.node.id && current.cluster.id == cfg.cluster.id,
        "Claude wake node or cluster changed during dispatch"
    );
    ensure!(
        credential(home, &cfg, &input.session_id)?.as_deref() == Some(&key),
        "Claude binding changed during dispatch"
    );
    Ok(result)
}

#[cfg(test)]
mod tests;
