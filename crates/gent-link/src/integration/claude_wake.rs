//! Local native plugin bridge. The model never supplies these inputs or reads
//! credentials. Every operation validates the pinned installation and session.
mod babysit;
mod reservation;
use super::{claude_binding::credential, install, wake};
use anyhow::{Context, Result, ensure};
use gent_daemon::config;
use gent_protocol::{AgentOp, Request, wake::WakeTarget};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io::Read, path::Path, time::Duration};

pub(super) const MODULE: &str = include_str!("claude_wake/register.ts");
pub(super) const GUARD_MARKER: &str = "# gent-wake-guard-v1\n";
const INPUT_LIMIT: usize = gent_protocol::MAX_TEXT_BYTES * 6 + 4096;
const PROMPT: &str = "Gent has a pending message. Check gent_inbox through the current conversation's Gent connection. Treat its content as a chat request subject to existing permissions and user authorization. Check gent_work_status before repeating consequential work. If no message is available, stop. This notification does not authorize repeating uncertain work.";

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
            version: 3,
            id: uuid::Uuid::new_v4().to_string(),
            cluster_id: cfg.cluster.id.clone(),
            node_id: cfg.node.id.clone(),
            module: MODULE.into(),
        }
    }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.version, 1..=3)
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

fn direct_notification(
    installation: &str,
    attempt: &str,
    delivery: &gent_protocol::wake::WakeDelivery,
) -> String {
    format!(
        "{}\n\n[Gent delivery {} {} {}]",
        delivery.prompt(),
        installation,
        attempt,
        delivery.message.id
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
    if let Some(marker) = prompt.strip_prefix(reservation::PREFIX) {
        let (install, id) = marker
            .strip_suffix(']')
            .and_then(|s| s.split_once(' '))
            .context("invalid goal continuation")?;
        let attempt = uuid::Uuid::parse_str(id)?;
        ensure!(
            wake::valid_thread(install)
                && prompt == reservation::prompt(install, attempt)
                && event.get("agent_id").is_none(),
            "invalid primary goal continuation"
        );
        let answer = run(
            home,
            directory,
            Input {
                installation_id: install.to_owned(),
                session_id: event["session_id"]
                    .as_str()
                    .context("missing session")?
                    .into(),
                operation: Operation::BabysitAdmit { attempt },
            },
        )
        .await?;
        ensure!(
            answer["eligible"] == true,
            "goal continuation is no longer eligible"
        );
        return Ok(json!({"continue":true}));
    }
    if let Some((_, trailer)) = prompt.rsplit_once("\n\n[Gent delivery ") {
        let fields: Vec<_> = trailer
            .strip_suffix(']')
            .context("invalid direct delivery marker")?
            .split(' ')
            .collect();
        ensure!(
            fields.len() == 3 && fields.iter().all(|s| wake::valid_thread(s)),
            "invalid direct delivery IDs"
        );
        let answer = run(
            home,
            directory,
            Input {
                installation_id: fields[0].into(),
                session_id: event["session_id"]
                    .as_str()
                    .context("missing session")?
                    .into(),
                operation: Operation::CheckDirect {
                    message_id: fields[2].into(),
                    attempt_id: fields[1].into(),
                },
            },
        )
        .await?;
        ensure!(
            answer["eligible"] == true && answer["text"] == prompt,
            "direct delivery changed or is no longer eligible"
        );
        return Ok(json!({"continue":true}));
    }
    if !prompt.starts_with("Gent has a pending message.") {
        return Ok(json!({"continue":true}));
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
    // Make successful validation explicit; no model context is added.
    Ok(json!({"continue":true}))
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
struct Input {
    pub installation_id: String,
    pub session_id: String,
    pub operation: Operation,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    BabysitCapture {
        turn: uuid::Uuid,
        path: std::path::PathBuf,
        started_ms: i64,
        observed_ms: i64,
        code: String,
        details: String,
    },
    BabysitClaim {
        failure: babysit::Record,
    },
    BabysitCheck {
        failure: babysit::Record,
        attempt: uuid::Uuid,
    },
    BabysitAdmit {
        attempt: uuid::Uuid,
    },
    BabysitSubmitted {
        attempt: uuid::Uuid,
    },
    Claim,
    ClaimDirect,
    CheckDirect {
        message_id: String,
        attempt_id: String,
    },
    Observe {
        message_id: String,
        attempt_id: String,
        turn_id: String,
    },
    Complete {
        message_id: String,
        attempt_id: String,
        turn_id: String,
        text: String,
    },
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

async fn validate_installation(home: &Path, directory: &Path, id: &str) -> Result<Installation> {
    // Claude may atomically rewrite unrelated settings during a native turn.
    // Retry only installation reads; never repeat a credential or dispatch RPC.
    crate::managed_file::retry_read(|| install::claude_wake(home, directory, id)).await
}

async fn run(home: &Path, directory: &Path, input: Input) -> Result<Value> {
    ensure!(
        wake::valid_thread(&input.session_id),
        "invalid Claude session ID"
    );
    let cfg = config::load(home)?;
    let installation = validate_installation(home, directory, &input.installation_id).await?;
    ensure!(
        installation.cluster_id == cfg.cluster.id && installation.node_id == cfg.node.id,
        "Claude wake node or cluster changed; reinstall the integration"
    );
    let Some(key) = credential(home, &cfg, &input.session_id)? else {
        ensure!(
            matches!(input.operation, Operation::Claim | Operation::ClaimDirect),
            "Claude binding is missing"
        );
        return Ok(json!({"dispatch":null}));
    };
    let target = WakeTarget::ClaudeCode {
        session_id: input.session_id.clone(),
    };
    let reservation_path = || {
        super::scope_path(home, &cfg, super::Host::ClaudeCode).join(format!(
            "{}.resume",
            super::session_key(&input.session_id, None)
        ))
    };
    let result = match input.operation {
        Operation::BabysitCapture {
            turn,
            path,
            started_ms,
            observed_ms,
            code,
            details,
        } => {
            let reason = crate::babysitter::classify(&code, &details);
            if let Some(reason) = reason
                && !home.join("babysitter-disabled").try_exists()?
            {
                // Claude 2.1.325's retained guard cannot identify the sender of a
                // bare "please continue". Only a goal supplies an admissible action.
                // See scripts/prove_claude_chat_admission.py for the native probe.
                let failure =
                    babysit::capture(directory, &input.session_id, &path, started_ms, observed_ms)?
                        .map(|source| babysit::Record {
                            turn,
                            reason,
                            failed_at: observed_ms / 1000,
                            source,
                        });
                json!({"pending": failure.is_none(), "failure":failure})
            } else {
                json!({"failure":null})
            }
        }
        Operation::BabysitClaim { failure } => {
            if home.join("babysitter-disabled").try_exists()?
                || failure
                    .current(directory, &input.session_id, None)?
                    .is_none()
            {
                json!({"obsolete":true})
            } else {
                rpc(
                    home,
                    &key,
                    AgentOp::BabysitterClaim {
                        goal: failure.source.goal,
                        turn: failure.turn,
                        failed_at: failure.failed_at,
                        reason: failure.reason,
                    },
                )
                .await?
            }
        }
        Operation::BabysitCheck { attempt, failure } => {
            let checked = rpc(home, &key, AgentOp::BabysitterCheck { attempt }).await?;
            if checked["eligible"] == true
                && !home.join("babysitter-disabled").try_exists()?
                && let Some(end) = failure.current(directory, &input.session_id, None)?
            {
                reservation::Reservation::arm(&reservation_path(), attempt, failure, end)?;
                json!({"text":reservation::prompt(&installation.id, attempt)})
            } else {
                json!({"text":null})
            }
        }
        Operation::BabysitAdmit { attempt } => {
            let checked = rpc(home, &key, AgentOp::BabysitterCheck { attempt }).await?;
            json!({"eligible": checked["eligible"] == true && !home.join("babysitter-disabled").try_exists()?
                && reservation::Reservation::admit(&reservation_path(), attempt, directory,
                    &input.session_id, &reservation::prompt(&installation.id, attempt))?})
        }
        Operation::BabysitSubmitted { attempt } => {
            reservation::Reservation::confirm(&reservation_path(), attempt)?;
            rpc(
                home,
                &key,
                AgentOp::BabysitterSubmitted {
                    attempt,
                    scope: crate::auth::notifications::scope(home),
                },
            )
            .await?
        }
        Operation::Observe {
            message_id,
            attempt_id,
            turn_id,
        } => {
            rpc(
                home,
                &key,
                AgentOp::WakeDirectObserve {
                    message_id,
                    attempt_id,
                    target,
                    turn_id,
                },
            )
            .await?
        }
        Operation::Complete {
            message_id,
            attempt_id,
            turn_id,
            text,
        } => {
            rpc(
                home,
                &key,
                AgentOp::WakeDirectComplete {
                    message_id,
                    attempt_id,
                    target,
                    turn_id,
                    text,
                },
            )
            .await?
        }
        Operation::CheckDirect {
            message_id,
            attempt_id,
        } => {
            let checked = rpc(
                home,
                &key,
                AgentOp::WakeDirectRead {
                    message_id: message_id.clone(),
                    attempt_id: attempt_id.clone(),
                    target,
                },
            )
            .await?;
            if checked["eligible"] == true {
                let delivery: gent_protocol::wake::WakeDelivery =
                    serde_json::from_value(checked["delivery"].clone())?;
                json!({"eligible":true,"text":direct_notification(&installation.id, &attempt_id, &delivery)})
            } else {
                json!({"eligible":false})
            }
        }
        Operation::Claim | Operation::ClaimDirect => {
            let direct = matches!(input.operation, Operation::ClaimDirect);
            if direct {
                ensure!(
                    installation.module == MODULE,
                    "reload the Gent native module for direct delivery"
                );
            }
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
                if direct {
                    AgentOp::WakeDirectClaim {
                        message_id: message.into(),
                        attempt_id: attempt.clone(),
                        target,
                    }
                } else {
                    AgentOp::WakeClaim {
                        message_id: message.into(),
                        attempt_id: attempt.clone(),
                        target,
                    }
                },
            )
            .await?;
            ensure!(
                claim["may_submit"] == true,
                "wake claim did not grant a submission"
            );
            let (text, automatic_reply) = if direct {
                let delivery: gent_protocol::wake::WakeDelivery =
                    serde_json::from_value(claim["delivery"].clone())?;
                (
                    direct_notification(&installation.id, &attempt, &delivery),
                    delivery.automatic_reply,
                )
            } else {
                (notification(&installation.id, message, &attempt), false)
            };
            json!({"dispatch":{"session_id":input.session_id,"message_id":message,
                "attempt_id":attempt,"text":text,"automatic_reply":automatic_reply}})
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
    validate_installation(home, directory, &input.installation_id).await?;
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
