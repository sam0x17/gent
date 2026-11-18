//! Recover native answers using the host's input identity, never the latest
//! assistant text from an arbitrary turn. Reading history never starts work.
use super::*;
use gent_protocol::wake::WakeRecord;

fn matched(turn: &Value, record: &WakeRecord) -> Result<bool> {
    let items = turn["items"]
        .as_array()
        .context("missing native turn items")?;
    let users: Vec<_> = items
        .iter()
        .filter(|i| i["type"] == "userMessage")
        .collect();
    if users.len() != 1 || users[0]["clientId"] != record.attempt_id {
        return Ok(false);
    }
    let content = users[0]["content"]
        .as_array()
        .context("missing native input")?;
    use sha2::{Digest, Sha256};
    Ok(content.len() == 1
        && content[0]["type"] == "text"
        && content[0]["text"].as_str().is_some_and(|text| {
            record
                .direct
                .as_ref()
                .is_some_and(|d| d.input_hash == format!("{:x}", Sha256::digest(text.as_bytes())))
        }))
}

fn answer(turn: &Value) -> Result<Option<String>> {
    match turn["status"].as_str() {
        Some("inProgress") => return Ok(None),
        Some("interrupted") => {
            return Ok(Some(
                "The remote turn was interrupted. Gent has not repeated the request.".into(),
            ));
        }
        Some("failed") => {
            return Ok(Some(
                "The remote turn failed. Gent has not repeated the request.".into(),
            ));
        }
        Some("completed") if turn["error"].is_null() => {}
        _ => anyhow::bail!("unrecognized native turn outcome"),
    }
    let items = turn["items"]
        .as_array()
        .context("missing native turn items")?;
    let final_messages: Vec<_> = items
        .iter()
        .filter(|i| i["type"] == "agentMessage" && i["phase"] == "final_answer")
        .collect();
    // Unknown phase is supported only for the final item, never a preamble
    // preceding tools. Exclude separately delivered asynchronous messages.
    let final_messages = if final_messages.is_empty() {
        items
            .last()
            .filter(|i| i["type"] == "agentMessage" && i["phase"].is_null())
            .into_iter()
            .collect()
    } else {
        final_messages
    };
    let mut parts = Vec::new();
    for item in final_messages {
        ensure!(
            item["delivery"].is_null()
                && item["moderation"]["moderated"] != true
                && item["questions"].is_null(),
            "native response requires host handling"
        );
        parts.push(
            item["text"]
                .as_str()
                .context("missing native response text")?,
        );
    }
    let text = parts.join("\n\n");
    if text.is_empty() {
        return Ok(Some(
            "The remote turn completed without a text response.".into(),
        ));
    }
    ensure!(
        text.len() <= gent_protocol::MAX_TEXT_BYTES,
        "native response exceeds Gent message size"
    );
    Ok(Some(text))
}

pub(super) async fn collect(
    home: &Path,
    socket: &Path,
    thread: &str,
    credential: &str,
) -> Result<()> {
    let target = WakeTarget::Codex {
        thread_id: thread.into(),
    };
    let pending = agent(
        home,
        credential,
        AgentOp::WakeDirectPending {
            target: target.clone(),
        },
    )
    .await?;
    let pending = pending["pending"]
        .as_array()
        .context("invalid direct wake list")?;
    if pending.is_empty() {
        return Ok(());
    }
    let mut pending = pending
        .iter()
        .map(|v| {
            Ok((
                serde_json::from_value::<WakeRecord>(v["record"].clone())?,
                v["automatic_reply"]
                    .as_bool()
                    .context("invalid direct reply flag")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut failed = false;
    let mut host = Host::connect_with_limit(socket, 32 * 1024 * 1024).await?;
    let mut cursor = Value::Null;
    for _ in 0..128 {
        let page = host.rpc("thread/turns/list", json!({"threadId":thread,"limit":16,"sortDirection":"desc","itemsView":"full","cursor":cursor})).await?;
        let turns = page["data"]
            .as_array()
            .context("invalid native turn page")?;
        ensure!(turns.len() <= 16, "oversized native turn page");
        for turn in turns {
            let mut handled = Vec::new();
            for (index, (record, automatic_reply)) in pending.iter().enumerate() {
                if !matched(turn, record)? {
                    continue;
                }
                let turn_id = turn["id"]
                    .as_str()
                    .context("missing native turn ID")?
                    .to_owned();
                ensure!(
                    crate::integration::wake::valid_thread(&turn_id),
                    "invalid native turn ID"
                );
                let result = async {
                    agent(
                        home,
                        credential,
                        AgentOp::WakeDirectObserve {
                            message_id: record.message_id.clone(),
                            attempt_id: record.attempt_id.clone(),
                            target: target.clone(),
                            turn_id: turn_id.clone(),
                        },
                    )
                    .await?;
                    if *automatic_reply && let Some(text) = answer(turn)? {
                        agent(
                            home,
                            credential,
                            AgentOp::WakeDirectComplete {
                                message_id: record.message_id.clone(),
                                attempt_id: record.attempt_id.clone(),
                                target: target.clone(),
                                turn_id,
                                text,
                            },
                        )
                        .await?;
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                failed |= result.is_err();
                handled.push(index);
            }
            for index in handled.into_iter().rev() {
                pending.remove(index);
            }
        }
        if pending.is_empty() || page["nextCursor"].is_null() {
            break;
        }
        let next = page["nextCursor"].as_str().context("invalid turn cursor")?;
        ensure!(
            !next.is_empty() && next.len() <= 512 && cursor != next,
            "invalid native pagination"
        );
        cursor = json!(next);
    }
    ensure!(!failed, "one or more native replies could not be collected");
    Ok(())
}

#[cfg(test)]
mod tests;
