//! Nested tools use separate receipt IDs. Bind them to an uninterrupted,
//! completed native exec call and its matching output in the failed root.
use super::*;

#[derive(Default)]
pub(super) struct Work {
    calls: HashSet<String>,
    receipts: HashSet<Uuid>,
}

fn scoped(fields: &Fields, failed: &Failed, turn: &str) -> bool {
    fields.within(&failed.thread, turn)
        && fields
            .internal_chat_message_metadata_passthrough
            .as_ref()
            .is_some_and(|m| m.turn_id.as_deref() == Some(turn))
}

fn receipt(item: &Fields, thread: &str) -> Option<Uuid> {
    if item.status.as_deref() != Some("completed") || item.questions.is_some() {
        return None;
    }
    let accepted = match item.r#type.as_deref()? {
        "CollabAgentToolCall" => {
            item.tool.as_deref() == Some("send_input")
                && item.sender_thread_id.as_deref() == Some(thread)
                && item.receiver_thread_ids.as_deref().is_some_and(
                    |ids| matches!(ids, [id] if id != thread && canonical_uuid(id).is_some()),
                )
        }
        "McpToolCall" => {
            item.server.as_deref() == Some("gent")
                && matches!(
                    item.tool.as_deref()?,
                    "gent_message_status"
                        | "gent_resolve"
                        | "gent_request_ids"
                        | "gent_send_non_blocking"
                )
        }
        _ => false,
    };
    if !accepted {
        return None;
    }
    canonical_uuid(item.id.as_deref()?.strip_prefix("exec-")?)
}

impl Work {
    pub(super) fn has_nested(&self) -> bool {
        !self.receipts.is_empty()
    }

    pub(super) fn group(
        &mut self,
        output: &Row,
        rows: &mut ReverseLines<'_>,
        line: &mut Vec<u8>,
        failed: &Failed,
        deadline: Instant,
    ) -> Result<bool> {
        let p = &output.payload;
        if output.r#type != "response_item"
            || p.r#type.as_deref() != Some("custom_tool_call_output")
            || p.name.is_some()
            || p.namespace.is_some()
            || p.id.as_deref().is_none_or(str::is_empty)
        {
            return Ok(false);
        }
        let Some(call) = p.call_id.as_deref().filter(|id| !id.is_empty()) else {
            return Ok(false);
        };
        let turn = failed.turn.to_string();
        if self.calls.len() >= MAX_CHAT_INPUTS
            || self.calls.contains(call)
            || !scoped(p, failed, &turn)
        {
            return Ok(false);
        }
        let mut group = rows.clone();
        let mut nested = HashSet::new();
        while Instant::now() < deadline {
            let Some(row) = Row::next(&mut group, line)? else {
                break;
            };
            let p = &row.payload;
            if row.r#type == "response_item" && p.r#type.as_deref() == Some("custom_tool_call") {
                if p.call_id.as_deref() != Some(call)
                    || p.name.as_deref() != Some("exec")
                    || p.namespace.is_some()
                    || p.status.as_deref() != Some("completed")
                    || !scoped(p, failed, &turn)
                {
                    break;
                }
                self.calls.insert(call.to_owned());
                self.receipts.extend(nested);
                *rows = group;
                return Ok(true);
            }
            if p.thread_id.as_deref() != Some(&failed.thread)
                || p.turn_id.as_deref() != Some(&turn)
                || !p.within(&failed.thread, &turn)
            {
                break;
            }
            if row.r#type == "token_usage_record" {
                continue;
            }
            if row.r#type != "event_msg"
                || p.r#type.as_deref() != Some("item_completed")
                || !p
                    .item
                    .as_ref()
                    .is_some_and(|i| i.within(&failed.thread, &turn))
                || !p
                    .started_at_ms
                    .zip(p.completed_at_ms)
                    .is_some_and(|(a, b)| {
                        a <= b
                            && a.div_euclid(1000) >= failed.started
                            && b.div_euclid(1000) <= failed.ended
                    })
            {
                break;
            }
            let Some(item) = p.item.as_deref() else { break };
            if item.r#type.as_deref() == Some("CommandExecution")
                && item.questions.is_none()
                && row.work(&failed.thread, &turn)
            {
                continue;
            }
            let Some(id) = receipt(item, &failed.thread) else {
                break;
            };
            if self.receipts.len() + nested.len() >= MAX_CHAT_INPUTS
                || self.receipts.contains(&id)
                || !nested.insert(id)
            {
                break;
            }
        }
        Ok(false)
    }
}
