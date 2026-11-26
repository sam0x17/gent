//! Recheck the machine-origin turn envelope after the first pass has bound
//! its sole user text to the adjacent scoped receipt.
use super::*;

impl Row {
    fn direct_work(&self, thread: &str, turn: &str) -> bool {
        let p = &self.payload;
        self.work(thread, turn)
            || (self.r#type == "event_msg"
                && p.r#type.as_deref() == Some("item_completed")
                && p.thread_id.as_deref() == Some(thread)
                && p.turn_id.as_deref() == Some(turn)
                && p.within(thread, turn)
                && p.item.as_ref().is_some_and(|i| {
                    matches!(
                        i.r#type.as_deref(),
                        Some("McpToolCall" | "CollabAgentToolCall")
                    ) && matches!(i.status.as_deref(), Some("completed" | "failed"))
                        && i.id.as_ref().is_some_and(|id| !id.is_empty())
                        && !i.name.as_deref().is_some_and(decision)
                        && i.within(thread, turn)
                }))
    }
}

pub(super) fn work(
    row: &Row,
    rows: &mut ReverseLines<'_>,
    line: &mut Vec<u8>,
    failed: &Failed,
    turn: &str,
    inputs: &mut &[ForegroundInput],
) -> Result<bool> {
    if !babysit::rollout::ordinary_work(line, &failed.thread, turn)? {
        return Ok(false);
    }
    if row.direct_work(&failed.thread, turn) {
        return Ok(true);
    }
    let p = &row.payload;
    let Some(item) = p
        .item
        .as_ref()
        .filter(|i| i.r#type.as_deref() == Some("UserMessage"))
    else {
        return Ok(false);
    };
    let Some((expected, rest)) = inputs.split_first() else {
        return Ok(false);
    };
    let client = expected.client.to_string();
    if row.r#type != "event_msg"
        || p.r#type.as_deref() != Some("item_completed")
        || p.thread_id.as_ref() != Some(&failed.thread)
        || p.turn_id.as_deref() != Some(turn)
        || !p.within(&failed.thread, turn)
        || p.client_id.as_ref().is_some_and(|id| id != &client)
        || item.client_id.as_ref() != Some(&client)
        || !item.within(&failed.thread, turn)
        || !rows.previous(line)?
        || !babysit::rollout::ordinary_work(line, &failed.thread, turn)?
        || user_source(line, &failed.thread, failed.turn, &client).is_none()
        || !serde_json::from_slice::<Row>(line)?
            .payload
            .internal_chat_message_metadata_passthrough
            .and_then(|m| m.content_item_kinds)
            .is_some_and(|kinds| kinds == ["user.text"])
    {
        return Ok(false);
    }
    *inputs = rest;
    Ok(true)
}
