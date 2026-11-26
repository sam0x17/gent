//! Verify the later of two inputs to a drained queue turn. The caller checks
//! its client ID and text digest against the direct delivery journal.
use super::*;

fn identity<'a>(p: &'a Event, thread: &str, turn: &Completed) -> Option<(&'a str, &'a str, i64)> {
    let item = p.item.as_ref()?;
    let at = p.completed_at_ms?;
    (p.r#type == "item_completed"
        && p.thread_id.as_deref() == Some(thread)
        && p.turn_id.as_ref() == Some(&turn.id)
        && item.r#type == "UserMessage"
        && (turn.started..=turn.ended).contains(&at.div_euclid(1000)))
    .then_some((
        item.id.as_deref().filter(|s| !s.is_empty())?,
        item.client_id.as_deref().filter(|s| !s.is_empty())?,
        at,
    ))
}

pub(super) fn confirm(
    rows: &ReverseLines<'_>,
    position: u64,
    initial: &Event,
    thread: &str,
    turn: &Completed,
) -> Result<Option<DirectInput>> {
    let Some((first_item, first_client, first_at)) = identity(initial, thread, turn) else {
        return Ok(None);
    };
    // Revisit just the later receipt and its adjacent response. A single-input
    // queue turn incurs no additional reads or decoding of user text.
    let mut cursor = ReverseLines {
        file: rows.file,
        floor: rows.floor,
        offset: position,
        end: 0,
        block: vec![0; rows.block.len()],
    };
    let mut line = Vec::new();
    if !cursor.previous(&mut line)? {
        return Ok(None);
    }
    let receipt: Record<Event> = serde_json::from_slice(&line)?;
    let Some((item, client, at)) = identity(&receipt.payload, thread, turn) else {
        return Ok(None);
    };
    if receipt.r#type != "event_msg"
        || item == first_item
        || client == first_client
        || at <= first_at
    {
        return Ok(None);
    }
    let Some(hash) = input_hash(&line, true) else {
        return Ok(None);
    };
    if !cursor.previous(&mut line)? {
        return Ok(None);
    }
    let turn_id = Uuid::parse_str(&turn.id)?;
    let row: Record<Event> = serde_json::from_slice(&line)?;
    let p = row.payload;
    if crate::wake::codex::ordinary::user_source(&line, thread, turn_id, client).is_none()
        || !p
            .internal_chat_message_metadata_passthrough
            .as_ref()
            .is_some_and(|m| {
                m.turn_id.as_ref() == Some(&turn.id)
                    && m.content_item_kinds
                        .as_deref()
                        .is_some_and(|k| k == ["user.text"])
            })
        || input_hash(&line, false).as_ref() != Some(&hash)
    {
        return Ok(None);
    }
    Ok(Some(DirectInput {
        completed_relay: true,
        turn: turn_id,
        client: client.into(),
        hash,
    }))
}
