//! A scoped tool declaration and its corresponding world-state delta may
//! precede the native turn context. The delta lists the newly declared tools.
use super::*;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Record<T> {
    payload: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delta {
    full: bool,
    state: State,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    top_level_tools: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    #[serde(rename = "type")]
    kind: String,
    role: String,
    id: String,
    tools: Vec<Namespace>,
}

#[derive(Deserialize)]
struct Namespace {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    tools: Vec<Definition>,
}
#[derive(Deserialize)]
struct Definition {
    #[serde(rename = "type")]
    kind: String,
    name: String,
}

pub(super) fn start(
    rows: &mut ReverseLines<'_>,
    line: &mut Vec<u8>,
    thread: &str,
    turn: &str,
) -> Result<Option<Row>> {
    let Some(row) = Row::next(rows, line)? else {
        return Ok(None);
    };
    if row.r#type != "world_state" {
        return Ok(Some(row));
    }
    declared_start(rows, line, thread, turn)
}

// Probe from the world-state row without consuming any ordinary proof records.
// An unfamiliar row can still contribute to the ordinary reader's result.
pub(in crate::wake::codex::ordinary::proof) fn foreground_start(
    rows: &ReverseLines<'_>,
    line: &mut Vec<u8>,
    thread: &str,
    turn: &str,
) -> bool {
    matches!(declared_start(&mut rows.clone(), line, thread, turn), Ok(Some(start))
        if start.r#type == "event_msg"
            && start.payload.r#type.as_deref() == Some("task_started")
            && start.payload.turn_id.as_deref() == Some(turn))
}

fn declared_start(
    rows: &mut ReverseLines<'_>,
    line: &mut Vec<u8>,
    thread: &str,
    turn: &str,
) -> Result<Option<Row>> {
    let Ok(delta) = serde_json::from_slice::<Record<Delta>>(line) else {
        return Ok(None);
    };
    let mut tools = delta.payload.state.top_level_tools;
    if delta.payload.full
        || tools.is_empty()
        || !tools
            .values()
            .all(|v| v.len() == 40 && v.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Ok(None);
    }
    if !Row::next(rows, line)?.is_some_and(|r| r.r#type == "response_item") {
        return Ok(None);
    }
    let Ok(declaration) = serde_json::from_slice::<Record<Declaration>>(line) else {
        return Ok(None);
    };
    let d = declaration.payload;
    if d.kind != "additional_tools"
        || d.role != "developer"
        || d.id.is_empty()
        || d.tools.is_empty()
    {
        return Ok(None);
    }
    for ns in d.tools {
        if ns.kind != "namespace" || ns.name.is_empty() || ns.tools.is_empty() {
            return Ok(None);
        }
        for tool in ns.tools {
            if !matches!(tool.kind.as_str(), "custom" | "function")
                || tool.name.is_empty()
                || tools
                    .remove(&format!("{}.{}", ns.name, tool.name))
                    .is_none()
            {
                return Ok(None);
            }
        }
    }
    if !tools.is_empty() {
        return Ok(None);
    }
    let Some(update) = Row::next(rows, line)? else {
        return Ok(None);
    };
    let p = update.payload;
    if update.r#type != "response_item"
        || p.r#type.as_deref() != Some("message")
        || p.role.as_deref() != Some("developer")
        || p.id.as_deref().is_none_or(str::is_empty)
        || p.call_id.is_some()
        || !p.within(thread, turn)
        || !p
            .internal_chat_message_metadata_passthrough
            .is_some_and(|m| {
                m.turn_id.as_deref() == Some(turn)
                    && m.content_item_kinds
                        .as_deref()
                        .is_some_and(|k| k == ["tools.incremental_update"])
                    && m.executed_tool_calls
                        .as_deref()
                        .is_none_or(|calls| calls.is_empty())
            })
    {
        return Ok(None);
    }
    Row::next(rows, line)
}
