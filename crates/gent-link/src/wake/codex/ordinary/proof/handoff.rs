//! A first, named host input may open its own root. The receipt identifies
//! the receiving item, without making a claim about the sender.
use super::*;
use crate::wake::codex::babysit::rollout::decision;

#[derive(Deserialize)]
struct Row {
    r#type: String,
    payload: Fields,
}

#[derive(Default, Deserialize)]
struct Fields {
    r#type: Option<String>,
    id: Option<String>,
    namespace: Option<String>,
    name: Option<String>,
    call_id: Option<String>,
    role: Option<String>,
    source: Option<String>,
    status: Option<String>,
    thread_id: Option<String>,
    turn_id: Option<String>,
    root_turn_id: Option<String>,
    item: Option<Box<Fields>>,
    internal_chat_message_metadata_passthrough: Option<Scope>,
}

#[derive(Deserialize)]
struct Scope {
    turn_id: Option<String>,
    thread_id: Option<String>,
    executed_tool_calls: Option<Vec<Tool>>,
    content_item_kinds: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Tool {
    name: String,
}

impl Fields {
    fn within(&self, thread: &str, turn: &str) -> bool {
        self.thread_id.as_deref().is_none_or(|id| id == thread)
            && self.turn_id.as_deref().is_none_or(|id| id == turn)
            && self.root_turn_id.as_deref().is_none_or(|id| id == turn)
            && self
                .internal_chat_message_metadata_passthrough
                .as_ref()
                .is_none_or(|m| {
                    m.thread_id.as_deref().is_none_or(|id| id == thread)
                        && m.turn_id.as_deref().is_none_or(|id| id == turn)
                        && !m
                            .executed_tool_calls
                            .iter()
                            .flatten()
                            .any(|tool| decision(&tool.name))
                        && !m
                            .content_item_kinds
                            .iter()
                            .flatten()
                            .any(|kind| kind == "user.goal")
                })
    }

    fn named(&self) -> bool {
        self.namespace.as_deref() == Some("codex_tui")
            && self.name.as_deref() == Some("send_message_to_thread")
            && self.call_id.is_none()
    }
}

impl Row {
    fn next(rows: &mut ReverseLines<'_>, line: &mut Vec<u8>) -> Result<Option<Self>> {
        if !rows.previous(line)? {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(line)?))
    }

    // Later native input, controls, decisions and unfamiliar activity close this path.
    fn work(&self, thread: &str, turn: &str, after_terminal: bool) -> bool {
        let p = &self.payload;
        let scoped = p.thread_id.as_deref() == Some(thread) && p.turn_id.as_deref() == Some(turn);
        p.within(thread, turn)
            && match (self.r#type.as_str(), p.r#type.as_deref()) {
                ("token_usage_record", _) => scoped,
                ("event_msg", Some("token_count")) | ("response_item", Some("reasoning")) => true,
                ("event_msg", Some("item_completed")) => {
                    scoped
                        && p.item.as_ref().is_some_and(|i| {
                            i.within(thread, turn)
                                && match i.r#type.as_deref() {
                                    Some("AgentMessage" | "Reasoning") => true,
                                    Some("FileChange") => i.status.as_deref() == Some("completed"),
                                    Some("CommandExecution") => {
                                        (i.status.as_deref() == Some("completed")
                                            || (after_terminal
                                                && i.status.as_deref() == Some("failed")))
                                            && matches!(
                                                i.source.as_deref(),
                                                Some(
                                                    "agent"
                                                        | "unified_exec_startup"
                                                        | "unified_exec_interaction"
                                                )
                                            )
                                    }
                                    _ => false,
                                }
                        })
                }
                ("response_item", Some("message")) => p.role.as_deref() == Some("assistant"),
                (
                    "response_item",
                    Some(
                        "function_call"
                        | "custom_tool_call"
                        | "function_call_output"
                        | "custom_tool_call_output",
                    ),
                ) => {
                    p.call_id.as_deref().is_some_and(|id| !id.is_empty())
                        && !p.name.as_deref().is_some_and(decision)
                }
                _ => false,
            }
    }
}

// This replay only runs after the ordinary reader reached the same proven
// task_started without finding user input. It shares that reader's time budget.
pub(super) fn read(
    file: &File,
    stamp: &Stamp,
    failed: &Failed,
    deadline: Instant,
) -> Result<Option<Uuid>> {
    let mut rows = ReverseLines::new(file, stamp.len, true)?;
    let mut line = Vec::new();
    let turn = failed.turn.to_string();
    // The first pass checked the exact terminal error and the strict tail receipt format.
    // In a machine-origin turn, a tail command must also have a non-human source.
    loop {
        if Instant::now() >= deadline {
            return Ok(None);
        }
        let Some(row) = Row::next(&mut rows, &mut line)? else {
            return Ok(None);
        };
        if row.r#type == "event_msg" && row.payload.r#type.as_deref() == Some("task_complete") {
            break;
        }
        if !terminal_command(&line, &failed.thread, failed.turn)
            || !row.work(&failed.thread, &turn, true)
        {
            return Ok(None);
        }
    }
    while Instant::now() < deadline {
        let Some(row) = Row::next(&mut rows, &mut line)? else {
            break;
        };
        if row.work(&failed.thread, &turn, false) {
            continue;
        }
        let p = row.payload;
        if row.r#type != "event_msg"
            || p.r#type.as_deref() != Some("item_completed")
            || p.thread_id.as_deref() != Some(&failed.thread)
            || p.turn_id.as_ref() != Some(&turn)
            || !p.within(&failed.thread, &turn)
        {
            break;
        }
        let Some(item) = p.item.filter(|i| {
            i.r#type.as_deref() == Some("FunctionCallOutput")
                && i.named()
                && i.within(&failed.thread, &turn)
        }) else {
            break;
        };
        let Some(id) = item
            .id
            .as_deref()
            .and_then(|s| s.strip_prefix("fco_"))
            .and_then(|s| Uuid::parse_str(s).ok())
            .filter(|id| !id.is_nil())
        else {
            break;
        };
        let Some(response) = Row::next(&mut rows, &mut line)? else {
            break;
        };
        let r = response.payload;
        if response.r#type != "response_item"
            || r.r#type.as_deref() != Some("function_call_output")
            || !r.named()
            || !r.within(&failed.thread, &turn)
            || r.id != item.id
            || r.id != Some(format!("fco_{id}"))
            || !r
                .internal_chat_message_metadata_passthrough
                .is_some_and(|m| m.turn_id.as_ref() == Some(&turn))
        {
            break;
        }
        let Some(context) = Row::next(&mut rows, &mut line)? else {
            break;
        };
        if context.r#type != "turn_context"
            || !context.payload.within(&failed.thread, &turn)
            || context.payload.turn_id.as_ref() != Some(&turn)
            || context.payload.root_turn_id.as_ref() != Some(&turn)
        {
            break;
        }
        let Some(start) = Row::next(&mut rows, &mut line)? else {
            break;
        };
        if start.r#type == "event_msg"
            && start.payload.r#type.as_deref() == Some("task_started")
            && start.payload.within(&failed.thread, &turn)
            && start.payload.turn_id.as_ref() == Some(&turn)
            && Instant::now() < deadline
            && stamp.matches(&failed.path)?
        {
            return Ok(Some(id));
        }
        break;
    }
    Ok(None)
}
