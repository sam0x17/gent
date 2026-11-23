//! Prove one completed queue admission between the failed turn and the current head.
use super::*;

#[derive(Default, Deserialize)]
#[serde(default)]
struct Event {
    r#type: String,
    thread_id: Option<String>,
    turn_id: Option<String>,
    started_at: Option<i64>,
    completed_at_ms: Option<i64>,
    turn_attribution: Option<Attribution>,
    role: Option<String>,
    namespace: Option<String>,
    name: Option<String>,
    call_id: Option<String>,
    item: Option<Item>,
    internal_chat_message_metadata_passthrough: Option<ItemMeta>,
}

#[derive(Deserialize)]
struct Item {
    r#type: String,
    client_id: Option<String>,
    id: Option<String>,
    tool: Option<String>,
    source: Option<String>,
    status: Option<String>,
    questions: Option<serde::de::IgnoredAny>,
}

impl Event {
    fn belongs_to(&self, thread: &str, turn: &str) -> bool {
        self.thread_id.as_deref().is_none_or(|id| id == thread)
            && self.turn_id.as_deref().is_none_or(|id| id == turn)
            && self
                .internal_chat_message_metadata_passthrough
                .as_ref()
                .is_none_or(|m| m.turn_id.as_deref().is_none_or(|id| id == turn))
    }

    fn starts(&self, turn: &Completed, trigger: &str) -> bool {
        self.turn_id.as_deref() == Some(&turn.id)
            && self.started_at == Some(turn.started)
            && self.turn_attribution.as_ref().is_some_and(|a| {
                a.turn_id.as_deref() == Some(&turn.id) && a.turn_trigger.as_deref() == Some(trigger)
            })
    }
}

fn passive_tool(name: &str) -> bool {
    matches!(
        name,
        "get_goal"
            | "functions.get_goal"
            | "functions__get_goal"
            | "clock.curr_time"
            | "clock__curr_time"
    )
}

fn decision(name: &str) -> bool {
    let name = name.rsplit(['.', ':']).next().unwrap_or(name);
    matches!(
        name.rsplit("__").next(),
        Some(
            "create_goal"
                | "update_goal"
                | "request_user_input"
                | "request_user_input_async"
                | "send_message_to_user_async"
                | "send_user_message_async"
        )
    )
}

#[derive(Default)]
struct Admission {
    user_message: bool,
    client_id: Option<String>,
    // Outputs occur first when walking backwards. Every call must consume its
    // own output. An incomplete wrapper inventory needs independent evidence
    // that execution began after the live goal's last mutation second.
    needs_later_start: bool,
    outputs: std::collections::HashMap<String, bool>,
}

impl Admission {
    fn item(&mut self, item: Item) -> bool {
        if item.questions.is_some() {
            return false;
        }
        match item.r#type.as_str() {
            "UserMessage" => {
                let Some(id) = item.client_id.filter(|id| !id.is_empty()) else {
                    return false;
                };
                self.client_id.replace(id).is_none() && !self.user_message
            }
            "AgentMessage" | "Reasoning" | "Plan" | "WebSearch" => true,
            "CommandExecution" => {
                self.needs_later_start = true;
                item.status.as_deref() == Some("completed")
                    && item.id.is_some_and(|id| !id.is_empty())
                    && matches!(
                        item.source.as_deref(),
                        Some("agent" | "unified_exec_startup" | "unified_exec_interaction")
                    )
            }
            "McpToolCall" => {
                self.needs_later_start = true;
                item.status.as_deref() == Some("completed")
                    && item.id.is_some_and(|id| !id.is_empty())
                    && item
                        .tool
                        .is_some_and(|name| !name.is_empty() && !decision(&name))
            }
            _ => false,
        }
    }

    fn response(&mut self, p: Event, id: &str) -> bool {
        let meta = p.internal_chat_message_metadata_passthrough.as_ref();
        match p.r#type.as_str() {
            "message" if p.role.as_deref() == Some("user") => {
                let Some(meta) = meta else { return false };
                let Some(kinds) = &meta.content_item_kinds else {
                    return false;
                };
                if meta.turn_id.as_deref() != Some(id) || kinds.is_empty() {
                    return false;
                }
                if kinds.iter().all(|kind| {
                    matches!(
                        kind.as_str(),
                        "user.text" | "user.image" | "user.audio" | "user.file"
                    )
                }) {
                    self.client_id.is_some() && !std::mem::replace(&mut self.user_message, true)
                } else {
                    kinds
                        .iter()
                        .all(|kind| kind == "environments.environment_context")
                }
            }
            "message" => p.role.as_deref() == Some("assistant"),
            "reasoning" | "web_search_call" => true,
            "function_call" | "custom_tool_call" => {
                let Some(name) = p.name.as_deref() else {
                    return false;
                };
                let Some(complete) = p.call_id.and_then(|id| self.outputs.remove(&id)) else {
                    return false;
                };
                if p.namespace.as_deref().is_some_and(|ns| ns != "functions") {
                    return false;
                }
                if matches!(
                    name,
                    "exec"
                        | "wait"
                        | "functions.exec"
                        | "functions.wait"
                        | "functions__exec"
                        | "functions__wait"
                ) {
                    self.needs_later_start |= !complete;
                    true
                } else {
                    passive_tool(name)
                }
            }
            "function_call_output" | "custom_tool_call_output" => {
                let Some(call_id) = p.call_id.filter(|id| !id.is_empty()) else {
                    return false;
                };
                let complete = meta.is_some_and(|m| {
                    m.turn_id.as_deref() == Some(id)
                        && m.tool_calls_complete == Some(true)
                        && m.executed_tool_calls
                            .as_ref()
                            .is_some_and(|calls| calls.iter().all(|t| passive_tool(&t.name)))
                });
                self.outputs.insert(call_id, complete).is_none()
            }
            _ => false,
        }
    }
}

pub(super) fn confirm(
    rows: &mut ReverseLines<'_>,
    line: &mut Vec<u8>,
    thread: &str,
    turn: &Completed,
    admissions: &mut HashSet<String>,
    updated_at: Option<i64>,
) -> Result<bool> {
    let mut admission = Admission::default();
    while rows.previous(line)? {
        let row: Record<Event> = serde_json::from_slice(line)?;
        let p = row.payload;
        if !p.belongs_to(thread, &turn.id)
            || p.internal_chat_message_metadata_passthrough
                .as_ref()
                .is_some_and(|m| {
                    m.content_item_kinds
                        .iter()
                        .flatten()
                        .any(|k| k == "user.goal")
                        || m.executed_tool_calls
                            .iter()
                            .flatten()
                            .any(|t| decision(&t.name))
                })
        {
            return Ok(false);
        }
        let valid = match (row.r#type.as_str(), p.r#type.as_str()) {
            ("event_msg", "task_started") => {
                return Ok(p.starts(turn, "queue")
                    && (!admission.needs_later_start
                        || updated_at.is_some_and(|t| turn.started > t))
                    && admission.user_message
                    && admission.outputs.is_empty()
                    && admission.client_id.is_some_and(|id| admissions.insert(id)));
            }
            ("event_msg", "item_completed") => {
                p.thread_id.as_deref() == Some(thread)
                    && p.turn_id.as_ref() == Some(&turn.id)
                    && p.item.is_some_and(|item| {
                        // Codex records a model tool call before dispatching it.
                        // Only an earlier, host-timed receipt in this same turn
                        // may clear the uncertainty of a later opaque call.
                        if matches!(item.r#type.as_str(), "Reasoning" | "UserMessage")
                            && let (Some(ms), Some(updated)) = (p.completed_at_ms, updated_at)
                            && (turn.started..=turn.ended).contains(&ms.div_euclid(1000))
                            && ms.div_euclid(1000) > updated
                        {
                            admission.needs_later_start = false;
                        }
                        admission.item(item)
                    })
            }
            ("event_msg", "token_count") | ("world_state", "") => true,
            ("token_usage_record", "") => {
                p.thread_id.as_deref() == Some(thread) && p.turn_id.as_ref() == Some(&turn.id)
            }
            ("turn_context", "") => p.turn_id.as_ref() == Some(&turn.id),
            ("response_item", _) => admission.response(p, &turn.id),
            _ => false,
        };
        if !valid {
            return Ok(false);
        }
    }
    Ok(false)
}

// An external active setter resets Codex's consecutive-empty-turn counter.
// Its immediate, successful, tool-free goal turn cannot reach the three-turn
// empty-response or execution-failure block. The unbudgeted goal also cannot
// stop on budget. Require the setter itself, including its thread identity.
pub(super) fn preceding_active_turn(
    rows: &mut ReverseLines<'_>,
    line: &mut Vec<u8>,
    goal: &Goal,
    failed: &Completed,
) -> Result<bool> {
    if goal.token_budget.is_some() || !rows.previous(line)? {
        return Ok(false);
    }
    let row: Record = serde_json::from_slice(line)?;
    let p = row.payload;
    let (Some(id), Some(started), Some(ended)) = (p.turn_id, p.started_at, p.completed_at) else {
        return Ok(false);
    };
    let prior = Completed { id, started, ended };
    if row.r#type != "event_msg"
        || p.r#type != "task_complete"
        || p.error.is_some()
        || !Uuid::parse_str(&prior.id).is_ok_and(|id| !id.is_nil())
        || prior.id == failed.id
        || started < goal.created_at
        || started > ended
        || ended > failed.started
    {
        return Ok(false);
    }
    let mut agent_message = false;
    while rows.previous(line)? {
        let row: Record<Event> = serde_json::from_slice(line)?;
        let p = row.payload;
        let meta = p.internal_chat_message_metadata_passthrough.as_ref();
        if !p.belongs_to(&goal.thread_id, &prior.id)
            || meta.is_some_and(|m| m.executed_tool_calls.is_some())
        {
            return Ok(false);
        }
        let valid = match (row.r#type.as_str(), p.r#type.as_str()) {
            ("event_msg", "task_started") => {
                if !agent_message || !p.starts(&prior, "goal") || !rows.previous(line)? {
                    return Ok(false);
                }
                let setter: Record = serde_json::from_slice(line)?;
                return Ok(setter.r#type == "event_msg"
                    && setter.payload.r#type == "thread_goal_updated"
                    && setter.payload.goal_thread.as_deref() == Some(&goal.thread_id)
                    && setter.payload.goal_turn.is_none()
                    && setter
                        .payload
                        .goal
                        .is_some_and(|g| same_active(&g, goal) && g.updated_at <= started));
            }
            ("event_msg", "item_completed") => {
                let ordinary = p.thread_id.as_ref() == Some(&goal.thread_id)
                    && p.turn_id.as_ref() == Some(&prior.id)
                    && p.item
                        .is_some_and(|it| it.r#type == "AgentMessage" && it.questions.is_none());
                agent_message |= ordinary;
                ordinary
            }
            ("response_item", "message") => match p.role.as_deref() {
                Some("assistant") => true,
                role => meta
                    .and_then(|m| m.content_item_kinds.as_ref())
                    .is_some_and(|kinds| {
                        !kinds.is_empty()
                            && kinds.iter().all(|k| {
                                matches!(
                                    (role, k.as_str()),
                                    (
                                        Some("developer"),
                                        "host_skills.instructions" | "permissions.instructions"
                                    ) | (
                                        Some("user"),
                                        "goal.internal_context"
                                            | "environments.environment_context"
                                    )
                                )
                            })
                    }),
            },
            ("response_item", "function_call_output") => {
                p.name.as_deref() == Some("goal_objective")
                    && p.namespace.as_deref() == Some("agent")
                    && p.call_id.is_none()
            }
            ("turn_context", "") => p.turn_id.as_ref() == Some(&prior.id),
            ("token_usage_record", "") => {
                p.thread_id.as_ref() == Some(&goal.thread_id)
                    && p.turn_id.as_ref() == Some(&prior.id)
            }
            ("event_msg", "thread_settings_applied") => {
                p.thread_id.as_ref() == Some(&goal.thread_id)
            }
            ("event_msg", "token_count") | ("world_state", "") => true,
            _ => false,
        };
        if !valid {
            return Ok(false);
        }
    }
    Ok(false)
}
