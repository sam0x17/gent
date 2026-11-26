//! Bind a native user admission to the records between its start and completion.
use super::*;

#[derive(Default, Deserialize)]
#[serde(default)]
struct Event {
    r#type: String,
    thread_id: Option<String>,
    turn_id: Option<String>,
    started_at: Option<i64>,
    started_at_ms: Option<i64>,
    completed_at_ms: Option<i64>,
    turn_attribution: Option<Attribution>,
    role: Option<String>,
    namespace: Option<String>,
    name: Option<String>,
    call_id: Option<String>,
    id: Option<String>,
    item: Option<Item>,
    internal_chat_message_metadata_passthrough: Option<ItemMeta>,
}

#[derive(Deserialize)]
struct Item {
    r#type: String,
    client_id: Option<String>,
    kind: Option<String>,
    #[serde(rename = "durationMs")]
    duration_ms: Option<u64>,
    id: Option<String>,
    tool: Option<String>,
    source: Option<String>,
    status: Option<String>,
    questions: Option<serde::de::IgnoredAny>,
    name: Option<String>,
    namespace: Option<String>,
    internal_chat_message_metadata_passthrough: Option<ItemMeta>,
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

    fn starts(&self, turn: &Completed, trigger: Option<&str>) -> bool {
        self.turn_id.as_deref() == Some(&turn.id)
            && self.started_at == Some(turn.started)
            && self.turn_attribution.as_ref().is_some_and(|a| {
                a.turn_id.as_deref() == Some(&turn.id) && a.turn_trigger.as_deref() == trigger
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

pub(super) enum Source<'a> {
    Queue(&'a mut queued_exec::Queue, Option<&'a Completed>),
    Foreground,                       // terminal recognized failure
    Direct(&'a mut Vec<DirectInput>), // completed, needs a matching journal entry
}

fn has_decision(meta: &ItemMeta) -> bool {
    meta.content_item_kinds
        .iter()
        .flatten()
        .any(|k| k == "user.goal")
        || meta
            .executed_tool_calls
            .iter()
            .flatten()
            .any(|t| decision(&t.name))
}

fn thread_message_result(namespace: Option<&str>, name: Option<&str>) -> bool {
    namespace == Some("codex_tui") && name == Some("send_message_to_thread")
}

#[derive(Default)]
struct Admission {
    // A host-delivered thread result has no in-turn invocation. Bind its
    // response item to the same named native receipt before accepting it.
    thread_result: Option<Option<String>>,
    thread_result_receipt: Option<String>,
    user_message: bool,
    user_receipt: bool,
    client_id: Option<String>,
    // Outputs occur first when walking backwards. Every call must consume its
    // own output. An incomplete wrapper inventory needs independent evidence
    // that execution began after the live goal's last mutation second.
    outputs: std::collections::HashMap<String, Output>,
    exec: queued_exec::Turn,
    sleeps: HashSet<String>,
    work_ms: Option<(i64, i64)>,
}

struct Output {
    complete: bool,
    scoped_exec: bool,
    scoped_function: bool,
}

impl Admission {
    fn work(&mut self, start_ms: Option<i64>) {
        // Without an execution timestamp only the ordinary admission or an
        // earlier in-turn reasoning/user receipt can establish the ordering.
        let start = start_ms.unwrap_or(i64::MIN);
        self.work_ms = Some(self.work_ms.map_or((start, start), |(first, last)| {
            (first.min(start), last.max(start))
        }));
    }

    fn timed_receipt(&mut self) {
        self.work_ms = None;
    }

    fn item(&mut self, item: Item, foreground: bool, turn: &str, started_ms: Option<i64>) -> bool {
        if item.questions.is_some()
            || item
                .internal_chat_message_metadata_passthrough
                .as_ref()
                .is_some_and(|m| {
                    has_decision(m) || m.turn_id.as_deref().is_some_and(|id| id != turn)
                })
        {
            return false;
        }
        match item.r#type.as_str() {
            "UserMessage" => {
                self.client_id = item.client_id.filter(|id| !id.is_empty());
                !std::mem::replace(&mut self.user_receipt, true) && !self.user_message
            }
            "AgentMessage" | "Reasoning" | "Plan" | "WebSearch" => true,
            "CommandExecution" => {
                self.work(started_ms);
                (item.status.as_deref() == Some("completed")
                    || !foreground && item.status.as_deref() == Some("failed"))
                    && item.id.is_some_and(|id| !id.is_empty())
                    && matches!(
                        item.source.as_deref(),
                        Some("agent" | "unified_exec_startup" | "unified_exec_interaction")
                    )
            }
            "FileChange" if !foreground => {
                self.work(started_ms);
                item.status.as_deref() == Some("completed")
                    && item.id.is_some_and(|id| !id.is_empty())
            }
            "Extension" if !foreground && item.kind.as_deref() == Some("clock.sleep") => {
                item.duration_ms.is_some()
                    && item.id.is_some_and(|id| {
                        self.outputs.get(&id).is_some_and(|o| o.scoped_function)
                            && self.sleeps.insert(id)
                    })
            }
            "FunctionCallOutput"
                if foreground
                    && thread_message_result(item.namespace.as_deref(), item.name.as_deref()) =>
            {
                item.id
                    .filter(|id| !id.is_empty())
                    .is_some_and(|id| self.thread_result_receipt.replace(id).is_none())
            }
            "McpToolCall" => {
                self.work(started_ms);
                (item.status.as_deref() == Some("completed")
                    || foreground && item.status.as_deref() == Some("failed"))
                    && item.id.is_some_and(|id| !id.is_empty())
                    && item
                        .tool
                        .is_some_and(|name| !name.is_empty() && !decision(&name))
            }
            _ => false,
        }
    }

    fn response(&mut self, p: Event, id: &str, foreground: bool) -> bool {
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
                    self.user_receipt && !std::mem::replace(&mut self.user_message, true)
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
                let Some(call) = p.call_id.filter(|id| !id.is_empty()) else {
                    return false;
                };
                let Some(output) = self.outputs.remove(&call) else {
                    return false;
                };
                let scoped = meta.is_some_and(|m| m.turn_id.as_deref() == Some(id));
                let paired_exec = p.r#type == "custom_tool_call"
                    && name == "exec"
                    && p.namespace.is_none()
                    && scoped
                    && output.scoped_exec;
                if !foreground && !self.exec.call(&call, paired_exec) {
                    return false;
                }
                if self.sleeps.remove(&call) {
                    return !foreground
                        && scoped
                        && output.scoped_function
                        && p.r#type == "function_call"
                        && p.namespace.as_deref() == Some("clock")
                        && name == "sleep";
                }
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
                    if !output.complete {
                        self.work(
                            meta.filter(|_| scoped)
                                .and_then(|m| m.create_time)
                                .filter(|time| time.is_finite() && *time >= 0.0)
                                .map(|time| (time * 1000.0) as i64),
                        );
                    }
                    true
                } else {
                    passive_tool(name)
                }
            }
            "function_call_output"
                if foreground
                    && thread_message_result(p.namespace.as_deref(), p.name.as_deref()) =>
            {
                self.thread_result.replace(p.id).is_none()
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
                let scoped =
                    p.namespace.is_none() && meta.is_some_and(|m| m.turn_id.as_deref() == Some(id));
                if !foreground
                    && p.r#type == "custom_tool_call_output"
                    && p.id
                        .as_deref()
                        .is_some_and(|item| !self.exec.output_id(item, &call_id))
                {
                    return false;
                }
                if !foreground && p.name.is_some() {
                    return scoped
                        && p.name.as_deref() == Some("exec")
                        && p.r#type == "custom_tool_call_output"
                        && p.id.is_some()
                        && !self.outputs.contains_key(&call_id)
                        && self.exec.supplement(call_id);
                }
                let output = Output {
                    complete,
                    scoped_exec: scoped && p.r#type == "custom_tool_call_output" && p.id.is_some(),
                    scoped_function: scoped
                        && p.r#type == "function_call_output"
                        && p.name.is_none(),
                };
                self.outputs.insert(call_id, output).is_none()
            }
            _ => false,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    #[serde(rename = "type")]
    _kind: String,
    role: String,
    id: String,
    tools: Vec<serde::de::IgnoredAny>,
}

fn developer_kind(p: &Event, turn: &str, kind: &str) -> bool {
    p.r#type == "message"
        && p.role.as_deref() == Some("developer")
        && p.internal_chat_message_metadata_passthrough
            .as_ref()
            .is_some_and(|m| {
                m.turn_id.as_deref() == Some(turn)
                    && m.content_item_kinds
                        .as_ref()
                        .is_some_and(|kinds| kinds.as_slice() == [kind])
            })
}

pub(super) fn confirm(
    rows: &mut ReverseLines<'_>,
    line: &mut Vec<u8>,
    thread: &str,
    turn: &Completed,
    source: Source<'_>,
    updated_at: Option<i64>,
    older: &HashSet<&str>,
) -> Result<bool> {
    let mut admission = Admission::default();
    let foreground = !matches!(source, Source::Queue(..));
    let direct = matches!(source, Source::Direct(_));
    let witness = match &source {
        Source::Queue(_, prior) => *prior,
        _ => None,
    };
    let mut receipt_hash = None;
    let mut message_hash = None;
    let mut needs_declaration = false;
    let mut needs_tool_update = false;
    while rows.previous(line)? {
        let row: Record<Event> = serde_json::from_slice(line)?;
        let p = row.payload;
        // Background completions may arrive during a subsequent turn. Their
        // owner must appear strictly earlier in this very replay, where its
        // independent terminal record will be checked before accepting it.
        if row.r#type == "event_msg"
            && p.r#type == "item_completed"
            && p.turn_id.as_deref().is_some_and(|id| older.contains(id))
            && let Ok(receipt) = serde_json::from_slice::<Record<Receipt>>(line)
            && (receipt.payload.background_turn(thread).is_some()
                || (!foreground
                    && receipt.payload.scoped(thread)
                    && receipt.payload.item.r#type == "CommandExecution"
                    && receipt.payload.item.kind.is_none()
                    && receipt.payload.item.status.as_deref() == Some("failed")
                    && p.item.as_ref().is_some_and(|i| {
                        matches!(
                            i.source.as_deref(),
                            Some("agent" | "unified_exec_startup" | "unified_exec_interaction")
                        )
                    })))
        {
            // A command belonging to the proved earlier turn may finish after
            // this queue starts. Its host clock and the scoped start times of
            // all later opaque work must agree before using it as a witness.
            if let Some(prior) = witness
                && p.turn_id.as_deref() == Some(&prior.id)
                && updated_at == Some(turn.started)
                && receipt.payload.item.r#type == "CommandExecution"
                && let (Some(start), Some(done), Some((first, last))) =
                    (p.started_at_ms, p.completed_at_ms, admission.work_ms)
                && (prior.started..=prior.ended).contains(&start.div_euclid(1000))
                && start <= done
                && done.div_euclid(1000) > turn.started
                && first >= done
                && last.div_euclid(1000) <= turn.ended
            {
                admission.timed_receipt();
            }
            continue;
        }
        if !p.belongs_to(thread, &turn.id)
            || p.internal_chat_message_metadata_passthrough
                .as_ref()
                .is_some_and(has_decision)
        {
            return Ok(false);
        }
        // These adjacent native records describe tool availability, never an
        // execution. Reject lone declarations and unbound developer messages.
        if needs_tool_update {
            if row.r#type != "response_item"
                || !developer_kind(&p, &turn.id, "tools.incremental_update")
            {
                return Ok(false);
            }
            needs_tool_update = false;
            continue;
        }
        if needs_declaration && !(row.r#type == "response_item" && p.r#type == "additional_tools") {
            return Ok(false);
        }
        if row.r#type == "response_item"
            && developer_kind(&p, &turn.id, "tools.deferred_namespaces")
        {
            needs_declaration = true;
            continue;
        }
        if row.r#type == "response_item" && p.r#type == "additional_tools" {
            let Ok(declaration) = serde_json::from_slice::<Record<Declaration>>(line) else {
                return Ok(false);
            };
            let d = declaration.payload;
            if d.role != "developer" || d.id.is_empty() || d.tools.is_empty() {
                return Ok(false);
            }
            needs_declaration = false;
            needs_tool_update = true;
            continue;
        }
        if direct {
            if row.r#type == "event_msg"
                && p.r#type == "item_completed"
                && p.item.as_ref().is_some_and(|i| i.r#type == "UserMessage")
            {
                receipt_hash = input_hash(line, true);
            }
            if row.r#type == "response_item"
                && p.r#type == "message"
                && p.role.as_deref() == Some("user")
                && p.internal_chat_message_metadata_passthrough
                    .as_ref()
                    .is_some_and(|m| {
                        m.content_item_kinds
                            .as_ref()
                            .is_some_and(|kinds| kinds.as_slice() == ["user.text"])
                    })
            {
                message_hash = input_hash(line, false);
            }
        }
        let valid = match (row.r#type.as_str(), p.r#type.as_str()) {
            ("event_msg", "task_started") => {
                if !admission.user_message
                    || !admission.outputs.is_empty()
                    || !admission.sleeps.is_empty()
                    || (admission.work_ms.is_some()
                        && !updated_at.is_some_and(|t| turn.started > t))
                {
                    return Ok(false);
                }
                let admitted = match source {
                    Source::Queue(queue, _) => {
                        p.starts(turn, Some("queue"))
                            && admission
                                .client_id
                                .is_some_and(|id| queue.admit(id, admission.exec))
                    }
                    Source::Foreground => p.starts(turn, Some("user")) || p.starts(turn, None),
                    Source::Direct(inputs) => {
                        let (Some(client), Some(hash)) = (admission.client_id, receipt_hash) else {
                            return Ok(false);
                        };
                        if message_hash.as_ref() != Some(&hash)
                            || !(p.starts(turn, Some("user")) || p.starts(turn, None))
                        {
                            return Ok(false);
                        }
                        inputs.push(DirectInput {
                            turn: Uuid::parse_str(&turn.id)?,
                            client,
                            hash,
                        });
                        true
                    }
                };
                let receipt_matches =
                    match (admission.thread_result, admission.thread_result_receipt) {
                        (None, None) => true,
                        (Some(id), Some(receipt)) => id.is_none_or(|id| id == receipt),
                        _ => false,
                    };
                return Ok(admitted && receipt_matches);
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
                            admission.timed_receipt();
                        }
                        admission.item(item, foreground, &turn.id, p.started_at_ms)
                    })
            }
            ("event_msg", "token_count") | ("world_state", "") => true,
            ("token_usage_record", "") => {
                p.thread_id.as_deref() == Some(thread) && p.turn_id.as_ref() == Some(&turn.id)
            }
            ("turn_context", "") => p.turn_id.as_ref() == Some(&turn.id),
            ("event_msg", "thread_settings_applied") if foreground => {
                p.thread_id.as_deref() == Some(thread)
            }
            ("response_item", "message")
                if foreground && p.role.as_deref() == Some("developer") =>
            {
                p.internal_chat_message_metadata_passthrough
                    .is_some_and(|m| {
                        m.content_item_kinds.is_some_and(|kinds| {
                            !kinds.is_empty()
                                && kinds.iter().all(|k| {
                                    matches!(
                                        k.as_str(),
                                        "host_skills.instructions"
                                            | "permissions.instructions"
                                            | "tools.incremental_update"
                                    )
                                })
                        })
                    })
            }
            ("response_item", _) => admission.response(p, &turn.id, foreground),
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
                if !agent_message || !p.starts(&prior, Some("goal")) || !rows.previous(line)? {
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
