//! The only file opened is the rollout returned by the bound thread's host.
use super::*;
use history::{Candidate, Completed, Failed};

mod queued;
use rustix::fs::{Mode, OFlags};
use std::{collections::HashSet, fs::File, io::BufReader, os::unix::fs::FileExt};

#[derive(Clone, PartialEq)]
pub(super) struct Evidence {
    path: PathBuf,
    candidate: Candidate,
    stamp: Stamp,
}

#[derive(Clone, PartialEq)]
struct Stamp {
    device: u64,
    inode: u64,
    size: u64,
    modified: std::time::SystemTime,
}

fn stamp(meta: std::fs::Metadata) -> Result<Stamp> {
    Ok(Stamp {
        device: meta.dev(),
        inode: meta.ino(),
        size: meta.len(),
        modified: meta.modified()?,
    })
}

impl Evidence {
    pub(super) async fn read(
        path: PathBuf,
        goal: Goal,
        candidate: Candidate,
        full: bool,
    ) -> Result<Option<(Self, Vec<DirectInput>)>> {
        tokio::task::spawn_blocking(move || {
            let thread = &goal.thread_id;
            let mut direct = Vec::new();
            let last = &candidate.latest().turn;
            let has_later_failure = candidate.later.iter().any(|t| t.failure.is_some());
            if !path.is_absolute()
                || !path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    n.starts_with("rollout-") && n.ends_with(&format!("-{thread}.jsonl"))
                })
            {
                return Ok(None);
            }
            let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
            let file = File::from(rustix::fs::open(&path, flags, Mode::empty())?);
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.uid() != rustix::process::geteuid().as_raw()
                || meta.len() == 0
            {
                return Ok(None);
            }
            let before = stamp(meta)?;
            let header = Record::<Identity>::deserialize(
                &mut serde_json::Deserializer::from_reader(BufReader::new(&file)),
            )?;
            if header.r#type != "session_meta" || header.payload.id != *thread {
                return Ok(None);
            }
            let mut rows = ReverseLines::new(&file, before.size, !candidate.later.is_empty())?;
            let mut line = Vec::new();
            let mut receipt_turns = HashSet::new();
            let mut admissions = HashSet::new();
            let mut older: HashSet<&str> = candidate
                .later
                .iter()
                .map(|t| t.times.id.as_str())
                .collect();
            let anchor_id = candidate.anchor.turn["id"]
                .as_str()
                .context("missing anchor ID")?;
            older.insert(anchor_id);
            for later in candidate
                .later
                .iter()
                .map(Some)
                .chain(std::iter::once(None))
            {
                loop {
                    if !rows.previous(&mut line)? {
                        return Ok(None);
                    }
                    let row: Record = serde_json::from_slice(&line)?;
                    let matched = match later {
                        Some(t) => match &t.failure {
                            Some(failed) => row.matches_failure(thread, failed),
                            None => row.completes_turn(
                                &t.times.id,
                                t.times.started,
                                t.times.ended,
                                None,
                            ),
                        },
                        None => row.matches_failure(thread, &candidate.anchor),
                    };
                    if matched {
                        break;
                    }
                    if row.r#type != "event_msg" || row.payload.r#type != "item_completed" {
                        return Ok(None);
                    }
                    let Some(id) = serde_json::from_slice::<Record<Receipt>>(&line)
                        .ok()
                        .and_then(|r| r.payload.background_turn(thread))
                    else {
                        return Ok(None);
                    };
                    if Uuid::parse_str(last["id"].as_str().unwrap_or("")) == Ok(id)
                        || later.is_some_and(|t| Uuid::parse_str(&t.times.id) == Ok(id))
                    {
                        return Ok(None);
                    }
                    receipt_turns.insert(id);
                }
                if !full {
                    break;
                }
                if let Some(t) = later {
                    older.remove(t.times.id.as_str());
                    receipt_turns.remove(&Uuid::parse_str(&t.times.id)?);
                    // A direct host admission can look identical to a human
                    // turn at task_started. Replay it from the same boundary,
                    // then verify its sole native input against Gent's journal.
                    let mut retry = rows.clone();
                    if !queued::confirm(
                        &mut rows,
                        &mut line,
                        thread,
                        &t.times,
                        queued::Source::Queue(&mut admissions),
                        Some(goal.updated_at),
                        &older,
                    )? {
                        let source = if t.failure.is_some() {
                            queued::Source::Foreground
                        } else {
                            queued::Source::Direct(&mut direct)
                        };
                        if !queued::confirm(
                            &mut retry,
                            &mut line,
                            thread,
                            &t.times,
                            source,
                            Some(goal.updated_at),
                            &older,
                        )? {
                            return Ok(None);
                        }
                        if t.failure.is_none()
                            && !direct
                                .last()
                                .is_some_and(|input| admissions.insert(input.client.clone()))
                        {
                            return Ok(None);
                        }
                        rows = retry;
                    }
                }
            }
            if full {
                let anchor = &candidate.anchor.turn;
                // Native goal timestamps have second precision. If the failed
                // queue admission shares that second, keep its terminal position
                // for a strict replay through the preceding active setter.
                let fallback = (!candidate.later.is_empty()
                    && anchor["startedAt"] == goal.updated_at)
                    .then(|| rows.clone());
                if !provider_stop(
                    &mut rows,
                    &mut line,
                    &goal,
                    anchor,
                    has_later_failure || !direct.is_empty(),
                )? {
                    let Some(mut retry) = fallback else {
                        return Ok(None);
                    };
                    let failed = Completed::read(anchor).context("invalid failed turn")?;
                    if !queued::confirm(
                        &mut retry,
                        &mut line,
                        thread,
                        &failed,
                        queued::Source::Queue(&mut admissions),
                        None,
                        &HashSet::new(),
                    )? {
                        return Ok(None);
                    }
                    // Historical background receipt IDs must still be checked
                    // against completions preceding the failed admission.
                    rows = retry.clone();
                    if !queued::preceding_active_turn(&mut retry, &mut line, &goal, &failed)? {
                        return Ok(None);
                    }
                }
                if !earlier_turns(&mut rows, &mut line, receipt_turns)? {
                    return Ok(None);
                }
            }
            if stamp(std::fs::symlink_metadata(&path)?)? != before {
                return Ok(None);
            }
            Ok(Some((
                Self {
                    path,
                    candidate,
                    stamp: before,
                },
                direct,
            )))
        })
        .await?
    }

    pub(super) async fn confirm(&self, goal: &Goal) -> Result<Option<Vec<DirectInput>>> {
        Ok(Self::read(
            self.path.clone(),
            goal.clone(),
            self.candidate.clone(),
            true,
        )
        .await?
        .and_then(|(proof, direct)| (proof == *self).then_some(direct)))
    }
}

pub(super) struct DirectInput {
    pub(super) turn: Uuid,
    pub(super) client: String,
    pub(super) hash: String,
}

// Read backwards a block at a time.
// Memory follows the largest individual record, independent of turn length.
#[derive(Clone)]
pub(in crate::wake::codex) struct ReverseLines<'a> {
    floor: u64,
    file: &'a File,
    offset: u64,
    block: Vec<u8>,
    end: usize,
}

impl<'a> ReverseLines<'a> {
    pub(in crate::wake::codex) fn new(
        file: &'a File,
        size: u64,
        retrospective: bool,
    ) -> Result<Self> {
        let mut newline = [0];
        file.read_exact_at(&mut newline, size - 1)?;
        ensure!(newline[0] == b'\n', "incomplete Codex rollout record");
        Ok(Self {
            file,
            // The older direct-failure path may verify a distant background
            // receipt. Bound queue and consecutive-failure replay to a suffix.
            floor: if retrospective {
                size.saturating_sub(64 * 1024 * 1024)
            } else {
                0
            },
            offset: size - 1,
            block: vec![0; 64 * 1024],
            end: 0,
        })
    }

    pub(in crate::wake::codex) fn previous(&mut self, line: &mut Vec<u8>) -> Result<bool> {
        line.clear();
        loop {
            if self.end == 0 {
                if self.offset == self.floor {
                    if self.floor != 0 {
                        return Ok(false);
                    }
                    line.reverse();
                    return Ok(!line.is_empty());
                }
                self.end = (self.offset - self.floor).min(self.block.len() as u64) as usize;
                self.offset -= self.end as u64;
                self.file
                    .read_exact_at(&mut self.block[..self.end], self.offset)?;
            }
            let bytes = &self.block[..self.end];
            if let Some(pos) = bytes.iter().rposition(|&b| b == b'\n') {
                if line.is_empty() {
                    line.extend_from_slice(&bytes[pos + 1..]);
                } else {
                    line.extend(bytes[pos + 1..].iter().rev());
                    line.reverse();
                }
                self.end = pos;
                return Ok(true);
            }
            line.extend(bytes.iter().rev());
            self.end = 0;
        }
    }
}

// Deserialize only native metadata. Tool output, message content, shell input
// and base instructions are skipped by serde without materializing their text.
#[derive(Deserialize)]
struct Identity {
    id: String,
}
#[derive(Deserialize)]
struct Record<P = Payload> {
    r#type: String,
    payload: P,
}

// Native ItemCompletedEvent metadata. Commands, output and messages are never
// used to decide whether a record is a receipt.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    #[serde(rename = "type")]
    _kind: String,
    thread_id: String,
    turn_id: Uuid,
    item: ReceiptItem,
    #[serde(rename = "content_token_count")]
    _content_token_count: Option<u64>,
    #[serde(rename = "started_at_ms")]
    _started_at_ms: Option<i64>,
    #[serde(rename = "completed_at_ms")]
    _completed_at_ms: Option<i64>,
}

#[derive(Deserialize)]
struct ReceiptItem {
    r#type: String,
    id: String,
    kind: Option<String>,
    status: Option<String>,
    internal_chat_message_metadata_passthrough: Option<serde::de::IgnoredAny>,
}

impl Receipt {
    fn background_turn(&self, thread: &str) -> Option<Uuid> {
        let turn = self.turn_id;
        let item = &self.item;
        (self.thread_id == thread
            && !turn.is_nil()
            && !item.id.is_empty()
            && item.internal_chat_message_metadata_passthrough.is_none()
            && matches!(
                (
                    item.r#type.as_str(),
                    item.kind.as_deref(),
                    item.status.as_deref()
                ),
                ("SubAgentActivity", Some("completed"), None)
                    | ("CommandExecution", None, Some("completed"))
            ))
        .then_some(turn)
    }
}

// provider_stop has already walked back through the failed turn. Only accept
// delayed receipts for turns that had already completed before that boundary.
fn earlier_turns(
    rows: &mut ReverseLines<'_>,
    line: &mut Vec<u8>,
    mut pending: HashSet<Uuid>,
) -> Result<bool> {
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Boundary {
        r#type: String,
        turn_id: Option<String>,
    }
    while !pending.is_empty() {
        if !rows.previous(line)? {
            return Ok(false);
        }
        let row: Record<Boundary> = serde_json::from_slice(line)?;
        match (row.r#type.as_str(), row.payload.r#type.as_str()) {
            ("session_meta", _) | ("event_msg", "thread_rolled_back") => return Ok(false),
            ("event_msg", "task_complete") => {
                if let Some(id) = row.payload.turn_id.and_then(|s| Uuid::parse_str(&s).ok()) {
                    pending.remove(&id);
                }
            }
            _ => {}
        }
    }
    Ok(true)
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Payload {
    r#type: String,
    thread_id: Option<String>,
    turn_id: Option<String>,
    started_at: Option<i64>,
    completed_at: Option<i64>,
    error: Option<ErrorMessage>,
    goal: Option<Goal>,
    #[serde(rename = "threadId")]
    goal_thread: Option<String>,
    #[serde(rename = "turnId")]
    goal_turn: Option<String>,
    turn_attribution: Option<Attribution>,
    name: Option<String>,
    internal_chat_message_metadata_passthrough: Option<ItemMeta>,
}

#[derive(Deserialize)]
struct ErrorMessage {
    message: String,
    #[serde(default)]
    codex_error_info: Value,
    additional_details: Option<String>,
    misalignment: Option<serde::de::IgnoredAny>,
}
#[derive(Deserialize)]
struct Attribution {
    turn_trigger: Option<String>,
    turn_id: Option<String>,
}
#[derive(Deserialize)]
struct ItemMeta {
    turn_id: Option<String>,
    tool_calls_complete: Option<bool>,
    content_item_kinds: Option<Vec<String>>,
    executed_tool_calls: Option<Vec<Tool>>,
}
#[derive(Deserialize)]
struct Tool {
    name: String,
}

impl Record {
    fn completes(&self, last: &Value) -> bool {
        let (Some(id), Some(started), Some(ended), Some(error)) = (
            last["id"].as_str(),
            last["startedAt"].as_i64(),
            last["completedAt"].as_i64(),
            last["error"]["message"].as_str(),
        ) else {
            return false;
        };
        self.completes_turn(id, started, ended, Some(error))
    }

    fn matches_failure(&self, thread: &str, failed: &Failed) -> bool {
        if self
            .payload
            .thread_id
            .as_deref()
            .is_some_and(|id| id != thread)
            || !self.completes(&failed.turn)
        {
            return false;
        }
        let Some(error) = &self.payload.error else {
            return false;
        };
        let native = &failed.turn["error"];
        // Match both representations of the provider-owned error, including
        // parameters of structured Codex error codes. The host API uses camel
        // case for the same fields the rollout serializes in snake case.
        error.misalignment.is_none()
            && error.additional_details.as_deref() == native["additionalDetails"].as_str()
            && same_error_info(&native["codexErrorInfo"], &error.codex_error_info)
    }

    fn completes_turn(&self, id: &str, started: i64, ended: i64, error: Option<&str>) -> bool {
        let p = &self.payload;
        self.r#type == "event_msg"
            && p.r#type == "task_complete"
            && p.turn_id.as_deref() == Some(id)
            && p.started_at == Some(started)
            && p.completed_at == Some(ended)
            && p.error.as_ref().map(|e| e.message.as_str()) == error
    }
}

fn same_error_info(api: &Value, rollout: &Value) -> bool {
    fn snake_case(name: &str) -> String {
        let mut snake = String::new();
        for c in name.chars() {
            if c.is_ascii_uppercase() {
                snake.push('_');
            }
            snake.push(c.to_ascii_lowercase());
        }
        snake
    }
    if api == rollout {
        return true;
    }
    match (api, rollout) {
        (Value::String(a), Value::String(b)) => snake_case(a) == *b,
        (Value::Object(a), Value::Object(b)) if a.len() == 1 && b.len() == 1 => {
            let (variant, details) = a.iter().next().expect("one variant");
            let Some(other) = b.get(&snake_case(variant)).or_else(|| b.get(variant)) else {
                return false;
            };
            if details == other {
                return true;
            }
            // Codex variants carry flat fields such as http_status_code.
            let (Some(fields), Some(recorded)) = (details.as_object(), other.as_object()) else {
                return false;
            };
            fields.len() == recorded.len()
                && fields
                    .iter()
                    .all(|(k, v)| recorded.get(&snake_case(k)) == Some(v))
        }
        _ => false,
    }
}

fn goal_tool(name: &str) -> bool {
    matches!(
        name,
        "update_goal" | "functions.update_goal" | "functions__update_goal"
    )
}

fn provider_stop(
    rows: &mut ReverseLines<'_>,
    line: &mut Vec<u8>,
    goal: &Goal,
    last: &Value,
    consecutive: bool,
) -> Result<bool> {
    let id = last["id"].as_str();
    let mut active_snapshot = false;
    while rows.previous(line)? {
        let row: Record = serde_json::from_slice(line)?;
        let p = row.payload;
        match (row.r#type.as_str(), p.r#type.as_str()) {
            ("event_msg", "task_started") => {
                if p.turn_id.as_deref() != id || p.started_at != last["startedAt"].as_i64() {
                    return Ok(false);
                }
                if consecutive
                    && (p.thread_id.as_ref().is_some_and(|t| t != &goal.thread_id)
                        || p.turn_attribution
                            .as_ref()
                            .is_some_and(|a| a.turn_id.as_deref() != id))
                {
                    return Ok(false);
                }
                // A later-second update inside this failed turn excludes a
                // preexisting block. Within one second use explicit active
                // evidence or the known goal at admission.
                if active_snapshot
                    || p.turn_attribution.is_some_and(|a| {
                        a.turn_trigger.as_deref() == Some("goal")
                            && a.turn_id.as_deref() == id
                            && (!consecutive || p.started_at.is_some_and(|t| goal.created_at <= t))
                    })
                    || (!consecutive && p.started_at.is_some_and(|start| goal.updated_at > start))
                {
                    return Ok(true);
                }
                while rows.previous(line)? {
                    let prior: Record = serde_json::from_slice(line)?;
                    if prior.r#type == "event_msg"
                        && prior.payload.r#type == "thread_settings_applied"
                    {
                        continue;
                    }
                    return Ok(prior.r#type == "event_msg"
                        && prior.payload.r#type == "thread_goal_updated"
                        && prior.payload.goal_thread.as_deref() == Some(&goal.thread_id)
                        && prior.payload.goal_turn.is_none()
                        && prior.payload.goal.is_some_and(|g| same_active(&g, goal)));
                }
                return Ok(false);
            }
            ("event_msg", "task_complete" | "turn_aborted" | "thread_rolled_back")
            | ("session_meta", _) => return Ok(false),
            _ if active_snapshot => {} // An older decision was superseded by this active setter.
            ("event_msg", "thread_goal_updated") => {
                active_snapshot = p.goal_thread.as_deref() == Some(&goal.thread_id)
                    && (p.goal_turn.is_none() || p.goal_turn.as_deref() == id)
                    && p.goal.is_some_and(|g| same_active(&g, goal));
                if !active_snapshot {
                    return Ok(false);
                }
            }
            ("event_msg", "thread_goal_cleared") => return Ok(false),
            ("response_item", _) => {
                if matches!(p.r#type.as_str(), "function_call" | "custom_tool_call")
                    && p.name.as_deref().is_some_and(goal_tool)
                {
                    return Ok(false);
                }
                if let Some(meta) = p.internal_chat_message_metadata_passthrough
                    && (meta
                        .content_item_kinds
                        .unwrap_or_default()
                        .iter()
                        .any(|k| k == "user.goal")
                        || meta
                            .executed_tool_calls
                            .unwrap_or_default()
                            .iter()
                            .any(|t| goal_tool(&t.name)))
                {
                    return Ok(false);
                }
            }
            _ => {}
        }
    }
    Ok(false)
}

fn same_active(snapshot: &Goal, goal: &Goal) -> bool {
    snapshot.status == "active"
        && snapshot.thread_id == goal.thread_id
        && snapshot.created_at == goal.created_at
        && snapshot.objective == goal.objective
        && snapshot.token_budget == goal.token_budget
}
