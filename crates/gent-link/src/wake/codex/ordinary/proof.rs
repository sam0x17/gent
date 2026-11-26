//! Bind the failed turn to native admission metadata and paired input receipts.
use super::super::babysit::rollout::{ReverseLines, terminal_command};
use super::*;
mod handoff;
#[cfg(test)]
mod handoff_tests;
mod legacy;
use super::super::babysit::rollout::input_hash;
use gent_protocol::babysitter::{ForegroundInput, ForegroundInputs, MAX_CHAT_INPUTS};
pub(in crate::wake::codex) use legacy::user_source;
use rustix::fs::{Mode, OFlags};
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs::{File, Metadata},
    io::{BufReader, Read},
    time::{Duration, Instant},
};

#[derive(PartialEq)]
pub(super) struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    modified: std::time::SystemTime,
}

impl Stamp {
    fn from(meta: Metadata) -> Result<Self> {
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            modified: meta.modified()?,
        })
    }
    pub(super) fn current(path: &Path) -> Result<Self> {
        Self::from(std::fs::symlink_metadata(path)?)
    }
    pub(super) fn matches(&self, path: &Path) -> Result<bool> {
        Ok(*self == Self::current(path)?)
    }
    pub(super) fn grew_from(&self, older: &Self) -> bool {
        self.dev == older.dev && self.ino == older.ino && self.len > older.len
    }
}

#[derive(Deserialize)]
struct Record {
    r#type: String,
    payload: Payload,
}

#[derive(Default, Deserialize)]
struct Payload {
    id: Option<String>,
    r#type: Option<String>,
    thread_id: Option<String>,
    turn_id: Option<String>,
    root_turn_id: Option<String>,
    started_at: Option<i64>,
    completed_at: Option<i64>,
    error: Option<Error>,
    turn_attribution: Option<Attribution>,
    history_mode: Option<String>,
    item: Option<Item>,
}
#[derive(Deserialize)]
struct Error {
    message: String,
}
#[derive(Deserialize)]
struct Attribution {
    turn_id: Uuid,
    turn_trigger: Option<String>,
    root_turn_id: Uuid,
    parent_turn_id: Option<Uuid>,
    initiating_agent_path: Option<serde::de::IgnoredAny>,
}
#[derive(Deserialize)]
struct Item {
    r#type: String,
    id: Option<String>,
    client_id: Option<String>,
}

// Each caller supplies the command receipts it can attribute across this boundary.
fn completion(
    rows: &mut ReverseLines<'_>,
    line: &mut Vec<u8>,
    thread: &str,
    turn: Uuid,
    deadline: Instant,
    mut receipt: impl FnMut(&[u8]) -> bool,
) -> Result<Option<Payload>> {
    while Instant::now() < deadline && rows.previous(line)? {
        let record: Record = serde_json::from_slice(line)?;
        let p = record.payload;
        if record.r#type == "event_msg" && p.r#type.as_deref() == Some("task_complete") {
            return Ok((p.turn_id.as_deref() == Some(&turn.to_string())
                && p.thread_id.as_deref().is_none_or(|id| id == thread))
            .then_some(p));
        }
        if !receipt(line) {
            break;
        }
    }
    Ok(None)
}

fn foreground_receipt(line: &[u8], item: &Item) -> Option<ForegroundInput> {
    #[derive(Deserialize)]
    struct Time<'a> {
        timestamp: &'a str,
    }
    let time: Time<'_> = serde_json::from_slice(line).ok()?;
    Some(ForegroundInput {
        client: canonical_uuid(item.client_id.as_deref()?)?,
        sha256: input_hash(line, true)?,
        received_at_ms: chrono::DateTime::parse_from_rfc3339(time.timestamp)
            .ok()?
            .timestamp_millis(),
    })
}

fn canonical_uuid(raw: &str) -> Option<Uuid> {
    Uuid::parse_str(raw)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == raw)
}

fn operator(failed: &Failed, mut inputs: Vec<Item>, trigger: Option<&str>) -> Option<ChatOrigin> {
    // A user may steer a running foreground turn. Keep every distinct native
    // input's client ID so the store can exclude Gent delivery at any position.
    if inputs.len() > 1 {
        let mut ids = HashSet::new();
        if !matches!(trigger, Some("user" | "composer"))
            || !inputs.iter().all(|i| {
                i.id.as_deref()
                    .is_some_and(|id| !id.is_empty() && ids.insert(id))
                    && i.client_id.as_deref().is_some_and(|id| !id.is_empty())
            })
        {
            return None;
        }
    }
    let first = inputs.pop()?;
    Some(ChatOrigin::Operator {
        turn: failed.turn,
        started_at: failed.started,
        client_id: first.client_id,
        additional_client_ids: inputs
            .into_iter()
            .rev()
            .map(|i| i.client_id)
            .collect::<Option<_>>()?,
    })
}

// The reverse scan ends at the oldest input. Only its client ID may match
// the durable admission for the preceding failure.
fn continuation(
    failed: &Failed,
    mut inputs: Vec<Item>,
    parent: Uuid,
    terminal: Payload,
    proven_sources: bool,
) -> Option<ChatOrigin> {
    terminal.error?;
    let first = inputs.pop()?;
    let client = first.client_id.as_deref()?;
    let attempt = Uuid::parse_str(client).ok()?;
    if inputs.is_empty() {
        return Some(ChatOrigin::Continuation { attempt });
    }
    let mut ids = HashSet::new();
    if !proven_sources
        || attempt.is_nil()
        || attempt.to_string() != client
        || !std::iter::once(&first).chain(&inputs).all(|i| {
            i.id.as_deref()
                .is_some_and(|id| !id.trim().is_empty() && ids.insert(id))
        })
    {
        return None;
    }
    Some(ChatOrigin::SteeredContinuation {
        attempt,
        parent,
        root: failed.root,
        started_at: failed.started,
        parent_failed_at: terminal.completed_at?,
        additional_client_ids: inputs
            .into_iter()
            .rev()
            .map(|i| i.client_id)
            .collect::<Option<_>>()?,
    })
}

pub(super) struct Evidence {
    pub(super) stamp: Stamp,
    pub(super) direct: Vec<babysit::rollout::DirectInput>,
}

pub(super) fn read(
    failed: &Failed,
    direct_handoff: bool,
) -> Result<Option<(ChatOrigin, Option<Uuid>, Evidence)>> {
    let path = &failed.path;
    if !path.is_absolute()
        || !path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|name| {
                name.starts_with("rollout-") && name.ends_with(&format!("-{}.jsonl", failed.thread))
            })
    {
        return Ok(None);
    }
    let file = File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() == 0 || meta.uid() != rustix::process::geteuid().as_raw() {
        return Ok(None);
    }
    let stamp = Stamp::from(meta)?;
    let header = Record::deserialize(&mut serde_json::Deserializer::from_reader(BufReader::new(
        (&file).take(1024 * 1024),
    )))?;
    if header.r#type != "session_meta" || header.payload.id.as_deref() != Some(&failed.thread) {
        return Ok(None);
    }
    let rows = ReverseLines::new(&file, stamp.len, true)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut evidence = Evidence {
        stamp,
        direct: Vec::new(),
    };
    let found = prove_turn(
        failed,
        &file,
        &header,
        rows,
        deadline,
        &mut evidence,
        direct_handoff,
    )?;
    Ok(found.map(|(origin, parent)| (origin, parent, evidence)))
}

fn prove_turn(
    failed: &Failed,
    file: &File,
    header: &Record,
    mut rows: ReverseLines<'_>,
    deadline: Instant,
    evidence: &mut Evidence,
    direct_handoff: bool,
) -> Result<Option<(ChatOrigin, Option<Uuid>)>> {
    let path = &failed.path;
    let stamp = &evidence.stamp;
    let legacy = failed.legacy_history && header.payload.history_mode.as_deref() == Some("legacy");
    let mut line = Vec::new();
    let mut previous = None;
    let Some(p) = completion(
        &mut rows,
        &mut line,
        &failed.thread,
        failed.turn,
        deadline,
        |line| {
            terminal_command(line, &failed.thread, failed.turn)
                || (failed.handoff_parent
                    && failed.turn == failed.root
                    && handoff::previous_receipt(&mut previous, line, failed))
        },
    )?
    else {
        return Ok(None);
    };
    let turn = failed.turn.to_string();
    if p.started_at != Some(failed.started)
        || p.completed_at != Some(failed.ended)
        || p.error.as_ref().map(|e| &e.message) != Some(&failed.error)
    {
        return Ok(None);
    }
    let mut inputs: Vec<Item> = Vec::new();
    let descendant = failed.root != failed.turn;
    let blocked = failed.goal["status"] == "blocked";
    let mut pending_receipt: Option<usize> = None;
    let mut sources = HashSet::new();
    // Earlier single-input hosts do not always supply response provenance.
    // Accumulate ambiguity here and require a complete pairing on multi-input descendants.
    let mut ambiguous = false;
    let mut named_before_inputs = false;
    // Walk backwards across the first user receipt, its message and the root context.
    // If anything intervenes before task_started, the mixed-input exception stays closed.
    let mut proven = Vec::new();
    let mut pending_input = None::<ForegroundInput>;
    let mut paired_message = false;
    let mut opening_context = false;
    while Instant::now() < deadline && rows.previous(&mut line)? {
        if blocked && !babysit::rollout::ordinary_work(&line, &failed.thread, &turn)? {
            return Ok(None);
        }
        let record: Record = serde_json::from_slice(&line)?;
        // The earliest native admission determines ownership, even if Gent's
        // delivery journal has since been pruned or the daemon predates this proof.
        if record.payload.r#type.as_deref() == Some("function_call_output")
            || record
                .payload
                .item
                .as_ref()
                .is_some_and(|i| i.r#type == "FunctionCallOutput")
        {
            named_before_inputs |= handoff::named_marker(&line);
        }
        let receipt = pending_receipt.take();
        let input = pending_input.take();
        let next_is_message = std::mem::take(&mut paired_message);
        let next_is_context = std::mem::take(&mut opening_context);
        if record.r#type != "event_msg" {
            if !legacy
                && record.r#type == "response_item"
                && record.payload.r#type.as_deref() == Some("message")
                && legacy::unpaired_user(&line).unwrap_or(true)
            {
                let source = receipt
                    .and_then(|index| inputs[index].client_id.as_deref())
                    .and_then(|client| {
                        legacy::user_source(&line, &failed.thread, failed.turn, client)
                    });
                paired_message = source.is_some();
                if paired_message
                    && let Some(input) = input
                    && input_hash(&line, false).as_ref() == Some(&input.sha256)
                {
                    proven.push(input);
                }
                ambiguous |= source.is_none_or(|id| !sources.insert(id));
            }
            if record.r#type == "turn_context" {
                let p = &record.payload;
                opening_context = next_is_message
                    && p.turn_id.as_ref() == Some(&turn)
                    && p.root_turn_id.as_ref() == Some(&turn)
                    && p.thread_id.as_ref().is_none_or(|id| id == &failed.thread);
            }
            if legacy && record.r#type == "response_item" && legacy::unpaired_user(&line)? {
                return Ok(None);
            }
            continue;
        }
        let p = record.payload;
        match p.r#type.as_deref() {
            Some("user_message") if legacy => {
                named_before_inputs = false;
                let Some(item) = legacy::input(&mut rows, &mut line, &failed.thread, failed.turn)?
                else {
                    return Ok(None);
                };
                if inputs.len() >= MAX_CHAT_INPUTS {
                    return Ok(None);
                }
                inputs.push(item);
            }
            Some("user_message") => ambiguous = true,
            Some(
                "turn_aborted"
                | "task_complete"
                | "thread_rolled_back"
                | "thread_goal_updated"
                | "thread_goal_cleared",
            ) => return Ok(None),
            Some("item_completed") => {
                let Some(item) = p.item.filter(|item| item.r#type == "UserMessage") else {
                    continue;
                };
                if legacy
                    || p.turn_id.as_ref() != Some(&turn)
                    || p.thread_id.as_ref() != Some(&failed.thread)
                    || inputs.len() >= MAX_CHAT_INPUTS
                {
                    return Ok(None);
                }
                named_before_inputs = false;
                pending_receipt = Some(inputs.len());
                if failed.handoff_parent && (!descendant || blocked) {
                    pending_input = foreground_receipt(&line, &item);
                }
                inputs.push(item);
            }
            Some("task_started") => {
                let Some(a) = p.turn_attribution else {
                    return Ok(None);
                };
                if p.turn_id.as_ref() != Some(&turn)
                    || p.started_at != Some(failed.started)
                    || a.turn_id != failed.turn
                    || a.root_turn_id != failed.root
                    || a.initiating_agent_path.is_some()
                    || !stamp.matches(path)?
                {
                    return Ok(None);
                }
                if blocked {
                    if inputs.len() != 1
                        || ambiguous
                        || sources.len() != 1
                        || header.payload.history_mode.as_deref() != Some("paginated")
                    {
                        return Ok(None);
                    }
                    if descendant {
                        use sha2::{Digest, Sha256};
                        let [input] = proven.as_slice() else {
                            return Ok(None);
                        };
                        if input.sha256 != format!("{:x}", Sha256::digest(PROMPT)) {
                            return Ok(None);
                        }
                        let Some(parent_id) = a.parent_turn_id else {
                            return Ok(None);
                        };
                        let Some((head, rest)) = failed.previous_turns.split_first() else {
                            return Ok(None);
                        };
                        let Some(mut parent) = Failed::from_head(
                            &failed.thread,
                            failed.path.clone(),
                            head,
                            failed.ended - gent_protocol::babysitter::CHAT_CHAIN_MAX_AGE
                                ..=failed.started,
                            failed.goal.clone(),
                            failed.legacy_history,
                            failed.handoff_parent,
                        ) else {
                            return Ok(None);
                        };
                        if a.turn_trigger.as_deref() != Some(TRIGGER)
                            || parent.turn != parent_id
                            || parent_id == failed.turn
                            || parent.root != failed.root
                            || p.root_turn_id.as_ref() != Some(&failed.root.to_string())
                        {
                            return Ok(None);
                        }
                        let Some(attempt) = inputs[0].client_id.as_deref().and_then(canonical_uuid)
                        else {
                            return Ok(None);
                        };
                        parent.previous_turns = rest.to_vec();
                        // Replay the adjacent genuine parent back to its original
                        // operator admission and provider block on the same file
                        // and deadline. The store separately binds the native
                        // client UUID to its latest admitted parent and budget.
                        if prove_turn(&parent, file, header, rows, deadline, evidence, false)?
                            .is_none()
                        {
                            return Ok(None);
                        }
                        return Ok(Some((
                            ChatOrigin::Continuation { attempt },
                            Some(parent_id),
                        )));
                    }
                    if a.turn_trigger.as_deref() != Some("user")
                        || a.parent_turn_id.is_some()
                        || p.root_turn_id.as_ref() != Some(&turn)
                        || proven.len() != 1
                        || failed.goal["updatedAt"]
                            .as_i64()
                            .is_none_or(|updated| updated >= failed.started)
                        || !babysit::rollout::prior_block::confirm(
                            &mut rows,
                            &mut line,
                            &failed.goal,
                            &failed.previous_turns,
                            failed.started,
                            deadline,
                            &mut evidence.direct,
                        )?
                    {
                        return Ok(None);
                    }
                }
                let origin = match a.turn_trigger.as_deref() {
                    None if (inputs.is_empty() || named_before_inputs)
                        && failed.handoff_parent
                        && header.payload.history_mode.as_deref() == Some("paginated")
                        && a.parent_turn_id.is_none()
                        && failed.root == failed.turn =>
                    {
                        if !inputs.is_empty() {
                            let mut ids = HashSet::new();
                            if !direct_handoff
                                || blocked
                                || previous.is_some()
                                || ambiguous
                                || proven.len() != inputs.len()
                                || sources.len() != inputs.len()
                                || !inputs.iter().all(|i| {
                                    i.id.as_deref()
                                        .is_some_and(|id| !id.trim().is_empty() && ids.insert(id))
                                })
                                || p.root_turn_id.as_ref() != Some(&turn)
                                || p.thread_id.as_ref().is_some_and(|id| id != &failed.thread)
                            {
                                return Ok(None);
                            }
                        }
                        let Some(item) =
                            handoff::read(file, stamp, failed, deadline, previous, &proven)?
                        else {
                            return Ok(None);
                        };
                        if inputs.is_empty() {
                            ChatOrigin::ThreadHandoff {
                                item,
                                started_at: failed.started,
                            }
                        } else {
                            let Some(thread) = canonical_uuid(&failed.thread) else {
                                return Ok(None);
                            };
                            proven.reverse();
                            return Ok(Some((
                                ChatOrigin::DirectHandoff {
                                    item,
                                    proof: ForegroundInputs {
                                        thread,
                                        turn: failed.turn,
                                        started_at: failed.started,
                                        inputs: proven,
                                    },
                                },
                                None,
                            )));
                        }
                    }
                    None | Some("user" | "composer")
                        if previous.is_none()
                            && !(named_before_inputs && a.turn_trigger.is_none())
                            && a.parent_turn_id.is_none()
                            && failed.root == failed.turn =>
                    {
                        let Some(origin) = operator(failed, inputs, a.turn_trigger.as_deref())
                        else {
                            return Ok(None);
                        };
                        origin
                    }
                    Some(TRIGGER) if failed.root != failed.turn => {
                        let Some(parent) = a
                            .parent_turn_id
                            .filter(|id| !id.is_nil() && id != &failed.turn)
                        else {
                            return Ok(None);
                        };
                        let Some(terminal) = completion(
                            &mut rows,
                            &mut line,
                            &failed.thread,
                            parent,
                            deadline,
                            |line| terminal_command(line, &failed.thread, parent),
                        )?
                        else {
                            return Ok(None);
                        };
                        let proven_sources =
                            !ambiguous && (legacy || sources.len() == inputs.len());
                        let Some(origin) =
                            continuation(failed, inputs, parent, terminal, proven_sources)
                        else {
                            return Ok(None);
                        };
                        origin
                    }
                    _ => return Ok(None),
                };
                let origin = if let ChatOrigin::Operator {
                    additional_client_ids,
                    ..
                } = &origin
                    && !additional_client_ids.is_empty()
                    && failed.handoff_parent
                    && a.turn_trigger.as_deref() == Some("user")
                    && header.payload.history_mode.as_deref() == Some("paginated")
                    && next_is_context
                    && !ambiguous
                    && sources.len() == additional_client_ids.len() + 1
                    && proven.len() == sources.len()
                    && p.thread_id.as_ref().is_none_or(|id| id == &failed.thread)
                    && p.root_turn_id.as_ref() == Some(&turn)
                    && let Some(thread) = canonical_uuid(&failed.thread)
                {
                    proven.reverse();
                    ChatOrigin::ForegroundInputs(ForegroundInputs {
                        thread,
                        turn: failed.turn,
                        started_at: failed.started,
                        inputs: proven,
                    })
                } else {
                    origin
                };
                return Ok(Some((origin, a.parent_turn_id)));
            }
            _ => {}
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests;
