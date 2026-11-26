//! Bind the failed turn to native admission metadata without reading prompt text.
use super::super::babysit::rollout::{ReverseLines, completed_command};
use super::*;
mod handoff;
#[cfg(test)]
mod handoff_tests;
mod legacy;
use gent_protocol::babysitter::MAX_CHAT_INPUTS;
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

// Only a completed command from this exact turn may arrive after its terminal
// record. A new user input, control event, or different turn ends the proof.
fn completion(
    rows: &mut ReverseLines<'_>,
    line: &mut Vec<u8>,
    thread: &str,
    turn: Uuid,
    deadline: Instant,
) -> Result<Option<Payload>> {
    while Instant::now() < deadline && rows.previous(line)? {
        let record: Record = serde_json::from_slice(line)?;
        let p = record.payload;
        if record.r#type == "event_msg" && p.r#type.as_deref() == Some("task_complete") {
            return Ok((p.turn_id.as_deref() == Some(&turn.to_string())
                && p.thread_id.as_deref().is_none_or(|id| id == thread))
            .then_some(p));
        }
        if !completed_command(line, thread, turn) {
            break;
        }
    }
    Ok(None)
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

pub(super) fn read(failed: &Failed) -> Result<Option<(ChatOrigin, Option<Uuid>, Stamp)>> {
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
    let legacy = failed.legacy_history && header.payload.history_mode.as_deref() == Some("legacy");
    let mut rows = ReverseLines::new(&file, stamp.len, true)?;
    let mut line = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    let Some(p) = completion(&mut rows, &mut line, &failed.thread, failed.turn, deadline)? else {
        return Ok(None);
    };
    let turn = failed.turn.to_string();
    if p.started_at != Some(failed.started)
        || p.completed_at != Some(failed.ended)
        || p.error.as_ref().map(|e| &e.message) != Some(&failed.error)
    {
        return Ok(None);
    }
    let mut inputs = Vec::new();
    while Instant::now() < deadline && rows.previous(&mut line)? {
        let record: Record = serde_json::from_slice(&line)?;
        if record.r#type != "event_msg" {
            if legacy && record.r#type == "response_item" && legacy::unpaired_user(&line)? {
                return Ok(None);
            }
            continue;
        }
        let p = record.payload;
        match p.r#type.as_deref() {
            Some("user_message") if legacy => {
                let Some(item) = legacy::input(&mut rows, &mut line, &failed.thread, failed.turn)?
                else {
                    return Ok(None);
                };
                if inputs.len() >= MAX_CHAT_INPUTS {
                    return Ok(None);
                }
                inputs.push(item);
            }
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
                let origin = match a.turn_trigger.as_deref() {
                    None if inputs.is_empty()
                        && failed.handoff_parent
                        && header.payload.history_mode.as_deref() == Some("paginated")
                        && a.parent_turn_id.is_none()
                        && failed.root == failed.turn =>
                    {
                        let Some(item) = handoff::read(&file, &stamp, failed, deadline)? else {
                            return Ok(None);
                        };
                        ChatOrigin::ThreadHandoff {
                            item,
                            started_at: failed.started,
                        }
                    }
                    None | Some("user" | "composer")
                        if a.parent_turn_id.is_none() && failed.root == failed.turn =>
                    {
                        let Some(origin) = operator(failed, inputs, a.turn_trigger.as_deref())
                        else {
                            return Ok(None);
                        };
                        origin
                    }
                    Some(TRIGGER) if failed.root != failed.turn => {
                        let (Some(parent), [item]) = (a.parent_turn_id, inputs.as_slice()) else {
                            return Ok(None);
                        };
                        let Some(attempt) = item
                            .client_id
                            .as_deref()
                            .and_then(|id| Uuid::parse_str(id).ok())
                        else {
                            return Ok(None);
                        };
                        // A goal control or a new turn could have landed between
                        // the previous admission check and this automatic start.
                        if completion(&mut rows, &mut line, &failed.thread, parent, deadline)?
                            .is_none_or(|p| p.error.is_none())
                        {
                            return Ok(None);
                        }
                        ChatOrigin::Continuation { attempt }
                    }
                    _ => return Ok(None),
                };
                return Ok(Some((origin, a.parent_turn_id, stamp)));
            }
            _ => {}
        }
    }
    Ok(None)
}
