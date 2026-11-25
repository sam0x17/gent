//! Bind the failed turn to native admission metadata without reading prompt text.
use super::super::babysit::rollout::ReverseLines;
use super::*;
use rustix::fs::{Mode, OFlags};
use serde::Deserialize;
use std::{
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
    pub(super) fn matches(&self, path: &Path) -> Result<bool> {
        Ok(*self == Self::from(std::fs::symlink_metadata(path)?)?)
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
}
#[derive(Deserialize)]
struct Item {
    r#type: String,
    client_id: Option<String>,
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
    let mut rows = ReverseLines::new(&file, stamp.len, true)?;
    let mut line = Vec::new();
    if !rows.previous(&mut line)? {
        return Ok(None);
    }
    let record: Record = serde_json::from_slice(&line)?;
    let p = record.payload;
    let turn = failed.turn.to_string();
    if record.r#type != "event_msg"
        || p.r#type.as_deref() != Some("task_complete")
        || p.turn_id.as_ref() != Some(&turn)
        || p.started_at != Some(failed.started)
        || p.completed_at != Some(failed.ended)
        || p.error.as_ref().map(|e| &e.message) != Some(&failed.error)
    {
        return Ok(None);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut input = None;
    while Instant::now() < deadline && rows.previous(&mut line)? {
        let record: Record = serde_json::from_slice(&line)?;
        if record.r#type != "event_msg" {
            continue;
        }
        let p = record.payload;
        match p.r#type.as_deref() {
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
                if p.turn_id.as_ref() != Some(&turn)
                    || p.thread_id.as_ref() != Some(&failed.thread)
                    || input.replace(item).is_some()
                {
                    return Ok(None);
                }
            }
            Some("task_started") => {
                let (Some(a), Some(item)) = (p.turn_attribution, input) else {
                    return Ok(None);
                };
                if p.turn_id.as_ref() != Some(&turn)
                    || p.started_at != Some(failed.started)
                    || a.turn_id != failed.turn
                    || a.root_turn_id != failed.root
                    || !stamp.matches(path)?
                {
                    return Ok(None);
                }
                let origin = match a.turn_trigger.as_deref() {
                    None | Some("user")
                        if a.parent_turn_id.is_none() && failed.root == failed.turn =>
                    {
                        ChatOrigin::Operator {
                            turn: failed.turn,
                            started_at: failed.started,
                            client_id: item.client_id,
                        }
                    }
                    Some(TRIGGER) if a.parent_turn_id.is_some() && failed.root != failed.turn => {
                        let Some(attempt) = item.client_id.and_then(|s| Uuid::parse_str(&s).ok())
                        else {
                            return Ok(None);
                        };
                        // A goal control or a new turn could have landed between
                        // the previous admission check and this automatic start.
                        if !rows.previous(&mut line)? {
                            return Ok(None);
                        }
                        let prior: Record = serde_json::from_slice(&line)?;
                        if prior.r#type != "event_msg"
                            || prior.payload.r#type.as_deref() != Some("task_complete")
                            || prior.payload.error.is_none()
                            || prior
                                .payload
                                .turn_id
                                .as_deref()
                                .and_then(|id| Uuid::parse_str(id).ok())
                                != a.parent_turn_id
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
