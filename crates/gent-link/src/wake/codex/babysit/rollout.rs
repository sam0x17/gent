//! The only file opened is the rollout returned by the bound thread's host.
use super::*;
use rustix::fs::{Mode, OFlags};
use std::{fs::File, io::BufReader, os::unix::fs::FileExt};

#[derive(Clone, PartialEq)]
pub(super) struct Evidence {
    path: PathBuf,
    last: Value,
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
        last: Value,
        full: bool,
    ) -> Result<Option<Self>> {
        tokio::task::spawn_blocking(move || {
            let thread = &goal.thread_id;
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
            let header = Header::deserialize(&mut serde_json::Deserializer::from_reader(
                BufReader::new(&file),
            ))?;
            if header.r#type != "session_meta" || header.payload.id != *thread {
                return Ok(None);
            }
            let mut rows = ReverseLines::new(&file, before.size)?;
            let mut line = Vec::new();
            if !rows.previous(&mut line)? {
                return Ok(None);
            }
            let end: Record = serde_json::from_slice(&line)?;
            if !end.completes(&last)
                || (full && !provider_stop(&mut rows, &mut line, &goal, &last)?)
                || stamp(std::fs::symlink_metadata(&path)?)? != before
            {
                return Ok(None);
            }
            Ok(Some(Self {
                path,
                last,
                stamp: before,
            }))
        })
        .await?
    }

    pub(super) async fn confirms(&self, goal: &Goal) -> Result<bool> {
        Ok(
            Self::read(self.path.clone(), goal.clone(), self.last.clone(), true)
                .await?
                .as_ref()
                == Some(self),
        )
    }
}

// Read backwards a block at a time, stopping at the failed turn's start.
// Memory follows the largest individual record, independent of turn length.
struct ReverseLines<'a> {
    file: &'a File,
    offset: u64,
    block: Vec<u8>,
    end: usize,
}

impl<'a> ReverseLines<'a> {
    fn new(file: &'a File, size: u64) -> Result<Self> {
        let mut newline = [0];
        file.read_exact_at(&mut newline, size - 1)?;
        ensure!(newline[0] == b'\n', "incomplete Codex rollout record");
        Ok(Self {
            file,
            offset: size - 1,
            block: vec![0; 64 * 1024],
            end: 0,
        })
    }

    fn previous(&mut self, line: &mut Vec<u8>) -> Result<bool> {
        line.clear();
        loop {
            if self.end == 0 {
                if self.offset == 0 {
                    line.reverse();
                    return Ok(!line.is_empty());
                }
                self.end = self.offset.min(self.block.len() as u64) as usize;
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
struct Header {
    r#type: String,
    payload: Identity,
}
#[derive(Deserialize)]
struct Identity {
    id: String,
}
#[derive(Deserialize)]
struct Record {
    r#type: String,
    payload: Payload,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Payload {
    r#type: String,
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
}
#[derive(Deserialize)]
struct Attribution {
    turn_trigger: Option<String>,
    turn_id: Option<String>,
}
#[derive(Deserialize)]
struct ItemMeta {
    content_item_kinds: Option<Vec<String>>,
    executed_tool_calls: Option<Vec<Tool>>,
}
#[derive(Deserialize)]
struct Tool {
    name: String,
}

impl Record {
    fn completes(&self, last: &Value) -> bool {
        let p = &self.payload;
        self.r#type == "event_msg"
            && p.r#type == "task_complete"
            && p.turn_id.as_deref() == last["id"].as_str()
            && p.started_at == last["startedAt"].as_i64()
            && p.completed_at == last["completedAt"].as_i64()
            && p.error.as_ref().map(|e| e.message.as_str()) == last["error"]["message"].as_str()
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
                // A later-second update inside this failed turn excludes a
                // preexisting block. Within one second use explicit active
                // evidence or the known goal at admission.
                if active_snapshot
                    || p.turn_attribution.is_some_and(|a| {
                        a.turn_trigger.as_deref() == Some("goal") && a.turn_id.as_deref() == id
                    })
                    || p.started_at.is_some_and(|start| goal.updated_at > start)
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
