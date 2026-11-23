//! Descending, items-free turn metadata. Only blocked goals can use earlier failures.
use super::*;
use std::collections::HashSet;

const PAGE_SIZE: usize = 32;
const MAX_TURNS: usize = 4096;

#[derive(Clone, PartialEq)]
pub(super) struct Completed {
    pub(super) id: String,
    pub(super) started: i64,
    pub(super) ended: i64,
}

impl Completed {
    pub(super) fn read(turn: &Value) -> Option<Self> {
        let id = turn["id"].as_str()?;
        let uuid = Uuid::parse_str(id).ok()?;
        let started = turn["startedAt"].as_i64()?;
        let ended = turn["completedAt"].as_i64()?;
        (!uuid.is_nil() && uuid.to_string() == id && started <= ended).then(|| Self {
            id: id.into(),
            started,
            ended,
        })
    }
}

pub(super) async fn candidate(
    host: &mut Host,
    goal: &Goal,
) -> Result<Option<(Value, Vec<Completed>, Failure)>> {
    let blocked = goal.status == "blocked";
    let limit = if blocked { PAGE_SIZE } else { 1 };
    let mut params = json!({"threadId":goal.thread_id,"limit":limit,"sortDirection":"desc","itemsView":"notLoaded"});
    let mut cursors = HashSet::new();
    let mut ids = HashSet::new();
    let mut queued: Vec<Completed> = Vec::new();
    // The daemon only admits failures from the last two hours. Its durable claim
    // still makes the final freshness and backoff decision.
    let oldest = gent_daemon::store::now() - 7200;
    let deadline = tokio::time::Instant::now() + RPC_TIMEOUT;
    let mut queue_checked = false;
    loop {
        let page = tokio::time::timeout_at(deadline, host.rpc("thread/turns/list", params.clone()))
            .await??;
        let turns = page["data"].as_array().context("invalid Codex turn page")?;
        if turns.is_empty() || turns.len() > limit {
            return Ok(None);
        }
        for turn in turns {
            let Some(times) = Completed::read(turn) else {
                return Ok(None);
            };
            if times.ended < oldest
                || times.ended < goal.updated_at
                || queued
                    .last()
                    .is_some_and(|newer| times.ended > newer.started)
                || ids.len() >= MAX_TURNS
                || !ids.insert(times.id.clone())
            {
                return Ok(None);
            }
            let reason = terminal_failure(turn);
            if reason.is_none()
                && (!blocked
                    || turn["status"] != "completed"
                    || turn.get("error") != Some(&Value::Null)
                    || times.started < goal.updated_at.max(oldest))
            {
                // All earlier turns ended by this start. A failed turn itself
                // may have started hours earlier and still have finished recently.
                return Ok(None);
            }
            if let Some(reason) = reason {
                let eligible = match goal.status.as_str() {
                    "blocked" => times.started <= goal.updated_at,
                    "active" => times.started >= goal.created_at,
                    "usageLimited" => {
                        times.started >= goal.created_at && reason == Failure::RateLimit
                    }
                    _ => false,
                };
                if !eligible
                    || (blocked && !queue_checked && !queue_empty(host, goal, deadline).await?)
                {
                    return Ok(None);
                }
                return Ok(Some((turn.clone(), queued, reason)));
            }
            queued.push(times);
        }
        let Some(next) = page["nextCursor"].as_str() else {
            return Ok(None);
        };
        if next.is_empty() || next.len() > 512 || !cursors.insert(next.to_owned()) {
            return Ok(None);
        }
        if ids.len() >= MAX_TURNS {
            return Ok(None);
        }
        if !queue_checked {
            if !queue_empty(host, goal, deadline).await? {
                return Ok(None);
            }
            queue_checked = true;
        }
        params["cursor"] = json!(next);
    }
}

async fn queue_empty(host: &mut Host, goal: &Goal, deadline: tokio::time::Instant) -> Result<bool> {
    let queue = tokio::time::timeout_at(
        deadline,
        host.rpc("thread/queue/list", json!({"threadId":goal.thread_id})),
    )
    .await??;
    Ok(queue["data"].as_array().is_some_and(Vec::is_empty) && queue["nextCursor"].is_null())
}
