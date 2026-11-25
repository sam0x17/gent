//! Descending, items-free turn metadata. Only blocked goals can use earlier failures.
use super::*;
use std::collections::HashSet;

const PAGE_SIZE: usize = 32;
const MAX_TURNS: usize = 4096;
const MAX_FAILURES: usize = 32;

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

#[derive(Clone, PartialEq)]
pub(super) struct Failed {
    pub(super) turn: Value,
    pub(super) reason: Failure,
}

#[derive(Clone, PartialEq)]
pub(super) struct Candidate {
    // The failure in which the goal last changed. For a blocked goal the
    // rollout must still prove that this turn caused the block.
    pub(super) anchor: Failed,
    pub(super) later: Vec<Later>, // newest first, without gaps
}

#[derive(Clone, PartialEq)]
pub(super) struct Later {
    pub(super) times: Completed,
    pub(super) failure: Option<Failed>,
}

impl Candidate {
    pub(super) fn latest(&self) -> &Failed {
        self.later
            .iter()
            .find_map(|t| t.failure.as_ref())
            .unwrap_or(&self.anchor)
    }
}

pub(super) async fn candidate(host: &mut Host, goal: &Goal) -> Result<Option<Candidate>> {
    let blocked = goal.status == "blocked";
    let limit = if blocked { PAGE_SIZE } else { 1 };
    let mut params = json!({"threadId":goal.thread_id,"limit":limit,"sortDirection":"desc","itemsView":"notLoaded"});
    let mut cursors = HashSet::new();
    let mut ids = HashSet::new();
    let mut failures = 0;
    let mut later = Vec::new();
    let mut newer_start = None;
    // The longer window is available only to the blocked-goal claim after
    // a complete native proof. Older provenance can never supply a fresher
    // timestamp. It is bounded by the turn, page, byte and RPC limits.
    let age = if blocked {
        gent_protocol::wake::VERIFIED_BLOCKED_MAX_AGE_SECS
    } else {
        7200
    };
    let oldest = gent_daemon::store::now() - age;
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
            if (failures == 0 && times.ended < oldest)
                || times.ended < goal.updated_at
                || newer_start.is_some_and(|start| times.ended > start)
                || ids.len() >= MAX_TURNS
                || !ids.insert(times.id.clone())
            {
                return Ok(None);
            }
            newer_start = Some(times.started);
            if let Some(reason) = terminal_failure(turn) {
                let failure = Failed {
                    turn: turn.clone(),
                    reason,
                };
                if blocked && times.started > goal.updated_at {
                    failures += 1;
                    if failures >= MAX_FAILURES {
                        return Ok(None);
                    }
                    later.push(Later {
                        times,
                        failure: Some(failure),
                    });
                    continue;
                }
                let eligible = match goal.status.as_str() {
                    "blocked" => true,
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
                return Ok(Some(Candidate {
                    anchor: failure,
                    later,
                }));
            }
            if !blocked
                || turn["status"] != "completed"
                || turn.get("error") != Some(&Value::Null)
                || times.started < goal.updated_at
                || (failures == 0 && times.started < oldest)
            {
                return Ok(None);
            }
            later.push(Later {
                times,
                failure: None,
            });
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
