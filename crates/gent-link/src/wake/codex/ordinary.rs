//! Continue only a loaded native thread’s latest eligible failed foreground turn.
use super::*;
use gent_protocol::{
    babysitter::{CHAT_FAILURE_MAX_AGE, ChatOrigin},
    notifications::Failure,
};
use uuid::Uuid;

mod proof;
pub(super) use proof::user_source;

const PROMPT: &str = "please continue";
const TRIGGER: &str = "gent_babysitter";
// Reserve descriptors for the goal failure and the original operator, plus
// both descendants that can still be eligible for a retry.
const PRIOR_QUEUES: usize = 6;
const RETRY_PARENTS: usize = 2;

#[derive(Clone, Debug, PartialEq)]
struct Failed {
    thread: String,
    path: PathBuf,
    turn: Uuid,
    root: Uuid,
    started: i64,
    ended: i64,
    reason: Failure,
    error: String,
    goal: Value,
    previous_turns: Vec<Value>,
    legacy_history: bool,
    handoff_parent: bool,
}

fn uuid(value: &Value) -> Option<Uuid> {
    let text = value.as_str()?;
    let parsed = Uuid::parse_str(text).ok()?;
    (!parsed.is_nil() && parsed.to_string() == text).then_some(parsed)
}

impl Failed {
    fn from_head(
        thread: &str,
        path: PathBuf,
        head: &Value,
        completed: std::ops::RangeInclusive<i64>,
        goal: Value,
        legacy_history: bool,
        handoff_parent: bool,
    ) -> Option<Self> {
        let reason = babysit::terminal_failure(head)?;
        let started = head["startedAt"].as_i64()?;
        let ended = head["completedAt"].as_i64()?;
        if started > ended || !completed.contains(&ended) {
            return None;
        }
        Some(Self {
            goal,
            previous_turns: Vec::new(),
            legacy_history,
            handoff_parent,
            thread: thread.into(),
            path,
            turn: uuid(&head["id"])?,
            root: uuid(&head["rootTurnId"])?,
            started,
            ended,
            reason,
            error: head["error"]["message"].as_str()?.into(),
        })
    }
}

async fn latest(host: &mut Host, thread: &str) -> Result<Option<Failed>> {
    let id = json!({"threadId":thread});
    let state = host
        .rpc(
            "thread/read",
            json!({"threadId":thread,"includeTurns":false}),
        )
        .await?;
    let t = &state["thread"];
    if t["id"] != thread
        || t["canAcceptDirectInput"] != true
        || !matches!(t["status"]["type"].as_str(), Some("idle" | "systemError"))
    {
        return Ok(None);
    }
    let Some(path) = t["path"].as_str() else {
        return Ok(None);
    };
    let goal_state = host.rpc("thread/goal/get", id.clone()).await?;
    let Some(goal) = goal_state.get("goal") else {
        return Ok(None);
    };
    if !goal.is_null()
        && (!matches!(goal["status"].as_str(), Some("complete" | "blocked"))
            || goal["threadId"] != thread
            || goal["objective"].as_str().is_none_or(str::is_empty)
            || goal["createdAt"]
                .as_i64()
                .zip(goal["updatedAt"].as_i64())
                .is_none_or(|(created, updated)| created < 0 || created > updated))
    {
        return Ok(None);
    }
    let blocked = goal["status"] == "blocked";
    let limit = if blocked {
        2 + PRIOR_QUEUES + RETRY_PARENTS
    } else {
        1
    };
    let page = host
        .rpc(
            "thread/turns/list",
            json!({"threadId":thread,"itemsView":"notLoaded","sortDirection":"desc","limit":limit}),
        )
        .await?;
    let Some((head, previous)) = page["data"]
        .as_array()
        .and_then(|turns| turns.split_first())
    else {
        return Ok(None);
    };
    if previous.len() >= limit {
        return Ok(None);
    }
    let now = gent_daemon::store::now();
    let Some(mut failed) = Failed::from_head(
        thread,
        path.into(),
        head,
        now - CHAT_FAILURE_MAX_AGE..=now,
        goal.clone(),
        t["historyMode"] == "legacy",
        t["historyMode"] == "paginated"
            && t["threadSource"] == "user"
            && t.get("parentThreadId") == Some(&Value::Null)
            && t.get("attachedToThreadId") == Some(&Value::Null)
            && matches!(t["source"].as_str(), Some("vscode" | "cli")),
    ) else {
        return Ok(None);
    };
    if goal["updatedAt"]
        .as_i64()
        .is_some_and(|at| at >= failed.started)
    {
        return Ok(None);
    }
    if blocked {
        if !failed.handoff_parent {
            return Ok(None);
        }
        let updated = goal["updatedAt"].as_i64();
        let Some(index) = previous.iter().position(|turn| {
            turn["completedAt"].as_i64() == updated && babysit::terminal_failure(turn).is_some()
        }) else {
            return Ok(None);
        };
        let Some(depth) = std::iter::once(head)
            .chain(&previous[..index])
            .position(|turn| uuid(&turn["id"]) == Some(failed.root))
        else {
            return Ok(None);
        };
        if depth > RETRY_PARENTS || index - depth > PRIOR_QUEUES {
            return Ok(None);
        }
        failed.previous_turns.extend_from_slice(&previous[..=index]);
    }
    let queue = host.rpc("thread/queue/list", id).await?;
    Ok(
        (queue["data"].as_array().is_some_and(Vec::is_empty) && queue["nextCursor"].is_null())
            .then_some(failed),
    )
}

pub(super) async fn inspect(
    home: &Path,
    registry: &Registry,
    thread: &str,
    credential: &str,
) -> Result<()> {
    let mut host = Host::connect(&registry.endpoint).await?;
    let Some(failed) = latest(&mut host, thread).await? else {
        return Ok(());
    };
    let probe = AgentOp::BabysitterChatProbe {
        turn: failed.turn,
        operator: failed.root,
        failed_at: failed.ended,
    };
    if agent(home, credential, probe).await?["inspect"] != true {
        return Ok(());
    }
    let candidate = failed.clone();
    let Some((origin, parent, mut evidence)) =
        tokio::task::spawn_blocking(move || proof::read(&candidate)).await??
    else {
        return Ok(());
    };
    if !babysit::confirmed_inputs(home, credential, thread, &evidence.direct).await? {
        return Ok(());
    }
    let response = agent(
        home,
        credential,
        AgentOp::BabysitterChatClaim {
            turn: failed.turn,
            failed_at: failed.ended,
            reason: failed.reason,
            origin: origin.clone(),
        },
    )
    .await?;
    let Some(attempt) = uuid(&response["claim"]) else {
        return Ok(());
    };
    let Some(operator_at) = response["operator_at"].as_i64() else {
        return Ok(());
    };
    if uuid(&response["operator"]) != Some(failed.root)
        || uuid(&response["parent"]) != parent
        || failed.goal["updatedAt"]
            .as_i64()
            .is_some_and(|completed| completed >= operator_at)
    {
        return Ok(());
    }
    // A stalled daemon or a sequence of slow host reads must not stretch the
    // admission window to the sum of all their independent RPC timeouts.
    let ready = tokio::time::timeout(Duration::from_secs(3), async {
        if agent(home, credential, AgentOp::BabysitterChatCheck { attempt }).await?["eligible"]
            != true
            || latest(&mut host, thread).await?.as_ref() != Some(&failed)
        {
            return Ok(false);
        }
        // A delayed completion can arrive while claiming. Reprove the same
        // admissions and reread the live queue/head before using that claim.
        let observed = proof::Stamp::current(&failed.path)?;
        if evidence.stamp != observed {
            if !observed.grew_from(&evidence.stamp) {
                return Ok(false);
            }
            let candidate = failed.clone();
            let Some((new_origin, new_parent, new_evidence)) =
                tokio::task::spawn_blocking(move || proof::read(&candidate)).await??
            else {
                return Ok(false);
            };
            if new_evidence.stamp != observed
                || new_evidence.direct != evidence.direct
                || new_origin != origin
                || new_parent != parent
                || latest(&mut host, thread).await?.as_ref() != Some(&failed)
            {
                return Ok(false);
            }
            evidence = new_evidence;
        }
        Ok::<_, anyhow::Error>(
            registry.credential(thread)?.as_deref() == Some(credential)
                && gent_daemon::config::ordinary_babysitter_enabled(home)?
                && babysit::confirmed_inputs(home, credential, thread, &evidence.direct).await?
                && evidence.stamp.matches(&failed.path)?,
        )
    })
    .await??;
    if !ready {
        return Ok(());
    }

    // 0.170 turn/start has no expected-head condition. Keep the final host reads
    // adjacent to admission. A lost response leaves the durable claim consumed.
    let result = host
        .rpc(
            "turn/start",
            json!({
                "threadId":thread, "clientUserMessageId":attempt,
                "turnTrigger":TRIGGER,"parentTurnId":failed.turn,"rootTurnId":failed.root,
                "input":[{"type":"text","text":PROMPT}]
            }),
        )
        .await?;
    let accepted = &result["turn"];
    ensure!(
        uuid(&accepted["id"]).is_some_and(|id| id != failed.turn)
            && uuid(&accepted["rootTurnId"]) == Some(failed.root),
        "Codex did not confirm a continuation of the claimed turn"
    );
    agent(
        home,
        credential,
        AgentOp::BabysitterChatSubmitted { attempt },
    )
    .await?;
    Ok(())
}
