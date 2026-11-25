//! Continue only a loaded native thread’s latest failed foreground user turn.
use super::*;
use gent_protocol::{
    babysitter::{CHAT_FAILURE_MAX_AGE, ChatOrigin},
    notifications::Failure,
};
use uuid::Uuid;

mod proof;

const PROMPT: &str = "please continue";
const TRIGGER: &str = "gent_babysitter";

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
}

fn uuid(value: &Value) -> Option<Uuid> {
    let text = value.as_str()?;
    let parsed = Uuid::parse_str(text).ok()?;
    (!parsed.is_nil() && parsed.to_string() == text).then_some(parsed)
}

impl Failed {
    fn from_head(thread: &str, path: PathBuf, head: &Value, now: i64, goal: Value) -> Option<Self> {
        let reason = babysit::terminal_failure(head)?;
        let started = head["startedAt"].as_i64()?;
        let ended = head["completedAt"].as_i64()?;
        if started > ended || !(now - CHAT_FAILURE_MAX_AGE..=now).contains(&ended) {
            return None;
        }
        Some(Self {
            goal,
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
        && (goal["status"] != "complete"
            || goal["threadId"] != thread
            || goal["objective"].as_str().is_none_or(str::is_empty)
            || goal["createdAt"]
                .as_i64()
                .zip(goal["updatedAt"].as_i64())
                .is_none_or(|(created, updated)| created < 0 || created > updated))
    {
        return Ok(None);
    }
    let page = host
        .rpc(
            "thread/turns/list",
            json!({"threadId":thread,"itemsView":"notLoaded","sortDirection":"desc","limit":1}),
        )
        .await?;
    let Some([head]) = page["data"].as_array().map(Vec::as_slice) else {
        return Ok(None);
    };
    let Some(failed) = Failed::from_head(
        thread,
        path.into(),
        head,
        gent_daemon::store::now(),
        goal.clone(),
    ) else {
        return Ok(None);
    };
    if goal["updatedAt"]
        .as_i64()
        .is_some_and(|at| at >= failed.started)
    {
        return Ok(None);
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
    let Some((origin, parent, stamp)) =
        tokio::task::spawn_blocking(move || proof::read(&candidate)).await??
    else {
        return Ok(());
    };
    let response = agent(
        home,
        credential,
        AgentOp::BabysitterChatClaim {
            turn: failed.turn,
            failed_at: failed.ended,
            reason: failed.reason,
            origin,
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
        Ok::<_, anyhow::Error>(
            agent(home, credential, AgentOp::BabysitterChatCheck { attempt }).await?["eligible"]
                == true
                && latest(&mut host, thread).await?.as_ref() == Some(&failed)
                && registry.credential(thread)?.as_deref() == Some(credential)
                && gent_daemon::config::ordinary_babysitter_enabled(home)?
                && stamp.matches(&failed.path)?,
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
