use super::*;
use crate::babysitter::{classify, fingerprint};
use gent_protocol::notifications::Failure;
use serde::Deserialize;
use uuid::Uuid;

mod rollout;

#[derive(Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Goal {
    thread_id: String,
    objective: String,
    status: String,
    created_at: i64,
    updated_at: i64,
    token_budget: Option<i64>,
}

impl Goal {
    fn fingerprint(&self) -> String {
        fingerprint(&[
            &self.thread_id,
            &self.created_at.to_string(),
            &self.objective,
        ])
    }
}

#[derive(PartialEq)]
struct Stall {
    goal: Goal,
    turn: Uuid,
    failed_at: i64,
    reason: Failure,
    rollout: Option<rollout::Evidence>,
}

fn terminal_failure(last: &Value) -> Option<Failure> {
    // An interrupted turn can retain an earlier provider error after the user
    // cancels. Only the terminal failed state attributes the stop to the error.
    let error = &last["error"];
    if last["status"] != "failed" || !error.is_object() || !error["misalignment"].is_null() {
        return None;
    }
    let code = match &error["codexErrorInfo"] {
        Value::String(code) => code.as_str(),
        Value::Object(info) if info.len() == 1 => info.keys().next()?.as_str(),
        Value::Null => "",
        _ => return None,
    };
    classify(
        code,
        &format!(
            "{} {}",
            error["message"].as_str()?,
            error["additionalDetails"].as_str().unwrap_or("")
        ),
    )
}

async fn stalled(host: &mut Host, thread: &str) -> Result<Option<Stall>> {
    let info = host
        .rpc(
            "thread/read",
            json!({"threadId":thread,"includeTurns":false}),
        )
        .await?;
    let meta = &info["thread"];
    if meta["id"] != thread
        || meta["canAcceptDirectInput"] != true
        || !matches!(
            meta["status"]["type"].as_str(),
            Some("idle" | "systemError")
        )
    {
        return Ok(None);
    }
    let turns = host
        .rpc(
            "thread/turns/list",
            json!({"threadId":thread,"limit":1,"sortDirection":"desc","itemsView":"notLoaded"}),
        )
        .await?;
    let [last] = turns["data"]
        .as_array()
        .context("invalid Codex turn page")?
        .as_slice()
    else {
        return Ok(None);
    };
    let Some(reason) = terminal_failure(last) else {
        return Ok(None);
    };
    let (Some(started), Some(failed_at)) =
        (last["startedAt"].as_i64(), last["completedAt"].as_i64())
    else {
        return Ok(None);
    };
    let turn: Uuid = serde_json::from_value(last["id"].clone())?;
    let info = host
        .rpc("thread/goal/get", json!({"threadId":thread}))
        .await?;
    let Some(goal) = serde_json::from_value::<Option<Goal>>(info["goal"].clone())? else {
        return Ok(None);
    };
    if goal.thread_id != thread
        || turn.is_nil()
        || failed_at < started
        || (goal.status != "blocked" && started < goal.created_at)
        || goal.updated_at < goal.created_at
        || goal.updated_at > failed_at
    {
        return Ok(None);
    }
    let rollout = match goal.status.as_str() {
        "active" => None,
        "usageLimited" if reason == Failure::RateLimit => None,
        "blocked" if goal.updated_at >= started => {
            let Some(path) = meta["path"].as_str().map(PathBuf::from) else {
                return Ok(None);
            };
            let queue = host
                .rpc("thread/queue/list", json!({"threadId":thread}))
                .await?;
            if !queue["data"].as_array().is_some_and(Vec::is_empty) {
                return Ok(None);
            }
            let Some(evidence) =
                rollout::Evidence::read(path, goal.clone(), last.clone(), false).await?
            else {
                return Ok(None);
            };
            Some(evidence)
        }
        _ => return Ok(None),
    };
    Ok(Some(Stall {
        goal,
        turn,
        failed_at,
        reason,
        rollout,
    }))
}

pub(super) async fn inspect(
    home: &Path,
    socket: &Path,
    thread: &str,
    credential: &str,
) -> Result<()> {
    if home.join("babysitter-disabled").try_exists()? {
        return Ok(());
    }
    let mut host = Host::connect(socket).await?;
    let Some(stall) = stalled(&mut host, thread).await? else {
        return Ok(());
    };
    let response = agent(
        home,
        credential,
        AgentOp::BabysitterClaim {
            goal: stall.goal.fingerprint(),
            turn: stall.turn,
            failed_at: stall.failed_at,
            reason: stall.reason,
        },
    )
    .await?;
    let Some(id) = response["claim"].as_str() else {
        return Ok(());
    };
    let attempt = Uuid::parse_str(id)?;
    // The historical scan runs once for a due claim. Before and after it the
    // cheap reads compare the live host state and the exact rollout stamp.
    if let Some(evidence) = &stall.rollout
        && !evidence.confirms(&stall.goal).await?
    {
        return Ok(());
    }
    if agent(home, credential, AgentOp::BabysitterCheck { attempt }).await?["eligible"] != true
        || stalled(&mut host, thread).await?.as_ref() != Some(&stall)
    {
        return Ok(());
    }
    // Setting Active asks Codex to continue its existing goal if idle. Its
    // automatic origin preserves the distinction from a user-authored instruction.
    let result = host
        .rpc(
            "thread/goal/set",
            json!({"threadId":thread,"status":"active","origin":"automatic"}),
        )
        .await?;
    let resumed: Goal = serde_json::from_value(result["goal"].clone())?;
    ensure!(
        resumed.status == "active"
            && resumed.fingerprint() == stall.goal.fingerprint()
            && resumed.token_budget == stall.goal.token_budget,
        "Codex returned a different goal or did not resume it"
    );
    agent(
        home,
        credential,
        AgentOp::BabysitterSubmitted {
            attempt,
            scope: crate::auth::notifications::scope(home),
        },
    )
    .await?;
    Ok(())
}
