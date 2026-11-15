//! Owner-requested attachment to a known background session. Never adopt, fork,
//! inject input, or infer completion of saved work from native inventory state.

use super::*;
use crate::integration::{claude_binding, runtime::Args, wake::valid_thread};
use gent_daemon::config;
use gent_protocol::{AgentOp, Request};
use zeroize::Zeroizing;

#[derive(PartialEq, Eq)]
struct Binding {
    credential: Zeroizing<String>,
    agent: String,
}

async fn binding(home: &Path, session: &str) -> Result<Binding> {
    let cfg = config::load(home)?;
    let credential = Zeroizing::new(
        claude_binding::credential(home, &cfg, session)?
            .context("use Gent in the original Claude conversation before starting it")?,
    );
    let identity = tokio::time::timeout(
        Duration::from_secs(5),
        gent_daemon::request(
            home,
            Request::Agent {
                credential: credential.to_string(),
                action: AgentOp::Identity,
            },
        ),
    )
    .await
    .context("Gent did not confirm the Claude binding")??;
    ensure!(
        identity["cluster_id"] == cfg.cluster.id && identity["agent"]["node_id"] == cfg.node.id,
        "Claude startup requires a local agent in the selected cluster"
    );
    let agent = identity["agent"]["id"]
        .as_str()
        .filter(|id| valid_thread(id))
        .context("invalid Claude agent identity")?
        .to_owned();
    Ok(Binding { credential, agent })
}

async fn target(home: &Path, directory: Option<PathBuf>) -> Result<install::ClaudeRuntime> {
    let target =
        crate::managed_file::retry_read(|| install::claude_runtime_target(home, directory.clone()))
            .await?;
    target.require_wake()?;
    Ok(target)
}

async fn verify(
    home: &Path,
    directory: &Option<PathBuf>,
    expected: &install::ClaudeRuntime,
    session: &str,
    bound: &Binding,
) -> Result<()> {
    ensure!(
        target(home, directory.clone()).await? == *expected,
        "Claude integration changed during startup"
    );
    ensure!(
        binding(home, session).await? == *bound,
        "Claude binding changed during startup"
    );
    Ok(())
}

fn select(rows: Vec<sessions::Session>, session: &str) -> Result<sessions::Session> {
    ensure!(valid_thread(session), "invalid Claude session UUID");
    let row = rows
        .into_iter()
        .find(|row| row.session_id.as_deref() == Some(session))
        .context("native session is absent; adopt it with Claude's background controls first")?;
    ensure!(
        row.native_kind == "background" && row.native_id.as_deref() == Some(&session[..8]),
        "session is not an identifiable native background session; use Claude's background controls first"
    );
    Ok(row)
}

async fn start(home: &Path, args: Args) -> Result<Value> {
    let session = args
        .session_id
        .as_deref()
        .context("Claude startup requires its full native session UUID")?;
    ensure!(valid_thread(session), "invalid Claude session UUID");
    let binary = args
        .host_binary
        .as_deref()
        .unwrap_or_else(|| Path::new("claude"));
    let expected = target(home, args.config_dir.clone()).await?;
    let bound = binding(home, session).await?;
    let initial = select(inspect(binary, &expected).await?, session)?;
    if initial.pid.is_none() {
        // Let the native supervisor reconcile a worker exit before attaching.
        // The later inventory checks, not this delay, establish the result.
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let mut attempts = 0;
    loop {
        verify(home, &args.config_dir, &expected, session, &bound).await?;
        let observed = select(inspect(binary, &expected).await?, session)?;
        ensure!(
            observed.native_id == initial.native_id && observed.cwd == initial.cwd,
            "Claude native target changed during startup"
        );
        verify(home, &args.config_dir, &expected, session, &bound).await?;
        if observed.pid.is_some() {
            return Ok(
                json!({"host":"claude-code","action":if attempts==0 {"already_running"} else {"attached"},
                "agent":bound.agent,"gent_binding_checked":true,"session":observed,
                "native_attach_attempts":attempts,"reported_running":true}),
            );
        }
        ensure!(
            attempts < 3,
            "Claude did not report the session running; inspect gent integration status claude-code --live before retrying"
        );
        let mut command = command(binary, &expected)?;
        command
            .args([
                "attach",
                initial.native_id.as_deref().context("missing native ID")?,
            ])
            .current_dir(&initial.cwd);
        let output = process::output(command, Duration::from_secs(15), OUTPUT_LIMIT).await?;
        ensure!(
            output.status.success(),
            "Claude attach failed; inspect native status in the selected profile before retrying"
        );
        attempts += 1;
        // A just-crashed native worker can remain briefly attachable in the
        // supervisor. EOF exits attach successfully without waking it. Recheck
        // the same identity before another bounded attach, never --bg --resume.
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

pub(in crate::integration::runtime) async fn run(home: &Path, args: Args) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(30), start(home, args))
        .await
        .context("Claude startup timed out; inspect native status before retrying")?
}

#[cfg(test)]
mod tests;
