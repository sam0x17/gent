//! Attachment to a known background session, with extra automatic eligibility.
//! Never adopt, fork,
//! inject input, or infer completion of saved work from native inventory state.

use super::*;
use crate::integration::{claude_binding, runtime::Args, wake::valid_thread};
use gent_daemon::config;
use gent_protocol::{AgentOp, Request};
use zeroize::Zeroizing;

#[derive(PartialEq, Eq)]
pub(super) struct Binding {
    pub credential: Zeroizing<String>,
    pub agent: String,
}

pub(super) async fn binding(home: &Path, session: &str) -> Result<Binding> {
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
        "Claude startup requires a local chat in the selected cluster"
    );
    let agent = identity["agent"]["id"]
        .as_str()
        .filter(|id| valid_thread(id))
        .context("invalid Claude chat identity")?
        .to_owned();
    Ok(Binding { credential, agent })
}

pub(super) async fn target(
    home: &Path,
    directory: Option<PathBuf>,
) -> Result<install::ClaudeRuntime> {
    let target =
        crate::managed_file::retry_read(|| install::claude_runtime_target(home, directory.clone()))
            .await?;
    target.require_wake()?;
    Ok(target)
}

pub(super) async fn pinned(home: &Path, directory: &Path) -> Result<install::ClaudeRuntime> {
    let target =
        crate::managed_file::retry_read(|| install::claude_runtime_pinned(home, directory)).await?;
    target.require_wake()?;
    Ok(target)
}

async fn verify(
    home: &Path,
    directory: &Option<PathBuf>,
    expected: &install::ClaudeRuntime,
    session: &str,
    bound: &Binding,
    use_pin: bool,
) -> Result<()> {
    let current = if use_pin {
        pinned(home, &expected.directory).await?
    } else {
        target(home, directory.clone()).await?
    };
    ensure!(
        current == *expected,
        "Claude integration changed during startup"
    );
    ensure!(
        binding(home, session).await? == *bound,
        "Claude binding changed during startup"
    );
    Ok(())
}

pub(super) fn select(rows: Vec<sessions::Session>, session: &str) -> Result<sessions::Session> {
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

async fn start(
    home: &Path,
    args: Args,
    automatic: Option<(&config::RecoveryAgent, &str)>,
) -> Result<Value> {
    let session = args
        .session_id
        .as_deref()
        .context("Claude startup requires its full native session UUID")?;
    ensure!(valid_thread(session), "invalid Claude session UUID");
    let binary = args
        .host_binary
        .as_deref()
        .unwrap_or_else(|| Path::new("claude"));
    let expected = if let Some((entry, _)) = automatic {
        pinned(home, &entry.config_dir).await?
    } else {
        target(home, args.config_dir.clone()).await?
    };
    let bound = binding(home, session).await?;
    let initial = select(inspect(binary, &expected).await?, session)?;
    if let Some((entry, agent)) = automatic {
        recovery::authorize(entry, agent, &bound, &initial)?;
    }
    if initial.pid.is_none() {
        // Let the native supervisor reconcile a worker exit before attaching.
        // The later inventory checks, not this delay, establish the result.
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let mut attempts = 0;
    loop {
        verify(
            home,
            &args.config_dir,
            &expected,
            session,
            &bound,
            automatic.is_some(),
        )
        .await?;
        let observed = select(inspect(binary, &expected).await?, session)?;
        ensure!(
            observed.native_id == initial.native_id && observed.cwd == initial.cwd,
            "Claude native target changed during startup"
        );
        verify(
            home,
            &args.config_dir,
            &expected,
            session,
            &bound,
            automatic.is_some(),
        )
        .await?;
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
        let evidence = if let Some((entry, agent)) = automatic {
            recovery::authorize(entry, agent, &bound, &observed)?;
            if !recovery::pending(home, &bound).await? {
                return Ok(json!({"action":"waiting"}));
            }
            match eligibility::inspect(&expected.directory, session, &observed.cwd).await {
                Ok(evidence) => Some(evidence),
                Err(error) => {
                    return Ok(json!({"action":"needs_owner","reason":format!("{error:#}")}));
                }
            }
        } else {
            None
        };
        if let Some(evidence) = evidence {
            verify(home, &args.config_dir, &expected, session, &bound, true).await?;
            if !recovery::pending(home, &bound).await? {
                return Ok(json!({"action":"waiting"}));
            }
            evidence.verify()?;
        }
        let mut command = if automatic.is_some() {
            automatic_command(binary, &expected)?
        } else {
            command(binary, &expected)?
        };
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
    tokio::time::timeout(Duration::from_secs(30), start(home, args, None))
        .await
        .context("Claude startup timed out; inspect native status before retrying")?
}

pub(super) async fn automatic(
    home: &Path,
    args: Args,
    entry: &config::RecoveryAgent,
    agent: &str,
) -> Result<Value> {
    tokio::time::timeout(
        Duration::from_secs(30),
        start(home, args, Some((entry, agent))),
    )
    .await
    .context("automatic Claude recovery timed out")?
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod test_support;
