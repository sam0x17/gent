mod install;
mod notification;
mod process;
mod release;
mod workflow;
use workflow::apply;

use crate::build_info::{self, Build};
use anyhow::{Context, Result, ensure};
use gent_daemon::config;
use install::Installation;
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const CHECK_INTERVAL: Duration = Duration::from_secs(300);

#[derive(clap::Subcommand)]
pub(crate) enum Command {
    /// Check stable and install a different revision now, even if auto-update is disabled.
    Install,
    /// Resolve stable and compare it with the binary on disk, without installing.
    Check,
    /// Show local update state and the installed revision without network access.
    Status,
    /// Enable automatic checks every five minutes on this node.
    Enable,
    /// Disable automatic checks and prevent an in-progress build from being published.
    Disable,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn eligible(build: &Build) -> bool {
    build.package == "gent-link"
        && build_info::valid_commit(&build.commit)
        && !build.dirty
        && build.target == build_info::current().target
        && build.update_protocol == 1
        && build.test_build == cfg!(feature = "test-updates")
}

async fn check(installation: &Installation) -> Result<Value> {
    let installed = install::inspect(&installation.binary).await?;
    let _progress = crate::ui::Progress::start("Checking GitHub stable");
    let blessed = release::resolve().await?;
    Ok(
        json!({"installed":installed,"blessed_commit":blessed.commit,
        "update_available": installed.commit != blessed.commit || installed.dirty,
        "repository":blessed.repository,"source":"github_stable_tag"}),
    )
}

pub(crate) async fn execute(home: &Path, command: Command) -> Result<Value> {
    if matches!(command, Command::Enable | Command::Disable) {
        let enabled = matches!(command, Command::Enable);
        config::edit_local(home, |cfg| cfg.set_updates(config::Updates { enabled }))?;
        return Ok(json!({"enabled":enabled,"check_interval_seconds":300,"scope":"this_node"}));
    }
    let installation = Installation::discover()?;
    let Some(installation) = installation else {
        ensure!(
            matches!(command, Command::Status),
            "automatic installation requires gent in CARGO_HOME/bin; install it with cargo first"
        );
        return Ok(
            json!({"state":"unsupported_installation","running":build_info::current(),"enabled":config::load(home)?.updates()?.enabled,"check_interval_seconds":300}),
        );
    };
    match command {
        Command::Check => check(&installation).await,
        Command::Install => apply(home, &installation, false).await,
        Command::Status => Ok(json!({"enabled":config::load(home)?.updates()?.enabled,
            "check_interval_seconds":300,"running":build_info::current(),
            "installed":install::inspect(&installation.binary).await?,
            "update":installation.status()?,"activation_pending":installation.pending()?.is_some(),
            "build_log":installation.directory.join("build.log")})),
        Command::Enable | Command::Disable => unreachable!(),
    }
}

fn activate(home: &Path, installation: &Installation) -> Result<()> {
    use std::os::unix::process::CommandExt;
    // exec preserves the service-manager PID and leaves native chat processes
    // and MCP connections alive. The daemon has already drained and unlocked.
    let error = std::process::Command::new(&installation.binary)
        .arg("--home")
        .arg(home)
        .args(["daemon", "run"])
        .exec();
    if let Some(pending) = installation.pending()? {
        let _lock = installation.lock()?;
        installation.rollback(&pending, "could not execute the updated daemon")?;
        return Err(std::process::Command::new(&installation.binary)
            .arg("--home")
            .arg(home)
            .args(["daemon", "run"])
            .exec()
            .into());
    }
    Err(error.into())
}

async fn monitor(home: &Path, installation: &Installation) {
    // Ready is an authenticated response from this process, not socket presence.
    loop {
        if let Ok(status) = crate::owner(home, gent_protocol::OwnerOp::Status).await
            && status["process_id"] == std::process::id()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    loop {
        match installation.healthy(&build_info::current()) {
            Ok(Some(build)) => {
                notification::installed(&build).await;
                break;
            }
            Ok(None) => break,
            Err(error) => {
                eprintln!("Gent update readiness pending: {error}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
    let interval = CHECK_INTERVAL;
    #[cfg(feature = "test-updates")]
    let interval = std::env::var("GENT_TEST_UPDATE_INTERVAL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|seconds| Duration::from_secs(seconds.max(1)))
        .unwrap_or(interval);
    let mut checks = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut activation = tokio::time::interval(Duration::from_secs(1));
    activation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = checks.tick() => {
                match config::load(home).and_then(|cfg| cfg.updates()) {
                    Ok(settings) if settings.enabled => {
                        if let Err(error) = apply(home, installation, true).await {
                            eprintln!("Gent automatic update pending: {error}");
                        }
                    }
                    Ok(_) => {}
                    Err(_) => eprintln!("Gent automatic updates paused: invalid local configuration"),
                }
            }
            _ = activation.tick() => {
                match installation.needs_restart(home) {
                    Ok(true) => return,
                    Ok(false) => {},
                    Err(error) => eprintln!("Gent update activation pending: {error}"),
                }
            }
        }
    }
}

pub(crate) async fn run_daemon(home: &Path) -> Result<()> {
    let daemon_lock = gent_daemon::DaemonLock::acquire(home)?;
    let mut installation = match Installation::discover() {
        Ok(installation) => installation,
        Err(error) => {
            eprintln!("Gent automatic updates unavailable: {error}");
            None
        }
    };
    if let Some(current) = &installation {
        match current.begin_startup(home, &build_info::current()) {
            Ok(true) => return activate(home, current),
            Ok(false) => {}
            Err(error) => {
                // Optional update bookkeeping must not take messaging offline.
                // Keep the journal for inspection and stop automatic mutations.
                eprintln!("Gent automatic updates unavailable: {error}");
                installation = None;
            }
        }
    }
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let daemon = async {
        #[cfg(feature = "test-updates")]
        if std::env::var("GENT_TEST_UPDATE_FAIL_COMMIT")
            .ok()
            .as_deref()
            == Some(&build_info::current().commit)
        {
            anyhow::bail!("injected update startup failure");
        }
        crate::auth::renewal::run_daemon(daemon_lock, async {
            let _ = stopped.await;
        })
        .await
    };
    tokio::pin!(daemon);
    let Some(installation) = installation else {
        return daemon.await;
    };
    let outcome = tokio::select! {
        biased;
        result = &mut daemon => Some(result),
        _ = monitor(home, &installation) => None,
    };
    if let Some(result) = outcome {
        if result.is_err()
            && let Some(pending) = installation.pending()?
            && pending.starting
            && pending.new == build_info::current()
        {
            let lock = installation.lock()?;
            installation.rollback(&pending, "updated daemon failed before reporting readiness")?;
            drop(lock);
            return activate(home, &installation);
        }
        return result;
    }
    let _ = stop.send(());
    daemon
        .await
        .context("daemon could not drain before update")?;
    activate(home, &installation)
}

#[cfg(test)]
mod tests;
