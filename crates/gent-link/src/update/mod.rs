mod cache;
mod channel;
mod coordination;
mod install;
mod integrations;
mod notification;
mod priority;
mod process;
mod release;
mod status;
mod workflow;
use workflow::{Trigger, apply};

use crate::build_info::{self, Build};
use anyhow::{Context, Result, ensure};
use gent_daemon::config;
use install::Installation;
use release::ReleaseRef;
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const CHECK_INTERVAL: Duration = Duration::from_secs(300);

#[derive(clap::Subcommand)]
pub(crate) enum Command {
    /// Check the selected channel and install a different revision now, even if auto-update is disabled.
    Install,
    /// Resolve the selected channel and compare it with the binary on disk, without installing.
    Check,
    /// Show local update state and the installed revision without network access.
    Status,
    /// Enable automatic checks every five minutes on this node.
    Enable,
    /// Pause routine updates on this node. Signed cluster channel switches still apply.
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

async fn check(home: &Path, installation: &Installation) -> Result<Value> {
    compare_release(home, install::version(&installation.binary).await?).await
}

pub(crate) async fn desktop_check(home: &Path) -> Result<Value> {
    match Installation::discover()? {
        Some(installation) => check(home, &installation).await,
        None => compare_release(home, build_info::version()).await,
    }
}

async fn compare_release(home: &Path, version: build_info::Version) -> Result<Value> {
    let installed = version.build;
    let channel = ReleaseRef::current(home)?;
    let _progress = crate::ui::Progress::start(&format!("Checking GitHub {}", channel.channel));
    let blessed = channel.resolve().await?;
    let resolution = blessed.resolution;
    Ok(
        json!({"installed":installed,"blessed_commit":resolution.blessed_commit,
        "resolved_ref":resolution.resolved_ref,"advertised_commit":resolution.advertised_commit,
        "update_available": !resolution.matches_build(&installed, version.bootstrap_commit.as_deref()),
        "repository":blessed.repository,"channel":channel.channel,"release_ref":channel.reference,"source":resolution.source}),
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
        return Ok(status::with_channel(
            home,
            json!({"state":"unsupported_installation","cli":build_info::current(),"enabled":config::load(home)?.updates()?.enabled,"check_interval_seconds":300}),
        ));
    };
    match command {
        Command::Check => check(home, &installation).await,
        Command::Install => apply(home, &installation, Trigger::Manual).await,
        Command::Status => status::report(home, &installation).await,
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

async fn wait_for_ready(home: &Path) {
    // Ready is an authenticated response from this process, not socket presence.
    loop {
        if let Ok(status) = crate::owner(home, gent_protocol::OwnerOp::Status).await
            && status["process_id"] == std::process::id()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(target_os = "macos")]
async fn repair_desktop(home: &Path) {
    let result: Result<()> = async {
        let binary = std::env::current_exe()?;
        // An old process can retain the path of a CLI already replaced on disk.
        if install::inspect(&binary).await? == build_info::current() {
            let user = std::env::var_os("HOME").context("missing user Applications directory")?;
            let home = home.to_owned();
            tokio::task::spawn_blocking(move || {
                crate::desktop::repair_installed(Path::new(&user), &binary, &home)
            })
            .await??;
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        eprintln!(
            "Gent Desktop app repair: {error:#}. Retry with gent desktop after quitting the old app."
        );
    }
}

async fn monitor(home: &Path, installation: &Installation) {
    wait_for_ready(home).await;
    let notification = loop {
        match installation.healthy(home, &build_info::current()) {
            Ok(Some(build)) => {
                break Some(build);
            }
            Ok(None) => break None,
            Err(error) => {
                eprintln!("Gent update readiness pending: {error}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    #[cfg(target_os = "macos")]
    repair_desktop(home).await;
    integrations::refresh(home, installation).await;
    if let Some(build) = notification {
        notification::installed(home, &build).await;
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
    let mut channels = tokio::time::interval(interval.min(Duration::from_secs(10)));
    channels.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut attempted = None;
    let mut activation = tokio::time::interval(Duration::from_secs(1));
    activation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = checks.tick() => {
                integrations::refresh(home, installation).await;
                match apply(home, installation, Trigger::Scheduled).await {
                    Ok(result) if result["state"] == "restart_for_channel" => return,
                    Err(error) => eprintln!("Gent automatic update pending: {error}"),
                    _ => {}
                }
            }
            _ = channels.tick() => {
                // This authenticated local hint avoids Git and reopening the
                // authority database each time. The writer independently reads
                // the signed selection under its lock, including at publication.
                if let Ok(status) = crate::owner(home, gent_protocol::OwnerOp::Status).await
                    && let Some(channel) = status["release_channel"].as_str()
                    && let Ok(channel) = channel.parse::<gent_protocol::ReleaseChannel>()
                {
                    if installation.applied_channel(home).ok() == Some(channel) {
                        attempted = None;
                        continue;
                    }
                    if attempted == Some(channel) {
                        continue;
                    }
                    match apply(home, installation, Trigger::ChannelChange).await {
                        Ok(result) if result["state"] == "restart_for_channel" => return,
                        Ok(result) if result["state"] == "already_running" => {}
                        result => {
                            attempted = Some(channel);
                            if let Err(error) = result {
                                eprintln!("Gent release channel switch pending: {error}");
                            }
                        }
                    }
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
    let daemon_lock = gent_daemon::DaemonLock::acquire(home)?
        .with_build_info(serde_json::to_value(build_info::current())?);
    let installation = match Installation::discover() {
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
                // Publication can still hold the writer lock during startup.
                // Serve normally and let authenticated readiness reconcile the
                // journal. Do not permanently disable the monitor after a race.
                eprintln!("Gent update startup recovery pending: {error}");
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
        // A launchd service or manually upgraded CLI can live outside CARGO_HOME.
        #[cfg(target_os = "macos")]
        tokio::select! {
            result = &mut daemon => return result,
            () = async { wait_for_ready(home).await; repair_desktop(home).await; } => {}
        }
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
