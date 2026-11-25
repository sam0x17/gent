//! Resolve and build a release while holding the installation's writer lock.
use super::{
    eligible,
    install::{self, Installation, Source, Status},
    now,
    release::{self, ReleaseRef},
};
use anyhow::{Result, ensure};
use gent_daemon::config;
use serde_json::{Value, json};
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Trigger {
    Manual,
    Scheduled,
    ChannelChange,
}

pub(super) async fn apply(
    home: &Path,
    installation: &Installation,
    trigger: Trigger,
) -> Result<Value> {
    let Some(_lock) =
        super::coordination::acquire(installation, trigger != Trigger::Manual).await?
    else {
        return Ok(json!({"state":"already_running"}));
    };
    let mut status = installation.status()?;
    let result = run(home, installation, trigger, &mut status).await;
    if let Err(error) = &result {
        status.phase = "failed".into();
        status.error = Some(error.to_string());
        let _ = installation.write("status.json", &status);
    }
    result
}

async fn run(
    home: &Path,
    installation: &Installation,
    trigger: Trigger,
    status: &mut Status,
) -> Result<Value> {
    if let Some(pending) = installation.pending()? {
        let same_home = pending.home == home.canonicalize()?;
        if same_home
            && !pending.starting
            && install::hash(&installation.binary)? == pending.old_hash
        {
            installation.interrupted_publication(&pending)?;
            *status = installation.status()?;
        } else {
            let next = if !same_home {
                "The pending update belongs to another Gent home; inspect gent update status --json."
            } else if pending.starting {
                "The new daemon has not acknowledged readiness; inspect gent daemon status before restarting."
            } else {
                "If this persists, run gent daemon restart, then gent update."
            };
            return Ok(
                json!({"state":"awaiting_activation","commit":pending.new.commit,"next":next}),
            );
        }
    }
    let channel = ReleaseRef::current(home)?;
    let transition = installation.applied_channel(home)? != channel.channel;
    let automatic = trigger != Trigger::Manual;
    if !transition {
        match trigger {
            Trigger::ChannelChange => return Ok(json!({"state":"channel_applied"})),
            Trigger::Scheduled if !config::load(home)?.updates()?.enabled => {
                return Ok(json!({"state":"disabled"}));
            }
            _ => {}
        }
    }
    let installed = install::inspect(&installation.binary).await?;
    if automatic && !eligible(&installed) {
        return Ok(json!({"state":"development_build","installed":installed}));
    }
    let expected_old = install::hash(&installation.binary)?;
    let progress = crate::ui::Progress::start(&format!("Checking GitHub {}", channel.channel));
    let release = channel.resolve().await?;
    let blessed = release.commit.clone();
    drop(progress);
    status.last_checked = Some(now());
    status.blessed_commit = Some(blessed.clone());
    // A new tip ends suppression of a failed revision, including a move
    // back to the already installed build.
    if status.failed_commit.as_deref() != Some(&blessed) {
        status.failed_commit = None;
    }
    if installed.commit == blessed && !installed.dirty && (!transition || eligible(&installed)) {
        if transition {
            ensure!(
                ReleaseRef::current(home)? == channel
                    && install::hash(&installation.binary)? == expected_old,
                "channel or installation changed during the check; retry for the selected release"
            );
            // A manual installation may already have put this commit on disk
            // while the daemon still serves the previous build. Leave the
            // switch unacknowledged until the selected process is running.
            let running_matches = if automatic {
                installed == crate::build_info::current()
            } else {
                crate::owner(home, gent_protocol::OwnerOp::Status)
                    .await
                    .is_ok_and(|daemon| daemon["build"] == json!(installed))
            };
            if !running_matches {
                status.phase = "awaiting_activation".into();
                status.error = None;
                installation.write("status.json", status)?;
                return Ok(
                    json!({"state":"restart_for_channel","channel":channel.channel,
                    "commit":blessed,"activation":"The selected release is on disk. The daemon will confirm the channel when it is running that build."}),
                );
            }
            installation.confirm_channel(home, channel.channel)?;
        }
        status.phase = "current".into();
        status.error = None;
        installation.write("status.json", &status)?;
        return Ok(
            json!({"state":"current","channel":channel.channel,"release_ref":channel.reference,"installed":installed}),
        );
    }
    if automatic && status.failed_commit.as_deref() == Some(&blessed) {
        status.phase = "rolled_back".into();
        installation.write("status.json", &status)?;
        return Ok(
            json!({"state":"rolled_back","channel":channel.channel,"release_ref":channel.reference,"commit":blessed,"next":"Run gent update install to retry this revision explicitly."}),
        );
    }
    status.phase = "building".into();
    status.error = None;
    installation.write("status.json", &status)?;
    let stage = tempfile::Builder::new()
        .prefix("stage-")
        .tempdir_in(&installation.directory)?;
    let progress = crate::ui::Progress::start(&format!(
        "Building {} release; daemon remains available",
        channel.channel
    ));
    let candidate = release::stage(
        &release,
        stage.path(),
        &installation.directory.join("target"),
        &installed.commit,
        &installation.directory.join("build.log"),
    )
    .await?;
    let new = install::inspect(&candidate).await?;
    ensure!(
        eligible(&new) && new.commit == blessed,
        "built binary does not match the selected revision and platform"
    );
    if let Err(error) = release::prune(
        &installation.directory.join("target"),
        &[&installed.commit, &blessed],
    )
    .await
    {
        eprintln!("Gent update cache cleanup pending: {error}");
    }
    ensure!(
        channel.resolve().await?.commit == blessed,
        "{} changed during the build; retry for the current release",
        channel.reference
    );
    if automatic && !transition && !config::load(home)?.updates()?.enabled {
        status.phase = "disabled".into();
        installation.write("status.json", &status)?;
        return Ok(json!({"state":"disabled","installation_preserved":true}));
    }
    drop(progress);
    let _progress = crate::ui::Progress::start("Installing verified release");
    ensure!(
        ReleaseRef::current(home)? == channel,
        "release channel changed during the build; retry for the selected channel"
    );
    installation.publish(
        home,
        installed,
        new,
        &candidate,
        &expected_old,
        Source {
            channel: channel.channel,
            automatic,
        },
    )?;
    status.phase = "awaiting_activation".into();
    status.failed_commit = None;
    installation.write("status.json", &status)?;
    Ok(
        json!({"state":"updated","channel":channel.channel,"release_ref":channel.reference,"commit":blessed,"activation":"The running Gent daemon will restart itself after draining accepted requests. Active chats stay open."}),
    )
}
