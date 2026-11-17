//! Resolve and build a release while holding the installation's writer lock.
use super::{
    eligible,
    install::{self, Installation, Status},
    now, release,
};
use anyhow::{Result, ensure};
use gent_daemon::config;
use serde_json::{Value, json};
use std::path::Path;

pub(super) async fn apply(
    home: &Path,
    installation: &Installation,
    automatic: bool,
) -> Result<Value> {
    let Some(_lock) = super::coordination::acquire(installation, automatic).await? else {
        return Ok(json!({"state":"already_running"}));
    };
    let mut status = installation.status()?;
    let result = run(home, installation, automatic, &mut status).await;
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
    automatic: bool,
    status: &mut Status,
) -> Result<Value> {
    if automatic && !config::load(home)?.updates()?.enabled {
        return Ok(json!({"state":"disabled"}));
    }
    if let Some(pending) = installation.pending()? {
        if install::hash(&installation.binary)? == pending.old_hash && !pending.starting {
            installation.interrupted_publication(&pending)?;
            *status = installation.status()?;
        } else {
            return Ok(json!({"state":"awaiting_activation","commit":pending.new.commit}));
        }
    }
    let installed = install::inspect(&installation.binary).await?;
    if automatic && !eligible(&installed) {
        return Ok(json!({"state":"development_build","installed":installed}));
    }
    let expected_old = install::hash(&installation.binary)?;
    let progress = crate::ui::Progress::start("Checking GitHub stable");
    let release = release::resolve().await?;
    let blessed = release.commit.clone();
    drop(progress);
    status.last_checked = Some(now());
    status.blessed_commit = Some(blessed.clone());
    status.error = None;
    if installed.commit == blessed && !installed.dirty {
        status.phase = "current".into();
        installation.write("status.json", &status)?;
        return Ok(json!({"state":"current","installed":installed}));
    }
    if automatic && status.failed_commit.as_deref() == Some(&blessed) {
        return Ok(
            json!({"state":"rolled_back","commit":blessed,"next":"Run gent update install to retry this revision explicitly."}),
        );
    }
    status.phase = "building".into();
    installation.write("status.json", &status)?;
    let stage = tempfile::Builder::new()
        .prefix("stage-")
        .tempdir_in(&installation.directory)?;
    let progress = crate::ui::Progress::start("Building stable release; daemon remains available");
    let candidate = release::stage(
        &release,
        stage.path(),
        &installation.directory.join("target"),
        &installation.directory.join("build.log"),
    )
    .await?;
    let new = install::inspect(&candidate).await?;
    ensure!(
        eligible(&new) && new.commit == blessed,
        "built binary does not match the clean stable revision and platform"
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
        release::resolve().await?.commit == blessed,
        "stable changed during the build; retry for the current release"
    );
    if automatic && !config::load(home)?.updates()?.enabled {
        status.phase = "disabled".into();
        installation.write("status.json", &status)?;
        return Ok(json!({"state":"disabled","installation_preserved":true}));
    }
    drop(progress);
    let _progress = crate::ui::Progress::start("Installing verified release");
    installation.publish(home, installed, new, &candidate, &expected_old, automatic)?;
    status.phase = "awaiting_activation".into();
    status.failed_commit = None;
    installation.write("status.json", &status)?;
    Ok(
        json!({"state":"updated","commit":blessed,"activation":"The running Gent daemon will restart itself after draining accepted requests. Active chats stay open."}),
    )
}
