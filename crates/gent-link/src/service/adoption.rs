//! Adopt the activated daemon's installation without changing registrations.
use super::*;
use crate::build_info::{self, Build};
use std::os::unix::{fs::MetadataExt, process::CommandExt};

async fn running(service: &Service, binary: &Path) -> Result<Option<(State, Value)>> {
    if !service
        .installed()?
        .is_some_and(|spec| spec.binary == binary)
    {
        return Ok(None);
    }
    let state = service.manager.inspect().await;
    if !state.owned_definition(&service.path) || !state.running {
        return Ok(None);
    }
    let Some(pid) = state.pid else {
        return Ok(None);
    };
    let Some(probe) = service
        .probe()
        .await
        .ok()
        .filter(|v| v["process_id"] == pid)
    else {
        return Ok(None);
    };
    Ok(Some((state, probe)))
}

/// Called after daemon readiness, including a normal start that finds an old
/// managed carrier. A gateway with build reporting handles its own adoption.
pub(crate) async fn refresh_legacy(home: &Path, binary: &Path) -> Result<()> {
    let service = Service::with_kind(home, Kind::Gateway).await?;
    if service.installed()?.is_none() {
        return Ok(());
    }
    let _lock = service.lock()?;
    let Some((state, probe)) = running(&service, binary).await? else {
        return Ok(());
    };
    if !probe["build"].is_null() || probe["transport"] != "hosted_bridge" {
        return Ok(());
    }
    ensure!(
        crate::update::installed_build(binary).await? == build_info::current(),
        "installation changed during gateway adoption"
    );
    let previous = service
        .installed()?
        .context("gateway registration disappeared")?
        .render()?;
    service.manager.drain_gateway(&state).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let next = service.manager.inspect().await;
        ensure!(
            next.owned_definition(&service.path) && next.domain == state.domain,
            "gateway registration changed while draining"
        );
        if next.pid != state.pid {
            if next.pid.is_none() && !next.running {
                ensure!(
                    service
                        .installed()?
                        .is_some_and(|spec| spec.render().ok().as_ref() == Some(&previous)),
                    "gateway definition changed while draining"
                );
                service.no_foreground(&next).await?;
                service.manager.start_loaded(&next).await?;
            }
            break;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "gateway is still draining"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    service.wait(true).await?;
    ensure!(
        service.probe().await?["build"] == json!(build_info::current()),
        "gateway has not reported the activated build"
    );
    Ok(())
}

pub(crate) struct Adoption {
    binary: PathBuf,
    installed: Build,
    _lock: fs::File,
}
impl Adoption {
    /// A second activation may arrive while an admitted request is draining.
    /// Resume serving the old build if the installed file and ready daemon diverged.
    pub(crate) async fn exec_if_ready(self, home: &Path) -> Result<()> {
        if activated_build(home).await != Some(self.installed.clone())
            || crate::update::installed_build(&self.binary).await.ok() != Some(self.installed)
        {
            return Ok(());
        }
        Err(std::process::Command::new(self.binary)
            .args(std::env::args_os().skip(1))
            .exec()
            .into())
    }
}

async fn activated_build(home: &Path) -> Option<Build> {
    let status = tokio::time::timeout(Duration::from_secs(1), owner(home, OwnerOp::Status))
        .await
        .ok()?
        .ok()?;
    serde_json::from_value(status["build"].clone()).ok()
}

fn stamp(binary: &Path) -> Result<(u64, u64, u64, i64, i64)> {
    let meta = fs::symlink_metadata(binary)?;
    Ok((
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
    ))
}

/// Continue to observe from the managed gateway when the activated daemon
/// predates gateway adoption. No updater or permanent helper is required there.
pub(crate) async fn watch(home: &Path) -> Adoption {
    let Ok(service) = Service::with_kind(home, Kind::Gateway).await else {
        return std::future::pending().await;
    };
    let Ok(Some(spec)) = service.installed() else {
        return std::future::pending().await;
    };
    let binary = spec.binary;
    let mut observed = None;
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let Ok(file) = stamp(&binary) else { continue };
        if observed == Some(file) {
            continue;
        }
        let Ok(Some((state, _))) = running(&service, &binary).await else {
            continue;
        };
        if state.pid != Some(std::process::id()) {
            return std::future::pending().await;
        }
        let Ok(installed) = crate::update::installed_build(&binary).await else {
            continue;
        };
        if installed == build_info::current() {
            observed = Some(file);
            continue;
        }
        let Ok(lock) = service.lock() else { continue };
        if activated_build(home).await.as_ref() == Some(&installed)
            && stamp(&binary).ok() == Some(file)
            && running(&service, &binary)
                .await
                .ok()
                .flatten()
                .is_some_and(|(state, _)| state.pid == Some(std::process::id()))
        {
            return Adoption {
                binary,
                installed,
                _lock: lock,
            };
        }
    }
}
