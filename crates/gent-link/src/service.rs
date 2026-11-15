//! Per-user service lifecycle. No account/model credentials enter service files.
mod command;
mod display;
mod files;
pub use command::GatewayCommand;
use command::{Action, Install};
pub use display::print;
mod manager;
use crate::{DaemonCommand, managed_file, owner};
use anyhow::{Context, Result, ensure};
use files::{Kind, Platform, Spec};
use fs2::FileExt;
use gent_daemon::config;
use gent_protocol::OwnerOp;
use manager::{Manager, State};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

struct Service {
    home: PathBuf,
    path: PathBuf,
    manager: Manager,
    kind: Kind,
}
impl Service {
    async fn new(home: &Path) -> Result<Self> {
        Self::with_kind(home, Kind::Daemon).await
    }
    async fn with_kind(home: &Path, kind: Kind) -> Result<Self> {
        let platform = Platform::native()?;
        let home = files::normalize(home)?;
        let user_home = PathBuf::from(
            std::env::var_os("HOME").context("HOME is required to locate user services")?,
        );
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        let path = files::location(platform, &home, &user_home, xdg.as_deref(), kind)?;
        let manager = Manager {
            platform,
            uid: manager::uid().await?,
            label: kind.label(platform, &home),
        };
        Ok(Self {
            home,
            path,
            manager,
            kind,
        })
    }
    fn installed(&self) -> Result<Option<Spec>> {
        files::read(
            &self.path,
            self.manager.platform,
            &self.home,
            self.manager.uid,
            self.kind,
        )
    }
    fn lock(&self) -> Result<fs::File> {
        ensure!(
            self.home.is_dir(),
            "Gent state directory is unavailable; restore it before changing its service"
        );
        config::private_dir(&self.home)?;
        let path = self.home.join(self.kind.lock());
        match fs::symlink_metadata(&path) {
            Ok(_) => files::owned_regular(&path, self.manager.uid)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        lock.try_lock_exclusive()
            .context("another Gent service operation is running; retry when it finishes")?;
        Ok(lock)
    }
    async fn probe(&self) -> Result<Value> {
        tokio::time::timeout(Duration::from_secs(1), async {
            match self.kind {
                Kind::Daemon => owner(&self.home, OwnerOp::Status).await,
                Kind::Gateway => crate::gateway::control::probe(&self.home).await,
            }
        })
        .await
        .context("Gent process did not respond")?
    }
    async fn status(&self) -> Value {
        let installed = self.installed();
        let mut state = self.manager.inspect().await;
        state.enabled &= matches!(&installed, Ok(Some(_)));
        let probe = self.probe().await;
        let running = probe.is_ok();
        let pid = probe.as_ref().ok().and_then(|v| v["process_id"].as_u64());
        let managed = running && pid == state.pid.map(u64::from);
        let mut value = probe.as_ref().ok().cloned().unwrap_or_else(|| json!({}));
        value[self.kind.name()] = json!({"running":running,"managed":managed,"pid":pid,"error":probe.err().map(|e|e.to_string())});
        value["service"] = serde_json::to_value(&state).expect("service status serializes");
        value["service"]["kind"] = json!(self.kind.name());
        value["service"]["backend"] = json!(self.manager.platform);
        value["service"]["installed"] = json!(matches!(&installed, Ok(Some(_))));
        value["service"]["label"] = self.manager.label.clone().into();
        value["service"]["file"] = json!(self.path);
        value["service"]["home"] = json!(self.home);
        if let Err(error) = installed {
            value["service"]["file_error"] = error.to_string().into();
        }
        value
    }
    async fn no_foreground(&self, state: &State) -> Result<()> {
        if let Ok(value) = self.probe().await {
            ensure!(
                value["process_id"].as_u64() == state.pid.map(u64::from),
                "a foreground or externally managed {} is using this state directory; stop it before controlling its service",
                self.kind.name()
            );
        }
        Ok(())
    }
    async fn wait(&self, running: bool) -> Result<()> {
        let until = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(value) = self.probe().await {
                if running {
                    let state = self.manager.inspect().await;
                    if state.running && value["process_id"].as_u64() == state.pid.map(u64::from) {
                        return Ok(());
                    }
                }
            } else if !running {
                let state = self.manager.inspect().await;
                if state.available && !state.running && state.pid.is_none() {
                    return Ok(());
                }
            }
            ensure!(
                tokio::time::Instant::now() < until,
                "{} did not reach the requested state; inspect its service status and logs",
                self.kind.name()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    fn prepare_log(&self) -> Result<()> {
        if self.manager.platform == Platform::Launchd {
            let path = self.home.join(format!("{}.log", self.kind.name()));
            match fs::symlink_metadata(&path) {
                Ok(_) => files::owned_regular(&path, self.manager.uid)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            fs::OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(path)?;
        }
        Ok(())
    }
    async fn logs(&self, lines: u32) -> Result<Value> {
        self.installed()?; // Never inspect an unrelated service under this label.
        let text = match self.manager.platform {
            Platform::Systemd => self.manager.journal(lines).await?,
            Platform::Launchd => {
                let path = self.home.join(format!("{}.log", self.kind.name()));
                if !path.exists() {
                    String::new()
                } else {
                    files::owned_regular(&path, self.manager.uid)?;
                    let mut file = fs::File::open(path)?;
                    let start = file.metadata()?.len().saturating_sub(2 * 1024 * 1024);
                    file.seek(SeekFrom::Start(start))?;
                    let mut bytes = Vec::new();
                    file.take(2 * 1024 * 1024).read_to_end(&mut bytes)?;
                    let text = String::from_utf8_lossy(&bytes);
                    let mut rows: Vec<_> = text.lines().collect();
                    if start > 0 && !rows.is_empty() {
                        rows.remove(0);
                    }
                    rows[rows.len().saturating_sub(lines as usize)..].join("\n")
                }
            }
        };
        Ok(
            json!({"backend":self.manager.platform,"label":self.manager.label,"lines":text.lines().collect::<Vec<_>>() }),
        )
    }
}

/// Fail before guided login/enrollment when this machine cannot install a service.
pub async fn preflight(home: &Path) -> Result<()> {
    let service = Service::new(home).await?;
    let state = service.manager.inspect().await;
    ensure!(
        state.available,
        "{}",
        state
            .error
            .as_deref()
            .unwrap_or("user service manager is unavailable; use gent daemon run")
    );
    ensure!(
        service.installed()?.is_some() || !state.loaded,
        "a service with this label is loaded without Gent's managed file; inspect {}",
        service.path.display()
    );
    service.no_foreground(&state).await
}

/// Inspect only the manager and registration. Doctor uses its own read-only
/// daemon operation instead of the ordinary status/projection path.
pub(crate) async fn diagnose(home: &Path) -> Result<Value> {
    let service = Service::new(home).await?;
    let installed = service.installed()?;
    let state = service.manager.inspect().await;
    Ok(
        json!({"installed":installed.is_some(),"available":state.available,
        "binary_available":installed.as_ref().is_some_and(|s| s.binary.is_file()),
        "loaded":state.loaded,"running":state.running,"enabled":state.enabled,
        "pid":state.pid,"last_exit":state.last_exit}),
    )
}

pub async fn execute(home: &Path, action: DaemonCommand) -> Result<Value> {
    control(home, Kind::Daemon, action.into()).await
}

pub(crate) async fn gateway(home: &Path, action: GatewayCommand) -> Result<Value> {
    control(home, Kind::Gateway, action.into()).await
}

async fn control(home: &Path, kind: Kind, mut action: Action) -> Result<Value> {
    let service = Service::with_kind(home, kind).await?;
    match action {
        Action::Status => return Ok(service.status().await),
        Action::Logs { lines } => return service.logs(lines).await,
        _ => {}
    }
    let before = service.manager.inspect().await;
    ensure!(
        before.available,
        "{}",
        before
            .error
            .as_deref()
            .unwrap_or("user service manager is unavailable; use gent daemon run")
    );
    let previous = service.installed()?;
    if previous.is_none() {
        ensure!(
            !before.loaded,
            "a service with this label is already loaded without Gent's managed file; inspect {}",
            service.path.display()
        );
    }
    match &action {
        Action::Install(Install::Daemon { local }) => {
            if !config::path(&service.home).exists() {
                local.as_deref().context("no Gent configuration; run gent auth login and gent cluster new NAME, or use gent daemon install --local NAME for a development cluster")?;
                config::private_dir(&service.home)?;
            }
        }
        Action::Uninstall if previous.is_none() => return Ok(service.status().await),
        Action::Install(Install::Gateway(_)) => {
            config::load(&service.home)?;
        }
        _ => ensure!(
            previous.is_some(),
            "service is not installed; install it first"
        ),
    }
    let _lock = service.lock()?;
    // Recheck ownership after acquiring the per-state mutation lock.
    let previous = service.installed()?;
    let before = service.manager.inspect().await;
    ensure!(
        before.available,
        "user service manager became unavailable; retry the command"
    );
    ensure!(
        previous.is_some() || !before.loaded,
        "loaded service has no Gent-managed file; inspect {}",
        service.path.display()
    );
    if let Action::Install(Install::Daemon { local }) = &action {
        if !config::path(&service.home).exists() {
            let _daemon = managed_file::lock(&service.home.join("daemon.lock"))?;
            let name = local
                .as_deref()
                .context("Gent configuration disappeared; restore it before installing")?;
            ensure!(
                fs::read_dir(&service.home)?.all(|entry| entry.is_ok_and(|e| matches!(
                    e.file_name().to_str(),
                    Some("service.lock" | "daemon.lock" | "auth")
                ))),
                "state exists without config.toml; restore the configuration before installing"
            );
            config::initialize(&service.home, name)?;
        }
        config::load(&service.home)?;
        config::read_private(&service.home.join("owner.key"))?;
    }
    service.no_foreground(&before).await?;
    if let Action::Install(Install::Gateway(options)) = &mut action {
        *options = options.for_service(&service.home).await?;
    }
    if matches!(action, Action::Start | Action::Restart)
        && let Some(options) = previous.as_ref().and_then(|spec| spec.gateway.as_ref())
    {
        options.for_service(&service.home).await?;
    }
    match action {
        Action::Install(installation) => {
            let binary = fs::canonicalize(std::env::current_exe()?)
                .context("cannot locate the running Gent binary; reinstall it first")?;
            let desired = match installation {
                Install::Daemon { .. } => {
                    Spec::new(service.manager.platform, service.home.clone(), binary)?
                }
                Install::Gateway(options) => Spec::gateway(
                    service.manager.platform,
                    service.home.clone(),
                    binary,
                    options,
                )?,
            };
            let changed =
                previous.as_ref().map(|spec| spec.render()).transpose()? != Some(desired.render()?);
            service.prepare_log()?;
            if changed {
                files::write(&service.path, &desired)?;
            }
            service
                .manager
                .install(&service.path, changed, &before)
                .await
                .context("service installation failed; inspect its service status and logs")?;
            service.wait(true).await?;
        }
        Action::Start | Action::Restart => {
            ensure!(
                previous.is_some(),
                "service was uninstalled; install it again"
            );
            service.prepare_log()?;
            service
                .manager
                .start(&service.path, &before, matches!(action, Action::Restart))
                .await?;
            service.wait(true).await?;
        }
        Action::Stop => {
            service.manager.stop(&before).await?;
            service.wait(false).await?;
        }
        Action::Uninstall => {
            service.manager.uninstall(&before).await?;
            service.wait(false).await?;
            service
                .installed()?
                .context("service file disappeared during uninstall")?;
            fs::remove_file(&service.path)?;
            fs::File::open(service.path.parent().unwrap())?.sync_all()?;
            service.manager.reload().await?;
        }
        _ => unreachable!(),
    }
    Ok(service.status().await)
}
