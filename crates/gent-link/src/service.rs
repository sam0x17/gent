//! Per-user service lifecycle. No account/model credentials enter service files.
mod files;
mod manager;
use crate::{DaemonCommand, managed_file, owner};
use anyhow::{Context, Result, ensure};
use files::{Platform, Spec};
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
}
impl Service {
    async fn new(home: &Path) -> Result<Self> {
        let platform = Platform::native()?;
        let home = files::normalize(home)?;
        let user_home = PathBuf::from(
            std::env::var_os("HOME").context("HOME is required to locate user services")?,
        );
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        let path = files::location(platform, &home, &user_home, xdg.as_deref())?;
        let manager = Manager {
            platform,
            uid: manager::uid().await?,
            label: files::label(platform, &home),
        };
        Ok(Self {
            home,
            path,
            manager,
        })
    }
    fn installed(&self) -> Result<Option<Spec>> {
        files::read(
            &self.path,
            self.manager.platform,
            &self.home,
            self.manager.uid,
        )
    }
    fn lock(&self) -> Result<fs::File> {
        ensure!(
            self.home.is_dir(),
            "Gent state directory is unavailable; restore it before changing its service"
        );
        config::private_dir(&self.home)?;
        let path = self.home.join("service.lock");
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
        tokio::time::timeout(Duration::from_secs(1), owner(&self.home, OwnerOp::Status))
            .await
            .context("daemon did not respond")?
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
        value["daemon"] = json!({"running":running,"managed":managed,"pid":pid,"error":probe.err().map(|e|e.to_string())});
        value["service"] = serde_json::to_value(&state).expect("service status serializes");
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
                "a foreground or externally managed daemon is using this state directory; stop it before controlling the Gent service"
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
                "daemon did not reach the requested state; inspect gent daemon status and gent daemon logs"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    fn prepare_log(&self) -> Result<()> {
        if self.manager.platform == Platform::Launchd {
            let path = self.home.join("daemon.log");
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
                let path = self.home.join("daemon.log");
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

pub async fn execute(home: &Path, action: DaemonCommand) -> Result<Value> {
    let service = Service::new(home).await?;
    match action {
        DaemonCommand::Status => return Ok(service.status().await),
        DaemonCommand::Logs { lines } => return service.logs(lines).await,
        DaemonCommand::Run => unreachable!(),
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
        DaemonCommand::Install { local } => {
            if !config::path(&service.home).exists() {
                local.as_deref().context("no Gent configuration; run gent auth login and gent cluster new NAME, or use gent daemon install --local NAME for a development cluster")?;
                config::private_dir(&service.home)?;
            }
        }
        DaemonCommand::Uninstall if previous.is_none() => return Ok(service.status().await),
        _ => ensure!(
            previous.is_some(),
            "service is not installed; run gent daemon install"
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
    if let DaemonCommand::Install { local } = &action {
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
    match action {
        DaemonCommand::Install { .. } => {
            let binary = fs::canonicalize(std::env::current_exe()?)
                .context("cannot locate the running Gent binary; reinstall it first")?;
            let desired = Spec::new(service.manager.platform, service.home.clone(), binary)?;
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
                .context(
                    "service installation failed; inspect gent daemon status and gent daemon logs",
                )?;
            service.wait(true).await?;
        }
        DaemonCommand::Start | DaemonCommand::Restart => {
            ensure!(
                previous.is_some(),
                "service was uninstalled; run gent daemon install"
            );
            service.prepare_log()?;
            service
                .manager
                .start(
                    &service.path,
                    &before,
                    matches!(action, DaemonCommand::Restart),
                )
                .await?;
            service.wait(true).await?;
        }
        DaemonCommand::Stop => {
            service.manager.stop(&before).await?;
            service.wait(false).await?;
        }
        DaemonCommand::Uninstall => {
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
pub fn print(value: &Value) {
    if let Some(lines) = value["lines"].as_array() {
        for line in lines {
            println!("{}", line.as_str().unwrap_or_default());
        }
        return;
    }
    let daemon = &value["daemon"];
    let service = &value["service"];
    println!(
        "Daemon: {}",
        if daemon["running"] == true {
            if daemon["managed"] == true {
                "running (managed service)"
            } else {
                "running (outside service)"
            }
        } else {
            "stopped or unavailable"
        }
    );
    println!(
        "Service: {} ({}, {})",
        if service["installed"] == true {
            "installed"
        } else {
            "not installed"
        },
        service["backend"].as_str().unwrap_or("unknown"),
        if service["enabled"] == true {
            "startup enabled"
        } else {
            "startup disabled"
        }
    );
    println!(
        "State directory: {}",
        service["home"].as_str().unwrap_or_default()
    );
    println!(
        "Service file: {}",
        service["file"].as_str().unwrap_or_default()
    );
    for key in ["error", "file_error"] {
        if let Some(error) = service[key].as_str() {
            println!("{error}");
        }
    }
    if daemon["running"] != true
        && let Some(error) = daemon["error"].as_str()
    {
        println!("{error}");
    }
}
