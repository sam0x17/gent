//! The tray belongs to the graphical login session. The service manager owns the daemon.
use crate::{DaemonCommand, managed_file, service};
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use gent_daemon::config;
use serde_json::json;
use std::{
    fs,
    io::ErrorKind,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
    process::Stdio,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixDatagram,
    process::Command,
};

mod login;
mod model;
pub(crate) use login::{installed, migrate, previously_configured, removed};

#[derive(Args)]
pub(crate) struct Options {
    /// Start in the tray without opening the window (used at login).
    #[arg(long, hide = true)]
    background: bool,
    #[command(subcommand)]
    command: Option<Action>,
}
#[derive(Subcommand)]
enum Action {
    /// Register the companion for graphical login and start it in this desktop session.
    Enable,
    /// Remove the login entry and quit the companion. The daemon keeps running.
    Disable,
}

pub(crate) async fn execute(
    home: &Path,
    options: Options,
    output: crate::ui::Output,
) -> Result<()> {
    let Some(action) = options.command else {
        return run(home, options.background).await;
    };
    match action {
        Action::Enable => login::enable(home)?,
        Action::Disable => login::disable(home)?,
    }
    output.print(&json!({"start_at_graphical_login": matches!(action, Action::Enable)}))
}

fn socket(home: &Path) -> std::path::PathBuf {
    home.join("desktop.sock")
}

pub(super) fn signal(home: &Path, bytes: &[u8]) -> Result<bool> {
    let path = socket(home);
    match fs::symlink_metadata(&path) {
        Ok(meta) => ensure!(
            meta.file_type().is_socket(),
            "unexpected file at {}",
            path.display()
        ),
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    }
    let channel = std::os::unix::net::UnixDatagram::unbound()?;
    channel.set_nonblocking(true)?;
    match channel.send_to(bytes, path) {
        Ok(_) => Ok(true),
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}

fn claim(home: &Path, background: bool) -> Result<Option<UnixDatagram>> {
    // Serialize probing and replacing a socket left by a crashed GUI.
    let _lock = managed_file::lock(&home.join("desktop-login.lock"))?;
    if background && !login::autostarts(home)? {
        return Ok(None);
    }
    if signal(home, if background { b"present" } else { b"show" })? {
        return Ok(None);
    }
    let path = socket(home);
    if fs::symlink_metadata(&path).is_ok() {
        fs::remove_file(&path)?;
    }
    Ok(Some(UnixDatagram::bind(path)?))
}

#[cfg(target_os = "linux")]
fn frontend(_home: &Path) -> Result<Command> {
    let mut cmd = Command::new("/usr/bin/python3");
    cmd.args(["-I", "-c", include_str!("desktop/linux.py")]);
    Ok(cmd)
}

#[cfg(target_os = "macos")]
fn frontend(home: &Path) -> Result<Command> {
    use std::{io::Write, os::unix::fs::PermissionsExt};
    let path = home.join("Gent Desktop");
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/GentDesktop"));
    if fs::read(&path).ok().as_deref() != Some(bytes) {
        let mut tmp = tempfile::NamedTempFile::new_in(home)?;
        tmp.write_all(bytes)?;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o700))?;
        tmp.persist(&path)?;
    }
    Ok(Command::new(path))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn frontend(_home: &Path) -> Result<Command> {
    bail!("Gent Desktop supports macOS and Linux")
}

fn install_icon(home: &Path) -> Result<std::path::PathBuf> {
    let icon = home.join("desktop-icon.png");
    let image = include_bytes!("../../../assets/branding/inkling-128.png");
    if fs::read(&icon).ok().as_deref() != Some(image) {
        config::write_private(&icon, image)?;
    }
    Ok(icon)
}

async fn run(home: &Path, background: bool) -> Result<()> {
    if !login::graphical_session() {
        if background || signal(home, b"show")? {
            return Ok(());
        }
        bail!("open Gent Desktop from a graphical login session");
    }
    ensure!(
        config::path(home).is_file(),
        "set up this node first with gent setup"
    );
    config::private_dir(home)?;
    let Some(channel) = claim(home, background)? else {
        return Ok(());
    };
    // Keep the bound socket alive through unlink. Other launchers can reclaim
    // its name only after the socket closes (or after a crash).
    let path = socket(home);
    let bound = fs::symlink_metadata(&path)?;
    let result = supervise(home, &channel, background).await;
    if let Ok(current) = fs::symlink_metadata(&path)
        && (bound.dev(), bound.ino()) == (current.dev(), current.ino())
    {
        fs::remove_file(path)?;
    }
    result
}

async fn supervise(home: &Path, socket: &UnixDatagram, background: bool) -> Result<()> {
    let icon = install_icon(home)?;
    let mut child = frontend(home)?
        .arg(icon)
        .arg(if background { "tray" } else { "window" })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("cannot start Gent Desktop")?;
    let mut input = child.stdin.take().unwrap();
    let mut events = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut activation = [0; 16];
    loop {
        let message = tokio::select! {
            size = socket.recv(&mut activation) => match &activation[..size?] {
                b"show" => json!({"show":true}),
                b"quit" => json!({"quit":true}),
                _ => continue,
            },
            line = events.next_line() => {
                let Some(line) = line? else { break };
                let action = match line.as_str() {
                    "refresh" => DaemonCommand::Status,
                    "start" => DaemonCommand::Start,
                    "stop" => DaemonCommand::Stop,
                    "restart" => DaemonCommand::Restart,
                    _ => continue,
                };
                match service::execute(home, action).await {
                    Ok(status) => model::snapshot(&status),
                    Err(e) => json!({"error":format!("{e:#}")}),
                }
            }
        };
        let mut bytes = serde_json::to_vec(&message)?;
        bytes.push(b'\n');
        if let Err(e) = input.write_all(&bytes).await {
            if e.kind() == ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
    }
    let status = child.wait().await?;
    if !status.success() {
        bail!("Gent Desktop exited with {status}")
    }
    Ok(())
}
