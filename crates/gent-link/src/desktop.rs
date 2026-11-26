//! The tray belongs to the graphical login session. The service manager owns the daemon.
use crate::{DaemonCommand, managed_file, service};
#[cfg(not(target_os = "macos"))]
use anyhow::Context;
use anyhow::{Result, bail, ensure};
use clap::{Args, Subcommand};
use gent_daemon::config;
use serde_json::json;
#[cfg(not(target_os = "macos"))]
use std::process::Stdio;
use std::{
    fs,
    io::ErrorKind,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
};
use tokio::{io::AsyncWriteExt, net::UnixDatagram};
#[cfg(not(target_os = "macos"))]
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

mod admin;
mod charts;
mod login;
mod model;
#[cfg(target_os = "macos")]
mod notification_app;
#[cfg(target_os = "macos")]
pub(crate) mod notification_delivery;
mod pages;
mod release_channel;
#[cfg(target_os = "linux")]
pub(crate) use login::label as desktop_entry_id;
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
    // A first-run window lives inside the auth-only area until enrollment finishes.
    if send_signal(&socket(home), bytes)? {
        return Ok(true);
    }
    send_signal(&socket(&home.join("auth/desktop")), bytes)
}

fn send_signal(path: &Path, bytes: &[u8]) -> Result<bool> {
    match fs::symlink_metadata(path) {
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

fn claim(home: &Path, runtime: &Path, background: bool) -> Result<Option<UnixDatagram>> {
    // Serialize probing and replacing a socket left by a crashed GUI.
    let _lock = managed_file::lock(&runtime.join("desktop-login.lock"))?;
    if background && !login::autostarts(home)? {
        return Ok(None);
    }
    if signal(home, if background { b"present" } else { b"show" })? {
        return Ok(None);
    }
    let path = socket(runtime);
    if fs::symlink_metadata(&path).is_ok() {
        fs::remove_file(&path)?;
    }
    Ok(Some(UnixDatagram::bind(path)?))
}

#[cfg(target_os = "linux")]
fn frontend(_home: &Path) -> Result<Command> {
    let mut cmd = Command::new("/usr/bin/python3");
    cmd.args([
        "-I",
        "-c",
        concat!(
            include_str!("desktop/linux.py"),
            "\n",
            include_str!("desktop/tabs.py"),
            "\n",
            include_str!("desktop/management.py"),
            "\n",
            include_str!("desktop/dashboard.py"),
            "\ndesktop = Desktop()\nGtk.main()\n"
        ),
    ]);
    Ok(cmd)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn frontend(_home: &Path) -> Result<Command> {
    bail!("Gent Desktop supports macOS and Linux")
}

fn install_icon(home: &Path) -> Result<std::path::PathBuf> {
    let icon = home.join("desktop-icon.png");
    let tray = home.join("inkling-tray-128.png");
    for (path, image) in [
        (
            &icon,
            include_bytes!("../branding/inkling-512.png").as_slice(),
        ),
        (
            &tray,
            include_bytes!("../branding/inkling-tray-128.png").as_slice(),
        ),
    ] {
        if fs::read(path).ok().as_deref() != Some(image) {
            config::write_private(path, image)?;
        }
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
    let configured = config::path(home).try_exists()?;
    if background && !configured {
        return Ok(());
    }
    config::private_dir(home)?;
    let runtime = if configured {
        home.to_owned()
    } else {
        let auth = home.join("auth");
        config::private_dir(&auth)?;
        let runtime = auth.join("desktop");
        config::private_dir(&runtime)?;
        runtime
    };
    let Some(channel) = claim(home, &runtime, background)? else {
        return Ok(());
    };
    // Keep the bound socket alive through unlink. Other launchers can reclaim
    // its name only after the socket closes (or after a crash).
    let path = socket(&runtime);
    let bound = fs::symlink_metadata(&path)?;
    let result = supervise(home, &runtime, &channel, background, configured).await;
    if let Ok(current) = fs::symlink_metadata(&path)
        && (bound.dev(), bound.ino()) == (current.dev(), current.ino())
    {
        fs::remove_file(path)?;
    }
    result
}

async fn cluster_status(home: &Path, action: DaemonCommand) -> Result<serde_json::Value> {
    let mut status = service::execute(home, action).await?;
    let enrolled = config::path(home).try_exists()?;
    status["enrolled"] = enrolled.into();
    if status["daemon"]["running"] == true {
        // Read cached membership only. Opening the overview must not probe peers.
        status["members"] = crate::owner(home, gent_protocol::OwnerOp::Nodes)
            .await
            .unwrap_or_default();
    } else if enrolled && let Ok(cfg) = crate::node_home::inspect(home) {
        status["node"]["name"] = cfg.node.name.into();
        status["cluster"]["name"] = cfg.cluster.name.into();
    }
    Ok(model::snapshot(&status))
}

async fn supervise(
    home: &Path,
    runtime: &Path,
    socket: &UnixDatagram,
    background: bool,
    configured: bool,
) -> Result<()> {
    let icon = install_icon(runtime)?;
    let mode = if background {
        "tray"
    } else if configured {
        "window"
    } else {
        "setup"
    };
    #[cfg(target_os = "macos")]
    let (mut child, mut input, mut events) = notification_app::launch(runtime, &icon, mode).await?;
    #[cfg(not(target_os = "macos"))]
    let (mut child, mut input, mut events) = {
        let mut child = frontend(runtime)?
            .arg(&icon)
            .arg(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("cannot start Gent Desktop")?;
        let input = child.stdin.take().unwrap();
        let events = BufReader::new(child.stdout.take().unwrap()).lines();
        (child, input, events)
    };
    let mut pages = pages::Pages::default();
    #[cfg(target_os = "macos")]
    let (destination, mut deliveries) = notification_delivery::channel();
    #[cfg(not(target_os = "macos"))]
    let destination = icon;
    let watch = crate::auth::notifications::desktop_loop(home, &destination);
    tokio::pin!(watch);
    let mut jobs = tokio::task::JoinSet::new();
    let mut channel_jobs = tokio::task::JoinSet::new();
    let mut activation = [0; 16];
    loop {
        #[cfg(target_os = "macos")]
        let next_banner = deliveries.next();
        #[cfg(not(target_os = "macos"))]
        let next_banner = std::future::pending();
        let message = tokio::select! {
            // macOS kqueue can miss the last writer closing a named FIFO.
            // open -W also wakes us when the GUI quits without another message.
            _ = child.wait() => break,
            banner = next_banner => banner,
            _=&mut watch=>anyhow::bail!("account notification watch stopped"),
            Some(result) = jobs.join_next() => result?,
            Some(result) = channel_jobs.join_next() => result?,
            size = socket.recv(&mut activation) => match &activation[..size?] {
                b"show" => json!({"show":true}),
                b"quit" => json!({"quit":true}),
                _ => continue,
            },
            line = events.next_line() => {
                let Some(line) = line? else { break };
                #[cfg(target_os = "macos")]
                if deliveries.receive(&line) { continue; }
                if line.starts_with('{') {
                    if let Ok(request) = serde_json::from_str::<release_channel::Request>(&line) {
                        if channel_jobs.is_empty() {
                            let home = home.to_owned();
                            channel_jobs.spawn(async move { request.respond(&home).await });
                            continue;
                        }
                        json!({"page":"release_channel","notice":"A channel request is in progress."})
                    } else if let Ok(admin::Request::Manage { action }) = serde_json::from_str(&line) {
                        if jobs.is_empty() {
                            let home = home.to_owned();
                            jobs.spawn(async move { action.respond(&home).await });
                            continue;
                        }
                        action.error("Another desktop operation is in progress")
                    } else {
                        pages.respond(home, &line).await
                    }
                } else {
                    let action = match line.as_str() {
                        "refresh" => DaemonCommand::Status,
                        "start" => DaemonCommand::Start,
                        "stop" => DaemonCommand::Stop,
                        "restart" => DaemonCommand::Restart,
                        _ => continue,
                    };
                    cluster_status(home, action).await.unwrap_or_else(|e| json!({"error":format!("{e:#}")}))
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
    drop(input);
    let status = child.wait().await?;
    if !status.success() {
        bail!("Gent Desktop exited with {status}")
    }
    Ok(())
}
