//! Install graphical-login entries separately from systemd's or launchd's daemon job.
use super::{install_icon, signal};
use crate::managed_file::{self, Snapshot};
use anyhow::{Context, Result, ensure};
use gent_daemon::config;
use std::{
    env,
    path::{Path, PathBuf},
    process::{Command as Process, Stdio},
};

#[cfg(target_os = "linux")]
pub(super) fn graphical_session() -> bool {
    ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|k| env::var_os(k).is_some_and(|v| !v.is_empty()))
}
#[cfg(target_os = "macos")]
fn aqua() -> String {
    format!("gui/{}", rustix::process::getuid().as_raw())
}
#[cfg(target_os = "macos")]
pub(super) fn graphical_session() -> bool {
    launchctl(&["print", &aqua()])
}
#[cfg(target_os = "macos")]
fn launchctl(args: &[&str]) -> bool {
    Process::new("/bin/launchctl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn graphical_session() -> bool {
    false
}

struct Entry {
    path: PathBuf,
    contents: String,
    marker: String,
}

fn text(path: &Path) -> Result<&str> {
    let s = path
        .to_str()
        .context("desktop login entry requires a UTF-8 path")?;
    ensure!(
        !s.chars().any(char::is_control),
        "control character in desktop login path"
    );
    Ok(s)
}

#[cfg(target_os = "linux")]
fn exec_arg(s: &str) -> String {
    // Exec tokenization follows desktop-entry string unescaping. % is a field code.
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' | '`' | '$' => {
                out.push_str("\\\\");
                out.push(ch);
            }
            '\\' => out.push_str("\\\\\\\\"),
            '%' => out.push_str("%%"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(target_os = "linux")]
fn entries(home: &Path, binary: &Path, label: &str) -> Result<Vec<Entry>> {
    let user = PathBuf::from(env::var_os("HOME").context("missing HOME")?);
    let xdg = |key: &str, base: &str| {
        env::var_os(key)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| user.join(base))
    };
    let args = format!(
        "{} --home {} desktop",
        exec_arg(text(binary)?),
        exec_arg(text(home)?)
    );
    let marker = format!("X-Gent-Desktop={label}");
    let mut entries = Vec::new();
    for (base, arg) in [
        (
            xdg("XDG_DATA_HOME", ".local/share").join("applications"),
            "",
        ),
        (
            xdg("XDG_CONFIG_HOME", ".config").join("autostart"),
            " --background",
        ),
    ] {
        let icon = text(&home.join("desktop-icon.png"))?.replace('\\', "\\\\");
        let contents = format!(
            "[Desktop Entry]\nType=Application\nName=Gent Desktop\nExec={args}{arg}\n\
             Icon={icon}\nTerminal=false\nCategories=Network;Utility;\n{marker}\n"
        );
        entries.push(Entry {
            path: base.join(format!("{label}.desktop")),
            contents,
            marker: marker.clone(),
        });
    }
    Ok(entries)
}

#[cfg(target_os = "macos")]
fn entries(home: &Path, binary: &Path, label: &str) -> Result<Vec<Entry>> {
    let user = PathBuf::from(env::var_os("HOME").context("missing HOME")?);
    let marker = format!("<!-- Gent Desktop {label} -->");
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let binary = esc(text(binary)?);
    let home = esc(text(home)?);
    let contents = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
{marker}
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array>
<string>{binary}</string><string>--home</string><string>{home}</string>
<string>desktop</string><string>--background</string>
</array>
<key>LimitLoadToSessionType</key><string>Aqua</string>
<key>RunAtLoad</key><true/>
</dict></plist>
"#
    );
    Ok(vec![Entry {
        path: user
            .join("Library/LaunchAgents")
            .join(format!("{label}.plist")),
        contents,
        marker,
    }])
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn entries(_: &Path, _: &Path, _: &str) -> Result<Vec<Entry>> {
    anyhow::bail!("unsupported desktop platform")
}

fn label(home: &Path) -> String {
    use sha2::{Digest, Sha256};
    let hash = format!("{:x}", Sha256::digest(home.as_os_str().as_encoded_bytes()));
    format!("link.gent.desktop.{}", &hash[..32])
}

pub(super) fn autostarts(home: &Path) -> Result<bool> {
    if home.join("desktop-disabled").try_exists()? {
        return Ok(false);
    }
    let entries = entries(home, &env::current_exe()?, &label(home))?;
    let entry = entries.last().context("desktop login entry unavailable")?;
    entry.path.try_exists().map_err(Into::into)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Change {
    Enable,
    Migrate,
    Remove,
}

fn reconcile(home: &Path, change: Change) -> Result<()> {
    let enable = change != Change::Remove;
    let label = label(home);
    let binary = env::current_exe()?;
    let entries = entries(home, &binary, &label)?;
    let mut snapshots = Vec::new();
    for entry in &entries {
        let file = Snapshot::read(&entry.path)?;
        ensure!(
            file.text
                .as_ref()
                .is_none_or(|s| s.lines().any(|l| l == entry.marker)),
            "unmanaged desktop login entry at {}",
            entry.path.display()
        );
        snapshots.push(file);
    }
    if enable {
        install_icon(home)?;
    }
    #[cfg(target_os = "macos")]
    let launch = if graphical_session() {
        let domain = aqua();
        let job = format!("{domain}/{label}");
        let registered = &snapshots[0].text;
        let loaded = launchctl(&["print", &job]);
        if loaded {
            ensure!(
                registered.is_some(),
                "loaded desktop agent has no managed registration"
            );
            if !enable || registered.as_ref() != Some(&entries[0].contents) {
                ensure!(
                    launchctl(&["bootout", &job]),
                    "could not unload desktop login agent"
                );
            }
        }
        Some((domain, job))
    } else {
        None
    };
    for (file, entry) in snapshots.iter().zip(&entries) {
        if enable {
            file.write(&entry.contents)?;
        } else {
            file.remove()?;
        }
    }
    #[cfg(target_os = "macos")]
    if let Some((domain, job)) = launch
        && enable
    {
        if !launchctl(&["print", &job]) {
            ensure!(
                launchctl(&["bootstrap", &domain, text(&entries[0].path)?])
                    || launchctl(&["print", &job]),
                "could not load desktop login agent"
            );
        } else if change == Change::Enable {
            ensure!(
                launchctl(&["kickstart", &job]),
                "could not start desktop login agent"
            );
        }
    }
    #[cfg(target_os = "linux")]
    if change == Change::Enable && graphical_session() {
        let mut child = Process::new(binary)
            .arg("--home")
            .arg(home)
            .args(["desktop", "--background"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
    if !enable {
        signal(home, b"quit")?;
    }
    Ok(())
}

pub(super) fn enable(home: &Path) -> Result<()> {
    ensure!(
        config::path(home).is_file(),
        "set up this node first with gent setup"
    );
    let _lock = managed_file::lock(&home.join("desktop-login.lock"))?;
    let marker = Snapshot::read(&home.join("desktop-disabled"))?;
    reconcile(home, Change::Enable)?;
    marker.remove()
}

/// A running settings window stays open when the user opts out of future logins.
/// The background entry point checks this marker before loading any UI.
pub(super) fn set_autostart(home: &Path, enabled: bool) -> Result<()> {
    let _lock = managed_file::lock(&home.join("desktop-login.lock"))?;
    let marker = Snapshot::read(&home.join("desktop-disabled"))?;
    if enabled {
        reconcile(home, Change::Migrate)?;
        marker.remove()
    } else {
        marker.write("disabled\n")
    }
}

pub(super) fn disable(home: &Path) -> Result<()> {
    if !config::path(home).is_file() && !previously_configured(home)? {
        return Ok(());
    }
    let _lock = managed_file::lock(&home.join("desktop-login.lock"))?;
    Snapshot::read(&home.join("desktop-disabled"))?.write("disabled\n")?;
    reconcile(home, Change::Remove)
}

pub(crate) fn installed(home: &Path) -> Result<()> {
    let _lock = managed_file::lock(&home.join("desktop-login.lock"))?;
    if !home.join("desktop-disabled").try_exists()? {
        reconcile(home, Change::Enable)?;
    }
    Ok(())
}
pub(crate) fn migrate(home: &Path, still_installed: impl FnOnce() -> Result<bool>) -> Result<()> {
    let _lock = managed_file::lock(&home.join("desktop-login.lock"))?;
    if !home.join("desktop-disabled").try_exists()? && still_installed()? {
        // XDG autostart runs in the desktop login's cgroup; a daemon child
        // would disappear whenever systemd restarts the daemon.
        reconcile(home, Change::Migrate)?;
    }
    Ok(())
}
pub(crate) fn removed(home: &Path) -> Result<()> {
    let _lock = managed_file::lock(&home.join("desktop-login.lock"))?;
    reconcile(home, Change::Remove)
}

pub(crate) fn previously_configured(home: &Path) -> Result<bool> {
    // The serialization lock persists across registration and removal. A
    // never-configured home must stay empty on an idempotent uninstall.
    Ok(home.join("desktop-login.lock").try_exists()?)
}
