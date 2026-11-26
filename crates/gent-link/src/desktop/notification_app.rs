//! Install the signed, data-free application in the per-user Applications folder.
use anyhow::{Context, Result, bail, ensure};
use rustix::fs::{CWD, RenameFlags, renameat_with};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use tokio::{
    io::{AsyncBufReadExt, BufReader, Lines},
    net::unix::pipe,
    process::{Child, Command},
};

macro_rules! bundled {
    ($file:literal) => {
        (
            $file,
            include_bytes!(concat!(env!("OUT_DIR"), "/Gent.app/Contents/", $file)),
        )
    };
}

const FILES: &[(&str, &[u8])] = &[
    bundled!("Info.plist"),
    bundled!("MacOS/GentDesktop"),
    bundled!("Resources/Inkling.icns"),
    bundled!("_CodeSignature/CodeResources"),
];

fn install(root: &Path) -> Result<PathBuf> {
    let app = root.join("Gent.app");
    let contents = app.join("Contents");
    let exists = match fs::symlink_metadata(&app) {
        Ok(meta) => {
            let info = contents.join("Info.plist");
            ensure!(
                meta.is_dir()
                    && meta.uid() == rustix::process::geteuid().as_raw()
                    && fs::read_to_string(info).is_ok_and(|plist| plist.contains(
                        "<key>CFBundleIdentifier</key><string>link.gent.notifications</string>"
                    ) && plist
                        .contains("<key>GentManagedDesktop</key><true/>")),
                "an unmanaged app already occupies ~/Applications/Gent.app"
            );
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    if exists {
        let executable = contents.join("MacOS/GentDesktop");
        let runnable = fs::metadata(executable).is_ok_and(|m| m.permissions().mode() & 0o100 != 0);
        if runnable
            && FILES.iter().all(|(path, bytes)| {
                fs::read(contents.join(path)).is_ok_and(|installed| installed == *bytes)
            })
        {
            return Ok(app);
        }
    }
    let stage = tempfile::tempdir_in(root)?;
    let contents = stage.path().join("Contents");
    // launchd may set umask 077. System services need to resolve the executable,
    // signature and icon; none of these files contain profile or account data.
    for dir in ["", "MacOS", "Resources", "_CodeSignature"] {
        let dir = contents.join(dir);
        fs::create_dir(&dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
    }
    for (name, bytes) in FILES {
        let path = contents.join(name);
        fs::write(&path, bytes)?;
        let mode = if name.starts_with("MacOS/") {
            0o755
        } else {
            0o644
        };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o755))?;
    // Never expose a mix of an old signature and new resources to Launch Services.
    let flags = if exists {
        RenameFlags::EXCHANGE
    } else {
        RenameFlags::NOREPLACE
    };
    renameat_with(CWD, stage.path(), CWD, &app, flags)?;
    Ok(app)
}

type Frontend = (Child, pipe::Sender, Lines<BufReader<pipe::Receiver>>);

// Finder supplies neither the CLI path nor the node home. Store the same
// foreground launch arguments separately from the signed, replaceable bundle.
fn save_launcher(user: &Path, binary: &Path, home: &Path) -> Result<()> {
    ensure!(
        binary.is_absolute() && home.is_absolute(),
        "expected absolute desktop launch paths"
    );
    let path = user.join("Library/Application Support/Gent/desktop-launch.json");
    let binding = serde_json::to_vec(&serde_json::json!({
        "binary": binary.to_str().context("desktop executable path is not UTF-8")?,
        "home": home.to_str().context("desktop home path is not UTF-8")?,
    }))?;
    gent_daemon::config::write_private(&path, &binding)
}

pub(super) async fn launch(
    home: &Path,
    runtime: &Path,
    icon: &Path,
    mode: &str,
) -> Result<Frontend> {
    let user = std::env::var_os("HOME").context("missing user Applications directory")?;
    let applications = Path::new(&user).join("Applications");
    ensure!(
        applications.is_absolute(),
        "expected an absolute user Applications directory"
    );
    match fs::create_dir(&applications) {
        Ok(()) => fs::set_permissions(&applications, fs::Permissions::from_mode(0o755))?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let meta = fs::metadata(&applications)?;
    ensure!(
        meta.is_dir() && crate::managed_file::owned_not_world_writable(&meta),
        "expected a user-owned Applications directory"
    );
    // Serialize installs across profiles until Launch Services has started this build.
    let _lock = crate::managed_file::lock(&applications.join(".gent-desktop-install.lock"))?;
    let app = install(&applications)?;
    save_launcher(Path::new(&user), &std::env::current_exe()?, home)?;
    launch_at(Path::new("/usr/bin/open"), &app, runtime, icon, mode).await
}

async fn launch_at(
    open: &Path,
    app: &Path,
    runtime: &Path,
    icon: &Path,
    mode: &str,
) -> Result<Frontend> {
    let pipes = tempfile::tempdir_in(runtime)?;
    let input = pipes.path().join("in");
    let output = pipes.path().join("out");
    let made = Command::new("/usr/bin/mkfifo")
        .args(["-m", "600"])
        .arg(&input)
        .arg(&output)
        .status()
        .await?;
    ensure!(made.success(), "could not create desktop pipes");
    let options = pipe::OpenOptions::new();
    // Open each reading end first. Keep the temporary ends until the app writes
    // its greeting so opening never blocks and startup cannot look like EOF.
    let input_guard = options.open_receiver(&input)?;
    let writer = options.open_sender(&input)?;
    let mut lines = BufReader::new(options.open_receiver(&output)?).lines();
    let output_guard = options.open_sender(&output)?;
    let mut child = Command::new(open)
        .args(["-n", "-g", "-W", "--stdin"])
        .arg(&input)
        .arg("--stdout")
        .arg(&output)
        .arg("-a")
        .arg(app)
        .arg("--args")
        .arg(icon)
        .arg(mode)
        .arg("--launch-services")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let ready = tokio::select! {
        line = lines.next_line() => line?,
        status = child.wait() => bail!("Launch Services exited before the desktop handshake ({})", status?),
        _ = tokio::time::sleep(Duration::from_secs(30)) => bail!("Launch Services desktop handshake timed out"),
    };
    ensure!(
        ready.as_deref() == Some("gent-desktop-ready"),
        "invalid desktop handshake"
    );
    drop((input_guard, output_guard, pipes));
    Ok((child, writer, lines))
}

#[cfg(test)]
mod tests;
