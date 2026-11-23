//! Launch the signed sender as a macOS application. Launch Services' exit status
//! only describes the launch; the sender acknowledges the notice on its own stdout.
use anyhow::{Context, Result, ensure};
use rustix::fs::{CWD, RenameFlags, renameat_with};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::process::Command;
use uuid::Uuid;

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
    bundled!("MacOS/GentNotifications"),
    bundled!("Resources/Inkling.icns"),
    bundled!("_CodeSignature/CodeResources"),
];

fn install(runtime: &Path) -> Result<PathBuf> {
    let root = runtime.join("desktop-notifications");
    gent_daemon::config::private_dir(&root)?;
    let _lock = crate::managed_file::lock(&root.join("install.lock"))?;
    let app = root.join("Gent.app");
    let contents = app.join("Contents");
    let exists = app.try_exists()?;
    if exists {
        ensure!(
            fs::symlink_metadata(&app)?.is_dir()
                && fs::read_to_string(contents.join("Info.plist"))?.contains(
                    "<key>CFBundleIdentifier</key><string>link.gent.notifications</string>"
                ),
            "unexpected application at {}",
            app.display()
        );
        let executable = contents.join("MacOS/GentNotifications");
        let runnable = fs::metadata(executable).is_ok_and(|m| m.permissions().mode() & 0o100 != 0);
        if runnable
            && FILES.iter().all(|(path, bytes)| {
                fs::read(contents.join(path)).is_ok_and(|installed| installed == *bytes)
            })
        {
            return Ok(app);
        }
    }
    let stage = tempfile::tempdir_in(&root)?;
    let contents = stage.path().join("Contents");
    for (path, bytes) in FILES {
        let path = contents.join(path);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, bytes)?;
    }
    fs::set_permissions(
        contents.join("MacOS/GentNotifications"),
        fs::Permissions::from_mode(0o700),
    )?;
    // Never expose a mix of an old signature and new resources to Launch Services.
    if exists {
        renameat_with(CWD, stage.path(), CWD, &app, RenameFlags::EXCHANGE)?;
    } else {
        fs::rename(stage.path(), &app)?;
    }
    Ok(app)
}

// Unit tests exercise the real cursor path without registering an app with the
// user's Launch Services database or submitting a notification to their session.
#[cfg(test)]
tokio::task_local! { pub(crate) static FIXTURE_OPEN: PathBuf; }

pub(crate) async fn display(icon: &Path, id: Uuid, title: &str, body: &str) -> Result<()> {
    // This is the active desktop runtime, including auth/desktop during first-run.
    let runtime = icon.parent().context("missing desktop runtime")?;
    let app = install(runtime)?;
    #[cfg(not(test))]
    let open = Path::new("/usr/bin/open");
    #[cfg(test)]
    let open = &FIXTURE_OPEN
        .try_with(Clone::clone)
        .context("missing isolated Launch Services fixture")?;
    submit(open, &app, id, title, body).await
}

async fn submit(open: &Path, app: &Path, id: Uuid, title: &str, body: &str) -> Result<()> {
    // Private, per-attempt files keep chat names off the command line and prevent
    // a stale acknowledgment from satisfying another attempt.
    let request = tempfile::NamedTempFile::new()?;
    let ack = tempfile::NamedTempFile::new()?;
    serde_json::to_writer(
        request.as_file(),
        &serde_json::json!({ "id": id, "title": title, "body": body }),
    )?;
    let status = tokio::time::timeout(
        Duration::from_secs(135),
        Command::new(open)
            .args(["-n", "-g", "-W", "--stdin"])
            .arg(request.path())
            .arg("--stdout")
            .arg(ack.path())
            .arg("-a")
            .arg(app)
            .args(["--args", "--deliver"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await??;
    ensure!(
        status.success() && fs::read(ack.path())? == id.to_string().as_bytes(),
        "macOS did not acknowledge the desktop notification"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
