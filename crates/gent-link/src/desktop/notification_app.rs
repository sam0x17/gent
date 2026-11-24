//! Install the signed tray application at the existing Gent.app URL so upgrades
//! keep the sender identity used by Notification Center.
use anyhow::{Result, ensure};
use rustix::fs::{CWD, RenameFlags, renameat_with};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
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

pub(super) fn install(runtime: &Path) -> Result<PathBuf> {
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
    let stage = tempfile::tempdir_in(&root)?;
    let contents = stage.path().join("Contents");
    for (path, bytes) in FILES {
        let path = contents.join(path);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, bytes)?;
    }
    fs::set_permissions(
        contents.join("MacOS/GentDesktop"),
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

#[cfg(test)]
mod tests;
