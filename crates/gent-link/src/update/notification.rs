//! Best-effort local desktop notification, only after automatic activation.
use crate::build_info::Build;
use std::time::Duration;
use tokio::process::Command;

pub(super) async fn installed(build: &Build) {
    let message = format!("Updated to {}. Gent is ready.", &build.commit[..12]);
    #[cfg(feature = "test-updates")]
    if let Some(log) = std::env::var_os("GENT_TEST_UPDATE_NOTIFICATIONS") {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
        {
            let _ = writeln!(file, "{}", build.commit);
        }
        return;
    }
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("/usr/bin/osascript");
        command.args([
            "-e",
            "on run argv\ndisplay notification (item 1 of argv) with title \"Gent\"\nend run",
            &message,
        ]);
        command
    };
    #[cfg(not(target_os = "macos"))]
    let mut command = {
        let mut command = Command::new("notify-send");
        command.args(["--app-name=Gent", "Gent updated", &message]);
        command
    };
    if let Err(error) = super::process::capture(&mut command, 4096, Duration::from_secs(5)).await {
        eprintln!("Gent updated; desktop notification unavailable: {error}");
    }
}
