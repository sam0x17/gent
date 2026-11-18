//! Give foreground work and the daemon preference over update compilation.
use std::path::Path;
use tokio::process::Command;

pub(super) fn command(executable: &Path) -> Command {
    let mut prefix = Vec::new();
    if Path::new("/usr/bin/nice").is_file() {
        prefix.extend(["/usr/bin/nice", "-n", "10"]);
    }
    #[cfg(target_os = "linux")]
    if Path::new("/usr/bin/ionice").is_file() {
        // --ignore still executes Cargo if this kernel denies I/O scheduling.
        prefix.extend(["/usr/bin/ionice", "--ignore", "--class", "3"]);
    }
    #[cfg(target_os = "macos")]
    if Path::new("/usr/bin/taskpolicy").is_file() {
        prefix.extend(["/usr/bin/taskpolicy", "-b"]);
    }
    match prefix.split_first() {
        Some((program, arguments)) => {
            let mut command = Command::new(program);
            command.args(arguments).arg(executable);
            command
        }
        None => Command::new(executable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn build_priority_is_inherited_without_lowering_the_daemon() {
        let before = rustix::process::getpriority_process(None).unwrap();
        // This child intentionally yields to foreground CPU and disk work.
        // Check its scheduling policy, not a five-second latency guarantee.
        let timeout = Duration::from_secs(30);
        let mut command = command(Path::new("sh"));
        command.args(["-c", "ps -o ni= -p $$"]);
        let output = super::super::process::capture(&mut command, 1024, timeout)
            .await
            .unwrap();
        let priority: i32 = std::str::from_utf8(&output)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        if Path::new("/usr/bin/nice").is_file() {
            assert!(priority >= (before + 10).min(19));
        }
        assert_eq!(rustix::process::getpriority_process(None).unwrap(), before);

        #[cfg(target_os = "linux")]
        if Path::new("/usr/bin/ionice").is_file() {
            let mut command = super::command(Path::new("sh"));
            command
                .args(["-c", "/usr/bin/ionice -p $$"])
                .env("LC_ALL", "C");
            let output = super::super::process::capture(&mut command, 1024, timeout)
                .await
                .unwrap();
            assert_eq!(std::str::from_utf8(&output).unwrap().trim(), "idle");
        }
    }
}
