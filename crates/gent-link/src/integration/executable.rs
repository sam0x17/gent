//! Native executables must also resolve under launchd/systemd's minimal PATH.
use super::Host;
use anyhow::{Context, Result, ensure};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

fn executable(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

pub(super) fn resolve(host: Host) -> Result<PathBuf> {
    let name = match host {
        Host::Codex => "codex",
        Host::ClaudeCode => "claude",
    };
    let mut directories: Vec<_> =
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .filter(|path| path.is_absolute())
            .collect();
    if let Some(home) = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
    {
        directories.extend(user_directories(&home));
    }
    directories.extend(
        [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/home/linuxbrew/.linuxbrew/bin",
            "/usr/bin",
            "/bin",
        ]
        .map(PathBuf::from),
    );
    find(name, directories).with_context(|| format!("{name} executable unavailable; checked PATH and standard user/Homebrew installation locations"))
}

fn user_directories(home: &Path) -> [PathBuf; 5] {
    [
        ".local/bin",
        ".cargo/bin",
        ".npm-global/bin",
        ".nix-profile/bin",
        ".codex/packages/standalone/current/bin",
    ]
    .map(|path| home.join(path))
}

fn find(name: &str, directories: impl IntoIterator<Item = PathBuf>) -> Option<PathBuf> {
    directories
        .into_iter()
        .map(|directory| directory.join(name))
        .find(|path| executable(path))
}

pub(super) fn selected(host: Host, explicit: Option<&Path>) -> Result<PathBuf> {
    let Some(path) = explicit else {
        return resolve(host);
    };
    if path.is_absolute() || path.components().count() > 1 {
        ensure!(
            executable(path),
            "host executable not found or not executable"
        );
        return Ok(std::path::absolute(path)?);
    }
    // Explicit alternative commands retain the caller's PATH semantics.
    find(
        path.to_str().context("host executable name is not UTF-8")?,
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .filter(|path| path.is_absolute()),
    )
    .context("host executable not found; use an absolute --host-binary path")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    fn script(path: &Path, mode: u32) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn minimal_service_path_finds_user_installation_and_keeps_upgrade_symlink() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path();
        script(&home.join("versions/claude"), 0o700);
        fs::create_dir_all(home.join(".local/bin")).unwrap();
        symlink(home.join("versions/claude"), home.join(".local/bin/claude")).unwrap();
        assert_eq!(
            find("claude", user_directories(home)),
            Some(home.join(".local/bin/claude"))
        );
        script(
            &home.join(".codex/packages/standalone/current/bin/codex"),
            0o700,
        );
        assert_eq!(
            find("codex", user_directories(home)),
            Some(home.join(".codex/packages/standalone/current/bin/codex"))
        );
    }

    #[test]
    fn path_precedence_skips_non_executables_and_accepts_homebrew_links() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("path");
        let brew = root.path().join("homebrew/bin");
        script(&first.join("claude"), 0o600);
        script(&brew.join("claude"), 0o755);
        assert_eq!(
            find("claude", [first.clone(), brew.clone()]),
            Some(brew.join("claude"))
        );
        script(&first.join("claude"), 0o700);
        assert_eq!(
            find("claude", [first.clone(), brew]),
            Some(first.join("claude"))
        );
    }
}
