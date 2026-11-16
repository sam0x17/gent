use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

pub(super) struct Fixture {
    _root: tempfile::TempDir,
    pub(super) home: PathBuf,
    pub(super) directory: PathBuf,
    pub(super) binary: PathBuf,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let path = root.path().canonicalize().unwrap();
        let value = Self {
            home: path.join("gent"),
            directory: path.join("claude ' $HOME"),
            binary: path.join("native ' $HOME"),
            _root: root,
        };
        gent_daemon::config::initialize(&value.home, "live").unwrap();
        value.script("printf '%s\\n' \"${CLAUDE_CONFIG_DIR-unset}\" \"$PWD\" \"$@\" > \"$0.args\"\ncat \"$0.reply\"\n");
        fs::write(format!("{}.reply", value.binary.display()), "[]").unwrap();
        value
    }
    pub(super) fn script(&self, body: &str) {
        fs::write(&self.binary, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(&self.binary, fs::Permissions::from_mode(0o700)).unwrap();
    }
    pub(super) fn install(&self, wake: bool) {
        install::change(
            &self.home,
            install::Args {
                move_profile: false,
                host: Host::ClaudeCode,
                config_dir: Some(self.directory.clone()),
                wake,
                wake_socket: None,
                vscode: false,
                vscode_settings: None,
            },
            true,
        )
        .unwrap();
    }
    pub(super) async fn status(&self) -> Value {
        status(&self.home, Some(self.directory.clone()), &self.binary)
            .await
            .unwrap()
    }
}
