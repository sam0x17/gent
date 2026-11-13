use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = fs::canonicalize(temp.path()).unwrap().join("rc");
    (temp, path)
}
fn put(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn binary(name: &str) -> PathBuf {
    Path::new("/tmp").join(name).join("gent")
}

#[test]
fn blocks_preserve_bytes_modes_and_later_edits_through_upgrade_and_removal() {
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
        for original in [
            "",
            "# existing\nexport EDIT=kept\n",
            "# final line lacks newline",
        ] {
            let (_temp, path) = fixture();
            put(&path, original);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            assert!(modify(&path, shell, Some(binary("a '$HOME & [*]"))).unwrap());
            let installed = fs::read_to_string(&path).unwrap();
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );
            assert!(!modify(&path, shell, Some(binary("a '$HOME & [*]"))).unwrap());
            assert_eq!(fs::read_to_string(&path).unwrap(), installed);
            let later = format!("# earlier edit\n{installed}# later edit\n");
            put(&path, &later);
            assert!(modify(&path, shell, Some(binary("upgrade"))).unwrap());
            let updated = fs::read_to_string(&path).unwrap();
            assert_eq!(updated.matches(BEGIN).count(), 1);
            assert_eq!(
                read(&updated, shell).unwrap().unwrap().spec.binary,
                binary("upgrade")
            );
            assert!(modify(&path, shell, None).unwrap());
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                format!("# earlier edit\n{original}# later edit\n")
            );
            assert!(!modify(&path, shell, None).unwrap());
        }
    }
}

#[test]
fn malformed_edited_duplicate_and_wrong_shell_blocks_are_preserved() {
    let (_temp, path) = fixture();
    let spec = Spec {
        version: 1,
        shell: Shell::Bash,
        binary: binary("valid"),
    };
    let rendered = spec.render().unwrap();
    for text in [
        rendered.replace(
            "completions bash",
            "completions bash; echo PRIVATE-SENTINEL",
        ),
        rendered.replace(END, ""),
        format!("{rendered}{rendered}"),
        format!("\n{BEGIN}PRIVATE-SENTINEL\n{END}"),
        rendered.trim_start().to_owned(),
        rendered.replace("# >>> gent shell v1:", "# >>> gent shell v2:"),
    ] {
        put(&path, &text);
        for desired in [None, Some(binary("new"))] {
            let error = modify(&path, Shell::Bash, desired).unwrap_err();
            assert!(!format!("{error:#}").contains("PRIVATE-SENTINEL"));
            assert_eq!(fs::read_to_string(&path).unwrap(), text);
        }
    }
    put(&path, &rendered);
    assert!(modify(&path, Shell::Zsh, None).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), rendered);
    assert!(
        Spec {
            binary: binary("bad:PATH"),
            ..spec.clone()
        }
        .render()
        .is_err()
    );
    assert!(
        Spec {
            binary: binary("bad\nline"),
            ..spec
        }
        .render()
        .is_err()
    );
}

#[test]
fn status_and_absent_removal_are_read_only_and_links_are_rejected() {
    let (temp, path) = fixture();
    let missing = path.join("missing");
    assert_eq!(inspect(&missing, Shell::Zsh).unwrap()["state"], "absent");
    assert!(!modify(&missing, Shell::Zsh, None).unwrap());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    std::os::unix::fs::symlink(&missing, &path).unwrap();
    assert!(modify(&path, Shell::Zsh, Some(binary("valid"))).is_err());
    assert!(managed_file::normalize(&path).is_err());
    fs::remove_file(&path).unwrap();
    put(&path, "# shell");
    let linked = temp.path().join("linked");
    fs::hard_link(&path, &linked).unwrap();
    assert!(modify(&path, Shell::Zsh, Some(binary("valid"))).is_err());
    fs::remove_file(&linked).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(modify(&path, Shell::Zsh, Some(binary("valid"))).is_err());
}

#[test]
fn shell_detection_and_startup_paths_are_explicit() {
    assert_eq!(
        Shell::detected(Some(std::ffi::OsStr::new("/bin/zsh"))).unwrap(),
        Shell::Zsh
    );
    assert_eq!(
        Shell::detected(Some(std::ffi::OsStr::new("/usr/bin/bash"))).unwrap(),
        Shell::Bash
    );
    assert!(Shell::detected(None).is_err());
    assert_eq!(
        Shell::detected(Some(std::ffi::OsStr::new("/bin/fish"))).unwrap(),
        Shell::Fish
    );
    assert!(Shell::detected(Some(std::ffi::OsStr::new("/bin/unsupported"))).is_err());
    let home = Some(Path::new("/home/user"));
    let zdir = Some(Path::new("/custom/zsh"));
    assert_eq!(
        default_path(Shell::Bash, home, zdir, None).unwrap(),
        Path::new("/home/user/.bashrc")
    );
    assert_eq!(
        default_path(Shell::Zsh, home, zdir, None).unwrap(),
        Path::new("/custom/zsh/.zshrc")
    );
    assert_eq!(
        default_path(Shell::Zsh, home, Some(Path::new("")), None).unwrap(),
        Path::new("/home/user/.zshrc")
    );
    assert!(default_path(Shell::Bash, None, zdir, None).is_err());
    assert_eq!(
        default_path(Shell::Fish, home, zdir, None).unwrap(),
        Path::new("/home/user/.config/fish/config.fish")
    );
    assert_eq!(
        default_path(Shell::Fish, None, None, Some(Path::new("/custom/config"))).unwrap(),
        Path::new("/custom/config/fish/config.fish")
    );
}

#[test]
fn concurrent_installers_leave_one_block_and_single_removal_restores_original() {
    let (_temp, path) = fixture();
    put(&path, "# preserved\n");
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| modify(&path, Shell::Zsh, Some(binary("valid"))).unwrap());
        }
    });
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text.matches(BEGIN).count(), 1);
    modify(&path, Shell::Zsh, None).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "# preserved\n");
}
