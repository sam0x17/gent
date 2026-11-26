use super::*;
use std::os::unix::fs::MetadataExt;

#[test]
fn user_app_install_preserves_foreign_apps_and_replaces_only_its_own_bundle() {
    let user = tempfile::tempdir().unwrap();
    let root = user.path().join("Applications");
    fs::create_dir(&root).unwrap();
    let app = root.join("Gent.app");
    fs::create_dir(&app).unwrap();
    fs::write(app.join("user file"), b"keep").unwrap();
    assert!(install(&root).is_err());
    assert_eq!(fs::read(app.join("user file")).unwrap(), b"keep");
    fs::rename(&app, root.join("original.app")).unwrap();

    assert_eq!(install(&root).unwrap(), app);
    let inode = fs::metadata(&app).unwrap().ino();
    install(&root).unwrap();
    assert_eq!(fs::metadata(&app).unwrap().ino(), inode);
    let contents = app.join("Contents");
    for dir in [
        &app,
        &contents,
        &contents.join("MacOS"),
        &contents.join("Resources"),
        &contents.join("_CodeSignature"),
    ] {
        assert_eq!(fs::metadata(dir).unwrap().mode() & 0o777, 0o755);
    }
    for (path, _) in FILES {
        assert_eq!(
            fs::metadata(contents.join(path)).unwrap().mode() & 0o777,
            if path.starts_with("MacOS/") {
                0o755
            } else {
                0o644
            }
        );
    }
    fs::write(contents.join("Resources/Inkling.icns"), b"old").unwrap();
    install(&root).unwrap();
    assert_ne!(fs::metadata(&app).unwrap().ino(), inode);
    assert!(
        std::process::Command::new("/usr/bin/codesign")
            .args([
                "--verify",
                "--strict",
                "-R=identifier link.gent.notifications"
            ])
            .arg(&app)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn finder_uses_the_registered_cli_and_home_without_a_shell_or_path_lookup() {
    let temp = tempfile::tempdir().unwrap();
    let user = temp.path().join("Mac user");
    let home = temp.path().join("node 'A' & B");
    let binary = temp.path().join("custom prefix").join("gent");
    fs::create_dir(binary.parent().unwrap()).unwrap();
    fs::write(
        &binary,
        r#"#!/bin/sh
printf '%s\n' "$@" > "$0.tmp" && /bin/mv "$0.tmp" "$0.args"
"#,
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = temp.path().join("launcher-test");
    let compile = std::process::Command::new("/usr/bin/xcrun")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--sdk",
            "macosx",
            "swiftc",
            "-swift-version",
            "5",
            "-warnings-as-errors",
            "src/desktop/Launcher.swift",
            "../../scripts/desktop-macos/launcher/main.swift",
            "-o",
        ])
        .arg(&fixture)
        .status()
        .unwrap();
    assert!(compile.success());
    let open = || {
        std::process::Command::new(&fixture)
            .arg(&user)
            .env("PATH", "/nonexistent")
            .status()
            .unwrap()
            .success()
    };
    assert!(!open());
    save_launcher(&user, &binary, &home).unwrap();
    let record = user.join("Library/Application Support/Gent/desktop-launch.json");
    assert_eq!(fs::metadata(&record).unwrap().mode() & 0o777, 0o600);
    assert!(open());
    let args = binary.with_extension("args");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !args.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read_to_string(args).unwrap(),
        format!("--home\n{}\ndesktop\n", home.display())
    );
    fs::set_permissions(&record, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!open());
    save_launcher(&user, &temp.path().join("removed-cli"), &home).unwrap();
    assert!(!open());
}

#[test]
fn passive_upgrade_repairs_the_legacy_bundle_after_quit_or_with_a_manual_presenter() {
    for running in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let user = temp.path();
        let apps = user.join("Applications");
        let volume = user.join("User Applications");
        fs::create_dir(&volume).unwrap();
        std::os::unix::fs::symlink(&volume, &apps).unwrap();
        fs::set_permissions(&volume, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(installation_lock(&apps).is_err());
        fs::set_permissions(&volume, fs::Permissions::from_mode(0o755)).unwrap();
        let app = install(&apps).unwrap();
        let executable = app.join("Contents/MacOS/GentDesktop");
        fs::write(&executable, b"old managed presenter").unwrap();
        let home = user.join("node");
        gent_daemon::config::private_dir(&home).unwrap();
        super::super::install_icon(&home).unwrap();
        fs::write(home.join("desktop-disabled"), "disabled").unwrap();
        let socket = home.join("desktop.sock");
        let presenter = running.then(|| std::os::unix::net::UnixDatagram::bind(&socket).unwrap());
        let binary = user.join("custom prefix/gent");
        repair_installed(user, &binary, &home).unwrap();
        assert_eq!(
            fs::read(&executable).unwrap(),
            bundled!("MacOS/GentDesktop").1
        );
        let record = user.join(LAUNCHER);
        let binding: Launcher = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
        assert_eq!(
            (binding.binary, binding.home),
            (binary.clone(), home.clone())
        );
        assert_eq!(socket.exists(), running);
        assert!(home.join("desktop-disabled").is_file());
        assert!(!user.join("Library/LaunchAgents").exists());
        if let Some(presenter) = presenter {
            presenter.set_nonblocking(true).unwrap();
            assert_eq!(
                presenter.recv(&mut [0; 16]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        let inode = fs::metadata(&app).unwrap().ino();
        let record_inode = fs::metadata(&record).unwrap().ino();
        repair_installed(user, &binary, &home).unwrap();
        assert_eq!(fs::metadata(&app).unwrap().ino(), inode);
        assert_eq!(fs::metadata(record).unwrap().ino(), record_inode);
    }
}

#[test]
fn passive_upgrade_leaves_absent_and_unrelated_installations_alone() {
    let temp = tempfile::tempdir().unwrap();
    let user = temp.path();
    let apps = user.join("Applications");
    let home = user.join("node");
    let binary = user.join("bin/gent");
    repair_installed(user, &binary, &home).unwrap();
    assert!(!apps.exists());

    fs::create_dir(&apps).unwrap();
    let app = install(&apps).unwrap();
    let executable = app.join("Contents/MacOS/GentDesktop");
    fs::write(&executable, b"other installation").unwrap();
    repair_installed(user, &binary, &home).unwrap();
    assert!(!user.join(LAUNCHER).exists());
    gent_daemon::config::private_dir(&home).unwrap();
    super::super::install_icon(&home).unwrap();
    for (cli, node) in [
        (binary.clone(), user.join("other")),
        (user.join("other/gent"), home.clone()),
    ] {
        save_launcher(user, &cli, &node).unwrap();
        let saved = fs::read(user.join(LAUNCHER)).unwrap();
        repair_installed(user, &binary, &home).unwrap();
        assert_eq!(fs::read(user.join(LAUNCHER)).unwrap(), saved);
        assert_eq!(fs::read(&executable).unwrap(), b"other installation");
    }
    fs::remove_file(user.join(LAUNCHER)).unwrap();
    fs::write(app.join("Contents/Info.plist"), "unmanaged app").unwrap();
    assert!(repair_installed(user, &binary, &home).is_err());
    assert!(!user.join(LAUNCHER).exists());
    assert_eq!(fs::read(executable).unwrap(), b"other installation");
}

#[tokio::test]
async fn launch_services_streams_survive_handshake_and_close_at_eof() {
    use tokio::io::AsyncWriteExt;
    let scratch = tempfile::tempdir().unwrap();
    let open = scratch.path().join("open");
    fs::write(&open, r#"#!/bin/sh
set -eu
test "$1 $2 $3 $4" = "-n -g -W --stdin"
test "$6" = "--stdout" && test "$8" = "-a" && test "$9" = "/path with spaces/Gent.app"
test "${10}" = "--args" && test "${11}" = "icon" && test "${12}" = "tray" && test "${13}" = "--launch-services"
test -p "$5" && test -p "$7"
test "$(/usr/bin/stat -f %Lp "$5")" = 600 && test "$(/usr/bin/stat -f %Lp "$7")" = 600
exec < "$5" > "$7"
printf 'gent-desktop-ready\nrefresh\n'
/bin/cat
"#).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o700)).unwrap();
    let (mut child, mut input, mut lines) = launch_at(
        &open,
        Path::new("/path with spaces/Gent.app"),
        scratch.path(),
        Path::new("icon"),
        "tray",
    )
    .await
    .unwrap();
    assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("refresh"));
    input.write_all(b"one\ntwo\n").await.unwrap();
    assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("one"));
    assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("two"));
    drop(input);
    assert!(
        tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    // The process exit is authoritative even if kqueue has no further pipe event.
    let failed = launch_at(
        Path::new("/usr/bin/false"),
        Path::new("Gent.app"),
        scratch.path(),
        Path::new("icon"),
        "tray",
    )
    .await;
    assert!(failed.is_err());
}

#[test]
fn native_notification_center_fixture() {
    let temp = tempfile::tempdir().unwrap();
    let app = install(temp.path()).unwrap();
    let fixture = temp.path().join("notification-fixture");
    let compiled = std::process::Command::new("/usr/bin/xcrun")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--sdk",
            "macosx",
            "swiftc",
            "-swift-version",
            "5",
            "-warnings-as-errors",
            "src/desktop/macos.swift",
            "src/desktop/macos_tabs.swift",
            "src/desktop/management.swift",
            "src/desktop/dashboard.swift",
            "src/desktop/notifications/Delivery.swift",
            "../../scripts/notifications-macos/main.swift",
            "-o",
        ])
        .arg(&fixture)
        .status()
        .unwrap();
    assert!(compiled.success());
    let result = std::process::Command::new(fixture)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg(app)
        .arg("branding/inkling-512.png")
        .status()
        .unwrap();
    assert!(result.success());
}
