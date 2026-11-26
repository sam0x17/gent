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
