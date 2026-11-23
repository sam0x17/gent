use super::*;
use std::os::unix::fs::MetadataExt;

#[test]
fn existing_desktop_gains_intact_signed_sender() {
    let node = tempfile::tempdir().unwrap();
    for runtime in [node.path().join("auth/desktop"), node.path().to_owned()] {
        fs::create_dir_all(&runtime).unwrap();
        let legacy = runtime.join("Gent Desktop");
        fs::write(&legacy, b"existing tray").unwrap();
        let root = install(&runtime).unwrap();
        let inode = || fs::metadata(&root).unwrap().ino();
        let first = inode();
        assert_eq!(install(&runtime).unwrap(), root);
        assert_eq!(inode(), first);

        let icon = root.join("Contents/Resources/Inkling.icns");
        fs::write(&icon, b"outdated").unwrap();
        install(&runtime).unwrap();
        assert_ne!(inode(), first);
        let verified = std::process::Command::new("/usr/bin/codesign")
            .args([
                "--verify",
                "--strict",
                "-R=identifier link.gent.notifications",
            ])
            .arg(&root)
            .status()
            .unwrap();
        assert!(verified.success());
        assert_eq!(fs::read(&legacy).unwrap(), b"existing tray");
    }
}

#[tokio::test]
async fn launch_needs_matching_native_acknowledgment() {
    let scratch = tempfile::tempdir().unwrap();
    let launcher = scratch.path().join("open");
    let app = scratch.path().join("profile with spaces/Gent.app");
    let id = Uuid::new_v4();
    for (reply, code, accepted) in [
        ("", 0, false),
        ("some other notice", 0, false),
        (&id.to_string(), 1, false),
        (&id.to_string(), 0, true),
    ] {
        let script = format!(
            r#"#!/bin/sh
set -eu
test "$1 $2 $3 $4" = "-n -g -W --stdin"
test "$6" = "--stdout" && test "$8" = "-a"
test "$9" = "${{0%/*}}/profile with spaces/Gent.app" && test "${{10}} ${{11}}" = "--args --deliver"
test "$(/usr/bin/plutil -extract id raw "$5")" = "{id}"
test "$(/usr/bin/plutil -extract title raw "$5")" = "Goal resumed"
test "$(/usr/bin/plutil -extract body raw "$5")" = 'A "quoted" chat resumed.'
printf '%s' '{reply}' > "$7"
exit {code}
"#
        );
        fs::write(&launcher, script).unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
        let result = submit(
            &launcher,
            &app,
            id,
            "Goal resumed",
            "A \"quoted\" chat resumed.",
        )
        .await;
        assert_eq!(result.is_ok(), accepted, "{result:?}");
    }
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
        .arg("../../assets/branding/inkling-512.png")
        .status()
        .unwrap();
    assert!(result.success());
}
