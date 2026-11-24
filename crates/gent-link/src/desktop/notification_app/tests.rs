use super::*;
use std::os::unix::fs::MetadataExt;

#[test]
fn existing_sender_is_replaced_by_the_signed_tray_app() {
    let node = tempfile::tempdir().unwrap();
    for runtime in [node.path().join("auth/desktop"), node.path().to_owned()] {
        fs::create_dir_all(&runtime).unwrap();
        let legacy = runtime.join("Gent Desktop");
        fs::write(&legacy, b"existing tray").unwrap();
        let root = runtime.join("desktop-notifications/Gent.app");
        gent_daemon::config::private_dir(root.parent().unwrap()).unwrap();
        let old_bin = root.join("Contents/MacOS/GentNotifications");
        fs::create_dir_all(old_bin.parent().unwrap()).unwrap();
        fs::write(&old_bin, b"old notification sender").unwrap();
        fs::write(
            root.join("Contents/Info.plist"),
            "<key>CFBundleIdentifier</key><string>link.gent.notifications</string>",
        )
        .unwrap();
        assert_eq!(install(&runtime).unwrap(), root);
        assert!(!old_bin.exists());
        assert!(root.join("Contents/MacOS/GentDesktop").is_file());
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
        .arg("../../assets/branding/inkling-512.png")
        .status()
        .unwrap();
    assert!(result.success());
}
