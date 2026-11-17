use super::*;
use clap::Parser;

fn options(host: Host, directory: &Path, flags: &[&str]) -> Args {
    let mut words = vec![
        "gent",
        "integration",
        "install",
        host.name(),
        "--config-dir",
        directory.to_str().unwrap(),
    ];
    words.extend_from_slice(flags);
    let cli = crate::Cli::try_parse_from(words).unwrap();
    let Some(crate::Command::Integration {
        command: crate::integration::Command::Install(args),
    }) = cli.command
    else {
        panic!("install arguments")
    };
    args
}

#[test]
fn default_installs_enable_wake_and_only_explicit_opt_out_removes_it() {
    for host in [Host::Codex, Host::ClaudeCode] {
        let (_temp, layout, spec) = fixture(host);
        config::initialize(&spec.home, "defaults").unwrap();
        let initial = change(&spec.home, options(host, &layout.directory, &[]), true).unwrap();
        assert_eq!(initial["delivery"]["mode"], "wake");
        assert_eq!(initial["delivery"]["state"], "configured_unverified");
        assert_eq!(initial["delivery"]["conversation_verified"], false);
        let record = get(&layout.record());
        let server = get(&layout.server);
        let again = change(&spec.home, options(host, &layout.directory, &[]), true).unwrap();
        assert_eq!(initial, again);
        assert_eq!(get(&layout.record()), record);
        assert_eq!(get(&layout.server), server);
        let disabled = change(
            &spec.home,
            options(host, &layout.directory, &["--no-wake"]),
            true,
        )
        .unwrap();
        assert_eq!(disabled["delivery"]["mode"], "manual");
        assert!(disabled["wake_socket"].is_null() && disabled["claude_wake"].is_null());
        assert_eq!(disabled["state"], "configured");
        let restored = change(&spec.home, options(host, &layout.directory, &[]), true).unwrap();
        assert_eq!(restored["delivery"]["mode"], "wake");
    }
}

#[test]
fn default_reinstall_keeps_custom_socket_and_vscode_until_explicitly_removed() {
    let (_temp, layout, spec) = fixture(Host::Codex);
    config::initialize(&spec.home, "defaults").unwrap();
    let settings = layout.directory.join("settings.json");
    let custom = layout.directory.join("custom.sock");
    let initial = change(
        &spec.home,
        options(
            Host::Codex,
            &layout.directory,
            &[
                "--wake-socket",
                custom.to_str().unwrap(),
                "--vscode",
                "--vscode-settings",
                settings.to_str().unwrap(),
            ],
        ),
        true,
    )
    .unwrap();
    let record = get(&layout.record());
    let repeated = change(
        &spec.home,
        options(Host::Codex, &layout.directory, &[]),
        true,
    )
    .unwrap();
    assert_eq!(repeated, initial);
    assert_eq!(get(&layout.record()), record);
    // Simulate losing the install's final journal write. A plain retry retains
    // the pending custom socket and IDE route, not the former absent setup.
    let (snapshot, mut state) = layout.read().unwrap();
    state.pending = Some(Transition {
        after: state.installed.take(),
    });
    save(&snapshot, &state).unwrap();
    let recovered = change(
        &spec.home,
        options(Host::Codex, &layout.directory, &[]),
        true,
    )
    .unwrap();
    assert_eq!(recovered, initial);
    let removed = change(
        &spec.home,
        options(Host::Codex, &layout.directory, &["--no-vscode"]),
        true,
    )
    .unwrap();
    assert!(removed["vscode"].is_null());
    assert_eq!(removed["wake_socket"], json!(custom));
    assert!(!layout.ide_launcher().exists());
    assert!(
        document::VscodeDocument::parse(Some(&get(&settings)))
            .unwrap()
            .entry
            .is_none()
    );
}

#[test]
fn contradictory_delivery_flags_are_rejected_before_installation() {
    for flags in [
        vec!["--wake", "--no-wake"],
        vec!["--no-wake", "--vscode"],
        vec!["--vscode", "--no-vscode"],
        vec!["--no-wake", "--wake-socket", "/tmp/unused.sock"],
    ] {
        let mut args = vec!["gent", "integration", "install", "codex"];
        args.extend(flags);
        assert!(crate::Cli::try_parse_from(args).is_err());
    }
}
