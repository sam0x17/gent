use super::*;
use clap::Parser;
use gent_daemon::config::{RelayConfig, ServiceConfig};
use std::{fs, io::Cursor, os::unix::fs::symlink};

fn options(args: &[&str]) -> Options {
    let cli = crate::Cli::try_parse_from(
        ["gent", "daemon", "install"]
            .into_iter()
            .chain(args.iter().copied()),
    )
    .unwrap();
    match cli.command.unwrap() {
        crate::Command::Daemon {
            command: Some(DaemonCommand::Install { setup, .. }),
        } => setup,
        _ => panic!("installer expected"),
    }
}

fn select(home: &Path, args: &[&str]) -> Result<Plan> {
    plan(home, None, &mut options(args), false)
}

fn fixture(home: &Path) -> config::Config {
    let mut cfg = config::initialize(home, "original").unwrap();
    cfg.cluster.local_only = false;
    cfg.relay = Some(RelayConfig {
        endpoint: "https://relay.example".into(),
        credential_file: home.join("relay.key"),
    });
    cfg.service = Some(ServiceConfig {
        origin: "https://accounts.example".into(),
        account_id: uuid::Uuid::new_v4().to_string(),
    });
    config::save(home, &cfg).unwrap();
    let token = format!("gent_t1.1700000000.{}", "a".repeat(64));
    config::write_private(&home.join("relay.key"), token.as_bytes()).unwrap();
    let setup = json!({
        "version": 1, "role": "owner", "service": cfg.service.as_ref().unwrap().origin,
        "account_id": cfg.service.as_ref().unwrap().account_id,
        "cluster_id": cfg.cluster.id, "node_id": cfg.node.id, "name": "original",
        "relay_endpoint": cfg.relay.as_ref().unwrap().endpoint,
        "initial": null, "credential": { "token": token, "session_hash": "b".repeat(64), "confirmed": true }
    });
    config::write_private(&home.join("service.json"), setup.to_string().as_bytes()).unwrap();
    cfg
}

#[test]
fn incompatible_setup_flags_fail_during_parsing() {
    for args in [
        vec!["--new", "one", "--local"],
        vec!["--new", "one", "--invite-file", "offer"],
        vec!["--name", "node"],
        vec!["--continue"],
        vec!["--shell", "fish"],
        vec!["--rc-file", "rc"],
        vec!["--headless", "--no-browser"],
        vec!["--headless", "--no-input"],
        vec!["--no-browser", "--no-input"],
        vec!["--local", "--service", "https://example.com"],
    ] {
        assert!(
            crate::Cli::try_parse_from(
                ["gent", "daemon", "install"]
                    .into_iter()
                    .chain(args.iter().copied())
            )
            .is_err(),
            "accepted {args:?}"
        );
    }
    options(&[
        "--new",
        "one",
        "--headless",
        "--hooks",
        "--shell",
        "zsh",
        "--rc-file",
        "rc",
    ]);
    options(&[
        "--invite-file",
        "offer",
        "--name",
        "node",
        "--continue",
        "--no-input",
    ]);
}

#[test]
fn terminal_input_is_bounded_and_closed_input_cancels() {
    for value in [
        "".into(),
        "unfinished".into(),
        "\tbad\n".into(),
        "bad\0\n".into(),
        "\x1b[2J\n".into(),
        format!("{}\n", "a".repeat(4096)),
    ] {
        assert!(answer(&mut Cursor::new(value), &mut Vec::new(), "prompt: ").is_err());
    }
    let mut output = Vec::new();
    assert_eq!(
        answer(
            &mut Cursor::new("  my cluster  \r\n"),
            &mut output,
            "prompt: "
        )
        .unwrap(),
        "my cluster"
    );
    assert_eq!(output, b"prompt: ");
}

#[test]
fn confirmation_reprompts_invalid_input_and_never_accepts_eof() {
    let mut output = Vec::new();
    assert!(
        confirm(
            &mut Cursor::new("maybe\nyes\n"),
            &mut output,
            "Install?",
            false
        )
        .unwrap()
    );
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("Please answer y or n.")
    );
    assert!(!confirm(&mut Cursor::new("\n"), &mut Vec::new(), "Discover?", false).unwrap());
    assert!(confirm(&mut Cursor::new("\n"), &mut Vec::new(), "Install?", true).unwrap());
    assert!(confirm(&mut Cursor::new(""), &mut Vec::new(), "Install?", true).is_err());
}

#[test]
fn setup_alias_has_identical_enrollment_and_noninteractive_flags() {
    for prefix in [vec!["gent", "setup"], vec!["gent", "daemon", "install"]] {
        let cli = crate::Cli::try_parse_from(prefix.into_iter().chain([
            "--new",
            "personal",
            "--no-input",
            "--discover-chats",
            "false",
        ]))
        .unwrap();
        let setup = match cli.command.unwrap() {
            crate::Command::Setup { setup, .. }
            | crate::Command::Daemon {
                command: Some(DaemonCommand::Install { setup, .. }),
            } => setup,
            _ => panic!("setup expected"),
        };
        assert!(setup.no_input);
        assert_eq!(setup.discover_chats, Some(false));
        assert_eq!(setup.new_cluster.as_deref(), Some("personal"));
    }
}

#[tokio::test]
async fn unattended_finish_preserves_integrations_and_discovery_preferences() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    config::initialize(&home, "proof").unwrap();
    let mut output = json!({});
    finish::run(&home, &mut output, false, Options::default())
        .await
        .unwrap();
    assert_eq!(output["setup_complete"], true);
    assert!(!config::load(&home).unwrap().extra.contains_key("discovery"));
    assert_eq!(output["setup_steps"].as_array().unwrap().len(), 1);
    finish::run(
        &home,
        &mut output,
        false,
        Options {
            discover_chats: Some(false),
            ..Options::default()
        },
    )
    .await
    .unwrap();
    assert!(config::load(&home).unwrap().extra.contains_key("discovery"));
    assert!(!config::load(&home).unwrap().discovery().unwrap().enabled);
}

#[test]
fn fresh_planning_does_not_create_state_or_replace_orphans() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    assert!(select(&home, &[]).is_err());
    assert!(select(&home, &["--no-input"]).is_err());
    assert_eq!(
        select(&home, &["--new", "original"]).unwrap(),
        Plan::Connect(Some("original".into()))
    );
    assert!(!home.exists());
    config::private_dir(&home).unwrap();
    config::write_private(&home.join("identity.key"), b"existing identity").unwrap();
    assert!(select(&home, &[]).is_err());
    assert_eq!(
        fs::read(home.join("identity.key")).unwrap(),
        b"existing identity"
    );
    assert!(!config::path(&home).exists());
}

#[test]
fn local_identity_survives_all_service_setup_choices() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    config::initialize(&home, "original").unwrap();
    let original = fs::read(config::path(&home)).unwrap();
    assert_eq!(select(&home, &[]).unwrap(), Plan::Existing);
    assert!(select(&home, &["--new", "original"]).is_err());
    // A configured node must refuse before even reading this missing invitation.
    let error = select(&home, &["--invite-file", "absent", "--name", "other"]).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("existing node state was preserved")
    );
    assert_eq!(fs::read(config::path(&home)).unwrap(), original);
}

#[test]
fn installed_owner_is_offline_repeatable_and_pins_service() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    fixture(&home);
    assert_eq!(
        select(&home, &["--new", "original"]).unwrap(),
        Plan::Existing
    );
    assert!(select(&home, &["--new", "changed"]).is_err());
    let mut options = options(&["--service", "https://accounts.example/"]);
    assert_eq!(
        plan(&home, None, &mut options, false).unwrap(),
        Plan::Existing
    );
    assert_eq!(options.service.as_deref(), Some("https://accounts.example"));
    assert!(select(&home, &["--service", "https://other.example"]).is_err());
    assert!(plan(&home, Some("local".into()), &mut Options::default(), false).is_err());
    fs::remove_file(home.join("relay.key")).unwrap();
    assert_eq!(select(&home, &[]).unwrap(), Plan::Connect(None));
    assert!(!home.join("relay.key").exists());
}

#[test]
fn installed_setup_rejects_retargeted_identity_account_and_relay() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    let cfg = fixture(&home);
    for change in 0..5 {
        let mut changed = cfg.clone();
        match change {
            0 => changed.node.id = uuid::Uuid::new_v4().to_string(),
            1 => changed.cluster.id = uuid::Uuid::new_v4().to_string(),
            2 => changed.service.as_mut().unwrap().account_id = uuid::Uuid::new_v4().to_string(),
            3 => changed.relay.as_mut().unwrap().endpoint = "https://other.example".into(),
            _ => changed.relay.as_mut().unwrap().credential_file = home.join("other.key"),
        }
        config::save(&home, &changed).unwrap();
        let bytes = fs::read(config::path(&home)).unwrap();
        assert!(select(&home, &[]).is_err(), "accepted mutation {change}");
        assert_eq!(fs::read(config::path(&home)).unwrap(), bytes);
    }
}

#[test]
fn pending_ssh_join_and_broken_config_links_are_preserved() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    let staged = config::pending_join(&home).unwrap();
    config::private_dir(&staged).unwrap();
    assert!(
        select(&home, &[])
            .unwrap_err()
            .to_string()
            .contains("SSH join")
    );
    assert!(select(&home, &["--new", "replacement"]).is_err());
    assert!(plan(&home, Some("local".into()), &mut Options::default(), false).is_err());
    assert!(staged.is_dir() && !home.exists());
    fs::remove_dir(staged).unwrap();
    config::private_dir(&home).unwrap();
    symlink(home.join("missing"), config::path(&home)).unwrap();
    assert!(select(&home, &[]).is_err());
    assert!(config::path(&home).is_symlink());
    assert!(!home.join("missing").exists());
}
