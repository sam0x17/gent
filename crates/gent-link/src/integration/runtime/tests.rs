use super::*;
use futures_util::{SinkExt, StreamExt};
use std::{fs, os::unix::fs::PermissionsExt};

fn args(directory: &Path) -> Args {
    Args {
        host: Host::Codex,
        config_dir: Some(directory.into()),
        host_binary: directory.join("must-not-launch"),
    }
}

#[tokio::test]
async fn runtime_checks_refuse_absent_polling_foreign_and_conflicting_installs_without_launch() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let root = root.path().canonicalize().unwrap();
    let home = root.join("gent");
    let dir = root.join("codex");
    gent_daemon::config::initialize(&home, "runtime").unwrap();
    assert!(start(&home, args(&dir)).await.is_err());
    assert_eq!(
        status(&home, Host::Codex, Some(dir.clone())).await.unwrap()["runtime"]["connected"],
        false
    );
    assert!(!dir.exists());
    let options = |wake, socket| install::Args {
        host: Host::Codex,
        config_dir: Some(dir.clone()),
        wake,
        wake_socket: socket,
    };
    install::change(&home, options(false, None), true).unwrap();
    assert!(
        start(&home, args(&dir))
            .await
            .unwrap_err()
            .to_string()
            .contains("not enabled")
    );
    install::change(&home, options(false, Some(root.join("custom.sock"))), true).unwrap();
    assert!(
        start(&home, args(&dir))
            .await
            .unwrap_err()
            .to_string()
            .contains("default socket")
    );
    install::change(&home, options(true, None), true).unwrap();
    let config = dir.join("config.toml");
    let before = fs::read(&config).unwrap();
    assert!(start(&root.join("another-gent"), args(&dir)).await.is_err());
    assert_eq!(fs::read(&config).unwrap(), before);
    let changed = String::from_utf8(before)
        .unwrap()
        .replace("command =", "unrelated_command =");
    fs::write(&config, &changed).unwrap();
    assert!(start(&home, args(&dir)).await.is_err());
    assert_eq!(fs::read_to_string(config).unwrap(), changed);
}

#[tokio::test]
async fn existing_codex_is_only_probed_and_invalid_responses_never_launch_a_replacement() {
    for valid in [true, false] {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let root = root.path().canonicalize().unwrap();
        let home = root.join("gent");
        let dir = root.join("codex");
        gent_daemon::config::initialize(&home, "runtime").unwrap();
        install::change(
            &home,
            install::Args {
                host: Host::Codex,
                config_dir: Some(dir.clone()),
                wake: true,
                wake_socket: None,
            },
            true,
        )
        .unwrap();
        let (_, socket) = install::codex_runtime_target(&home, Some(dir.clone()), true).unwrap();
        let parent = socket.parent().unwrap();
        fs::create_dir(parent).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut methods = Vec::new();
            while let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) =
                stream.next().await
            {
                let request: Value = serde_json::from_str(&text).unwrap();
                let method = request["method"].as_str().unwrap();
                methods.push(method.to_string());
                let response = match method {
                    "initialize" => json!({}),
                    "initialized" => continue,
                    "thread/loaded/list" if valid => json!({"data":[],"nextCursor":null}),
                    "thread/loaded/list" => json!({"data":"invalid"}),
                    _ => panic!("unexpected host operation: {method}"),
                };
                stream
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        json!({"id":request["id"],"result":response})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
            }
            methods
        });
        let result = start(&home, args(&dir)).await;
        if valid {
            let value = result.unwrap();
            assert_eq!(value["action"], "already_running");
            assert_eq!(
                value["runtime"],
                json!({"connected":true,"loaded_threads_on_page":0,"has_more":false})
            );
            assert!(value["native_start"].is_null());
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("existing Codex endpoint could not be verified")
            );
        }
        assert_eq!(
            server.await.unwrap(),
            ["initialize", "initialized", "thread/loaded/list"]
        );
    }
}

#[tokio::test]
async fn launcher_uses_scoped_arguments_without_shell_expansion_and_bounds_output() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let binary = root.path().join("codex ' $HOME");
    let directory = root.path().join("config ' $HOME");
    fs::write(&binary,"#!/bin/sh\nprintf '%s\\n' \"$CODEX_HOME\" \"$@\" > \"$0.args\"\nprintf '%s\\n' '{\"status\":\"started\",\"socketPath\":\"/fixture.sock\",\"appServerVersion\":\"fixture\"}'\n").unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(launch(&binary, &directory).await.unwrap().status, "started");
    let recorded = fs::read_to_string(binary.with_file_name("codex ' $HOME.args")).unwrap();
    assert_eq!(
        recorded.lines().collect::<Vec<_>>(),
        [directory.to_str().unwrap(), "app-server", "daemon", "start"]
    );
    assert!(!directory.exists());
    fs::write(&binary, "#!/bin/sh\nhead -c 65537 /dev/zero\n").unwrap();
    assert!(
        launch(&binary, &directory)
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeded its limit")
    );
}
