use super::test_support::Fixture;
use super::*;
use std::fs;

fn row() -> Value {
    json!({"id":"abcd1234","sessionId":uuid::Uuid::new_v4().to_string(),
        "kind":"background","cwd":"/work/fixture","pid":23,"status":"idle",
        "state":"done","name":"PRIVATE_TITLE","futureField":"PRIVATE_CONTENT"})
}

#[test]
fn native_inventory_preserves_uncertainty_and_never_returns_titles_or_other_payloads() {
    let mut rows = Vec::new();
    for (index, pid, status, state) in [
        (0, Some(23), Some("idle"), Some("done")),
        (1, Some(24), Some("busy"), Some("working")),
        (2, Some(25), None, None),
        (3, None, None, Some("done")),
        (4, None, None, Some("working")),
        (5, None, Some("busy"), Some("stopped")),
    ] {
        let mut entry = row();
        entry["id"] = format!("id-{index}").into();
        entry["sessionId"] = Value::Null;
        entry["pid"] = json!(pid);
        entry["status"] = json!(status);
        entry["state"] = json!(state);
        rows.push(entry);
    }
    let parsed =
        serde_json::to_value(sessions::parse(&serde_json::to_vec(&rows).unwrap()).unwrap())
            .unwrap();
    let states: Vec<_> = parsed
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["state"].as_str().unwrap())
        .collect();
    assert_eq!(
        states,
        [
            "reported_idle",
            "reported_busy",
            "reported_running",
            "inactive_complete",
            "inactive_incomplete",
            "inactive_unknown"
        ]
    );
    assert!(!parsed.to_string().contains("PRIVATE_"));
    assert!(parsed[4]["session_id"].is_null());

    let mut interactive = row();
    interactive.as_object_mut().unwrap().remove("id");
    interactive["kind"] = "interactive".into();
    let parsed = serde_json::to_value(
        sessions::parse(&serde_json::to_vec(&json!([interactive])).unwrap()).unwrap(),
    )
    .unwrap();
    assert!(parsed[0]["native_id"].is_null());
    assert!(parsed[0]["session_id"].is_string());
    assert_eq!(parsed[0]["state"], "reported_idle");
}

#[test]
fn ambiguous_malformed_and_excessive_native_inventory_is_refused_without_echoing_input() {
    for bytes in [
        b"PRIVATE_SECRET".as_slice(),
        br#"{"private":"PRIVATE_SECRET"}"#,
    ] {
        let error = sessions::parse(bytes).err().unwrap();
        assert!(!error.to_string().contains("PRIVATE_SECRET"));
    }
    for (field, value) in [
        ("pid", json!(1)),
        ("pid", json!(-1)),
        ("pid", json!(u32::MAX)),
        ("cwd", json!("relative")),
        ("cwd", json!("/path\ncontrol")),
        ("sessionId", json!(uuid::Uuid::nil().to_string())),
        ("sessionId", json!("foreign")),
        ("state", json!("\u{1b}bad")),
        ("kind", json!("")),
    ] {
        let mut invalid = row();
        invalid[field] = value;
        assert!(sessions::parse(&serde_json::to_vec(&json!([invalid])).unwrap()).is_err());
    }
    let first = row();
    let mut second = first.clone();
    second["id"] = "another".into();
    assert!(sessions::parse(&serde_json::to_vec(&json!([first, second])).unwrap()).is_err());
    let mut unidentified = row();
    unidentified["id"] = Value::Null;
    unidentified["sessionId"] = Value::Null;
    assert!(sessions::parse(&serde_json::to_vec(&json!([unidentified])).unwrap()).is_err());
    let rows: Vec<_> = (0..1024)
        .map(|n| {
            let mut r = row();
            r["id"] = format!("id-{n}").into();
            r
        })
        .collect();
    assert_eq!(
        sessions::parse(&serde_json::to_vec(&rows).unwrap())
            .unwrap()
            .len(),
        1024
    );
    let mut excessive = rows;
    excessive.push(row());
    assert!(sessions::parse(&serde_json::to_vec(&excessive).unwrap()).is_err());
}

#[tokio::test]
async fn live_inspection_uses_only_the_native_list_command_in_the_validated_profile() {
    for wake in [false, true] {
        let fixture = Fixture::new();
        fixture.install(wake);
        let config = fixture.directory.join(".claude.json");
        let before = fs::read(&config).unwrap();
        let result = fixture.status().await;
        assert_eq!(
            result["runtime"],
            json!({"inspected":true,"source":"claude_agents",
            "reported_running":0,"session_count":0,"sessions":[],"gent_bindings_checked":false})
        );
        let arguments = fs::read_to_string(format!("{}.args", fixture.binary.display())).unwrap();
        assert_eq!(
            arguments.lines().collect::<Vec<_>>(),
            [
                fixture.directory.to_str().unwrap(),
                fixture.directory.to_str().unwrap(),
                "agents",
                "--json",
                "--all"
            ]
        );
        assert_eq!(fs::read(config).unwrap(), before);
        assert!(!fixture.home.join("host-bindings").exists());
        let mut target =
            install::claude_runtime_target(&fixture.home, Some(fixture.directory.clone())).unwrap();
        target.custom_directory = false;
        inspect(&fixture.binary, &target).await.unwrap();
        let arguments = fs::read_to_string(format!("{}.args", fixture.binary.display())).unwrap();
        assert_eq!(arguments.lines().next(), Some("unset"));
    }
}

#[tokio::test]
async fn invalid_managed_installations_never_invoke_the_native_executable() {
    for mode in ["absent", "disabled", "pending", "conflict", "foreign"] {
        let fixture = Fixture::new();
        if mode != "absent" {
            fixture.install(true);
        }
        match mode {
            "disabled" => {
                let path = fixture.directory.join("settings.json");
                let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value["disableAllHooks"] = true.into();
                fs::write(path, value.to_string()).unwrap();
            }
            "pending" => {
                let path = fixture.directory.join(".gent-claude-code.json");
                let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value["pending"] = json!({"after":value["installed"]});
                fs::write(path, value.to_string()).unwrap();
            }
            "conflict" => {
                fs::write(fixture.directory.join(".claude.json"), "{}").unwrap();
            }
            "foreign" => {
                let path = fixture.directory.join(".gent-claude-code.json");
                let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value["installed"]["home"] = "/other/gent".into();
                fs::write(path, value.to_string()).unwrap();
            }
            _ => {}
        }
        assert_eq!(
            fixture.status().await["runtime"]["inspected"],
            false,
            "{mode}"
        );
        assert!(
            !fixture
                .binary
                .with_file_name("native ' $HOME.args")
                .exists()
        );
    }
}

#[tokio::test]
async fn native_failures_and_concurrent_configuration_changes_do_not_return_an_inventory() {
    for body in [
        "printf 'PRIVATE_STDERR' >&2\nexit 1\n",
        "printf 'PRIVATE_INVALID_JSON'\n",
        "exec head -c 1048577 /dev/zero\n",
        "printf '{}' > \"$CLAUDE_CONFIG_DIR/.claude.json\"\nprintf '[]'\n",
    ] {
        let fixture = Fixture::new();
        fixture.install(true);
        fixture.script(body);
        let value = fixture.status().await;
        assert_eq!(value["runtime"]["inspected"], false);
        assert!(value["runtime"]["sessions"].is_null());
        assert!(!value["runtime"].to_string().contains("PRIVATE_"));
    }
}

#[tokio::test]
async fn bounded_native_commands_time_out_without_waiting_for_host_exit() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "exec sleep 30"]);
    let started = std::time::Instant::now();
    let error = process::output(command, Duration::from_millis(50), 1024)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("timed out"));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn automatic_startup_uses_profile_and_excludes_transient_provider_environment() {
    let fixture = Fixture::new();
    fixture.install(true);
    let target = install::claude_runtime_pinned(&fixture.home, &fixture.directory).unwrap();
    let command = automatic_command(&fixture.binary, &target).unwrap();
    let environment: std::collections::BTreeMap<_, _> = command.as_std().get_envs().collect();
    assert_eq!(
        environment.get(std::ffi::OsStr::new("CLAUDE_CONFIG_DIR")),
        Some(&Some(fixture.directory.as_os_str()))
    );
    for key in [
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDECODE",
        "CLAUDE_CODE_EXTRA_BODY",
    ] {
        assert!(!environment.contains_key(std::ffi::OsStr::new(key)));
    }
    assert!(environment.contains_key(std::ffi::OsStr::new("HOME")));
}
