use super::*;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

fn fixture(host: Host) -> (tempfile::TempDir, Layout, Spec) {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let dir = root.join("host");
    let server = dir.join(if host == Host::Codex {
        "config.toml"
    } else {
        ".claude.json"
    });
    let layout = Layout::at(host, dir.clone(), server).unwrap();
    files::directory(&dir).unwrap();
    let spec = Spec {
        home: root.join("gent ' $HOME"),
        binary: root.join("gent"),
        wake_socket: None,
    };
    (temp, layout, spec)
}
fn put(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn get(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

#[test]
fn codex_wake_opt_in_upgrades_legacy_install_and_removes_only_managed_arguments() {
    let (_temp, layout, mut spec) = fixture(Host::Codex);
    put(&layout.server, "model = 'keep-model'\n");
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    assert!(!get(&layout.record()).contains("wake_socket"));
    spec.wake_socket = Some(spec.home.join("host socket"));
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    assert!(get(&layout.server).contains("--wake-socket"));
    assert!(get(&layout.server).contains("keep-model"));
    assert!(spec.fragments(Host::ClaudeCode).is_err());
    let mut invalid = spec.clone();
    invalid.wake_socket = Some(PathBuf::from("relative"));
    assert!(mutate(&layout, &spec.home, Some(invalid)).is_err());
    mutate(&layout, &spec.home, None).unwrap();
    assert!(!get(&layout.server).contains("--wake-socket"));
    assert!(get(&layout.server).contains("keep-model"));
}

#[test]
fn installation_preserves_unrelated_text_and_removal_preserves_state() {
    for host in [Host::Codex, Host::ClaudeCode] {
        let (_temp, layout, mut spec) = fixture(host);
        let unrelated = if host == Host::Codex {
            "# retain this comment\nmodel = 'existing-model'\n[mcp_servers.other]\ncommand = 'other' # leave alone\n[model_providers.custom]\nname = 'custom'\nbase_url = 'https://example.invalid'\n"
        } else {
            "{\n  \"oauthAccount\": { \"secret\": \"PRIVATE-SENTINEL\" },\n  \"mcpServers\": { \"other\": {\"command\":\"other\"} },\n  \"projects\": {}\n}\n"
        };
        put(&layout.server, unrelated);
        fs::set_permissions(&layout.server, fs::Permissions::from_mode(0o640)).unwrap();
        if let Some(settings) = &layout.settings {
            put(
                settings,
                "{\n  \"permissions\": { \"deny\": [\"Bash\"] },\n  \"hooks\": {\"PreToolUse\":[{\"matcher\":\"Bash\",\"hooks\":[{\"type\":\"command\",\"command\":\"true\"}]}]}\n}\n",
            );
        }
        mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
        let first = get(&layout.server);
        let record = get(&layout.record());
        assert!(!record.contains("PRIVATE-SENTINEL") && !record.contains("existing-model"));
        assert_eq!(fs::metadata(&layout.server).unwrap().mode() & 0o777, 0o640);
        assert_eq!(fs::metadata(layout.record()).unwrap().mode() & 0o777, 0o600);
        assert_eq!(inspect(&layout, &spec.home).unwrap()["state"], "configured");
        mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
        assert_eq!(get(&layout.server), first);
        assert_eq!(get(&layout.record()), record);
        spec.binary = spec.binary.with_file_name("upgraded binary '$SHELL");
        mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
        assert!(get(&layout.server).contains("upgraded binary"));
        mutate(&layout, &spec.home, None).unwrap();
        assert_eq!(inspect(&layout, &spec.home).unwrap()["state"], "absent");
        let final_text = get(&layout.server);
        if host == Host::Codex {
            assert_eq!(final_text, unrelated);
        } else {
            assert!(final_text.contains("\"oauthAccount\": { \"secret\": \"PRIVATE-SENTINEL\" }"));
            assert!(final_text.contains("\"other\": {\"command\":\"other\"}"));
            let settings = get(layout.settings.as_ref().unwrap());
            assert!(settings.contains("\"permissions\": { \"deny\": [\"Bash\"] }"));
            let value: Value = serde_json::from_str(&settings).unwrap();
            assert_eq!(value["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        }
        let last = get(&layout.server);
        mutate(&layout, &spec.home, None).unwrap();
        assert_eq!(get(&layout.server), last);
    }
}

#[test]
fn malformed_duplicate_foreign_or_edited_entries_fail_without_echoing_secrets() {
    for invalid in [
        "{\"secret\": PRIVATE-SENTINEL}",
        "{\"secret\":\"PRIVATE-SENTINEL\",}",
        "{\"secret\":\"PRIVATE-SENTINEL\",\"secret\":0}",
        "{\"s\":{\"x\":1,\"x\":2}}",
        "{\"s\":{\"x\":1,\"\\u0078\":2}}",
        "null",
        "",
        "{\"hooks\":null}",
    ] {
        let (_temp, layout, spec) = fixture(Host::ClaudeCode);
        put(layout.settings.as_ref().unwrap(), invalid);
        let error = mutate(&layout, &spec.home, Some(spec.clone())).unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE-SENTINEL"));
        assert!(!layout.server.exists() && !layout.record().exists());
        assert_eq!(get(layout.settings.as_ref().unwrap()), invalid);
    }
    let (_temp, layout, spec) = fixture(Host::Codex);
    put(&layout.server, "secret = PRIVATE-SENTINEL");
    assert!(
        !format!(
            "{:#}",
            mutate(&layout, &spec.home, Some(spec.clone())).unwrap_err()
        )
        .contains("PRIVATE-SENTINEL")
    );
    put(&layout.server, "[mcp_servers.gent]\ncommand = 'foreign'\n");
    assert!(mutate(&layout, &spec.home, Some(spec.clone())).is_err());
    assert!(mutate(&layout, &spec.home, None).is_err());
    // An identical manually added entry still has no Gent ownership record.
    let fragment = spec.fragments(Host::Codex).unwrap()["mcp_servers"]["gent"].clone();
    put(
        &layout.server,
        &Document::parse(None, Host::Codex)
            .unwrap()
            .set_server(Some(&fragment))
            .unwrap(),
    );
    assert!(mutate(&layout, &spec.home, Some(spec.clone())).is_err());
    fs::remove_file(&layout.server).unwrap();
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let edited = format!("{}enabled = false\n", get(&layout.server));
    put(&layout.server, &edited);
    assert_eq!(inspect(&layout, &spec.home).unwrap()["state"], "conflict");
    assert!(mutate(&layout, &spec.home, None).is_err());
    assert_eq!(get(&layout.server), edited);
}

#[test]
fn disabled_hooks_and_changed_hook_preflight_precede_all_writes() {
    let (_temp, layout, spec) = fixture(Host::ClaudeCode);
    let path = layout.settings.as_ref().unwrap();
    put(path, "{\"disableAllHooks\":true}");
    assert!(mutate(&layout, &spec.home, Some(spec.clone())).is_err());
    assert!(!layout.server.exists() && !layout.record().exists());
    put(path, "{}");
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let initial = get(&layout.server);
    let text = get(path);
    put(path, &text.replace("\"timeout\": 10", "\"timeout\": 11"));
    assert!(mutate(&layout, &spec.home, None).is_err());
    assert_eq!(get(&layout.server), initial);
    put(path, &text);
    let mut value: Value = serde_json::from_str(&text).unwrap();
    value["disableAllHooks"] = true.into();
    put(path, &value.to_string());
    assert_eq!(
        inspect(&layout, &spec.home).unwrap()["state"],
        "hooks_disabled"
    );
    mutate(&layout, &spec.home, None).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&get(path)).unwrap()["disableAllHooks"],
        true
    );
}

#[test]
fn recovery_finishes_each_partial_operation_and_retains_later_unrelated_edits() {
    // Interrupt before/after each host file for install, upgrade and uninstall.
    for operation in 0..3 {
        for completed in 0..=2 {
            let (_temp, layout, spec) = fixture(Host::ClaudeCode);
            if operation > 0 {
                mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
            }
            let desired = if operation == 2 {
                None
            } else {
                Some(Spec {
                    binary: spec.binary.with_file_name("new-gent"),
                    ..spec.clone()
                })
            };
            let (snapshot, mut state) = layout.read().unwrap();
            let edits = layout
                .edits(state.installed.as_ref(), desired.as_ref(), false, true)
                .unwrap();
            state.pending = Some(Transition {
                after: desired.clone(),
            });
            save(&snapshot, &state).unwrap();
            for edit in edits.into_iter().take(completed) {
                edit.apply().unwrap();
            }
            let mut host: Value =
                serde_json::from_str(&fs::read_to_string(&layout.server).unwrap_or("{}".into()))
                    .unwrap();
            host["newHostSetting"] = "PRIVATE-SENTINEL".into();
            put(&layout.server, &host.to_string());
            let before_status = get(&layout.record());
            assert_eq!(
                inspect(&layout, &spec.home).unwrap()["state"],
                "recovery_pending"
            );
            assert_eq!(before_status, get(&layout.record()));
            mutate(&layout, &spec.home, desired.clone()).unwrap();
            assert_eq!(layout.read().unwrap().1.installed, desired);
            assert_eq!(
                serde_json::from_str::<Value>(&get(&layout.server)).unwrap()["newHostSetting"],
                "PRIVATE-SENTINEL"
            );
            assert!(!get(&layout.record()).contains("PRIVATE-SENTINEL"));
        }
    }
}

#[test]
fn path_links_shared_files_concurrent_changes_and_other_owners_are_rejected() {
    let (temp, layout, spec) = fixture(Host::Codex);
    let target = temp.path().join("absent");
    std::os::unix::fs::symlink(&target, &layout.server).unwrap();
    assert!(mutate(&layout, &spec.home, Some(spec.clone())).is_err());
    assert!(!target.exists());
    fs::remove_file(&layout.server).unwrap();
    put(&layout.server, "");
    let link = temp.path().join("hardlink");
    fs::hard_link(&layout.server, &link).unwrap();
    assert!(mutate(&layout, &spec.home, Some(spec.clone())).is_err());
    fs::remove_file(link).unwrap();
    fs::set_permissions(&layout.server, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(mutate(&layout, &spec.home, Some(spec.clone())).is_err());
    fs::set_permissions(&layout.server, fs::Permissions::from_mode(0o600)).unwrap();
    let snapshot = Snapshot::read(&layout.server).unwrap();
    put(&layout.server, "# host changed this\n");
    assert!(snapshot.write("discarded edit").is_err());
    assert_eq!(get(&layout.server), "# host changed this\n");
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let foreign = Spec {
        home: temp.path().join("other"),
        ..spec.clone()
    };
    assert!(mutate(&layout, &foreign.home, Some(foreign.clone())).is_err());
    assert!(mutate(&layout, &foreign.home, None).is_err());
    assert!(
        !inspect(&layout, &foreign.home).unwrap()["current_home"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn read_only_status_and_absent_uninstall_do_not_create_host_files() {
    let (temp, layout, spec) = fixture(Host::Codex);
    fs::remove_dir(&layout.directory).unwrap();
    assert_eq!(inspect(&layout, &spec.home).unwrap()["state"], "absent");
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    mutate(&layout, &spec.home, None).unwrap();
    assert!(!layout.server.exists() && !layout.record().exists());
}

#[test]
fn inline_toml_server_tables_survive_install_and_remove() {
    let (_temp, layout, spec) = fixture(Host::Codex);
    put(
        &layout.server,
        "# inline\nmcp_servers = {other = {command = 'other'}}\nmodel = 'mine'\n",
    );
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    assert_eq!(inspect(&layout, &spec.home).unwrap()["state"], "configured");
    mutate(&layout, &spec.home, None).unwrap();
    assert!(get(&layout.server).contains("other = {command = 'other'}"));
    assert!(get(&layout.server).contains("model = 'mine'"));
}

#[test]
fn recovery_refuses_changed_managed_fragments_and_normalized_paths_remain_stable() {
    let (_temp, layout, spec) = fixture(Host::ClaudeCode);
    let (snapshot, mut state) = layout.read().unwrap();
    state.pending = Some(Transition {
        after: Some(spec.clone()),
    });
    save(&snapshot, &state).unwrap();
    put(
        layout.settings.as_ref().unwrap(),
        "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"^mcp__gent__gent_\",\"hooks\":[]}]}}",
    );
    assert!(mutate(&layout, &spec.home, Some(spec.clone())).is_err());
    assert!(!layout.server.exists());
    assert!(layout.read().unwrap().1.pending.is_some());
    fs::remove_file(layout.settings.as_ref().unwrap()).unwrap();
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let again = Layout::at(layout.host, layout.directory.clone(), layout.server.clone()).unwrap();
    assert_eq!(again.server, layout.server);
    assert_eq!(again.settings, layout.settings);
    assert_eq!(inspect(&again, &spec.home).unwrap()["state"], "configured");
    let record = layout.record();
    fs::set_permissions(&record, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(mutate(&layout, &spec.home, None).is_err());
}
