use super::*;
mod defaults;
mod provider_switcher;
mod retirement;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

pub(super) fn fixture(host: Host) -> (tempfile::TempDir, Layout, Spec) {
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
        claude_wake: None,
        codex_ide: None,
    };
    (temp, layout, spec)
}
pub(super) fn put(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
pub(super) fn get(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

fn enable_claude(spec: &mut Spec) {
    let cfg = config::initialize(&spec.home, "claude-install").unwrap();
    spec.claude_wake = Some(claude_wake::Installation::new(&cfg));
}

fn enable_ide(layout: &Layout, spec: &mut Spec) -> PathBuf {
    let settings = layout.directory.join("vscode-settings.json");
    spec.wake_socket = Some(layout.wake_socket().unwrap());
    spec.codex_ide = Some(vscode::Installation::new(settings.clone()));
    settings
}

#[test]
fn vscode_comments_user_settings_and_ownership_survive_install_move_and_removal() {
    let (_temp, layout, mut spec) = fixture(Host::Codex);
    let settings = enable_ide(&layout, &mut spec);
    let original = "// user preferences\n{\n  \"window.zoomLevel\": 2, // keep\n  \"private\": \"never-journal-this\",\n}\n";
    put(&settings, original);
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let installed = get(&settings);
    assert!(installed.contains("// user preferences") && installed.contains("// keep"));
    assert!(installed.contains("never-journal-this"));
    assert!(!get(&layout.record()).contains("never-journal-this"));
    assert_eq!(
        fs::metadata(layout.ide_launcher()).unwrap().mode() & 0o777,
        0o700
    );
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    assert_eq!(get(&settings), installed);
    let moved = settings.with_file_name("another-profile.json");
    spec.codex_ide.as_mut().unwrap().settings = moved.clone();
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    assert!(
        document::VscodeDocument::parse(Some(&get(&settings)))
            .unwrap()
            .entry
            .is_none()
    );
    assert!(get(&settings).contains("never-journal-this"));
    assert!(get(&moved).contains("chatgpt.cliExecutable"));
    mutate(&layout, &spec.home, None).unwrap();
    assert!(!layout.ide_launcher().exists());
    assert!(
        document::VscodeDocument::parse(Some(&get(&moved)))
            .unwrap()
            .entry
            .is_none()
    );
}

#[test]
fn vscode_refuses_foreign_overrides_malformed_jsonc_and_edited_launchers_before_writes() {
    let (_temp, layout, mut spec) = fixture(Host::Codex);
    let settings = enable_ide(&layout, &mut spec);
    for original in [
        r#"{"chatgpt.cliExecutable":"/user/custom-codex"}"#,
        r#"{"x":1,"x":2}"#,
        r#"{"a":1 "b":2}"#,
        r#"{'private-secret': 42}"#,
    ] {
        put(&settings, original);
        assert!(mutate(&layout, &spec.home, Some(spec.clone())).is_err());
        assert_eq!(get(&settings), original);
        assert!(
            !layout.server.exists() && !layout.ide_launcher().exists() && !layout.record().exists()
        );
    }
    put(&settings, "{}");
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let before = get(&settings);
    put(&layout.ide_launcher(), "user edits");
    assert!(mutate(&layout, &spec.home, None).is_err());
    assert_eq!(get(&settings), before);
    assert_eq!(get(&layout.ide_launcher()), "user edits");
}

#[test]
fn vscode_install_update_and_uninstall_recover_every_partial_file_transition() {
    for operation in 0..3 {
        for completed in 0..4 {
            let (_temp, layout, mut spec) = fixture(Host::Codex);
            let settings = enable_ide(&layout, &mut spec);
            put(&settings, "{\"user\":true,}\n");
            if operation != 0 {
                mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
            }
            let desired = if operation == 2 {
                None
            } else {
                Some(Spec {
                    binary: spec.binary.with_file_name("new ' $binary"),
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
            recover(&layout).unwrap();
            assert_eq!(layout.read().unwrap().1.installed, desired);
            assert!(get(&settings).contains("\"user\":true"));
            assert_eq!(layout.ide_launcher().exists(), desired.is_some());
            if desired.is_some() {
                assert!(Snapshot::read(&layout.ide_launcher()).unwrap().executable());
            }
        }
    }
}

#[test]
fn retained_guard_upgrades_legacy_installs_preserves_other_hooks_and_fails_closed() {
    let (_temp, layout, mut spec) = fixture(Host::ClaudeCode);
    enable_claude(&mut spec);
    let current = spec.clone();
    spec.claude_wake.as_mut().unwrap().version = 1;
    let settings = layout.settings.as_ref().unwrap();
    let other = json!({"hooks":[{"type":"command", "command":"echo user-hook"}]});
    put(
        settings,
        &json!({"hooks":{"UserPromptSubmit":[other]}}).to_string(),
    );
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    assert!(
        Document::parse(Some(&get(settings)), Host::ClaudeCode)
            .unwrap()
            .wake_guard()
            .unwrap()
            .is_none()
    );
    spec.claude_wake.as_mut().unwrap().version = 2;
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let legacy = Document::parse(Some(&get(settings)), Host::ClaudeCode).unwrap();
    assert!(legacy.wake_guard().unwrap().unwrap()["hooks"][0]["onFailure"].is_null());
    assert!(
        claude_wake(
            &spec.home,
            &layout.directory,
            &spec.claude_wake.as_ref().unwrap().id
        )
        .is_err()
    );
    mutate(&layout, &spec.home, Some(current.clone())).unwrap();
    let doc = Document::parse(Some(&get(settings)), Host::ClaudeCode).unwrap();
    let guard = doc.wake_guard().unwrap().unwrap();
    assert_eq!(guard["hooks"][0]["onFailure"], "block");
    let command = guard["hooks"][0]["command"].as_str().unwrap();
    // Missing runtime must use Claude's blocking exit status, not its ordinary
    // hook-error path. The fixture's home contains a quote and a dollar sign.
    let output = std::process::Command::new("/bin/sh")
        .args(["-c", command])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let original = get(settings);
    let mut value: Value = serde_json::from_str(&original).unwrap();
    value["hooks"]["UserPromptSubmit"]
        .as_array_mut()
        .unwrap()
        .push(guard.clone());
    put(settings, &value.to_string());
    assert!(mutate(&layout, &spec.home, None).is_err());
    put(settings, &original);
    mutate(&layout, &spec.home, None).unwrap();
    let value: Value = serde_json::from_str(&get(settings)).unwrap();
    assert_eq!(value["hooks"]["UserPromptSubmit"], json!([other]));
}

#[test]
fn claude_plugin_installation_preserves_owned_versions_and_revokes_old_helpers() {
    let (_temp, layout, mut spec) = fixture(Host::ClaudeCode);
    enable_claude(&mut spec);
    let id = spec.claude_wake.as_ref().unwrap().id.clone();
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    assert_eq!(
        claude_wake(&spec.home, &layout.directory, &id).unwrap().id,
        id
    );
    let record = get(&layout.record());
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    assert_eq!(get(&layout.record()), record);
    let module = layout.directory.join("skills/gent-wake/hooks/register.ts");
    assert!(get(&module).contains("--config-dir"));
    // A generated old version is checked against its recorded bytes when the
    // template changes. It is never overwritten without checking ownership.
    let previous = get(&module);
    let mut next = spec.clone();
    let wake = next.claude_wake.as_mut().unwrap();
    wake.id = uuid::Uuid::new_v4().to_string();
    wake.module.push_str("\n// fixture upgraded module\n");
    mutate(&layout, &spec.home, Some(next.clone())).unwrap();
    assert_ne!(get(&module), previous);
    assert!(claude_wake(&spec.home, &layout.directory, &id).is_err());
    let id = &next.claude_wake.as_ref().unwrap().id;
    assert!(claude_wake(&spec.home, &layout.directory, id).is_ok());
    let keep = module.with_file_name("user-notes.txt");
    put(&keep, "user content");
    next.claude_wake = None;
    mutate(&layout, &spec.home, Some(next)).unwrap();
    assert!(claude_wake(&spec.home, &layout.directory, &spec.claude_wake.unwrap().id).is_err());
    assert!(!module.exists());
    assert_eq!(get(&keep), "user content");
    assert!(get(&layout.server).contains("gent"));
}

#[test]
fn claude_wake_recovers_every_install_upgrade_and_removal_boundary() {
    for operation in 0..3 {
        for completed in 0..=5 {
            let (_temp, layout, mut spec) = fixture(Host::ClaudeCode);
            enable_claude(&mut spec);
            if operation > 0 {
                mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
            }
            let mut desired = spec.clone();
            desired.binary = desired.binary.with_file_name("updated-gent");
            let desired = (operation != 2).then_some(desired);
            let (snapshot, mut state) = layout.read().unwrap();
            let edits = layout
                .edits(state.installed.as_ref(), desired.as_ref(), false, true)
                .unwrap();
            assert_eq!(edits.len(), 5);
            state.pending = Some(Transition {
                after: desired.clone(),
            });
            save(&snapshot, &state).unwrap();
            for edit in edits.into_iter().take(completed) {
                edit.apply().unwrap();
            }
            assert!(
                claude_wake(
                    &spec.home,
                    &layout.directory,
                    &spec.claude_wake.as_ref().unwrap().id
                )
                .is_err()
            );
            mutate(&layout, &spec.home, desired.clone()).unwrap();
            assert_eq!(layout.read().unwrap().1.installed, desired);
            assert_eq!(
                inspect(&layout, &spec.home).unwrap()["state"],
                if operation == 2 {
                    "absent"
                } else {
                    "configured"
                }
            );
        }
    }
}

#[test]
fn claude_wake_preserves_modified_plugin_files_and_refuses_disabled_identity_hook() {
    let (_temp, layout, mut spec) = fixture(Host::ClaudeCode);
    enable_claude(&mut spec);
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let record = get(&layout.record());
    let module = layout.directory.join("skills/gent-wake/hooks/register.ts");
    let original = get(&module);
    put(&module, "user edited module");
    assert!(mutate(&layout, &spec.home, None).is_err());
    assert_eq!(get(&module), "user edited module");
    assert_eq!(get(&layout.record()), record);
    let id = &spec.claude_wake.as_ref().unwrap().id;
    assert!(claude_wake(&spec.home, &layout.directory, id).is_err());
    put(&module, &original);
    let settings = layout.settings.as_ref().unwrap();
    let mut value: Value = serde_json::from_str(&get(settings)).unwrap();
    value["disableAllHooks"] = true.into();
    put(settings, &value.to_string());
    assert!(claude_wake(&spec.home, &layout.directory, id).is_err());
    // Uninstall still works when all hooks have been disabled.
    mutate(&layout, &spec.home, None).unwrap();
    assert!(!module.exists());
}

#[test]
fn claude_bridge_uses_recorded_default_layout_without_creating_another_config() {
    let (_temp, layout, mut spec) = fixture(Host::ClaudeCode);
    fs::set_permissions(
        layout.directory.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    enable_claude(&mut spec);
    let layout = Layout::at(
        Host::ClaudeCode,
        layout.directory.clone(),
        layout.directory.parent().unwrap().join(".claude.json"),
    )
    .unwrap();
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let id = &spec.claude_wake.as_ref().unwrap().id;
    assert!(claude_wake(&spec.home, &layout.directory, id).is_ok());
    assert!(!layout.directory.join(".claude.json").exists());
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

#[test]
fn recovery_pins_both_claude_layouts_and_rejects_redirected_records() {
    for custom in [false, true] {
        let (_temp, layout, mut spec) = fixture(Host::ClaudeCode);
        fs::set_permissions(
            layout.directory.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        enable_claude(&mut spec);
        let directory = layout.directory.parent().unwrap().join(".claude");
        let server = if custom {
            directory.join(".claude.json")
        } else {
            directory.parent().unwrap().join(".claude.json")
        };
        let layout = Layout::at(Host::ClaudeCode, directory, server).unwrap();
        mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
        let runtime = claude_runtime_pinned(&spec.home, &layout.directory).unwrap();
        runtime.require_wake().unwrap();
        assert_eq!(runtime.custom_directory, custom);
        assert_eq!(runtime.directory, layout.directory);
        assert_eq!(layout.directory.join(".claude.json").exists(), custom);
        let (snapshot, mut state) = layout.read().unwrap();
        state.server = layout.directory.join("foreign.json");
        save(&snapshot, &state).unwrap();
        assert!(claude_runtime_pinned(&spec.home, &layout.directory).is_err());
        assert!(!state.server.exists());
    }
}
