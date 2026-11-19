use super::super::tests::{fixture, get, put};
use super::*;

fn old_claude() -> (tempfile::TempDir, Layout, Spec) {
    let (temp, layout, mut spec) = fixture(Host::ClaudeCode);
    let cfg = config::initialize(&spec.home, "refresh").unwrap();
    spec.claude_wake = Some(claude_wake::Installation::new(&cfg));
    spec.claude_wake.as_mut().unwrap().module = "export function register(on) {}\n".into();
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    (temp, layout, spec)
}

#[test]
fn refresh_updates_the_recorded_module_and_preserves_unrelated_settings_and_retry_identity() {
    let (_root, layout, spec) = old_claude();
    remember(&spec.home, &layout).unwrap();
    let settings = layout.settings.as_ref().unwrap();
    let mut doc: Value = serde_json::from_str(&get(settings)).unwrap();
    doc["theme"] = json!("unrelated-setting");
    put(settings, &serde_json::to_string(&doc).unwrap());
    let report = refresh_one(&spec.home, &layout, &spec.binary).unwrap();
    assert_eq!(report["state"], "refreshed");
    let new = layout.read().unwrap().1.installed.unwrap();
    let wake = new.claude_wake.unwrap();
    assert_ne!(wake.id, spec.claude_wake.as_ref().unwrap().id);
    assert_eq!(wake.module, claude_wake::MODULE);
    assert_eq!(
        serde_json::from_str::<Value>(&get(settings)).unwrap()["theme"],
        "unrelated-setting"
    );
    let record = get(&layout.record());
    assert_eq!(
        refresh_one(&spec.home, &layout, &spec.binary).unwrap()["state"],
        "current"
    );
    assert_eq!(record, get(&layout.record()));
    let targets = read(&spec.home).unwrap().1.targets;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].directory, layout.directory);
}

#[test]
fn refresh_upgrades_legacy_manual_delivery_without_reinstalling_removed_integrations() {
    for host in [Host::Codex, Host::ClaudeCode] {
        let (_root, layout, spec) = fixture(host);
        config::initialize(&spec.home, "refresh").unwrap();
        mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
        remember(&spec.home, &layout).unwrap();
        refresh_one(&spec.home, &layout, &spec.binary).unwrap();
        let upgraded = layout.read().unwrap().1.installed.unwrap();
        assert_eq!(upgraded.home, spec.home);
        assert_eq!(upgraded.binary, spec.binary);
        match host {
            Host::Codex => assert_eq!(upgraded.wake_socket, Some(layout.wake_socket().unwrap())),
            Host::ClaudeCode => assert!(upgraded.claude_wake.is_some()),
        }
        assert_eq!(
            refresh_one(&spec.home, &layout, &spec.binary).unwrap()["state"],
            "current"
        );
        mutate(&layout, &spec.home, None).unwrap();
        assert_eq!(
            refresh_one(&spec.home, &layout, &spec.binary).unwrap()["state"],
            "uninstalled"
        );
        assert!(layout.read().unwrap().1.installed.is_none());
        assert_eq!(read(&spec.home).unwrap().1.targets.len(), 1);
    }
}

#[test]
fn edited_module_blocks_only_that_target_and_foreign_installs_are_not_adopted() {
    let (_root, layout, spec) = old_claude();
    let module = layout.directory.join("skills/gent-wake/hooks/register.ts");
    put(&module, "user-edited-module");
    let record = get(&layout.record());
    let report = refresh_targets(&spec.home, &spec.binary, vec![Target::from_layout(&layout)]);
    assert_eq!(report["blocked"], 1);
    assert_eq!(get(&module), "user-edited-module");
    assert_eq!(get(&layout.record()), record);
    assert_eq!(
        refresh_one(&spec.home.join("foreign"), &layout, &spec.binary).unwrap()["state"],
        "other_node"
    );
    assert_eq!(
        refresh_one(
            &spec.home,
            &layout,
            &spec.binary.with_extension("different")
        )
        .unwrap()["state"],
        "different_binary"
    );
}

#[test]
fn refresh_recovers_interrupted_removal_and_keeps_custom_codex_routes() {
    let (_root, layout, mut spec) = fixture(Host::Codex);
    config::initialize(&spec.home, "refresh").unwrap();
    spec.wake_socket = Some(layout.directory.join("custom.sock"));
    spec.codex_ide =
        Some(vscode::Installation::select(layout.directory.join("vscode-settings.json")).unwrap());
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    refresh_one(&spec.home, &layout, &spec.binary).unwrap();
    assert_eq!(layout.read().unwrap().1.installed, Some(spec.clone()));
    let (snapshot, mut state) = layout.read().unwrap();
    state.pending = Some(Transition { after: None });
    save(&snapshot, &state).unwrap();
    assert_eq!(
        refresh_one(&spec.home, &layout, &spec.binary).unwrap()["state"],
        "uninstalled"
    );
    assert!(layout.read().unwrap().1.pending.is_none());
    assert!(!layout.ide_launcher().exists());
}

#[test]
fn explicit_installs_remember_custom_directories_and_refresh_absence_creates_nothing() {
    let (_root, layout, spec) = fixture(Host::Codex);
    config::initialize(&spec.home, "refresh").unwrap();
    assert_eq!(
        refresh_one(&spec.home, &layout, &spec.binary).unwrap()["state"],
        "absent"
    );
    assert!(!layout.record().exists());
    let args = Args {
        host: Host::Codex,
        config_dir: Some(layout.directory.clone()),
        wake: false,
        wake_socket: None,
        vscode: false,
        no_vscode: false,
        vscode_settings: None,
    };
    change(&spec.home, args, true).unwrap();
    assert_eq!(
        read(&spec.home).unwrap().1.targets[0].directory,
        layout.directory
    );
}

#[test]
fn codex_refresh_preserves_tool_approval_preferences_but_rejects_changed_commands() {
    let (_root, layout, spec) = fixture(Host::Codex);
    config::initialize(&spec.home, "refresh").unwrap();
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let preferences = "\n[mcp_servers.gent.tools.gent_register]\napproval_mode = \"approve\"\n";
    put(&layout.server, &(get(&layout.server) + preferences));
    let mut updated = spec.clone();
    updated.wake_socket = Some(layout.directory.join("native.sock"));
    mutate(&layout, &spec.home, Some(updated.clone())).unwrap();
    let text = get(&layout.server);
    let doc = Document::parse(Some(&text), Host::Codex).unwrap();
    assert_eq!(
        doc.server().unwrap().unwrap()["tools"]["gent_register"]["approval_mode"],
        "approve"
    );
    assert_eq!(
        refresh_one(&spec.home, &layout, &spec.binary).unwrap()["state"],
        "current"
    );
    let mut changed = doc.server().unwrap().unwrap().clone();
    changed["command"] = json!("/another/executable");
    put(&layout.server, &doc.set_server(Some(&changed)).unwrap());
    let before = get(&layout.server);
    assert!(mutate(&layout, &spec.home, Some(spec.clone())).is_err());
    assert_eq!(get(&layout.server), before);
}
