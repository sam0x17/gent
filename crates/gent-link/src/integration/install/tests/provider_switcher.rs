use super::*;

fn provider_fixture() -> (tempfile::TempDir, Layout, Spec, PathBuf, PathBuf) {
    let (root, layout, mut spec) = fixture(Host::Codex);
    let settings = layout.directory.join("settings.json");
    let shim = layout
        .directory
        .join("globalStorage/durosoft.ai-provider-switcher/codex/codex-shim");
    files::directory(shim.parent().unwrap()).unwrap();
    put(&shim, "#!/bin/sh\nexit 0\n");
    put(
        &settings,
        &format!(
            "// retain provider settings\n{{\"chatgpt.cliExecutable\":{},\"provider.fixture.secret\":\"never-journal-this\",}}\n",
            json!(shim)
        ),
    );
    spec.wake_socket = Some(layout.wake_socket().unwrap());
    (root, layout, spec, settings, shim)
}

#[test]
fn provider_switcher_keeps_its_cli_and_uninstall_restores_only_gents_wrapper() {
    let (_root, layout, mut spec, settings, shim) = provider_fixture();
    let original = get(&settings);
    assert!(vscode::Installation::select(settings.clone()).is_err());
    assert_eq!(get(&settings), original);
    assert!(!layout.record().exists());
    put(
        &shim.with_file_name("app-server-wrapper-v1"),
        "ai-provider-switcher/app-server-wrapper/v1\n",
    );
    spec.codex_ide = Some(vscode::Installation::select(settings.clone()).unwrap());
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let doc = document::VscodeDocument::parse(Some(&get(&settings))).unwrap();
    assert_eq!(doc.entry, Some(json!(shim)));
    assert_eq!(doc.wrapper, Some(json!(layout.ide_launcher())));
    assert!(get(&layout.ide_launcher()).contains("codex-wrapper"));
    assert!(!get(&layout.record()).contains("never-journal-this"));
    assert_eq!(
        inspect(&layout, &spec.home).unwrap()["vscode"]["transport"],
        "provider_switcher"
    );
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    mutate(&layout, &spec.home, None).unwrap();
    let doc = document::VscodeDocument::parse(Some(&get(&settings))).unwrap();
    assert_eq!(doc.entry, Some(json!(shim)));
    assert!(doc.wrapper.is_none());
    assert!(
        get(&settings).contains("retain provider settings")
            && get(&settings).contains("never-journal-this")
    );
    assert!(!layout.ide_launcher().exists());
}

#[test]
fn provider_wrapper_recovery_preserves_settings_and_rejects_foreign_replacements() {
    for operation in 0..3 {
        for completed in 0..4 {
            let (_root, layout, mut spec, settings, shim) = provider_fixture();
            put(
                &shim.with_file_name("app-server-wrapper-v1"),
                "ai-provider-switcher/app-server-wrapper/v1\n",
            );
            spec.codex_ide = Some(vscode::Installation::select(settings.clone()).unwrap());
            if operation != 0 {
                mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
            }
            let desired = if operation == 2 {
                None
            } else {
                Some(Spec {
                    binary: spec.binary.with_file_name("new gent"),
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
            assert_eq!(
                document::VscodeDocument::parse(Some(&get(&settings)))
                    .unwrap()
                    .entry,
                Some(json!(shim))
            );
            if let Some(spec) = desired {
                let changed = get(&settings).replace(
                    &layout.ide_launcher().display().to_string(),
                    "/some/other/wrapper",
                );
                put(&settings, &changed);
                assert!(mutate(&layout, &spec.home, None).is_err());
                assert_eq!(get(&settings), changed);
            }
        }
    }
}
