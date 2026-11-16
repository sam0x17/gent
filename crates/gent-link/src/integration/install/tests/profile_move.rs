use super::*;

#[test]
fn moving_is_explicit_and_preserves_profile_data_and_unrelated_settings() {
    for host in [Host::Codex, Host::ClaudeCode] {
        let (temp, layout, original) = fixture(host);
        config::initialize(&original.home, "original").unwrap();
        let target = Spec {
            home: temp.path().join("selected"),
            ..original.clone()
        };
        config::initialize(&target.home, "selected").unwrap();
        let keys = [&original, &target].map(|s| get(&s.home.join("owner.key")));
        put(
            &layout.server,
            if host == Host::Codex {
                "# keep my settings\nmodel = 'user-model'\n"
            } else {
                "{\"userSetting\":\"keep my settings\"}"
            },
        );
        mutate(&layout, &original.home, Some(original.clone()), false).unwrap();
        let before = get(&layout.server);
        assert!(mutate(&layout, &target.home, Some(target.clone()), false).is_err());
        assert_eq!(get(&layout.server), before);
        mutate(&layout, &target.home, Some(target.clone()), true).unwrap();
        assert_eq!(
            inspect(&layout, &target.home).unwrap()["current_home"],
            true
        );
        assert_eq!(
            inspect(&layout, &target.home).unwrap()["state"],
            "configured"
        );
        assert!(get(&layout.server).contains("keep my settings"));
        assert_eq!(
            keys,
            [&original, &target].map(|s| get(&s.home.join("owner.key")))
        );
        let after = get(&layout.server);
        mutate(&layout, &target.home, Some(target.clone()), true).unwrap();
        assert_eq!(get(&layout.server), after);
        assert!(mutate(&layout, &original.home, None, false).is_err());
        assert!(mutate(&layout, &target.home, None, true).is_err());

        // Explicit movement still refuses a manually changed managed entry.
        put(
            &layout.server,
            &after.replace(original.binary.to_str().unwrap(), "/unowned/gent"),
        );
        let edited = get(&layout.server);
        let record = get(&layout.record());
        assert!(mutate(&layout, &original.home, Some(original.clone()), true).is_err());
        assert_eq!(get(&layout.server), edited);
        assert_eq!(get(&layout.record()), record);
    }
}

#[test]
fn interrupted_moves_resume_only_their_target_and_preserve_host_edits() {
    for host in [Host::Codex, Host::ClaudeCode] {
        for completed in 0..=2 {
            let (temp, layout, original) = fixture(host);
            mutate(&layout, &original.home, Some(original.clone()), false).unwrap();
            let target = Spec {
                home: temp.path().join("selected"),
                ..original.clone()
            };
            let foreign = Spec {
                home: temp.path().join("unrelated"),
                ..original.clone()
            };
            let edits = layout
                .edits(Some(&original), Some(&target), false, true)
                .unwrap();
            let (snapshot, mut state) = layout.read().unwrap();
            state.pending = Some(Transition {
                after: Some(target.clone()),
            });
            save(&snapshot, &state).unwrap();
            for edit in edits.into_iter().take(completed) {
                edit.apply().unwrap();
            }
            let before = get(&layout.server);
            let record = get(&layout.record());
            assert!(mutate(&layout, &foreign.home, Some(foreign.clone()), true).is_err());
            assert_eq!(get(&layout.server), before);
            assert_eq!(get(&layout.record()), record);
            let changed = if host == Host::Codex {
                format!("# concurrent host edit\n{before}")
            } else {
                let mut doc: Value = serde_json::from_str(&before).unwrap();
                doc["userSetting"] = json!("concurrent host edit");
                doc.to_string()
            };
            put(&layout.server, &changed);
            assert!(mutate(&layout, &target.home, Some(target.clone()), false).is_err());
            mutate(&layout, &target.home, Some(target.clone()), true).unwrap();
            let state = layout.read().unwrap().1;
            assert!(state.pending.is_none());
            assert_eq!(state.installed, Some(target.clone()));
            assert!(get(&layout.server).contains("concurrent host edit"));
            assert_eq!(
                inspect(&layout, &target.home).unwrap()["state"],
                "configured"
            );
        }
    }
}
