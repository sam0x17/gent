use super::*;

#[test]
fn retirement_removes_only_the_nodes_managed_host_entries() {
    for host in [Host::Codex, Host::ClaudeCode] {
        let (_temp, layout, spec) = fixture(host);
        let original = if host == Host::Codex {
            "model = \"keep-me\"\n"
        } else {
            "{\"keep\":true}"
        };
        put(&layout.server, original);
        mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
        let installed = get(&layout.server);
        retire_layout(&layout, &[spec.home.with_file_name("other")]).unwrap();
        assert_eq!(get(&layout.server), installed);
        retire_layout(&layout, std::slice::from_ref(&spec.home)).unwrap();
        let doc = Document::parse(Some(&get(&layout.server)), host).unwrap();
        assert!(doc.server().unwrap().is_none());
        assert!(get(&layout.server).contains(if host == Host::Codex {
            "keep-me"
        } else {
            "keep"
        }));
        retire_layout(&layout, std::slice::from_ref(&spec.home)).unwrap();
    }
}

#[test]
fn edited_entries_stop_retirement_without_erasing_user_changes() {
    let (_temp, layout, spec) = fixture(Host::Codex);
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let edited = get(&layout.server).replace("serve", "edited");
    put(&layout.server, &edited);
    assert!(retire_layout(&layout, std::slice::from_ref(&spec.home)).is_err());
    assert_eq!(get(&layout.server), edited);
    assert!(layout.read().unwrap().1.installed.is_some());
}

#[test]
fn reset_finishes_interrupted_legacy_move_before_removing_both_bindings() {
    let (_temp, layout, first) = fixture(Host::Codex);
    mutate(&layout, &first.home, Some(first.clone())).unwrap();
    let mut next = first.clone();
    next.home = first.home.join("clusters/legacy");
    let (snapshot, mut state) = layout.read().unwrap();
    state.pending = Some(Transition {
        after: Some(next.clone()),
    });
    save(&snapshot, &state).unwrap();
    // A move outside the retiring node requires separate resolution.
    assert!(retire_layout(&layout, std::slice::from_ref(&first.home)).is_err());
    retire_layout(&layout, &[first.home, next.home]).unwrap();
    assert!(layout.read().unwrap().1.installed.is_none());
    assert!(layout.read().unwrap().1.pending.is_none());
}
