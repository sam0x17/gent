use super::*;
use std::fs;

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    peer: PathBuf,
    root_id: String,
    peer_id: String,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = managed_file::normalize(&directory.path().join("root")).unwrap();
        let peer = managed_file::normalize(&directory.path().join("peer")).unwrap();
        let root_id = config::initialize(&root, "first").unwrap().cluster.id;
        let peer_id = config::initialize(&peer, "second").unwrap().cluster.id;
        Self {
            _directory: directory,
            root,
            peer,
            root_id,
            peer_id,
        }
    }
}

#[test]
fn missing_context_status_is_read_only_and_switch_never_initializes_state() {
    let folder = tempfile::tempdir().unwrap();
    let root = managed_file::normalize(&folder.path().join("missing")).unwrap();
    assert_eq!(list(&root).unwrap()["profiles"], json!([]));
    assert_eq!(resolve(&root, None).unwrap(), root);
    assert!(resolve(&root, Some("missing")).is_err());
    assert!(switch(&root, None, false).is_err());
    assert!(switch(&root, Some("missing".into()), false).is_err());
    assert!(!root.exists());
}

#[test]
fn profile_selection_preserves_identities_and_per_command_override_is_read_only() {
    let f = Fixture::new();
    let peer_config = fs::read(config::path(&f.peer)).unwrap();
    let credentials: Vec<_> = [&f.root, &f.peer]
        .iter()
        .map(|h| fs::read(h.join("owner.key")).unwrap())
        .collect();
    add(&f.root, &f.peer).unwrap();
    assert_eq!(config::load(&f.root).unwrap().version, 2);
    assert_eq!(resolve(&f.root, None).unwrap(), f.root);
    switch(&f.root, Some("second".into()), false).unwrap();
    assert_eq!(resolve(&f.root, None).unwrap(), f.peer);
    let selected = fs::read(config::path(&f.root)).unwrap();
    assert_eq!(resolve(&f.root, Some(&f.root_id)).unwrap(), f.root);
    assert_eq!(resolve(&f.root, Some("first")).unwrap(), f.root);
    assert_eq!(fs::read(config::path(&f.root)).unwrap(), selected);
    assert_eq!(fs::read(config::path(&f.peer)).unwrap(), peer_config);
    add(&f.root, &f.peer).unwrap();
    assert_eq!(
        list(&f.root).unwrap()["profiles"].as_array().unwrap().len(),
        2
    );
    for (i, h) in [&f.root, &f.peer].iter().enumerate() {
        assert_eq!(fs::read(h.join("owner.key")).unwrap(), credentials[i]);
    }
    assert!(
        !switch(&f.root, Some(f.peer_id.clone()), false).unwrap()["changed"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stale_projection_and_other_local_edits_cannot_undo_selection() {
    let f = Fixture::new();
    let mut stale = config::load(&f.root).unwrap();
    add(&f.root, &f.peer).unwrap();
    switch(&f.root, Some(f.peer_id.clone()), false).unwrap();
    stale.cluster.name = "renamed owner".into();
    config::save(&f.root, &stale).unwrap();
    assert_eq!(resolve(&f.root, None).unwrap(), f.peer);
    let current = config::load(&f.root).unwrap();
    assert_eq!(current.cluster.name, "renamed owner");
    assert_eq!(current.version, 2);
    let lock = config::state_lock(&f.root, "config.lock").unwrap();
    let before = fs::read(config::path(&f.root)).unwrap();
    assert!(switch(&f.root, Some(f.root_id.clone()), false).is_err());
    assert!(config::save(&f.root, &stale).is_err());
    assert_eq!(fs::read(config::path(&f.root)).unwrap(), before);
    drop(lock);
    assert_eq!(resolve(&f.root, None).unwrap(), f.peer);
    stale.node.id = uuid::Uuid::new_v4().to_string();
    assert!(config::save(&f.root, &stale).is_err());
}

#[test]
fn renamed_ambiguous_missing_and_replaced_profiles_never_fall_back() {
    let f = Fixture::new();
    add(&f.root, &f.peer).unwrap();
    let mut peer = config::load(&f.peer).unwrap();
    peer.cluster.name = "first".into();
    config::save(&f.peer, &peer).unwrap();
    assert!(switch(&f.root, Some("first".into()), false).is_err());
    switch(&f.root, Some(f.peer_id.clone()), false).unwrap();
    peer.cluster.name = "renamed".into();
    config::save(&f.peer, &peer).unwrap();
    assert_eq!(resolve(&f.root, Some("renamed")).unwrap(), f.peer);
    peer.node.id = uuid::Uuid::new_v4().to_string();
    config::save(&f.peer, &peer).unwrap();
    assert!(resolve(&f.root, None).is_err());
    assert!(switch(&f.root, Some(f.peer_id.clone()), false).is_err());
    let listing = list(&f.root).unwrap();
    assert_eq!(listing["active_cluster"], f.peer_id);
    assert_eq!(
        listing["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["cluster_id"] == f.peer_id)
            .unwrap()["available"],
        false
    );
    fs::remove_file(config::path(&f.peer)).unwrap();
    assert!(resolve(&f.root, None).is_err());
    switch(&f.root, Some(f.root_id), false).unwrap();
    assert_eq!(resolve(&f.root, None).unwrap(), f.root);
}

#[test]
fn profiles_reject_symlinks_aliases_duplicate_cluster_nodes_and_invalid_registry() {
    let f = Fixture::new();
    add(&f.root, &f.peer).unwrap();
    let renamed = f.peer.with_extension("original");
    fs::rename(&f.peer, &renamed).unwrap();
    std::os::unix::fs::symlink(&renamed, &f.peer).unwrap();
    assert!(add(&f.root, &f.peer).is_err());
    assert!(resolve(&f.root, Some(&f.peer_id)).is_err());
    fs::remove_file(&f.peer).unwrap();
    fs::rename(renamed, &f.peer).unwrap();
    let duplicate = f.peer.with_extension("duplicate");
    config::private_dir(&duplicate).unwrap();
    config::save(&duplicate, &config::load(&f.peer).unwrap()).unwrap();
    assert!(add(&f.root, &duplicate).is_err());
    let good = fs::read(config::path(&f.root)).unwrap();
    let mut cfg = config::load(&f.root).unwrap();
    let mut registry = cfg.contexts().unwrap().unwrap();
    registry.active_cluster = uuid::Uuid::new_v4().to_string();
    cfg.extra
        .insert("contexts".into(), toml::Value::try_from(registry).unwrap());
    config::write_private(
        &config::path(&f.root),
        toml::to_string(&cfg).unwrap().as_bytes(),
    )
    .unwrap();
    assert!(config::load(&f.root).is_err());
    assert!(resolve(&f.root, None).is_err());
    config::write_private(&config::path(&f.root), &good).unwrap();
    assert_eq!(resolve(&f.root, None).unwrap(), f.root);
}

#[test]
fn profile_capacity_preserves_existing_registration_and_rejects_new_entry() {
    let f = Fixture::new();
    add(&f.root, &f.peer).unwrap();
    config::edit_local(&f.root, |cfg| {
        let mut registry = cfg.contexts()?.unwrap();
        for _ in registry.profiles.len()..Contexts::LIMIT {
            let id = uuid::Uuid::new_v4().to_string();
            registry.profiles.insert(
                id.clone(),
                ContextProfile {
                    home: f.root.join("missing").join(id),
                    node_id: uuid::Uuid::new_v4().to_string(),
                },
            );
        }
        cfg.set_contexts(registry)
    })
    .unwrap();
    add(&f.root, &f.peer).unwrap();
    let third = f.peer.with_extension("third");
    config::initialize(&third, "third").unwrap();
    let before = fs::read(config::path(&f.root)).unwrap();
    assert!(add(&f.root, &third).is_err());
    assert_eq!(fs::read(config::path(&f.root)).unwrap(), before);
    switch(&f.root, Some(f.peer_id), false).unwrap();
}

#[test]
fn terminal_selection_requires_bounded_complete_input_and_available_profiles() {
    let listing = json!({"profiles":[{"available":false,"cluster_id":"bad"},{"available":true,"cluster_id":"good","name":"selected"}]});
    let mut output = Vec::new();
    assert_eq!(
        choice(&mut &b"1\n"[..], &mut output, &listing).unwrap(),
        "good"
    );
    for input in ["", "0\n", "2\n", "1", "-1\n", "1\u{1b}\n"] {
        assert!(choice(&mut input.as_bytes(), &mut Vec::new(), &listing).is_err());
    }
    assert!(
        choice(
            &mut ("1".repeat(4097) + "\n").as_bytes(),
            &mut Vec::new(),
            &listing
        )
        .is_err()
    );
}

#[test]
fn unapplied_policy_validation_does_not_block_status_selection_or_config_path() {
    let f = Fixture::new();
    add(&f.root, &f.peer).unwrap();
    let mut cfg = config::load(&f.root).unwrap();
    cfg.policy.rules.push(gent_protocol::Rule {
        actor: gent_protocol::Selector::Agent("invalid-agent-id".into()),
        peer: gent_protocol::Selector::All,
        permission: gent_protocol::Permission::Send,
        effect: gent_protocol::Effect::Allow,
    });
    assert!(cfg.validate().is_err());
    config::write_private(
        &config::path(&f.root),
        toml::to_string(&cfg).unwrap().as_bytes(),
    )
    .unwrap();
    assert_eq!(resolve(&f.root, None).unwrap(), f.root);
    switch(&f.root, Some(f.peer_id.clone()), false).unwrap();
    assert_eq!(resolve(&f.root, None).unwrap(), f.peer);
    assert_eq!(
        serde_json::to_value(inspect(&f.root).unwrap().policy).unwrap(),
        serde_json::to_value(cfg.policy).unwrap()
    );
}
