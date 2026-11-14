use super::*;

fn local(name: &str) -> Intent {
    Intent::New {
        name: name.into(),
        local: true,
    }
}
fn ticket(root: &Path, intent: Intent) -> Ticket {
    match prepare(root, root, intent).unwrap() {
        Selection::Managed(ticket) => ticket,
        _ => panic!("expected reserved child profile"),
    }
}
fn fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = managed_file::normalize(&directory.path().join("root")).unwrap();
    config::initialize(&root, "original").unwrap();
    (directory, root)
}

#[test]
fn local_reservation_survives_interrupted_key_config_and_registration_writes() {
    let (_directory, root) = fixture();
    let original = inspect(&root).unwrap();
    let first = ticket(&root, local("second"));
    let home = first.home.clone();
    let cluster = first.journal.jobs[0]
        .initial
        .as_ref()
        .unwrap()
        .cluster
        .id
        .clone();
    // Interruption after the owner credential is durable, before config.toml.
    let owner = config::binding(&home.join("owner.key")).unwrap();
    drop(first);
    let mut retry = ticket(&root, local("second"));
    assert_eq!(retry.home, home);
    retry.initialize_local().unwrap();
    assert_eq!(inspect(&home).unwrap().cluster.id, cluster);
    assert_eq!(
        config::read_private(&home.join("owner.key")).unwrap(),
        owner
    );
    assert_eq!(resolve(&root, None).unwrap(), root);
    assert_eq!(list(&root).unwrap()["pending"].as_array().unwrap().len(), 1);
    let journal = fs::read(root.join(JOURNAL)).unwrap();
    retry.finish(json!({})).unwrap();
    assert_eq!(resolve(&root, None).unwrap(), home);
    // Lose the completion write after registry selection has committed.
    config::write_private(&root.join(JOURNAL), &journal).unwrap();
    drop(retry);
    let mut retry = ticket(&root, local("second"));
    let daemon_lock = config::state_lock(&home, "daemon.lock").unwrap();
    retry.initialize_local().unwrap(); // Existing running service needs no reset.
    retry.finish(json!({})).unwrap();
    drop(retry);
    let mut retry = ticket(&root, local("second"));
    assert!(retry.ready());
    retry.initialize_local().unwrap();
    retry.finish(retry.existing_result().unwrap()).unwrap();
    assert_eq!(
        list(&root).unwrap()["profiles"].as_array().unwrap().len(),
        2
    );
    assert_eq!(list(&root).unwrap()["pending"], json!([]));
    assert_eq!(inspect(&root).unwrap().node.id, original.node.id);
    drop(daemon_lock);
}

#[test]
fn lost_journal_pin_or_profile_state_never_allocates_replacement_identity() {
    let (_directory, root) = fixture();
    let mut job = ticket(&root, local("second"));
    job.initialize_local().unwrap();
    job.finish(json!({})).unwrap();
    let home = job.home.clone();
    drop(job);
    let journal = fs::read(root.join(JOURNAL)).unwrap();
    fs::remove_file(root.join(JOURNAL)).unwrap();
    assert!(prepare(&root, &root, local("second")).is_err());
    assert!(prepare(&root, &root, local("third")).is_err());
    assert!(list(&root).is_err());
    config::write_private(&root.join(JOURNAL), &journal).unwrap();
    let original = fs::read(config::path(&root)).unwrap();
    let mut missing_registry = inspect(&root).unwrap();
    missing_registry.extra.remove("contexts");
    assert!(missing_registry.validate_local().is_err());
    let mut invalid_registry = inspect(&root).unwrap();
    invalid_registry
        .extra
        .insert("contexts".into(), toml::Value::String("invalid".into()));
    assert!(invalid_registry.validate_local().is_err());
    let mut cfg = inspect(&root).unwrap();
    cfg.extra.remove("profile_setup");
    assert!(cfg.validate_local().is_err());
    cfg.version = 2;
    cfg.extra.remove("local_features");
    config::write_private(
        &config::path(&root),
        toml::to_string(&cfg).unwrap().as_bytes(),
    )
    .unwrap();
    assert!(prepare(&root, &root, local("third")).is_err());
    config::write_private(&config::path(&root), &original).unwrap();
    fs::remove_file(config::path(&home)).unwrap();
    assert!(prepare(&root, &root, local("second")).is_err());
    assert!(!config::path(&home).exists());
    assert_eq!(fs::read(root.join(JOURNAL)).unwrap(), journal);
}

#[test]
fn empty_journal_initialization_recovers_and_stale_projection_preserves_pin() {
    let (_directory, root) = fixture();
    let stale = inspect(&root).unwrap();
    let journal = read(&root, &stale).unwrap();
    save(&root, &journal).unwrap();
    let first = ticket(&root, local("second"));
    assert_eq!(first.journal.id, journal.id);
    config::save(&root, &stale).unwrap();
    assert_eq!(
        inspect(&root).unwrap().profile_setup().unwrap(),
        Some(journal.id.clone())
    );
    drop(first);
    let mut corrupt: Value =
        serde_json::from_slice(&fs::read(root.join(JOURNAL)).unwrap()).unwrap();
    corrupt["id"] = json!(Uuid::new_v4().to_string());
    config::write_private(&root.join(JOURNAL), &serde_json::to_vec(&corrupt).unwrap()).unwrap();
    assert!(prepare(&root, &root, local("second")).is_err());
}

#[test]
fn changed_join_routing_and_wrong_published_cluster_are_rejected() {
    let (_directory, root) = fixture();
    let cluster = Uuid::new_v4().to_string();
    let intent = Intent::Join {
        cluster: cluster.clone(),
        name: "laptop".into(),
        route: json!({"kind":"ssh","via":"owner"}),
    };
    let job = ticket(&root, intent.clone());
    let home = job.home.clone();
    drop(job);
    let changed = Intent::Join {
        cluster,
        name: "different".into(),
        route: json!({"kind":"ssh","via":"owner"}),
    };
    assert!(prepare(&root, &root, changed).is_err());
    config::initialize(&home, "unrelated").unwrap();
    let mut job = ticket(&root, intent);
    assert!(job.finish(json!({})).is_err());
    assert_eq!(resolve(&root, None).unwrap(), root);
}

#[test]
fn profile_capacity_and_concurrent_setup_preserve_pending_reservations() {
    let (_directory, root) = fixture();
    let held = ticket(&root, local("second"));
    assert!(prepare(&root, &root, local("third")).is_err());
    let journal = fs::read(root.join(JOURNAL)).unwrap();
    drop(held);
    config::edit_local(&root, |cfg| {
        let mut registry = registry(&root, cfg)?;
        for _ in 1..Contexts::LIMIT - 1 {
            let id = Uuid::new_v4().to_string();
            registry.profiles.insert(
                id.clone(),
                ContextProfile {
                    home: root.join(id),
                    node_id: Uuid::new_v4().to_string(),
                },
            );
        }
        cfg.set_contexts(registry)
    })
    .unwrap();
    assert!(prepare(&root, &root, local("third")).is_err());
    assert_eq!(fs::read(root.join(JOURNAL)).unwrap(), journal);
    let mut resumed = ticket(&root, local("second"));
    resumed.initialize_local().unwrap();
    resumed.finish(json!({})).unwrap();
    assert_eq!(
        list(&root).unwrap()["profiles"].as_array().unwrap().len(),
        Contexts::LIMIT
    );
}

#[tokio::test]
async fn primary_creation_retry_selects_existing_profiles_after_rename() {
    let (_directory, root) = fixture();
    let result = create(&root, &root, "second".into(), true).await.unwrap();
    let home = PathBuf::from(result["profile"]["home"].as_str().unwrap());
    config::edit_local(&home, |cfg| {
        cfg.cluster.name = "renamed".into();
        Ok(())
    })
    .unwrap();
    super::super::switch(&root, Some("original".into()), false).unwrap();
    let retry = create(&root, &root, "second".into(), true).await.unwrap();
    assert_eq!(result["profile"], retry["profile"]);
    assert_eq!(resolve(&root, None).unwrap(), home);
}

#[tokio::test]
async fn completed_ssh_join_retry_uses_pinned_identity_after_node_rename() {
    use clap::Parser;
    let (_directory, root) = fixture();
    let cluster = Uuid::new_v4().to_string();
    let arguments = |name: &str| {
        let cli = crate::Cli::try_parse_from([
            "gent", "cluster", "join", &cluster, "--via", "owner", "--name", name,
        ])
        .unwrap();
        match cli.command.unwrap() {
            crate::Command::Cluster {
                command: Some(crate::ClusterCommand::Join(args)),
            } => args,
            _ => panic!("expected join arguments"),
        }
    };
    let mut job = ticket(&root, arguments("original-node").intent().unwrap());
    let home = job.home.clone();
    let mut cfg = config::initialize(&home, "fixture").unwrap();
    cfg.cluster.id = cluster.clone();
    cfg.node.name = "original-node".into();
    config::save(&home, &cfg).unwrap();
    job.finish(json!({})).unwrap();
    drop(job);
    config::edit_local(&home, |cfg| {
        cfg.node.name = "renamed-node".into();
        Ok(())
    })
    .unwrap();
    let daemon = config::state_lock(&home, "daemon.lock").unwrap();
    let result = join(&root, &root, arguments("original-node"))
        .await
        .unwrap();
    assert_eq!(result["node"]["id"], cfg.node.id);
    assert_eq!(result["node"]["name"], "renamed-node");
    assert_eq!(result["already_configured"], true);
    assert!(
        join(&root, &root, arguments("changed-request"))
            .await
            .is_err()
    );
    drop(daemon);
}
