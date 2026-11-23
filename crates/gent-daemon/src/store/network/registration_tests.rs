use super::*;

#[tokio::test]
async fn conversation_activity_syncs_resolves_and_survives_polling_restart_and_restriction() {
    let mut pair = Pair::new().await;
    rename(&mut pair, 0, "rtao", 1).unwrap();
    rename(&mut pair, 1, "rtao", 1).unwrap();
    let now = now();
    for (index, age) in [(0, 200), (1, 100)] {
        let id = pair.agents[index].clone();
        owner(
            &mut pair,
            index,
            OwnerOp::ObserveActivity {
                agent_id: id,
                last_activity_at: now - age,
            },
        )
        .unwrap();
    }
    pair.pump();
    for store in &mut pair.stores {
        store.presence_tick().unwrap();
    }
    pair.pump();
    let resolve = || AgentOp::Resolve {
        name: "rtao".into(),
        node: None,
        provider: None,
    };
    let selected = pair.agent(0, resolve()).unwrap();
    assert_eq!(selected["selected"]["id"], pair.agents[1]);
    assert_eq!(selected["selected"]["last_activity_at"], now - 100);
    pair.agent(0, AgentOp::Identity).unwrap();
    pair.agent(0, AgentOp::Inbox).unwrap();
    pair.reopen(0);
    assert_eq!(
        pair.agent(0, resolve()).unwrap()["selected"]["id"],
        pair.agents[1]
    );
    let remote = pair.agents[1].clone();
    assert!(
        owner(
            &mut pair,
            0,
            OwnerOp::ObserveActivity {
                agent_id: remote.clone(),
                last_activity_at: now
            }
        )
        .is_err()
    );
    owner(
        &mut pair,
        1,
        OwnerOp::ObserveActivity {
            agent_id: remote.clone(),
            last_activity_at: now - 300,
        },
    )
    .unwrap();
    pair.pump();
    assert_eq!(
        pair.agent(0, resolve()).unwrap()["selected"]["last_activity_at"],
        now - 100
    );
    let mut policy = pair.stores[0].config.policy.clone();
    policy.rules.push(Rule {
        actor: Selector::All,
        peer: Selector::Agent(remote.clone()),
        permission: Permission::Enumerate,
        effect: Effect::Deny,
    });
    owner(&mut pair, 0, OwnerOp::SetPolicy { policy }).unwrap();
    let restricted = pair.agent(0, resolve()).unwrap();
    assert!(!restricted.to_string().contains(&remote));
}

#[tokio::test]
async fn clearing_retired_directory_keeps_node_labels_history_and_revocation() {
    let mut pair = Pair::new().await;
    let sent = pair.send(vec![]).unwrap();
    pair.pump();
    let node = pair.stores[1].identity.node.id().to_owned();
    let name = pair.stores[0]
        .identity
        .state(&pair.stores[0].db)
        .unwrap()
        .state()
        .nodes[&node]
        .name
        .clone();
    owner(&mut pair, 0, OwnerOp::RemoveNode { node_id: node }).unwrap();
    let directory = owner(&mut pair, 0, OwnerOp::Agents).unwrap();
    let retired = directory
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == pair.agents[1])
        .unwrap();
    assert_eq!(retired["node_name"], name);
    assert_eq!(retired["retired"], true);
    assert_eq!(
        owner(&mut pair, 0, OwnerOp::ClearRetiredAgents { dry_run: true }).unwrap()["eligible"],
        1
    );
    assert_eq!(
        owner(&mut pair, 0, OwnerOp::Agents)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        owner(&mut pair, 0, OwnerOp::ClearRetiredAgents { dry_run: false }).unwrap()["cleared"],
        1
    );
    pair.reopen(0);
    assert_eq!(
        owner(&mut pair, 0, OwnerOp::ClearRetiredAgents { dry_run: false }).unwrap()["cleared"],
        0
    );
    assert_eq!(
        owner(&mut pair, 0, OwnerOp::Agents)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(details(&mut pair, 0, 1)["revoked"], true);
    assert!(
        pair.agent(
            0,
            AgentOp::MessageStatus {
                message_id: sent["message_id"].as_str().unwrap().into()
            }
        )
        .is_ok()
    );
}

#[tokio::test]
async fn discovery_keeps_duplicate_names_distinct_and_labels_only_visible_nodes() {
    let mut pair = Pair::new().await;
    let mut discovery_policy = Policy::default();
    discovery_policy.rules.push(Rule {
        actor: Selector::All,
        peer: Selector::All,
        permission: Permission::Enumerate,
        effect: Effect::Allow,
    });
    owner(
        &mut pair,
        0,
        OwnerOp::SetPolicy {
            policy: discovery_policy,
        },
    )
    .unwrap();
    rename(&mut pair, 0, "cit", 1).unwrap();
    rename(&mut pair, 1, "cit", 1).unwrap();
    let local_duplicate = pair.stores[0]
        .execute(Request::Agent {
            credential: config::secret(),
            action: AgentOp::Register {
                name: "cit".into(),
                provider: "another-host".into(),
            },
        })
        .unwrap()["agent"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    pair.pump();
    let found = pair.agent(0, AgentOp::Agents).unwrap();
    let entries = found.as_array().unwrap();
    assert_eq!(entries.len(), 3);
    let state = pair.stores[0].identity.state(&pair.stores[0].db).unwrap();
    for row in entries {
        assert_eq!(row["name"], "cit");
        assert_eq!(
            row["node_name"],
            state.state().nodes[row["node_id"].as_str().unwrap()].name
        );
    }
    assert_eq!(
        entries
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    assert!(entries.iter().any(|r| r["id"] == local_duplicate));
    let mut policy = pair.stores[0].config.policy.clone();
    policy.rules.push(gent_protocol::Rule {
        actor: gent_protocol::Selector::Agent(pair.agents[0].clone()),
        peer: gent_protocol::Selector::Agent(pair.agents[1].clone()),
        permission: gent_protocol::Permission::Enumerate,
        effect: gent_protocol::Effect::Deny,
    });
    owner(&mut pair, 0, OwnerOp::SetPolicy { policy }).unwrap();
    let restricted = pair.agent(0, AgentOp::Agents).unwrap();
    assert!(!restricted.to_string().contains(&pair.agents[1]));
    assert!(!restricted.to_string().contains("joined"));
}

fn owner(pair: &mut Pair, index: usize, action: OwnerOp) -> Result<Value> {
    let credential = config::read_private(&pair.homes[index].path().join("owner.key"))?;
    pair.stores[index].execute(Request::Owner { credential, action })
}

fn details(pair: &mut Pair, index: usize, target: usize) -> Value {
    owner(
        pair,
        index,
        OwnerOp::Agent {
            agent_id: pair.agents[target].clone(),
        },
    )
    .unwrap()
}

fn rename(pair: &mut Pair, index: usize, name: &str, expected_generation: u64) -> Result<Value> {
    pair.agent(
        index,
        AgentOp::Rename {
            name: name.into(),
            expected_generation,
        },
    )
}

fn registration(pair: &Pair, index: usize) -> Registration {
    let store = &pair.stores[index];
    store
        .network_session(&store.db, store.identity.state(&store.db).unwrap())
        .registration(&pair.agents[index])
        .unwrap()
}

fn import(pair: &Pair, registration: &Registration) -> Result<()> {
    let store = &pair.stores[1];
    let tx = store.db.unchecked_transaction()?;
    store
        .network_session(&tx, store.identity.state(&tx)?)
        .import_registration(pair.stores[0].identity.node.id(), registration)?;
    tx.commit()?;
    Ok(())
}

#[tokio::test]
async fn renaming_survives_restarts_without_changing_bindings_permissions_or_pending_messages() {
    let mut pair = Pair::new().await;
    let policy = pair.stores[0].identity.state(&pair.stores[0].db).unwrap();
    let original = [details(&mut pair, 0, 0), details(&mut pair, 1, 1)];
    let sent = pair.send(vec![]).unwrap();
    pair.pump();
    rename(&mut pair, 0, "Builder 🐈", 1).unwrap();
    let reviewer = pair.agents[1].clone();
    owner(
        &mut pair,
        1,
        OwnerOp::RenameAgent {
            agent_id: reviewer,
            name: "Reviewer".into(),
            expected_generation: 1,
        },
    )
    .unwrap();
    pair.reopen(0);
    pair.reopen(1);
    pair.pump();
    for (index, old) in original.iter().enumerate() {
        let observed = details(&mut pair, index, index);
        for key in ["id", "node_id", "provider", "revoked"] {
            assert_eq!(observed[key], old[key], "{key}");
        }
        assert_eq!(observed["registration_generation"], 2);
        assert_eq!(
            details(&mut pair, 1 - index, index)["name"],
            observed["name"]
        );
        let resumed = pair
            .agent(
                index,
                AgentOp::Register {
                    name: "old resume name".into(),
                    provider: "other label".into(),
                },
            )
            .unwrap();
        assert_eq!(resumed["agent"]["id"], old["id"]);
        assert_eq!(resumed["agent"]["name"], observed["name"]);
        assert_eq!(resumed["agent"]["provider"], old["provider"]);
        assert_eq!(resumed["registration_generation"], 2);
    }
    assert_eq!(
        pair.stores[0]
            .identity
            .state(&pair.stores[0].db)
            .unwrap()
            .checkpoint(),
        policy.checkpoint()
    );
    let inbox = pair.agent(1, AgentOp::Inbox).unwrap();
    assert_eq!(inbox[0]["id"], sent["message_id"]);
    let replied = pair
        .agent(
            1,
            AgentOp::Reply {
                message_id: sent["message_id"].as_str().unwrap().into(),
                request_id: Uuid::now_v7().to_string(),
                text: "same exchange after renaming".into(),
                files: vec![],
                file_ids: vec![],
            },
        )
        .unwrap();
    pair.pump();
    assert_eq!(
        pair.agent(0, AgentOp::Inbox).unwrap()[0]["id"],
        replied["message_id"]
    );
}

#[tokio::test]
async fn exact_retries_and_noops_cannot_overwrite_intervening_renames() {
    let mut pair = Pair::new().await;
    rename(&mut pair, 0, "first", 1).unwrap();
    let queued: i64 = pair.stores[0]
        .db
        .query_row("SELECT COUNT(*) FROM network_events", [], |r| r.get(0))
        .unwrap();
    for expected in [1, 2] {
        assert_eq!(
            rename(&mut pair, 0, "first", expected).unwrap()["registration_generation"],
            2
        );
        assert_eq!(
            pair.stores[0]
                .db
                .query_row("SELECT COUNT(*) FROM network_events", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            queued
        );
    }
    let agent_id = pair.agents[0].clone();
    assert!(
        owner(
            &mut pair,
            0,
            OwnerOp::RenameAgent {
                agent_id,
                name: "racing owner".into(),
                expected_generation: 1
            }
        )
        .is_err()
    );
    rename(&mut pair, 0, "second", 2).unwrap();
    rename(&mut pair, 0, "first", 3).unwrap();
    assert!(rename(&mut pair, 0, "first", 1).is_err());
    assert!(rename(&mut pair, 0, "second", 2).is_err());
    assert_eq!(details(&mut pair, 0, 0)["registration_generation"], 4);
}

#[tokio::test]
async fn rename_is_scoped_to_the_local_active_registration_and_current_authority() {
    let mut pair = Pair::new().await;
    for label in ["", "  ", "line\nbreak", &"é".repeat(65)] {
        assert!(rename(&mut pair, 0, label, 1).is_err());
    }
    for expected in [0, gent_protocol::MAX_REGISTRATION_GENERATION, u64::MAX] {
        assert!(rename(&mut pair, 0, "changed", expected).is_err());
    }
    // A model cannot choose another identity or change host metadata with this tool.
    for key in ["agent_id", "provider", "node_id"] {
        let mut arguments = json!({"op":"rename","name":"changed","expected_generation":1});
        arguments[key] = json!(pair.agents[1]);
        assert!(serde_json::from_value::<AgentOp>(arguments).is_err());
    }
    let remote = pair.agents[1].clone();
    assert!(
        owner(
            &mut pair,
            0,
            OwnerOp::RenameAgent {
                agent_id: remote,
                name: "changed".into(),
                expected_generation: 1
            }
        )
        .is_err()
    );
    assert_eq!(details(&mut pair, 0, 0)["registration_generation"], 1);
    pair.stores[0]
        .db
        .execute("UPDATE request_clock SET floor=floor+86400", [])
        .unwrap();
    let local = pair.agents[0].clone();
    assert!(
        owner(
            &mut pair,
            0,
            OwnerOp::RenameAgent {
                agent_id: local.clone(),
                name: "changed".into(),
                expected_generation: 1
            }
        )
        .is_err()
    );
    assert!(rename(&mut pair, 0, "changed", 1).is_err());
    owner(&mut pair, 0, OwnerOp::Renew).unwrap();
    owner(
        &mut pair,
        0,
        OwnerOp::Revoke {
            agent_id: local.clone(),
        },
    )
    .unwrap();
    assert!(rename(&mut pair, 0, "changed", 1).is_err());
    assert!(
        owner(
            &mut pair,
            0,
            OwnerOp::RenameAgent {
                agent_id: local,
                name: "changed".into(),
                expected_generation: 2
            }
        )
        .is_err()
    );
}

#[tokio::test]
async fn failed_name_generation_or_publication_writes_roll_back_together() {
    let mut pair = Pair::new().await;
    for statement in [
        "CREATE TRIGGER fail_rename BEFORE UPDATE OF name ON agents BEGIN SELECT RAISE(ABORT,'name failure'); END;",
        "CREATE TRIGGER fail_rename BEFORE UPDATE ON network_origins BEGIN SELECT RAISE(ABORT,'generation failure'); END;",
        "CREATE TRIGGER fail_rename BEFORE INSERT ON network_events BEGIN SELECT RAISE(ABORT,'publication failure'); END;",
    ] {
        let before = details(&mut pair, 0, 0);
        pair.stores[0].db.execute_batch(statement).unwrap();
        assert!(rename(&mut pair, 0, "changed", 1).is_err());
        assert_eq!(details(&mut pair, 0, 0), before);
        pair.stores[0]
            .db
            .execute_batch("DROP TRIGGER fail_rename")
            .unwrap();
        pair.reopen(0);
    }
    rename(&mut pair, 0, "changed", 1).unwrap();
    pair.reopen(0);
    pair.pump();
    assert_eq!(details(&mut pair, 1, 0)["name"], "changed");
}

#[tokio::test]
async fn stale_embedded_registrations_cannot_restore_old_names_or_revoked_agents() {
    let mut pair = Pair::new().await;
    let old = registration(&pair, 0);
    rename(&mut pair, 0, "new", 1).unwrap();
    pair.pump();
    import(&pair, &old).unwrap();
    assert_eq!(details(&mut pair, 1, 0)["name"], "new");
    let mut conflict = registration(&pair, 0);
    conflict.name = "conflicting same generation".into();
    assert!(import(&pair, &conflict).is_err());
    let current = registration(&pair, 0);
    let id = pair.agents[0].clone();
    owner(&mut pair, 0, OwnerOp::Revoke { agent_id: id }).unwrap();
    pair.pump();
    import(&pair, &current).unwrap();
    assert_eq!(details(&mut pair, 1, 0)["revoked"], true);
    let mut forged = current;
    forged.generation += 2;
    assert!(import(&pair, &forged).is_err());
}

#[tokio::test]
async fn generation_exhaustion_reserves_space_for_revocation() {
    let mut pair = Pair::new().await;
    let max = gent_protocol::MAX_REGISTRATION_GENERATION;
    pair.stores[0]
        .db
        .execute(
            "UPDATE network_origins SET generation=?1 WHERE agent=?2",
            params![max - 2, pair.agents[0]],
        )
        .unwrap();
    rename(&mut pair, 0, "last rename", max - 2).unwrap();
    assert!(rename(&mut pair, 0, "one too many", max - 1).is_err());
    rename(&mut pair, 0, "last rename", max - 2).unwrap();
    let id = pair.agents[0].clone();
    owner(&mut pair, 0, OwnerOp::Revoke { agent_id: id }).unwrap();
    pair.pump();
    assert_eq!(details(&mut pair, 1, 0)["registration_generation"], max);
    assert_eq!(details(&mut pair, 1, 0)["revoked"], true);
}

#[tokio::test]
async fn invalid_saved_legacy_provenance_cannot_publish_a_rename() {
    let mut pair = Pair::new().await;
    let store = &pair.stores[0];
    let state = store.identity.state(&store.db).unwrap();
    let mut certificate = store
        .identity
        .signing_owner(&store.db)
        .unwrap()
        .bind_legacy_agent(
            &state,
            &pair.agents[0],
            store.identity.node.id(),
            now() as u64,
        )
        .unwrap();
    certificate.signature[0] ^= 1;
    store
        .db
        .execute(
            "UPDATE network_origins SET nonce=NULL,legacy=?1 WHERE agent=?2",
            params![serde_json::to_vec(&certificate).unwrap(), pair.agents[0]],
        )
        .unwrap();
    let before = details(&mut pair, 0, 0);
    assert!(rename(&mut pair, 0, "invalid origin", 1).is_err());
    assert_eq!(details(&mut pair, 0, 0), before);
    assert_eq!(
        pair.stores[0]
            .db
            .query_row("SELECT COUNT(*) FROM network_events", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(details(&mut pair, 1, 0)["name"], before["name"]);
}

#[tokio::test]
async fn remote_unregistration_requires_admin_and_converges_after_restart() {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    let chat = pair.agents[0].clone();
    let caller = pair.stores[1].identity.node.id().to_owned();
    let action = OwnerOp::Revoke { agent_id: chat };
    for allow in [false, true] {
        pair.owner(
            0,
            OwnerOp::DelegateConfiguration {
                node_id: caller.clone(),
                allow,
            },
        )
        .unwrap();
        pair.pump();
        if !allow {
            assert!(pair.owner(1, action.clone()).is_err());
        }
    }
    assert_eq!(pair.owner(1, action.clone()).unwrap()["state"], "queued");
    pair.reopen(1);
    pair.pump();
    assert_eq!(details(&mut pair, 0, 0)["revoked"], true);
    let changed = details(&mut pair, 1, 0);
    assert_eq!(changed["revoked"], true);
    assert_eq!(pair.owner(1, action).unwrap()["revoked"], true);
    assert_eq!(details(&mut pair, 1, 0), changed);
}

#[tokio::test]
async fn remote_permission_edit_replaces_one_selector_rule_and_inherit_removes_it() {
    let mut pair = Pair::new().await;
    super::directory_push_tests::negotiate(&mut pair);
    let caller = pair.stores[1].identity.node.id().to_string();
    pair.owner(
        0,
        OwnerOp::DelegateConfiguration {
            node_id: caller,
            allow: true,
        },
    )
    .unwrap();
    pair.pump();
    let actor = Selector::Agent(pair.agents[0].clone());
    let peer = Selector::Agent(pair.agents[1].clone());
    let original = pair.owner(0, OwnerOp::PermissionRules).unwrap()["rules"].clone();
    let original: Vec<Rule> = serde_json::from_value(original).unwrap();
    let unrelated =
        |r: &Rule| r.actor != actor || r.peer != peer || r.permission != Permission::Send;
    for effect in [Some(Effect::Deny), Some(Effect::Allow), None] {
        let action = OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit: ConfigurationEdit::SetPermissionRule {
                actor: actor.clone(),
                peer: peer.clone(),
                permission: Permission::Send,
                effect,
            },
        };
        pair.owner(1, action.clone()).unwrap();
        pair.pump();
        assert_eq!(pair.owner(1, action).unwrap()["state"], "applied");
        let expected: Vec<_> = original
            .iter()
            .filter(|r| unrelated(r))
            .cloned()
            .chain(effect.map(|effect| Rule {
                actor: actor.clone(),
                peer: peer.clone(),
                permission: Permission::Send,
                effect,
            }))
            .collect();
        for node in [0, 1] {
            assert_eq!(
                pair.owner(node, OwnerOp::PermissionRules).unwrap()["rules"],
                json!(expected)
            );
        }
    }
}
