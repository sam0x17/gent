use super::*;
use crate::messages::EditResult;
use gent_protocol::administration::*;

async fn rule_setup(group: bool) -> (Pair, String, Vec<PermissionRuleChange>) {
    let (mut p, _, _) = setup().await;
    let node = p.stores[0].identity.node.id().to_owned();
    let actor = if group {
        let mut policy = p.stores[0]
            .identity
            .state(&p.stores[0].db)
            .unwrap()
            .state()
            .policy
            .clone();
        policy
            .groups
            .insert("workers".into(), vec![p.agents[0].clone()]);
        p.owner(0, OwnerOp::SetPolicy { policy }).unwrap();
        Selector::Group("workers".into())
    } else {
        Selector::Node(node.clone())
    };
    let grant = Uuid::new_v4().to_string();
    p.owner(
        0,
        OwnerOp::Configure {
            request_id: grant.clone(),
            edit: ConfigurationEdit::GrantPermissionAdmin {
                selector_rules: true,
                grant_id: grant.clone(),
                administrator: p.agents[1].clone(),
                actor,
                peer: Selector::All,
                permissions: vec![Permission::Send],
                lifetime_seconds: 3600,
            },
        },
    )
    .unwrap();
    p.pump();
    let changes = vec![PermissionRuleChange {
        grant_id: grant.clone(),
        actor: if group {
            Selector::Agent(p.agents[0].clone())
        } else {
            Selector::Node(node)
        },
        peer: Selector::All,
        permission: Permission::Send,
        decision: RuleDecision::Deny,
    }];
    (p, grant, changes)
}

#[tokio::test]
async fn selector_rules_cross_nodes_without_node_admin_and_share_request_identity() {
    let (mut p, _, changes) = rule_setup(false).await;
    let id = Uuid::now_v7().to_string();
    let action = AgentOp::PermissionRuleApply {
        request_id: id.clone(),
        changes: changes.clone(),
    };
    assert_eq!(p.agent(1, action.clone()).unwrap()["state"], "queued");
    p.send(vec![]).unwrap();
    p.stores[1] = Store::open(p.homes[1].path()).unwrap();
    p.pump();
    let result = p.agent(1, action.clone()).unwrap();
    assert_eq!(result["state"], "applied");
    assert!(p.send(vec![]).is_err());
    let conflict = p
        .agent(
            1,
            AgentOp::PermissionApply {
                request_id: id.clone(),
                changes: vec![PermissionChange {
                    grant_id: changes[0].grant_id.clone(),
                    actor: p.agents[0].clone(),
                    peer: p.agents[1].clone(),
                    permission: Permission::Send,
                    decision: RuleDecision::Deny,
                }],
            },
        )
        .unwrap_err();
    assert!(conflict.to_string().contains("another edit"));
    assert_eq!(
        p.agent(1, AgentOp::PermissionRequest { request_id: id })
            .unwrap(),
        result
    );
    let audit = p
        .owner(
            0,
            OwnerOp::PermissionAdminHistory {
                administrator: Some(p.agents[1].clone()),
                before: None,
            },
        )
        .unwrap();
    assert_eq!(audit["entries"][0]["selector_rules"], true);
    assert_eq!(audit["entries"][0]["changes"], json!(changes));
    assert_eq!(
        audit["entries"][0]["origin"],
        p.stores[1].identity.node.id()
    );
}

#[tokio::test]
async fn queued_selector_edits_recheck_revocation_expiry_and_current_group_scope() {
    for reason in ["revocation", "expiry", "group"] {
        let (mut p, grant, changes) = rule_setup(true).await;
        let id = Uuid::now_v7().to_string();
        let action = AgentOp::PermissionRuleApply {
            request_id: id.clone(),
            changes: changes.clone(),
        };
        assert_eq!(p.agent(1, action.clone()).unwrap()["state"], "queued");
        match reason {
            "revocation" => {
                p.owner(
                    0,
                    OwnerOp::Configure {
                        request_id: Uuid::new_v4().to_string(),
                        edit: ConfigurationEdit::RevokePermissionAdmin { grant_id: grant },
                    },
                )
                .unwrap();
            }
            "expiry" => {
                // Advance only the accepting session, without sleeping or
                // changing signed grant bytes. Subsequent delivery is a retry.
                let store = &p.stores[0];
                let tx = store.db.unchecked_transaction().unwrap();
                let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
                session.timestamp += 3601;
                session
                    .accept_configuration(
                        p.stores[1].identity.node.id(),
                        crate::store::administration::request_id(&p.agents[1], &id).unwrap(),
                        ConfigurationEdit::AgentPermissionRules {
                            administrator: p.agents[1].clone(),
                            request_id: id.clone(),
                            changes,
                        },
                    )
                    .unwrap();
                tx.commit().unwrap();
            }
            _ => {
                let mut policy = p.stores[0]
                    .identity
                    .state(&p.stores[0].db)
                    .unwrap()
                    .state()
                    .policy
                    .clone();
                policy.groups.insert("workers".into(), vec![]);
                p.owner(0, OwnerOp::SetPolicy { policy }).unwrap();
            }
        }
        p.stores[0] = Store::open(p.homes[0].path()).unwrap();
        p.stores[1] = Store::open(p.homes[1].path()).unwrap();
        p.pump();
        let result = p.agent(1, action).unwrap();
        assert_eq!(result["state"], "rejected", "{reason}: {result}");
        assert_eq!(
            result["reason"],
            "permission change unavailable or no longer authorized"
        );
        assert!(result.get("revision").is_none());
        p.send(vec![]).unwrap();
    }
}

#[tokio::test]
async fn owner_refuses_forged_rule_origin_and_widened_selectors() {
    let (p, _, changes) = rule_setup(false).await;
    let store = &p.stores[0];
    let tx = store.db.unchecked_transaction().unwrap();
    let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
    let before = session.state.checkpoint().clone();
    for forged_origin in [true, false] {
        let user_id = Uuid::now_v7().to_string();
        let id = crate::store::administration::request_id(&p.agents[1], &user_id).unwrap();
        let mut changes = changes.clone();
        if !forged_origin {
            changes[0].actor = Selector::All;
        }
        let result = session.accept_configuration(
            p.stores[usize::from(!forged_origin)].identity.node.id(),
            id,
            ConfigurationEdit::AgentPermissionRules {
                administrator: p.agents[1].clone(),
                request_id: user_id,
                changes,
            },
        );
        if forged_origin {
            result.unwrap_err();
            assert!(session.configuration_status(&id.to_string()).is_err());
        } else {
            result.unwrap();
            assert_eq!(
                session
                    .configuration_status_for(p.stores[1].identity.node.id(), &id.to_string())
                    .unwrap()["state"],
                "rejected"
            );
        }
        assert_eq!(session.state.checkpoint(), &before);
    }
    tx.rollback().unwrap();
}
async fn setup() -> (Pair, String, Vec<PermissionChange>) {
    let mut p = Pair::new().await;
    let node = p.stores[1].identity.node.id().to_owned();
    p.owner(
        0,
        OwnerOp::DelegateConfiguration {
            node_id: node,
            allow: false,
        },
    )
    .unwrap();
    let grant = Uuid::new_v4().to_string();
    p.owner(
        0,
        OwnerOp::Configure {
            request_id: grant.clone(),
            edit: ConfigurationEdit::GrantPermissionAdmin {
                selector_rules: false,
                grant_id: grant.clone(),
                administrator: p.agents[1].clone(),
                actor: Selector::Agent(p.agents[0].clone()),
                peer: Selector::Agent(p.agents[1].clone()),
                permissions: vec![Permission::Send],
                lifetime_seconds: 3600,
            },
        },
    )
    .unwrap();
    p.pump();
    let changes = vec![PermissionChange {
        grant_id: grant.clone(),
        actor: p.agents[0].clone(),
        peer: p.agents[1].clone(),
        permission: Permission::Send,
        decision: RuleDecision::Deny,
    }];
    (p, grant, changes)
}

#[tokio::test]
async fn delegated_agent_edits_cross_encrypted_nodes_without_node_admin_and_recheck_revocation() {
    let (mut p, grant, changes) = setup().await;
    let id = Uuid::now_v7().to_string();
    let action = AgentOp::PermissionApply {
        request_id: id.clone(),
        changes: changes.clone(),
    };
    assert_eq!(p.agent(1, action.clone()).unwrap()["state"], "queued");
    p.send(vec![]).unwrap(); // A queued request has not changed the owner's policy.
    assert!(
        p.owner(
            1,
            OwnerOp::Configure {
                request_id: Uuid::new_v4().to_string(),
                edit: ConfigurationEdit::Renew
            }
        )
        .is_err()
    );
    p.stores[1] = Store::open(p.homes[1].path()).unwrap();
    assert_eq!(p.agent(1, action.clone()).unwrap()["state"], "queued");
    p.pump();
    assert_eq!(
        p.agent(
            1,
            AgentOp::PermissionRequest {
                request_id: id.clone()
            }
        )
        .unwrap()["state"],
        "applied"
    );
    assert_eq!(p.agent(1, action).unwrap()["state"], "applied");
    assert!(p.send(vec![]).is_err());
    for i in 0..2 {
        let explanation = p
            .owner(
                i,
                OwnerOp::PermissionExplain {
                    actor: p.agents[0].clone(),
                    peer: p.agents[1].clone(),
                },
            )
            .unwrap();
        assert_eq!(explanation["policy"]["send_unsolicited"]["allowed"], false);
    }
    let mut next = changes;
    next[0].decision = RuleDecision::Allow;
    let pending = Uuid::now_v7().to_string();
    let action = AgentOp::PermissionApply {
        request_id: pending.clone(),
        changes: next,
    };
    assert_eq!(p.agent(1, action.clone()).unwrap()["state"], "queued");
    p.owner(
        0,
        OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit: ConfigurationEdit::RevokePermissionAdmin { grant_id: grant },
        },
    )
    .unwrap();
    p.stores[0] = Store::open(p.homes[0].path()).unwrap();
    p.stores[1] = Store::open(p.homes[1].path()).unwrap();
    p.pump();
    let rejected = p
        .agent(
            1,
            AgentOp::PermissionRequest {
                request_id: pending,
            },
        )
        .unwrap();
    assert_eq!(rejected["state"], "rejected");
    assert_eq!(
        rejected["reason"],
        "permission change unavailable or no longer authorized"
    );
    assert!(rejected.get("revision").is_none());
    assert_eq!(p.agent(1, action).unwrap(), rejected);
    assert!(p.send(vec![]).is_err());
}

#[tokio::test]
async fn owner_checks_authenticated_origin_and_batch_scope_even_for_forged_node_proposals() {
    let (p, _, changes) = setup().await;
    let store = &p.stores[0];
    let tx = store.db.unchecked_transaction().unwrap();
    let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
    let old = session.state.checkpoint().clone();
    let user_id = Uuid::now_v7().to_string();
    let id = crate::store::administration::request_id(&p.agents[1], &user_id).unwrap();
    // A trusted node can only attribute scoped edits to agents bound to itself.
    session
        .accept_configuration(
            store.identity.node.id(),
            id,
            ConfigurationEdit::AgentPermissions {
                administrator: p.agents[1].clone(),
                request_id: user_id,
                changes: changes.clone(),
            },
        )
        .unwrap_err();
    assert_eq!(session.state.checkpoint(), &old);
    assert!(session.configuration_status(&id.to_string()).is_err());
    let mut bad = changes;
    bad[0].permission = Permission::Enumerate;
    let user_id = Uuid::now_v7().to_string();
    let id = crate::store::administration::request_id(&p.agents[1], &user_id).unwrap();
    session
        .accept_configuration(
            p.stores[1].identity.node.id(),
            id,
            ConfigurationEdit::AgentPermissions {
                administrator: p.agents[1].clone(),
                request_id: user_id,
                changes: bad,
            },
        )
        .unwrap();
    assert_eq!(session.state.checkpoint(), &old);
    let result: Vec<u8> = tx
        .query_row(
            "SELECT result FROM configuration_edits WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(matches!(
        serde_json::from_slice::<EditResult>(&result).unwrap(),
        EditResult::Rejected { .. }
    ));
    tx.rollback().unwrap();
}
