use super::*;
use gent_protocol::administration::*;

async fn setup() -> (Pair, String, Vec<GroupChange>) {
    let mut p = Pair::new().await;
    p.owner(
        0,
        OwnerOp::DelegateConfiguration {
            node_id: p.stores[1].identity.node.id().into(),
            allow: false,
        },
    )
    .unwrap();
    let mut policy = p.stores[0]
        .identity
        .state(&p.stores[0].db)
        .unwrap()
        .state()
        .policy
        .clone();
    policy
        .groups
        .insert("team".into(), vec![p.agents[0].clone()]);
    policy
        .groups
        .insert("scope".into(), vec![p.agents[0].clone()]);
    policy.rules.push(Rule {
        actor: Selector::Group("team".into()),
        peer: Selector::All,
        permission: Permission::Send,
        effect: Effect::Deny,
    });
    p.owner(0, OwnerOp::SetPolicy { policy }).unwrap();
    let grant = Uuid::new_v4().to_string();
    p.owner(
        0,
        OwnerOp::Configure {
            request_id: grant.clone(),
            edit: ConfigurationEdit::GrantGroupAdmin {
                grant_id: grant.clone(),
                administrator: p.agents[1].clone(),
                group: "team".into(),
                members: Selector::Group("scope".into()),
                actions: vec![GroupAction::Add, GroupAction::Remove],
                lifetime_seconds: 3600,
            },
        },
    )
    .unwrap();
    p.pump();
    let changes = vec![GroupChange {
        grant_id: grant.clone(),
        group: "team".into(),
        member: p.agents[0].clone(),
        action: GroupAction::Remove,
    }];
    (p, grant, changes)
}

#[tokio::test]
async fn group_changes_cross_nodes_without_node_admin_and_recheck_queued_authority() {
    for reason in ["revocation", "scope", "expiry"] {
        let (mut p, grant, changes) = setup().await;
        let id = Uuid::now_v7().to_string();
        let op = AgentOp::GroupApply {
            request_id: id.clone(),
            changes: changes.clone(),
        };
        assert_eq!(p.agent(1, op.clone()).unwrap()["state"], "queued");
        assert!(p.send(vec![]).is_err());
        p.stores[1] = Store::open(p.homes[1].path()).unwrap();
        p.pump();
        assert_eq!(p.agent(1, op).unwrap()["state"], "applied");
        p.send(vec![]).unwrap();
        let audit = p
            .owner(
                0,
                OwnerOp::GroupAdminHistory {
                    administrator: Some(p.agents[1].clone()),
                    before: None,
                },
            )
            .unwrap();
        assert_eq!(audit["entries"][0]["changes"], json!(changes));
        assert_eq!(audit["entries"][0]["group_membership"], true);
        let mut changes = changes;
        changes[0].action = GroupAction::Add;
        let id = Uuid::now_v7().to_string();
        let op = AgentOp::GroupApply {
            request_id: id.clone(),
            changes: changes.clone(),
        };
        assert_eq!(p.agent(1, op.clone()).unwrap()["state"], "queued");
        match reason {
            "revocation" => {
                p.owner(
                    0,
                    OwnerOp::Configure {
                        request_id: Uuid::new_v4().to_string(),
                        edit: ConfigurationEdit::RevokeGroupAdmin { grant_id: grant },
                    },
                )
                .unwrap();
            }
            "scope" => {
                p.owner(
                    0,
                    OwnerOp::Configure {
                        request_id: Uuid::new_v4().to_string(),
                        edit: ConfigurationEdit::GroupMembers {
                            group: "scope".into(),
                            members: vec![p.agents[0].clone()],
                            action: GroupAction::Remove,
                        },
                    },
                )
                .unwrap();
            }
            _ => {
                let store = &p.stores[0];
                let tx = store.db.unchecked_transaction().unwrap();
                let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
                session.timestamp += 3601;
                session
                    .accept_configuration(
                        p.stores[1].identity.node.id(),
                        crate::store::administration::request_id(&p.agents[1], &id).unwrap(),
                        ConfigurationEdit::AgentGroups {
                            administrator: p.agents[1].clone(),
                            request_id: id,
                            changes,
                        },
                    )
                    .unwrap();
                tx.commit().unwrap();
            }
        }
        p.stores[0] = Store::open(p.homes[0].path()).unwrap();
        p.stores[1] = Store::open(p.homes[1].path()).unwrap();
        p.pump();
        let result = p.agent(1, op.clone()).unwrap();
        assert_eq!(result["state"], "rejected", "{reason}: {result}");
        assert!(result.get("revision").is_none());
        assert_eq!(p.agent(1, op).unwrap(), result);
        p.send(vec![]).unwrap();
    }
}

#[tokio::test]
async fn group_owner_refuses_forged_origin_and_atomic_out_of_scope_batches() {
    let (p, _, changes) = setup().await;
    let store = &p.stores[0];
    let tx = store.db.unchecked_transaction().unwrap();
    let mut session = store.network_session(&tx, store.identity.state(&tx).unwrap());
    let before = session.state.checkpoint().clone();
    for wrong_origin in [true, false] {
        let request = Uuid::now_v7().to_string();
        let id = crate::store::administration::request_id(&p.agents[1], &request).unwrap();
        let mut changes = changes.clone();
        if !wrong_origin {
            changes.push(GroupChange {
                member: p.agents[1].clone(),
                ..changes[0].clone()
            });
        }
        let result = session.accept_configuration(
            p.stores[usize::from(!wrong_origin)].identity.node.id(),
            id,
            ConfigurationEdit::AgentGroups {
                administrator: p.agents[1].clone(),
                request_id: request,
                changes,
            },
        );
        if wrong_origin {
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
