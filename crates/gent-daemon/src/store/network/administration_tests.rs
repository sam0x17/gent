use super::*;
use crate::messages::EditResult;
use gent_protocol::administration::*;
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
