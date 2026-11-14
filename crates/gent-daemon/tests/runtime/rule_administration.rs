use super::*;
use gent_protocol::administration::*;
fn call(f: &mut Fixture, i: usize, op: AgentOp) -> Response {
    agent(&mut f.store, &f.keys[i], op)
}
fn err(r: Response) -> String {
    match r {
        Response::Error(e) => e,
        Response::Ok(v) => panic!("unexpected success {v}"),
    }
}
fn grant(
    f: &mut Fixture,
    actor: Selector,
    peer: Selector,
    permissions: Vec<Permission>,
    selector_rules: bool,
) -> String {
    let id = Uuid::new_v4().to_string();
    let value = ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::Configure {
            request_id: id.clone(),
            edit: ConfigurationEdit::GrantPermissionAdmin {
                administrator: f.agents[0].clone(),
                grant_id: id.clone(),
                actor,
                peer,
                permissions,
                selector_rules,
                lifetime_seconds: 3600,
            },
        },
    ));
    assert_eq!(value["state"], "applied");
    id
}
fn apply(request: &str, changes: &[PermissionRuleChange]) -> AgentOp {
    AgentOp::PermissionRuleApply {
        request_id: request.into(),
        changes: changes.to_vec(),
    }
}
fn rules(grant: &str, peer: Selector) -> Vec<PermissionRuleChange> {
    [Permission::Enumerate, Permission::Send, Permission::Receive]
        .map(|permission| PermissionRuleChange {
            grant_id: grant.into(),
            actor: Selector::All,
            peer: peer.clone(),
            permission,
            decision: RuleDecision::Allow,
        })
        .into()
}

#[test]
fn selector_rules_are_opt_in_hide_members_and_cover_future_agents_after_restart() {
    let mut f = Fixture::new();
    let a = f.agents[0].clone();
    let hidden = f.agents[1].clone();
    let old = grant(
        &mut f,
        Selector::All,
        Selector::SameNode,
        vec![Permission::Enumerate, Permission::Send, Permission::Receive],
        false,
    );
    assert_eq!(
        ok(call(&mut f, 0, AgentOp::PermissionRuleScopes))["grants"],
        json!([])
    );
    assert_eq!(
        err(call(
            &mut f,
            0,
            apply(
                &Uuid::now_v7().to_string(),
                &rules(&old, Selector::SameNode)
            )
        )),
        "recipient or message unavailable"
    );
    let id = grant(
        &mut f,
        Selector::All,
        Selector::SameNode,
        vec![Permission::Enumerate, Permission::Send, Permission::Receive],
        true,
    );
    let changes = rules(&id, Selector::SameNode);
    let scope = ok(call(&mut f, 0, AgentOp::PermissionRuleScopes));
    assert_eq!(scope["grants"].as_array().unwrap().len(), 1);
    assert!(!scope.to_string().contains(&hidden));
    let preview = ok(call(
        &mut f,
        0,
        AgentOp::PermissionRulePreview {
            changes: changes.clone(),
        },
    ));
    assert!(!preview.to_string().contains(&hidden));
    assert_eq!(ok(call(&mut f, 0, AgentOp::Agents)), json!([]));
    let mut wide = changes.clone();
    wide[0].peer = Selector::All;
    assert_eq!(
        err(call(&mut f, 0, apply(&Uuid::now_v7().to_string(), &wide))),
        "recipient or message unavailable"
    );
    let request = Uuid::now_v7().to_string();
    let result = ok(call(&mut f, 0, apply(&request, &changes)));
    assert_eq!(result["state"], "applied");
    assert!(result.get("revision").is_none());
    f.send();
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(ok(call(&mut f, 0, apply(&request, &changes))), result);
    let key = config::secret();
    let newcomer = ok(agent(
        &mut f.store,
        &key,
        AgentOp::Register {
            name: "later".into(),
            provider: "unknown-host".into(),
        },
    ))["agent"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let visible = ok(agent(&mut f.store, &key, AgentOp::Agents));
    assert!(
        visible
            .as_array()
            .unwrap()
            .iter()
            .any(|peer| peer["id"] == a)
    );
    ok(call(
        &mut f,
        0,
        AgentOp::Send {
            recipient: newcomer,
            request_id: Uuid::now_v7().to_string(),
            text: "future matches".into(),
            files: vec![],
            file_ids: vec![],
        },
    ));
    let audit = ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::PermissionAdminHistory {
            administrator: Some(a),
            before: None,
        },
    ));
    assert_eq!(audit["entries"][0]["selector_rules"], true);
    assert_eq!(audit["entries"][0]["changes"], json!(changes));
    ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit: ConfigurationEdit::RevokePermissionAdmin { grant_id: id },
        },
    ));
    assert_eq!(ok(call(&mut f, 0, apply(&request, &changes))), result);
    assert_eq!(
        err(call(
            &mut f,
            0,
            apply(&Uuid::now_v7().to_string(), &changes)
        )),
        "recipient or message unavailable"
    );
}

#[test]
fn rule_scopes_do_not_disclose_hidden_agent_grants_or_unselected_group_names() {
    let mut f = Fixture::new();
    let hidden = f.agents[1].clone();
    let mut policy = Policy::default();
    policy
        .groups
        .insert("private-group".into(), vec![hidden.clone()]);
    f.set(policy);
    grant(
        &mut f,
        Selector::Agent(hidden.clone()),
        Selector::All,
        vec![Permission::Send],
        true,
    );
    let id = grant(
        &mut f,
        Selector::All,
        Selector::All,
        vec![Permission::Send],
        true,
    );
    let scope = ok(call(&mut f, 0, AgentOp::PermissionRuleScopes));
    assert_eq!(scope["grants"].as_array().unwrap().len(), 1);
    assert!(!scope.to_string().contains(&hidden));
    assert!(!scope.to_string().contains("private-group"));
    for selector in [
        Selector::Agent(hidden.clone()),
        Selector::Agent(Uuid::new_v4().to_string()),
        Selector::Group("private-group".into()),
        Selector::Group("missing".into()),
        Selector::Node(Uuid::new_v4().to_string()),
    ] {
        let changes = vec![PermissionRuleChange {
            grant_id: id.clone(),
            actor: Selector::All,
            peer: selector,
            permission: Permission::Send,
            decision: RuleDecision::Allow,
        }];
        assert_eq!(
            err(call(&mut f, 0, AgentOp::PermissionRulePreview { changes })),
            "recipient or message unavailable"
        );
    }
    let group = grant(
        &mut f,
        Selector::Group("private-group".into()),
        Selector::All,
        vec![Permission::Send],
        true,
    );
    let preview = ok(call(
        &mut f,
        0,
        AgentOp::PermissionRulePreview {
            changes: vec![PermissionRuleChange {
                grant_id: group,
                actor: Selector::Group("private-group".into()),
                peer: Selector::All,
                permission: Permission::Send,
                decision: RuleDecision::Allow,
            }],
        },
    ));
    assert!(!preview.to_string().contains(&hidden));
    assert!(serde_json::from_value::<AgentOp>(json!({"op":"permission_rule_apply","request_id":Uuid::now_v7(),"changes":[],"administrator":hidden})).is_err());
}

#[test]
fn selector_batches_cannot_bootstrap_visibility_and_failed_audit_rolls_back_policy() {
    let mut f = Fixture::new();
    let id = grant(
        &mut f,
        Selector::All,
        Selector::All,
        vec![Permission::Enumerate, Permission::Send, Permission::Receive],
        true,
    );
    let changes = rules(&id, Selector::SameNode);
    let mut bootstrap = changes.clone();
    bootstrap.push(PermissionRuleChange {
        grant_id: id,
        actor: Selector::Agent(f.agents[0].clone()),
        peer: Selector::Agent(f.agents[1].clone()),
        permission: Permission::Send,
        decision: RuleDecision::Allow,
    });
    assert_eq!(
        err(call(
            &mut f,
            0,
            apply(&Uuid::now_v7().to_string(), &bootstrap)
        )),
        "recipient or message unavailable"
    );
    let before = ok(owner(&mut f.store, &f.owner_rpc, OwnerOp::Status))["authority"].clone();
    let request = Uuid::now_v7().to_string();
    f.db().execute_batch("CREATE TRIGGER fail_edit BEFORE INSERT ON configuration_edits BEGIN SELECT RAISE(ABORT,'test disk failure'); END;").unwrap();
    assert!(err(call(&mut f, 0, apply(&request, &changes))).contains("test disk failure"));
    assert_eq!(
        ok(owner(&mut f.store, &f.owner_rpc, OwnerOp::Status))["authority"],
        before
    );
    assert_eq!(ok(call(&mut f, 0, AgentOp::Agents)), json!([]));
    assert_eq!(
        err(call(
            &mut f,
            0,
            AgentOp::PermissionRequest {
                request_id: request.clone()
            }
        )),
        "recipient or message unavailable"
    );
    f.db().execute_batch("DROP TRIGGER fail_edit;").unwrap();
    assert_eq!(
        ok(call(&mut f, 0, apply(&request, &changes)))["state"],
        "applied"
    );
    f.send();
}
