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
fn edit(f: &mut Fixture, edit: ConfigurationEdit) -> Value {
    ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit,
        },
    ))
}
fn grant(f: &mut Fixture, group: &str, members: Selector) -> String {
    let id = Uuid::new_v4().to_string();
    let admin = f.agents[0].clone();
    assert_eq!(
        edit(
            f,
            ConfigurationEdit::GrantGroupAdmin {
                grant_id: id.clone(),
                administrator: admin,
                group: group.into(),
                members,
                actions: vec![GroupAction::Add, GroupAction::Remove],
                lifetime_seconds: 3600
            }
        )["state"],
        "applied"
    );
    id
}
fn setup() -> (Fixture, String) {
    let mut f = Fixture::new();
    let mut p = Policy::default();
    p.groups.insert("team".into(), vec![f.agents[0].clone()]);
    for (a, b) in [(0, 1), (1, 0)] {
        p.rules.push(Rule {
            actor: Selector::Agent(f.agents[a].clone()),
            peer: Selector::Agent(f.agents[b].clone()),
            permission: Permission::Enumerate,
            effect: Effect::Allow,
        });
    }
    for permission in [Permission::Send, Permission::Receive] {
        p.rules.push(Rule {
            actor: Selector::Group("team".into()),
            peer: Selector::Group("team".into()),
            permission,
            effect: Effect::Allow,
        });
    }
    f.set(p);
    let id = grant(&mut f, "team", Selector::All);
    (f, id)
}
fn change(f: &Fixture, grant_id: &str, action: GroupAction) -> GroupChange {
    GroupChange {
        grant_id: grant_id.into(),
        group: "team".into(),
        member: f.agents[1].clone(),
        action,
    }
}
fn apply(id: &str, changes: &[GroupChange]) -> AgentOp {
    AgentOp::GroupApply {
        request_id: id.into(),
        changes: changes.to_vec(),
    }
}

#[test]
fn group_edits_change_delivery_preserve_private_retries_and_record_owner_audit() {
    let (mut f, grant) = setup();
    let peer = f.agents[1].clone();
    assert_eq!(
        ok(call(
            &mut f,
            0,
            AgentOp::PermissionCheck { peer: peer.clone() }
        ))["policy"]["send_unsolicited"]["allowed"],
        false
    );
    let changes = vec![change(&f, &grant, GroupAction::Add)];
    assert_eq!(
        ok(call(
            &mut f,
            0,
            AgentOp::GroupPreview {
                changes: changes.clone()
            }
        ))["changes"],
        json!(changes)
    );
    let request = Uuid::now_v7().to_string();
    let result = ok(call(&mut f, 0, apply(&request, &changes)));
    assert_eq!(result["state"], "applied");
    for private in ["revision", "writer", "config_saved", "config_error"] {
        assert!(result.get(private).is_none());
    }
    f.send();
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(ok(call(&mut f, 0, apply(&request, &changes))), result);
    assert_eq!(
        ok(call(
            &mut f,
            0,
            AgentOp::GroupRequest {
                request_id: request.clone()
            }
        )),
        result
    );
    assert_eq!(
        err(call(
            &mut f,
            1,
            AgentOp::GroupRequest {
                request_id: request.clone()
            }
        )),
        "recipient or message unavailable"
    );
    assert!(
        err(call(
            &mut f,
            0,
            AgentOp::PermissionApply {
                request_id: request,
                changes: vec![]
            }
        ))
        .contains("another edit")
    );
    let removed = vec![change(&f, &grant, GroupAction::Remove)];
    ok(call(
        &mut f,
        0,
        apply(&Uuid::now_v7().to_string(), &removed),
    ));
    assert_eq!(
        ok(call(&mut f, 0, AgentOp::PermissionCheck { peer }))["policy"]["send_unsolicited"]["allowed"],
        false
    );
    let admin = f.agents[0].clone();
    let audit = ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::GroupAdminHistory {
            administrator: Some(admin),
            before: None,
        },
    ));
    assert_eq!(audit["entries"].as_array().unwrap().len(), 2);
    assert_eq!(audit["entries"][0]["group_membership"], true);
    assert_eq!(audit["entries"][0]["changes"], json!(removed));
    assert!(audit["entries"][0]["revision"].is_number());
    let permissions = ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::PermissionAdminHistory {
            administrator: None,
            before: None,
        },
    ));
    assert_eq!(permissions["entries"], json!([]));
}

#[test]
fn group_reads_and_edits_hide_unavailable_members_and_grants() {
    let (mut f, id) = setup();
    let hidden = ok(agent(
        &mut f.store,
        &config::secret(),
        AgentOp::Register {
            name: "secret".into(),
            provider: "test".into(),
        },
    ))["agent"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    edit(
        &mut f,
        ConfigurationEdit::GroupMembers {
            group: "team".into(),
            members: vec![hidden.clone()],
            action: GroupAction::Add,
        },
    );
    grant(&mut f, "team", Selector::Agent(hidden.clone()));
    let scopes = ok(call(&mut f, 0, AgentOp::GroupAdminScopes));
    assert_eq!(scopes["grants"].as_array().unwrap().len(), 1);
    assert!(!scopes.to_string().contains(&hidden));
    let members = ok(call(
        &mut f,
        0,
        AgentOp::GroupMembers {
            group: "team".into(),
        },
    ));
    assert!(!members.to_string().contains(&hidden));
    assert_eq!(members["members"].as_array().unwrap().len(), 1);
    assert!(members.get("total").is_none());
    for member in [hidden, Uuid::new_v4().to_string()] {
        for action in [GroupAction::Add, GroupAction::Remove] {
            let changes = vec![GroupChange {
                grant_id: id.clone(),
                group: "team".into(),
                member: member.clone(),
                action,
            }];
            assert_eq!(
                err(call(&mut f, 0, AgentOp::GroupPreview { changes })),
                "recipient or message unavailable"
            );
        }
    }
    edit(
        &mut f,
        ConfigurationEdit::CreateGroup {
            name: "secret-group".into(),
        },
    );
    for group in ["secret-group", "missing"] {
        assert_eq!(
            err(call(
                &mut f,
                0,
                AgentOp::GroupMembers {
                    group: group.into()
                }
            )),
            "recipient or message unavailable"
        );
    }
    assert_eq!(
        ok(call(&mut f, 1, AgentOp::GroupAdminScopes))["grants"],
        json!([])
    );
    assert_eq!(
        err(call(
            &mut f,
            1,
            AgentOp::GroupMembers {
                group: "team".into()
            }
        )),
        "recipient or message unavailable"
    );
    assert!(serde_json::from_value::<AgentOp>(json!({"op":"group_apply","administrator":f.agents[0],"request_id":Uuid::now_v7(),"changes":[]})).is_err());
}

#[test]
fn group_batches_cannot_expand_their_own_scope_and_audit_failures_roll_back() {
    let (mut f, unscoped) = setup();
    edit(
        &mut f,
        ConfigurationEdit::RevokeGroupAdmin { grant_id: unscoped },
    );
    edit(
        &mut f,
        ConfigurationEdit::CreateGroup {
            name: "scope".into(),
        },
    );
    let scope = grant(&mut f, "scope", Selector::All);
    let team = grant(&mut f, "team", Selector::Group("scope".into()));
    let member = f.agents[1].clone();
    let changes = vec![
        GroupChange {
            grant_id: scope,
            group: "scope".into(),
            member,
            action: GroupAction::Add,
        },
        change(&f, &team, GroupAction::Add),
    ];
    let request = Uuid::now_v7().to_string();
    assert_eq!(
        err(call(&mut f, 0, apply(&request, &changes))),
        "recipient or message unavailable"
    );
    let before = ok(owner(&mut f.store, &f.owner_rpc, OwnerOp::Status))["authority"].clone();
    f.db().execute_batch("CREATE TRIGGER fail_edit BEFORE INSERT ON configuration_edits BEGIN SELECT RAISE(ABORT,'test disk failure'); END;").unwrap();
    assert!(err(call(&mut f, 0, apply(&request, &changes[..1]))).contains("test disk failure"));
    assert_eq!(
        ok(owner(&mut f.store, &f.owner_rpc, OwnerOp::Status))["authority"],
        before
    );
    f.db().execute_batch("DROP TRIGGER fail_edit;").unwrap();
    ok(call(&mut f, 0, apply(&request, &changes[..1])));
    // A separate accepted scope update can authorize a later membership edit.
    ok(call(
        &mut f,
        0,
        apply(&Uuid::now_v7().to_string(), &changes[1..]),
    ));
    f.send();
}

#[test]
fn group_revocation_expiry_and_referenced_deletion_preserve_history() {
    let (mut f, id) = setup();
    let changes = vec![change(&f, &id, GroupAction::Add)];
    let request = Uuid::now_v7().to_string();
    let result = ok(call(&mut f, 0, apply(&request, &changes)));
    assert_eq!(
        edit(
            &mut f,
            ConfigurationEdit::DeleteGroup {
                name: "team".into()
            }
        )["state"],
        "rejected"
    );
    f.db()
        .execute("UPDATE request_clock SET floor=?1", [now() + 3601])
        .unwrap();
    assert_eq!(
        ok(call(&mut f, 0, AgentOp::GroupAdminScopes))["grants"],
        json!([])
    );
    assert_eq!(
        err(call(
            &mut f,
            0,
            apply(&Uuid::now_v7().to_string(), &changes)
        )),
        "recipient or message unavailable"
    );
    edit(&mut f, ConfigurationEdit::RevokeGroupAdmin { grant_id: id });
    assert_eq!(ok(call(&mut f, 0, apply(&request, &changes))), result);
    f.send();
    // Owner lifecycle for unreferenced groups also works, including empty lists.
    assert_eq!(
        edit(
            &mut f,
            ConfigurationEdit::CreateGroup {
                name: "temporary".into()
            }
        )["state"],
        "applied"
    );
    assert_eq!(
        edit(
            &mut f,
            ConfigurationEdit::DeleteGroup {
                name: "temporary".into()
            }
        )["state"],
        "applied"
    );
}

#[test]
fn group_scopes_can_name_rules_but_do_not_confer_permission_editing_authority() {
    let (mut f, group_grant) = setup();
    let mut changes = vec![PermissionRuleChange {
        grant_id: group_grant.clone(),
        actor: Selector::Group("team".into()),
        peer: Selector::All,
        permission: Permission::Send,
        decision: RuleDecision::Deny,
    }];
    assert_eq!(
        err(call(
            &mut f,
            0,
            AgentOp::PermissionRulePreview {
                changes: changes.clone()
            }
        )),
        "recipient or message unavailable"
    );
    let rule_grant = Uuid::new_v4().to_string();
    let admin = f.agents[0].clone();
    edit(
        &mut f,
        ConfigurationEdit::GrantPermissionAdmin {
            grant_id: rule_grant.clone(),
            administrator: admin,
            actor: Selector::All,
            peer: Selector::All,
            permissions: vec![Permission::Send],
            selector_rules: true,
            lifetime_seconds: 3600,
        },
    );
    changes[0].grant_id = rule_grant;
    ok(call(
        &mut f,
        0,
        AgentOp::PermissionRulePreview {
            changes: changes.clone(),
        },
    ));
    let mut guessed = changes.clone();
    edit(
        &mut f,
        ConfigurationEdit::CreateGroup {
            name: "private".into(),
        },
    );
    guessed[0].actor = Selector::Group("private".into());
    assert_eq!(
        err(call(
            &mut f,
            0,
            AgentOp::PermissionRulePreview { changes: guessed }
        )),
        "recipient or message unavailable"
    );
    edit(
        &mut f,
        ConfigurationEdit::RevokeGroupAdmin {
            grant_id: group_grant,
        },
    );
    assert_eq!(
        err(call(&mut f, 0, AgentOp::PermissionRulePreview { changes })),
        "recipient or message unavailable"
    );
}
