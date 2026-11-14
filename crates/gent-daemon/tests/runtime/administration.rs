use super::*;
use gent_protocol::administration::*;
fn call(f: &mut Fixture, i: usize, op: AgentOp) -> Response {
    agent(&mut f.store, &f.keys[i], op)
}
fn error(r: Response) -> String {
    match r {
        Response::Error(e) => e,
        Response::Ok(v) => panic!("unexpected success: {v}"),
    }
}
fn setup() -> (Fixture, String, Vec<PermissionChange>) {
    let mut f = Fixture::new();
    let mut p = Policy::default();
    for (a, b) in [(0, 1), (1, 0)] {
        p.rules.push(Rule {
            actor: Selector::Agent(f.agents[a].clone()),
            peer: Selector::Agent(f.agents[b].clone()),
            permission: Permission::Enumerate,
            effect: Effect::Allow,
        });
    }
    f.set(p);
    let grant = Uuid::new_v4().to_string();
    ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::Configure {
            request_id: grant.clone(),
            edit: ConfigurationEdit::GrantPermissionAdmin {
                selector_rules: false,
                grant_id: grant.clone(),
                administrator: f.agents[0].clone(),
                actor: Selector::All,
                peer: Selector::All,
                permissions: vec![Permission::Enumerate, Permission::Receive, Permission::Send],
                lifetime_seconds: 3600,
            },
        },
    ));
    let changes = [(0, 1, Permission::Send), (1, 0, Permission::Receive)]
        .map(|(a, b, permission)| PermissionChange {
            grant_id: grant.clone(),
            actor: f.agents[a].clone(),
            peer: f.agents[b].clone(),
            permission,
            decision: RuleDecision::Allow,
        })
        .to_vec();
    (f, grant, changes)
}
fn apply(id: &str, changes: &[PermissionChange]) -> AgentOp {
    AgentOp::PermissionApply {
        request_id: id.into(),
        changes: changes.to_vec(),
    }
}
fn status(f: &mut Fixture) -> Value {
    ok(owner(&mut f.store, &f.owner_rpc, OwnerOp::Status))
}

#[test]
fn administration_preview_apply_audit_retry_restart_and_revocation() {
    let (mut f, grant, changes) = setup();
    let original = status(&mut f)["authority"]["revision"].clone();
    let preview = ok(call(
        &mut f,
        0,
        AgentOp::PermissionPreview {
            changes: changes.clone(),
        },
    ));
    assert_eq!(
        preview["relationships"][0]["policy"]["reply_policy"]["allowed"],
        true
    );
    assert_eq!(status(&mut f)["authority"]["revision"], original);
    let id = Uuid::now_v7().to_string();
    let result = ok(call(&mut f, 0, apply(&id, &changes)));
    assert_eq!(result["state"], "applied");
    for private in ["revision", "writer", "config_saved", "config_error"] {
        assert!(result.get(private).is_none());
    }
    f.send();
    let audit = ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::ConfigurationRequests { request_id: None },
    ));
    let audit = &audit[0];
    assert_eq!(audit["administrator"], f.agents[0]);
    assert_eq!(audit["agent_request_id"], id);
    assert_eq!(audit["changes"], json!(changes));
    assert!(audit["revision"].as_u64().unwrap() > original.as_u64().unwrap());
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(ok(call(&mut f, 0, apply(&id, &changes))), result);
    assert_eq!(
        error(call(
            &mut f,
            1,
            AgentOp::PermissionRequest {
                request_id: id.clone()
            }
        )),
        "recipient or message unavailable"
    );
    assert_eq!(
        error(call(&mut f, 1, apply(&id, &changes))),
        "recipient or message unavailable"
    );
    let mut changed = changes.clone();
    changed[0].decision = RuleDecision::Deny;
    assert!(error(call(&mut f, 0, apply(&id, &changed))).contains("another edit"));
    ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::Configure {
            request_id: Uuid::new_v4().to_string(),
            edit: ConfigurationEdit::RevokePermissionAdmin { grant_id: grant },
        },
    ));
    assert_eq!(ok(call(&mut f, 0, apply(&id, &changes))), result);
    assert_eq!(
        error(call(
            &mut f,
            0,
            apply(&Uuid::now_v7().to_string(), &changes)
        )),
        "recipient or message unavailable"
    );
    f.send(); // Revoking editing authority does not revoke prior message grants.
}

#[test]
fn hidden_peers_and_batch_scope_cannot_be_bootstrapped_or_forged() {
    let (mut f, grant, changes) = setup();
    let hidden_key = config::secret();
    let hidden = ok(agent(
        &mut f.store,
        &hidden_key,
        AgentOp::Register {
            name: "hidden".into(),
            provider: "secret".into(),
        },
    ))["agent"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let actor = f.agents[0].clone();
    let mut failures = Vec::new();
    for peer in [hidden.clone(), Uuid::new_v4().to_string()] {
        failures.push(error(call(
            &mut f,
            0,
            AgentOp::PermissionAdminCheck {
                actor: actor.clone(),
                peer,
            },
        )));
    }
    assert_eq!(failures, vec!["recipient or message unavailable"; 2]);
    // A first change cannot manufacture discovery for a later change in a batch.
    let mut batch = changes.clone();
    batch.push(PermissionChange {
        grant_id: grant,
        actor: actor.clone(),
        peer: hidden,
        permission: Permission::Enumerate,
        decision: RuleDecision::Allow,
    });
    let before = status(&mut f)["authority"].clone();
    assert_eq!(
        error(call(
            &mut f,
            0,
            AgentOp::PermissionPreview {
                changes: batch.clone()
            }
        )),
        "recipient or message unavailable"
    );
    assert_eq!(
        error(call(&mut f, 0, apply(&Uuid::now_v7().to_string(), &batch))),
        "recipient or message unavailable"
    );
    assert_eq!(status(&mut f)["authority"], before);
    assert!(serde_json::from_value::<AgentOp>(json!({"op":"permission_apply","request_id":Uuid::now_v7(),"administrator":actor,"changes":changes})).is_err());
    assert!(serde_json::from_value::<AgentOp>(json!({"op":"permission_apply","request_id":Uuid::now_v7(),"changes":[],"admin_grants":{}})).is_err());
    let mut duplicate = changes.clone();
    duplicate.push(changes[0].clone());
    assert!(
        error(call(
            &mut f,
            0,
            apply(&Uuid::now_v7().to_string(), &duplicate)
        ))
        .contains("duplicate")
    );
}

#[test]
fn failed_audit_commit_rolls_back_policy_and_expiry_blocks_new_changes() {
    let (mut f, _, changes) = setup();
    let before = status(&mut f)["authority"].clone();
    let id = Uuid::now_v7().to_string();
    f.db().execute_batch("CREATE TRIGGER fail_edit BEFORE INSERT ON configuration_edits BEGIN SELECT RAISE(ABORT,'test disk failure'); END;").unwrap();
    assert!(error(call(&mut f, 0, apply(&id, &changes))).contains("test disk failure"));
    assert_eq!(status(&mut f)["authority"], before);
    assert_eq!(
        error(call(
            &mut f,
            0,
            AgentOp::PermissionRequest {
                request_id: id.clone()
            }
        )),
        "recipient or message unavailable"
    );
    f.db().execute_batch("DROP TRIGGER fail_edit;").unwrap();
    ok(call(&mut f, 0, apply(&id, &changes)));
    f.db()
        .execute("UPDATE request_clock SET floor=?1", [now() + 3601])
        .unwrap();
    assert_eq!(
        error(call(
            &mut f,
            0,
            apply(&Uuid::now_v7().to_string(), &changes)
        )),
        "recipient or message unavailable"
    );
    assert_eq!(
        ok(call(&mut f, 0, apply(&id, &changes)))["state"],
        "applied"
    );
}
