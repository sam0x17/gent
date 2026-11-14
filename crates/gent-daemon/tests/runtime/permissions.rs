use super::*;

fn check(f: &mut Fixture, actor: usize, peer: &str) -> Response {
    agent(
        &mut f.store,
        &f.keys[actor],
        AgentOp::PermissionCheck { peer: peer.into() },
    )
}
fn explain(f: &mut Fixture) -> Value {
    ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::PermissionExplain {
            actor: f.agents[0].clone(),
            peer: f.agents[1].clone(),
        },
    ))
}
fn error(response: Response) -> String {
    match response {
        Response::Error(e) => e,
        Response::Ok(v) => panic!("unexpected success: {v}"),
    }
}
fn send_to(f: &mut Fixture, actor: usize, recipient: &str) -> Response {
    agent(
        &mut f.store,
        &f.keys[actor],
        AgentOp::Send {
            recipient: recipient.into(),
            request_id: Uuid::now_v7().to_string(),
            text: "permission proof".into(),
            files: vec![],
            file_ids: vec![],
        },
    )
}
fn reply(f: &mut Fixture, message: &Value) -> Response {
    agent(
        &mut f.store,
        &f.keys[1],
        AgentOp::Reply {
            message_id: message["message_id"].as_str().unwrap().into(),
            request_id: Uuid::now_v7().to_string(),
            text: "reply proof".into(),
            files: vec![],
            file_ids: vec![],
        },
    )
}

#[test]
fn permission_check_hides_unknown_hidden_and_revoked_peers_and_owner_details() {
    let mut f = Fixture::new();
    let [a, b] = f.agents.clone();
    let missing = error(check(&mut f, 0, &Uuid::new_v4().to_string()));
    assert_eq!(missing, "recipient or message unavailable");
    assert_eq!(error(check(&mut f, 0, &b)), missing);
    let hidden_key = config::secret();
    let hidden = ok(agent(
        &mut f.store,
        &hidden_key,
        AgentOp::Register {
            name: "secret-peer".into(),
            provider: "hidden-host".into(),
        },
    ))["agent"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut policy = Policy::default();
    policy
        .groups
        .insert("private-team".into(), vec![a.clone(), b.clone()]);
    policy
        .groups
        .insert("hidden-team".into(), vec![hidden.clone()]);
    policy.rules.push(Rule {
        actor: Selector::Group("private-team".into()),
        peer: Selector::Group("private-team".into()),
        permission: Permission::Enumerate,
        effect: Effect::Allow,
    });
    f.set(policy);
    let summary = ok(check(&mut f, 0, &b));
    assert_eq!(summary["actor"], a);
    assert_eq!(summary["peer"], b);
    assert_eq!(summary["policy"]["enumerate"], true);
    let serialized = summary.to_string();
    for private in [
        &hidden,
        "private-team",
        "hidden-team",
        "hidden-host",
        "secret-peer",
        "matching_rules",
        "traces",
        "groups",
    ] {
        assert!(!serialized.contains(private), "{serialized}");
    }
    assert!(summary.get("authority").is_none());
    assert!(summary.get("revision").is_none());
    assert_eq!(error(check(&mut f, 0, &hidden)), missing);
    assert_eq!(
        error(owner(
            &mut f.store,
            &f.keys[0],
            OwnerOp::PermissionExplain {
                actor: a.clone(),
                peer: b.clone(),
            }
        )),
        "unauthorized"
    );
    assert!(
        serde_json::from_value::<AgentOp>(json!({"op":"permission_check","peer":b,"actor":hidden}))
            .is_err()
    );
    assert!(
        serde_json::from_value::<AgentOp>(json!({"op":"permission_explain","actor":a,"peer":b}))
            .is_err()
    );
    ok(owner(
        &mut f.store,
        &f.owner_rpc,
        OwnerOp::Revoke {
            agent_id: b.clone(),
        },
    ));
    assert_eq!(error(check(&mut f, 0, &b)), missing);
    let explanation = explain(&mut f);
    assert_eq!(explanation["revoked"]["peer"], true);
    assert_eq!(
        explanation["traces"]["actor_to_peer"][0]["decision"],
        "revoked"
    );
    assert_eq!(explanation["policy"]["reply_policy"]["allowed"], false);
}

#[test]
fn permission_explanation_tracks_signed_policy_and_actual_send_reply_and_restart() {
    let mut f = Fixture::new();
    let [a, b] = f.agents.clone();
    let mut policy = Policy::default();
    // Both agents enumerate; A may initiate, B can only reply.
    for (actor, peer, permission) in [
        (&a, &b, Permission::Enumerate),
        (&b, &a, Permission::Enumerate),
        (&a, &b, Permission::Send),
        (&b, &a, Permission::Receive),
    ] {
        policy.rules.push(Rule {
            actor: Selector::Agent(actor.clone()),
            peer: Selector::Agent(peer.clone()),
            permission,
            effect: Effect::Allow,
        });
    }
    f.set(policy.clone());
    let summary = ok(check(&mut f, 0, &b));
    assert_eq!(summary["policy"]["send_unsolicited"]["allowed"], true);
    assert_eq!(summary["policy"]["receive_unsolicited"]["allowed"], false);
    assert_eq!(summary["policy"]["reply_policy"]["allowed"], true);
    let received = f.send();
    assert_eq!(
        error(send_to(&mut f, 1, &a)),
        "recipient or message unavailable"
    );
    ok(reply(&mut f, &received));
    let baseline = explain(&mut f);
    assert_eq!(
        baseline["traces"]["actor_to_peer"][1]["decision"],
        "no_matching_rule"
    );
    assert_eq!(baseline["authority"]["revision"], 1);
    assert_eq!(baseline["authority"]["fresh"], true);
    for entry in baseline["matching_rules"].as_array().unwrap() {
        let index = entry["index"].as_u64().unwrap() as usize;
        assert_eq!(
            entry["rule"],
            serde_json::to_value(&policy.rules[index]).unwrap()
        );
    }
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(explain(&mut f), baseline);
    assert_eq!(ok(check(&mut f, 0, &b)), summary);
    // A broad allow after a deny must not hide the matching deny in the trace.
    policy.rules.push(Rule {
        actor: Selector::Agent(a.clone()),
        peer: Selector::Agent(b.clone()),
        permission: Permission::Receive,
        effect: Effect::Deny,
    });
    policy.rules.push(Rule {
        actor: Selector::All,
        peer: Selector::SameNode,
        permission: Permission::Receive,
        effect: Effect::Allow,
    });
    f.set(policy);
    let after = explain(&mut f);
    assert_eq!(after["authority"]["revision"], 2);
    assert_eq!(
        after["traces"]["actor_to_peer"][1]["decision"],
        "explicit_deny"
    );
    assert_eq!(
        after["traces"]["actor_to_peer"][1]["matching_rules"],
        json!([4, 5])
    );
    assert_eq!(
        after["policy"]["send_unsolicited"]["blocked_by"],
        json!(["sender_receive_denied"])
    );
    assert_eq!(ok(check(&mut f, 0, &b))["policy"], after["policy"]);
    assert_eq!(
        error(send_to(&mut f, 0, &b)),
        "recipient or message unavailable"
    );
    assert_eq!(
        error(reply(&mut f, &received)),
        "recipient or message unavailable"
    );
}

#[test]
fn self_messaging_is_blocked_and_expired_authority_is_owner_inspectable() {
    let mut f = Fixture::new();
    f.set(permit());
    let [a, b] = f.agents.clone();
    let summary = ok(check(&mut f, 0, &a));
    for gate in ["send_unsolicited", "receive_unsolicited", "reply_policy"] {
        assert_eq!(summary["policy"][gate]["blocked_by"], json!(["same_agent"]));
        assert_eq!(summary["policy"][gate]["allowed"], false);
    }
    assert_eq!(
        error(send_to(&mut f, 0, &a)),
        "recipient or message unavailable"
    );
    let expiry = explain(&mut f)["authority"]["expires_at"].as_i64().unwrap();
    f.db()
        .execute("UPDATE request_clock SET floor=?1", [expiry + 1])
        .unwrap();
    assert_eq!(explain(&mut f)["authority"]["fresh"], false);
    assert!(error(check(&mut f, 0, &b)).contains("expired"));
}
