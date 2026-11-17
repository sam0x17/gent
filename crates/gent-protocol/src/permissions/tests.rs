use super::*;
fn agent(id: &str, node: &str) -> Agent {
    Agent {
        id: id.into(),
        node_id: node.into(),
        name: id.into(),
        provider: "fixture".into(),
        last_seen: 0,
        revoked: false,
    }
}

#[test]
fn new_cluster_permissions_cover_current_and_future_agents_without_administration() {
    let policy = Policy::cluster_default();
    let a = agent("existing", "desktop");
    for b in [agent("local", "desktop"), agent("later", "laptop")] {
        assert!(policy.visible(&a, &b) && policy.visible(&b, &a));
        assert!(policy.can_open(&a, &b) && policy.can_open(&b, &a));
        assert!(policy.can_reply(&a, &b) && policy.can_reply(&b, &a));
        let mut revoked = b.clone();
        revoked.revoked = true;
        assert!(!policy.visible(&a, &revoked));
        assert!(!policy.can_open(&a, &revoked));
        assert!(!policy.can_reply(&revoked, &a));
    }
    assert!(!policy.relationship(&a, &a).send_unsolicited.allowed);
    assert!(policy.relay_grants.is_empty());
    assert!(policy.admin_grants.is_empty());
    assert!(policy.group_admin_grants.is_empty());
    // Existing empty policies retain their signed representation and meaning.
    let empty: Policy = serde_json::from_str(r#"{"rules":[],"groups":{}}"#).unwrap();
    assert!(!empty.visible(&a, &agent("legacy", "laptop")));
    assert_eq!(
        serde_json::to_string(&empty).unwrap(),
        r#"{"rules":[],"groups":{}}"#
    );
}

#[test]
fn blacklist_restrictions_override_defaults_without_restricting_other_pairs() {
    let (a, b, c) = (agent("a", "one"), agent("b", "two"), agent("c", "two"));
    for permission in [Permission::Enumerate, Permission::Send, Permission::Receive] {
        let mut policy = Policy::cluster_default();
        let deny = Rule {
            actor: Selector::Agent(a.id.clone()),
            peer: Selector::Agent(b.id.clone()),
            permission,
            effect: Effect::Deny,
        };
        policy.rules.push(deny.clone());
        policy.rules.push(Rule {
            effect: Effect::Allow,
            ..deny
        });
        assert!(!policy.can_open(&a, &b));
        assert!(policy.can_open(&a, &c) && policy.can_open(&c, &b));
        assert_eq!(policy.visible(&a, &b), permission != Permission::Enumerate);
        assert_eq!(policy.can_reply(&a, &b), permission == Permission::Send);
        assert_eq!(policy.can_open(&b, &a), permission == Permission::Send);
        // Removing just this pair's overrides restores the cluster defaults.
        policy.rules.truncate(3);
        assert!(policy.can_open(&a, &b));
    }
}

#[test]
fn every_directional_decision_combination_agrees_with_messaging_semantics() {
    let (a, b) = (agent("a", "one"), agent("b", "two"));
    for mut variant in 0..729 {
        let mut p = Policy::default();
        let mut decisions = [None; 6];
        for (i, permission) in [Permission::Enumerate, Permission::Send, Permission::Receive]
            .into_iter()
            .cycle()
            .take(6)
            .enumerate()
        {
            let (actor, peer) = if i < 3 { (&a, &b) } else { (&b, &a) };
            decisions[i] = match variant % 3 {
                0 => None,
                1 => Some(Effect::Allow),
                _ => Some(Effect::Deny),
            };
            variant /= 3;
            if let Some(effect) = decisions[i] {
                p.rules.push(Rule {
                    actor: Selector::Agent(actor.id.clone()),
                    peer: Selector::Agent(peer.id.clone()),
                    permission,
                    effect,
                });
            }
        }
        let allowed = |i| decisions[i] == Some(Effect::Allow);
        let denied = |i| decisions[i] == Some(Effect::Deny);
        let send = allowed(0) && allowed(3) && allowed(1) && allowed(5) && !denied(2);
        let receive = allowed(0) && allowed(3) && allowed(4) && allowed(2) && !denied(5);
        let reply = allowed(0) && allowed(3) && !denied(2) && !denied(5);
        let r = p.relationship(&a, &b);
        assert_eq!(r.enumerate, allowed(0));
        assert_eq!(r.send_unsolicited.allowed, send);
        assert_eq!(r.receive_unsolicited.allowed, receive);
        assert_eq!(r.reply_policy.allowed, reply);
        assert_eq!(p.can_open(&a, &b), send);
        assert_eq!(p.can_reply(&b, &a), reply);
        let mut revoked = b.clone();
        revoked.revoked = true;
        assert!(!p.relationship(&a, &revoked).send_unsolicited.allowed);
        assert!(!p.relationship(&revoked, &a).reply_policy.allowed);
    }
}

#[test]
fn traces_cover_groups_nodes_blacklists_and_every_matching_rule_in_signed_order() {
    let (a, mut b) = (agent("a", "one"), agent("b", "one"));
    let mut p = Policy::default();
    p.groups.insert("team".into(), vec![a.id.clone()]);
    p.rules = vec![
        Rule {
            actor: Selector::All,
            peer: Selector::SameNode,
            permission: Permission::Enumerate,
            effect: Effect::Allow,
        },
        Rule {
            actor: Selector::Group("team".into()),
            peer: Selector::Node("one".into()),
            permission: Permission::Enumerate,
            effect: Effect::Deny,
        },
        Rule {
            actor: Selector::Agent("a".into()),
            peer: Selector::Agent("b".into()),
            permission: Permission::Enumerate,
            effect: Effect::Allow,
        },
    ];
    let trace = p.trace(&a, &b);
    assert!(matches!(trace[0].decision, Decision::ExplicitDeny));
    assert_eq!(trace[0].matching_rules, vec![0, 1, 2]);
    b.node_id = "two".into();
    assert_eq!(p.trace(&a, &b)[0].matching_rules, vec![2]);
    assert!(matches!(p.trace(&a, &b)[0].decision, Decision::Allow));
    b.revoked = true;
    assert!(matches!(p.trace(&a, &b)[0].decision, Decision::Revoked));
    assert!(
        p.relationship(&a, &a)
            .send_unsolicited
            .blocked_by
            .contains(&Blocker::SameAgent)
    );
}
