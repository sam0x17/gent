use super::*;

#[test]
fn group_membership_scopes_bind_administrator_action_location_and_time() {
    let mut admin = agent("admin", "one");
    let mut member = agent("member", "one");
    let mut p = Policy::default();
    let mut grant = GroupAdminGrant {
        administrator: admin.id.clone(),
        group: "team".into(),
        members: Selector::SameNode,
        actions: vec![GroupAction::Add],
        issued_at: 10,
        expires_at: 20,
    };
    assert!(p.group_admin_allows(&grant, &admin, &member, GroupAction::Add, 10));
    assert!(p.group_admin_allows(&grant, &admin, &admin, GroupAction::Add, 10));
    assert!(!p.group_admin_allows(&grant, &member, &admin, GroupAction::Add, 10));
    assert!(!p.group_admin_allows(&grant, &admin, &member, GroupAction::Remove, 10));
    for now in [9, 20] {
        assert!(!p.group_admin_allows(&grant, &admin, &member, GroupAction::Add, now));
    }
    member.node_id = "two".into();
    assert!(!p.group_admin_allows(&grant, &admin, &member, GroupAction::Add, 10));
    grant.members = Selector::Node("two".into());
    assert!(p.group_admin_allows(&grant, &admin, &member, GroupAction::Add, 10));
    grant.members = Selector::Group("scope".into());
    p.groups.insert("scope".into(), vec![member.id.clone()]);
    assert!(p.group_admin_allows(&grant, &admin, &member, GroupAction::Add, 10));
    member.revoked = true;
    assert!(!p.group_admin_allows(&grant, &admin, &member, GroupAction::Add, 10));
    member.revoked = false;
    admin.revoked = true;
    assert!(!p.group_admin_allows(&grant, &admin, &member, GroupAction::Add, 10));
}

#[test]
fn selector_rule_containment_never_covers_pairs_outside_the_owner_scope() {
    let admin = agent("admin", "one");
    let mut policy = Policy::default();
    policy
        .groups
        .insert("g".into(), vec!["a".into(), "future".into()]);
    policy
        .groups
        .insert("h".into(), vec!["a".into(), "b".into()]);
    let a = agent("a", "one");
    let b = agent("b", "two");
    let known = BTreeMap::from([(a.id.clone(), a.clone()), (b.id.clone(), b.clone())]);
    let people = [
        a,
        b,
        agent("future", "two"),
        agent("unknown", "one"),
        agent("third", "three"),
    ];
    let selectors = [
        Selector::All,
        Selector::SameNode,
        Selector::Agent("a".into()),
        Selector::Agent("b".into()),
        Selector::Node("one".into()),
        Selector::Node("two".into()),
        Selector::Group("g".into()),
        Selector::Group("h".into()),
    ];
    for ga in &selectors {
        for gp in &selectors {
            let grant = AdminGrant {
                administrator: admin.id.clone(),
                actor: ga.clone(),
                peer: gp.clone(),
                permissions: vec![Permission::Send],
                selector_rules: true,
                issued_at: 1,
                expires_at: 10,
            };
            for ca in &selectors {
                for cp in &selectors {
                    let change = PermissionRuleChange {
                        grant_id: "grant".into(),
                        actor: ca.clone(),
                        peer: cp.clone(),
                        permission: Permission::Send,
                        decision: RuleDecision::Allow,
                    };
                    if policy.admin_allows_rule(&grant, &admin, &change, &known, 5) {
                        for actor in &people {
                            for peer in &people {
                                if policy.matches(ca, actor, peer)
                                    && policy.matches(cp, peer, actor)
                                {
                                    assert!(
                                        policy.matches(ga, actor, peer)
                                            && policy.matches(gp, peer, actor),
                                        "{ga:?}/{gp:?} covered {ca:?}/{cp:?}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn selector_rules_require_opt_in_and_do_not_infer_group_containment_from_members() {
    let admin = agent("admin", "one");
    let mut policy = Policy::default();
    policy.groups.insert("g".into(), vec!["a".into()]);
    policy.groups.insert("h".into(), vec!["a".into()]);
    let mut grant = AdminGrant {
        administrator: admin.id.clone(),
        actor: Selector::Group("g".into()),
        peer: Selector::All,
        permissions: vec![Permission::Enumerate],
        selector_rules: false,
        issued_at: 1,
        expires_at: 10,
    };
    let mut change = PermissionRuleChange {
        grant_id: "grant".into(),
        actor: grant.actor.clone(),
        peer: grant.peer.clone(),
        permission: Permission::Enumerate,
        decision: RuleDecision::Allow,
    };
    assert!(!policy.admin_allows_rule(&grant, &admin, &change, &BTreeMap::new(), 5));
    grant.selector_rules = true;
    assert!(policy.admin_allows_rule(&grant, &admin, &change, &BTreeMap::new(), 5));
    change.actor = Selector::Group("h".into());
    assert!(!policy.admin_allows_rule(&grant, &admin, &change, &BTreeMap::new(), 5));
}
fn agent(id: &str, node: &str) -> Agent {
    Agent {
        id: id.into(),
        node_id: node.into(),
        name: id.into(),
        provider: "test".into(),
        last_seen: 0,
        revoked: false,
    }
}
#[test]
fn administrative_scope_binds_identity_membership_selectors_permissions_and_time() {
    let (admin, a, mut b) = (agent("admin", "one"), agent("a", "one"), agent("b", "one"));
    let mut p = Policy::default();
    p.groups.insert("actors".into(), vec![a.id.clone()]);
    let mut grant = AdminGrant {
        selector_rules: false,
        administrator: admin.id.clone(),
        actor: Selector::Group("actors".into()),
        peer: Selector::SameNode,
        permissions: vec![Permission::Send],
        issued_at: 10,
        expires_at: 20,
    };
    assert!(p.admin_allows(&grant, &admin, &a, &b, Permission::Send, 10));
    assert!(!p.admin_allows(&grant, &a, &a, &b, Permission::Send, 10));
    assert!(!p.admin_allows(&grant, &admin, &a, &b, Permission::Receive, 10));
    for time in [9, 20, 21] {
        assert!(!p.admin_allows(&grant, &admin, &a, &b, Permission::Send, time));
    }
    b.node_id = "two".into();
    assert!(!p.admin_allows(&grant, &admin, &a, &b, Permission::Send, 10));
    grant.peer = Selector::Node("two".into());
    assert!(p.admin_allows(&grant, &admin, &a, &b, Permission::Send, 10));
    b.revoked = true;
    assert!(!p.admin_allows(&grant, &admin, &a, &b, Permission::Send, 10));
    b.revoked = false;
    p.groups.get_mut("actors").unwrap().clear();
    assert!(!p.admin_allows(&grant, &admin, &a, &b, Permission::Send, 10));
}
#[test]
fn replacing_pair_rules_cannot_remove_broad_denials_or_change_other_pairs() {
    let (a, b, c) = (agent("a", "one"), agent("b", "two"), agent("c", "two"));
    let mut p = Policy::default();
    p.rules.push(Rule {
        actor: Selector::All,
        peer: Selector::All,
        permission: Permission::Send,
        effect: Effect::Deny,
    });
    let mut change = PermissionChange {
        grant_id: "test".into(),
        actor: a.id.clone(),
        peer: b.id.clone(),
        permission: Permission::Send,
        decision: RuleDecision::Allow,
    };
    p.apply_permission_changes(&[change.clone()]);
    assert_eq!(p.decision(&a, &b, Permission::Send), Some(Effect::Deny));
    p.rules.remove(0);
    assert_eq!(p.decision(&a, &b, Permission::Send), Some(Effect::Allow));
    assert_eq!(p.decision(&a, &c, Permission::Send), None);
    change.decision = RuleDecision::Deny;
    p.apply_permission_changes(&[change.clone()]);
    assert_eq!(p.decision(&a, &b, Permission::Send), Some(Effect::Deny));
    change.decision = RuleDecision::Inherit;
    p.apply_permission_changes(&[change]);
    assert_eq!(p.decision(&a, &b, Permission::Send), None);
}
