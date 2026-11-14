use super::*;
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
