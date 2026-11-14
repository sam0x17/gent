//! Selector-rule administration is opt-in and never implies directory access.
use super::*;
use gent_protocol::administration::{AdminGrant, PermissionRuleChange};

pub(in crate::store) fn validate_changes(changes: &[PermissionRuleChange]) -> Result<()> {
    ensure!(
        !changes.is_empty() && changes.len() <= MAX_PERMISSION_CHANGES,
        "permission batch must contain 1 to 32 changes"
    );
    for (i, change) in changes.iter().enumerate() {
        let id = Uuid::parse_str(&change.grant_id).context(UNAVAILABLE)?;
        ensure!(
            !id.is_nil() && id.to_string() == change.grant_id,
            UNAVAILABLE
        );
        for selector in [&change.actor, &change.peer] {
            match selector {
                Selector::Agent(id) | Selector::Node(id) => {
                    let parsed = Uuid::parse_str(id).context(UNAVAILABLE)?;
                    ensure!(!parsed.is_nil() && parsed.to_string() == *id, UNAVAILABLE);
                }
                Selector::Group(name) => {
                    config::label(name).map_err(|_| anyhow::anyhow!(UNAVAILABLE))?
                }
                _ => {}
            }
        }
        ensure!(
            !changes[..i].iter().any(|c| c.actor == change.actor
                && c.peer == change.peer
                && c.permission == change.permission),
            "duplicate permission change"
        );
    }
    Ok(())
}

impl StoreSession<'_> {
    fn rule_grant_visible(&self, admin: &Agent, grant: &AdminGrant) -> bool {
        grant.administrator == admin.id
            && grant.selector_rules
            && !admin.revoked
            && grant.issued_at <= self.timestamp as u64
            && (self.timestamp as u64) < grant.expires_at
            && [&grant.actor, &grant.peer].into_iter().all(|s| match s {
                Selector::Agent(id) => self.admin_peer(admin, id).is_ok(),
                _ => true,
            })
    }
    pub(in crate::store) fn permission_rule_scopes(&self, admin: &Agent) -> Result<Value> {
        let grants:Vec<_>=self.config.policy.admin_grants.iter().filter(|(_,g)|self.rule_grant_visible(admin,g))
            .map(|(id,g)|json!({"grant_id":id,"actor":g.actor,"peer":g.peer,"permissions":g.permissions,"expires_at":g.expires_at})).collect();
        Ok(
            json!({"administrator":admin.id,"grants":grants,"max_changes":MAX_PERMISSION_CHANGES,
            "scope":"selector rules may affect hidden and future matching agents; no membership or matching counts are disclosed"}),
        )
    }
    pub(in crate::store) fn agent_permission_rule_policy(
        &self,
        origin: &str,
        administrator: &str,
        changes: &[PermissionRuleChange],
    ) -> Result<Policy> {
        validate_changes(changes)?;
        self.state.require_fresh(self.timestamp as u64)?;
        let admin = self.get_agent(administrator)?;
        ensure!(!admin.revoked && admin.node_id == origin, UNAVAILABLE);
        let grants: Vec<_> = self
            .config
            .policy
            .admin_grants
            .values()
            .filter(|g| self.rule_grant_visible(&admin, g))
            .collect();
        let mut known = BTreeMap::new();
        let mut nodes = std::collections::BTreeSet::from([admin.node_id.clone()]);
        for agent in self
            .all_agents()?
            .into_iter()
            .filter(|a| self.config.policy.visible(&admin, a))
        {
            nodes.insert(agent.node_id);
        }
        for change in changes {
            let grant = self
                .config
                .policy
                .admin_grants
                .get(&change.grant_id)
                .context(UNAVAILABLE)?;
            ensure!(self.rule_grant_visible(&admin, grant), UNAVAILABLE);
            for selector in [&change.actor, &change.peer] {
                match selector {
                    Selector::Agent(id) => {
                        known.insert(id.clone(), self.admin_peer(&admin, id)?);
                    }
                    Selector::Group(name) => {
                        ensure!(
                            grants
                                .iter()
                                .any(|g| [&g.actor, &g.peer].contains(&selector))
                                && self.config.policy.groups.contains_key(name),
                            UNAVAILABLE
                        );
                    }
                    Selector::Node(id) => {
                        ensure!(
                            (nodes.contains(id)
                                || grants
                                    .iter()
                                    .any(|g| [&g.actor, &g.peer].contains(&selector)))
                                && self.state.state().nodes.contains_key(id),
                            UNAVAILABLE
                        );
                    }
                    _ => {}
                }
            }
            ensure!(
                self.config.policy.admin_allows_rule(
                    grant,
                    &admin,
                    change,
                    &known,
                    self.timestamp as u64
                ),
                UNAVAILABLE
            );
        }
        let mut policy = self.config.policy.clone();
        policy.apply_permission_rules(changes);
        gent_crypto::validate_policy(&policy)?;
        Ok(policy)
    }
    pub(in crate::store) fn permission_rule_preview(
        &self,
        admin: &Agent,
        changes: &[PermissionRuleChange],
    ) -> Result<Value> {
        self.agent_permission_rule_policy(&admin.node_id, &admin.id, changes)?;
        Ok(json!({"administrator":admin.id,"changes":changes,
            "scope":"preview only; replaces rules with these exact selectors and permission; other overlapping rules still apply; hidden and future agents can be affected; no reservation"}))
    }
    pub(in crate::store) fn permission_rule_apply(
        &mut self,
        admin: &Agent,
        request: &str,
        changes: Vec<PermissionRuleChange>,
    ) -> Result<Value> {
        let id = request_id(&admin.id, request)?;
        self.submit_configuration(
            &id.to_string(),
            ConfigurationEdit::AgentPermissionRules {
                administrator: admin.id.clone(),
                request_id: request.into(),
                changes,
            },
        )?;
        self.permission_request(admin, request)
    }
}
