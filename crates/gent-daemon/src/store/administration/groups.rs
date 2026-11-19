//! Group changes use independent owner grants and pre-edit membership.
use super::*;
use gent_protocol::administration::{GroupAction, GroupAdminGrant, GroupChange};

fn canonical_id(value: &str) -> Result<()> {
    let id = Uuid::parse_str(value).context(UNAVAILABLE)?;
    ensure!(!id.is_nil() && id.to_string() == value, UNAVAILABLE);
    Ok(())
}

pub(in crate::store) fn validate_changes(changes: &[GroupChange]) -> Result<()> {
    ensure!(
        !changes.is_empty() && changes.len() <= MAX_PERMISSION_CHANGES,
        "group batch must contain 1 to 32 changes"
    );
    for (i, change) in changes.iter().enumerate() {
        canonical_id(&change.grant_id)?;
        canonical_id(&change.member)?;
        config::label(&change.group).map_err(|_| anyhow::anyhow!(UNAVAILABLE))?;
        ensure!(
            !changes[..i]
                .iter()
                .any(|c| c.group == change.group && c.member == change.member),
            "duplicate group member change"
        );
    }
    Ok(())
}

pub(in crate::store) fn validate_members(group: &str, members: &[String]) -> Result<()> {
    config::label(group)?;
    ensure!(
        !members.is_empty() && members.len() <= 32,
        "group batch must contain 1 to 32 members"
    );
    for (i, member) in members.iter().enumerate() {
        canonical_id(member)?;
        ensure!(
            !members[..i].contains(member),
            "duplicate group member change"
        );
    }
    Ok(())
}

pub(in crate::store) fn change_member(
    policy: &mut Policy,
    group: &str,
    member: &str,
    action: GroupAction,
) -> Result<()> {
    let members = policy.groups.get_mut(group).context(UNAVAILABLE)?;
    match action {
        GroupAction::Add if !members.iter().any(|m| m == member) => members.push(member.into()),
        GroupAction::Remove => members.retain(|m| m != member),
        _ => {}
    }
    Ok(())
}

impl StoreSession<'_> {
    pub(super) fn group_scope_known(&self, admin: &Agent, selector: &Selector) -> bool {
        self.config.policy.group_admin_grants.values().any(|g| {
            self.group_grant_visible(admin, g)
                && (g.members == *selector || *selector == Selector::Group(g.group.clone()))
        })
    }

    fn group_grant_visible(&self, admin: &Agent, grant: &GroupAdminGrant) -> bool {
        !admin.revoked
            && grant.administrator == admin.id
            && grant.issued_at <= self.timestamp as u64
            && (self.timestamp as u64) < grant.expires_at
            && match &grant.members {
                Selector::Agent(id) => self.admin_peer(admin, id).is_ok(),
                _ => true,
            }
    }

    pub(in crate::store) fn group_admin_scopes(&self, admin: &Agent) -> Result<Value> {
        let grants: Vec<_> = self.config.policy.group_admin_grants.iter()
            .filter(|(_, g)| self.group_grant_visible(admin, g))
            .map(|(id, g)| json!({"grant_id":id,"group":g.group,"members":g.members,"actions":g.actions,"expires_at":g.expires_at})).collect();
        Ok(
            json!({"administrator":admin.id,"grants":grants,"max_changes":MAX_PERMISSION_CHANGES,
            "scope":"membership changes affect every rule and existing editing scope using the group; named members must already be visible; same_node compares each member with the administrator"}),
        )
    }

    pub(in crate::store) fn group_members(&self, admin: &Agent, group: &str) -> Result<Value> {
        let grants: Vec<_> = self
            .config
            .policy
            .group_admin_grants
            .values()
            .filter(|g| g.group == group && self.group_grant_visible(admin, g))
            .collect();
        ensure!(!grants.is_empty(), UNAVAILABLE);
        let members = self.config.policy.groups.get(group).context(UNAVAILABLE)?;
        let visible: Vec<_> = self
            .all_agents()?
            .into_iter()
            .filter(|a| {
                members.contains(&a.id)
                    && (a.id == admin.id || self.config.policy.visible(admin, a))
                    && grants.iter().any(|g| {
                        g.actions.iter().any(|action| {
                            self.config.policy.group_admin_allows(
                                g,
                                admin,
                                a,
                                *action,
                                self.timestamp as u64,
                            )
                        })
                    })
            })
            .collect();
        Ok(
            json!({"group":group,"members":visible,"scope":"only visible members within your active editing scopes; not a complete membership list"}),
        )
    }

    pub(in crate::store) fn agent_group_policy(
        &self,
        origin: &str,
        administrator: &str,
        changes: &[GroupChange],
    ) -> Result<Policy> {
        validate_changes(changes)?;
        self.state.require_fresh(self.timestamp as u64)?;
        let admin = self.get_agent(administrator)?;
        ensure!(
            !admin.revoked && self.state.transport_host(&admin.node_id)? == origin,
            UNAVAILABLE
        );
        for change in changes {
            let member = self.admin_peer(&admin, &change.member)?;
            let grant = self
                .config
                .policy
                .group_admin_grants
                .get(&change.grant_id)
                .context(UNAVAILABLE)?;
            ensure!(
                grant.group == change.group
                    && self.group_grant_visible(&admin, grant)
                    && self.config.policy.group_admin_allows(
                        grant,
                        &admin,
                        &member,
                        change.action,
                        self.timestamp as u64
                    ),
                UNAVAILABLE
            );
        }
        let mut policy = self.config.policy.clone();
        for change in changes {
            change_member(&mut policy, &change.group, &change.member, change.action)?;
        }
        gent_crypto::validate_policy(&policy)?;
        Ok(policy)
    }

    pub(in crate::store) fn group_preview(
        &self,
        admin: &Agent,
        changes: &[GroupChange],
    ) -> Result<Value> {
        self.agent_group_policy(
            self.state.transport_host(&admin.node_id)?,
            &admin.id,
            changes,
        )?;
        Ok(json!({"administrator":admin.id,"changes":changes,
            "scope":"preview only; membership affects all rules and editing scopes using the group; no matching directory or counts; acceptance rechecks current authority"}))
    }

    pub(in crate::store) fn group_apply(
        &mut self,
        admin: &Agent,
        request: &str,
        changes: Vec<GroupChange>,
    ) -> Result<Value> {
        let id = request_id(&admin.id, request)?;
        self.submit_configuration(
            &id.to_string(),
            ConfigurationEdit::AgentGroups {
                administrator: admin.id.clone(),
                request_id: request.into(),
                changes,
            },
        )?;
        self.permission_request(admin, request)
    }
}
