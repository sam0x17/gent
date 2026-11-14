//! Scoped permission administration. Grants never confer discovery or further
//! delegation. Endpoints must authenticate the administrator and peer visibility.
use super::*;

pub const MAX_ADMIN_GRANT_LIFETIME: u64 = 7 * 24 * 60 * 60;
pub const MAX_PERMISSION_CHANGES: usize = 32;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupAction {
    Add,
    Remove,
}

/// Membership authority affects every policy use of this group, including
/// existing administration scopes. It never creates or modifies another grant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupAdminGrant {
    pub administrator: String,
    pub group: String,
    /// SameNode compares a candidate member with the administrator's node.
    pub members: Selector,
    pub actions: Vec<GroupAction>,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupChange {
    pub grant_id: String,
    pub group: String,
    pub member: String,
    pub action: GroupAction,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdminGrant {
    pub administrator: String,
    pub actor: Selector,
    pub peer: Selector,
    pub permissions: Vec<Permission>,
    /// Separate opt-in to manage selector rules, including future matches.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub selector_rules: bool,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleDecision {
    Allow,
    Deny,
    Inherit,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PermissionChange {
    pub grant_id: String,
    pub actor: String,
    pub peer: String,
    pub permission: Permission,
    pub decision: RuleDecision,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PermissionRuleChange {
    pub grant_id: String,
    pub actor: Selector,
    pub peer: Selector,
    pub permission: Permission,
    pub decision: RuleDecision,
}

impl Policy {
    pub fn group_admin_allows(
        &self,
        grant: &GroupAdminGrant,
        administrator: &Agent,
        member: &Agent,
        action: GroupAction,
        now: u64,
    ) -> bool {
        !administrator.revoked
            && !member.revoked
            && grant.administrator == administrator.id
            && grant.issued_at <= now
            && now < grant.expires_at
            && grant.actions.contains(&action)
            && self.matches(&grant.members, member, administrator)
    }

    pub fn admin_allows(
        &self,
        grant: &AdminGrant,
        administrator: &Agent,
        actor: &Agent,
        peer: &Agent,
        permission: Permission,
        now: u64,
    ) -> bool {
        !administrator.revoked
            && !actor.revoked
            && !peer.revoked
            && actor.id != peer.id
            && grant.administrator == administrator.id
            && grant.issued_at <= now
            && now < grant.expires_at
            && grant.permissions.contains(&permission)
            && self.matches(&grant.actor, actor, peer)
            && self.matches(&grant.peer, peer, actor)
    }

    /// Caller must authenticate and validate the ENTIRE batch against the
    /// original policy before invoking this. Only exact agent-pair rules change.
    pub fn apply_permission_changes(&mut self, changes: &[PermissionChange]) {
        for change in changes {
            self.replace_rule(
                Selector::Agent(change.actor.clone()),
                Selector::Agent(change.peer.clone()),
                change.permission,
                change.decision,
            );
        }
    }
    pub fn apply_permission_rules(&mut self, changes: &[PermissionRuleChange]) {
        for change in changes {
            self.replace_rule(
                change.actor.clone(),
                change.peer.clone(),
                change.permission,
                change.decision,
            );
        }
    }
    fn replace_rule(
        &mut self,
        actor: Selector,
        peer: Selector,
        permission: Permission,
        decision: RuleDecision,
    ) {
        self.rules
            .retain(|r| r.actor != actor || r.peer != peer || r.permission != permission);
        let effect = match decision {
            RuleDecision::Allow => Some(Effect::Allow),
            RuleDecision::Deny => Some(Effect::Deny),
            RuleDecision::Inherit => None,
        };
        if let Some(effect) = effect {
            self.rules.push(Rule {
                actor,
                peer,
                permission,
                effect,
            });
        }
    }
    pub fn admin_allows_rule(
        &self,
        grant: &AdminGrant,
        administrator: &Agent,
        change: &PermissionRuleChange,
        known: &BTreeMap<String, Agent>,
        now: u64,
    ) -> bool {
        !administrator.revoked
            && grant.administrator == administrator.id
            && grant.selector_rules
            && grant.issued_at <= now
            && now < grant.expires_at
            && grant.permissions.contains(&change.permission)
            && self.selector_within(&grant.actor, &change.actor, &change.peer, known)
            && self.selector_within(&grant.peer, &change.peer, &change.actor, known)
    }
    fn selector_within(
        &self,
        scope: &Selector,
        subject: &Selector,
        other: &Selector,
        known: &BTreeMap<String, Agent>,
    ) -> bool {
        if *scope == Selector::All || scope == subject {
            return true;
        }
        match (scope, subject) {
            (Selector::Node(node), Selector::Agent(id)) => {
                known.get(id).is_some_and(|a| a.node_id == *node)
            }
            (Selector::Group(group), Selector::Agent(id)) => self
                .groups
                .get(group)
                .is_some_and(|members| members.contains(id)),
            (Selector::SameNode, _) => {
                if *other == Selector::SameNode {
                    return true;
                }
                let node = |selector: &Selector| match selector {
                    Selector::Node(id) => Some(id.clone()),
                    Selector::Agent(id) => known.get(id).map(|a| a.node_id.clone()),
                    _ => None,
                };
                node(subject).is_some_and(|n| Some(n) == node(other))
            }
            _ => false,
        }
    }
}
