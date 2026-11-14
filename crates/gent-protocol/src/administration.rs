//! Scoped permission administration. Grants never confer discovery or further
//! delegation. Endpoints must authenticate the administrator and peer visibility.
use super::*;

pub const MAX_ADMIN_GRANT_LIFETIME: u64 = 7 * 24 * 60 * 60;
pub const MAX_PERMISSION_CHANGES: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdminGrant {
    pub administrator: String,
    pub actor: Selector,
    pub peer: Selector,
    pub permissions: Vec<Permission>,
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

impl Policy {
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
            let actor = Selector::Agent(change.actor.clone());
            let peer = Selector::Agent(change.peer.clone());
            self.rules.retain(|r| {
                r.actor != actor || r.peer != peer || r.permission != change.permission
            });
            let effect = match change.decision {
                RuleDecision::Allow => Some(Effect::Allow),
                RuleDecision::Deny => Some(Effect::Deny),
                RuleDecision::Inherit => None,
            };
            if let Some(effect) = effect {
                self.rules.push(Rule {
                    actor,
                    peer,
                    permission: change.permission,
                    effect,
                });
            }
        }
    }
}
