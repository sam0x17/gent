//! Effective policy gates shared with message authorization. Rule traces are
//! for the local owner only; agent tools must first verify peer visibility.
use super::*;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Blocker {
    SenderCannotEnumerate,
    RecipientCannotEnumerate,
    SenderSendNotAllowed,
    RecipientReceiveNotAllowed,
    SenderReceiveDenied,
    RecipientReceiveDenied,
    SameAgent,
}
#[derive(Debug, Serialize)]
pub struct Gate {
    pub allowed: bool,
    pub blocked_by: Vec<Blocker>,
}
impl Gate {
    fn new(checks: impl IntoIterator<Item = (Blocker, bool)>, same: bool) -> Self {
        let mut blocked_by: Vec<_> = checks
            .into_iter()
            .filter_map(|(reason, allowed)| (!allowed).then_some(reason))
            .collect();
        if same {
            blocked_by.push(Blocker::SameAgent);
        }
        Self {
            allowed: blocked_by.is_empty(),
            blocked_by,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Relationship {
    pub enumerate: bool,
    pub send_unsolicited: Gate,
    pub receive_unsolicited: Gate,
    /// Policy only. A valid received message/exchange and remaining quota are
    /// still required; this is never an issued reply grant.
    pub reply_policy: Gate,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    ExplicitDeny,
    NoMatchingRule,
    Revoked,
}
#[derive(Debug, Serialize)]
pub struct Trace {
    pub permission: Permission,
    pub decision: Decision,
    /// Zero-based positions in the current signed policy's rules array.
    pub matching_rules: Vec<usize>,
}
impl Policy {
    pub(super) fn matching_rules<'a>(
        &'a self,
        actor: &'a Agent,
        peer: &'a Agent,
        permission: Permission,
    ) -> impl Iterator<Item = (usize, &'a Rule)> {
        self.rules.iter().enumerate().filter(move |(_, rule)| {
            rule.permission == permission
                && self.matches(&rule.actor, actor, peer)
                && self.matches(&rule.peer, peer, actor)
        })
    }
    fn checks<'a>(
        &'a self,
        sender: &'a Agent,
        recipient: &'a Agent,
        kinds: &'static [Blocker],
    ) -> impl Iterator<Item = (Blocker, bool)> + 'a {
        kinds.iter().copied().map(move |reason| {
            let allowed = match reason {
                Blocker::SenderCannotEnumerate => self.visible(sender, recipient),
                Blocker::RecipientCannotEnumerate => self.visible(recipient, sender),
                Blocker::SenderSendNotAllowed => {
                    self.decision(sender, recipient, Permission::Send) == Some(Effect::Allow)
                }
                Blocker::RecipientReceiveNotAllowed => {
                    self.decision(recipient, sender, Permission::Receive) == Some(Effect::Allow)
                }
                Blocker::SenderReceiveDenied => {
                    self.decision(sender, recipient, Permission::Receive) != Some(Effect::Deny)
                }
                Blocker::RecipientReceiveDenied => {
                    self.decision(recipient, sender, Permission::Receive) != Some(Effect::Deny)
                }
                Blocker::SameAgent => sender.id != recipient.id,
            };
            (reason, allowed)
        })
    }
    pub(super) fn open_checks<'a>(
        &'a self,
        sender: &'a Agent,
        recipient: &'a Agent,
    ) -> impl Iterator<Item = (Blocker, bool)> + 'a {
        self.checks(
            sender,
            recipient,
            &[
                Blocker::SenderCannotEnumerate,
                Blocker::RecipientCannotEnumerate,
                Blocker::SenderSendNotAllowed,
                Blocker::RecipientReceiveNotAllowed,
                Blocker::SenderReceiveDenied,
            ],
        )
    }
    pub(super) fn reply_checks<'a>(
        &'a self,
        sender: &'a Agent,
        recipient: &'a Agent,
    ) -> impl Iterator<Item = (Blocker, bool)> + 'a {
        self.checks(
            sender,
            recipient,
            &[
                Blocker::SenderCannotEnumerate,
                Blocker::RecipientCannotEnumerate,
                Blocker::SenderReceiveDenied,
                Blocker::RecipientReceiveDenied,
            ],
        )
    }
    pub fn relationship(&self, actor: &Agent, peer: &Agent) -> Relationship {
        let same = actor.id == peer.id;
        Relationship {
            enumerate: self.visible(actor, peer),
            send_unsolicited: Gate::new(self.open_checks(actor, peer), same),
            receive_unsolicited: Gate::new(self.open_checks(peer, actor), same),
            reply_policy: Gate::new(self.reply_checks(actor, peer), same),
        }
    }
    pub fn trace(&self, actor: &Agent, peer: &Agent) -> Vec<Trace> {
        [Permission::Enumerate, Permission::Receive, Permission::Send]
            .into_iter()
            .map(|permission| Trace {
                permission,
                decision: if actor.revoked || peer.revoked {
                    Decision::Revoked
                } else {
                    match self.decision(actor, peer, permission) {
                        Some(Effect::Allow) => Decision::Allow,
                        Some(Effect::Deny) => Decision::ExplicitDeny,
                        None => Decision::NoMatchingRule,
                    }
                },
                matching_rules: self
                    .matching_rules(actor, peer, permission)
                    .map(|(index, _)| index)
                    .collect(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
