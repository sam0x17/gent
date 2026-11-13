//! Portable identities, local RPC types, and endpoint permission semantics.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_FRAME_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_EXCHANGE_MESSAGES: u32 = 32;
pub const EXCHANGE_TTL_SECONDS: i64 = 24 * 60 * 60;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Agent {
    pub id: String,
    pub node_id: String,
    pub name: String,
    pub provider: String,
    pub last_seen: i64,
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Selector {
    All,
    Agent(String),
    Node(String),
    SameNode,
    Group(String),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Enumerate,
    Receive,
    Send,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub actor: Selector,
    pub peer: Selector,
    pub permission: Permission,
    pub effect: Effect,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Group membership is owner-managed, never supplied by an agent.
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
}

impl Policy {
    fn matches(&self, selector: &Selector, subject: &Agent, other: &Agent) -> bool {
        match selector {
            Selector::All => true,
            Selector::Agent(id) => subject.id == *id,
            Selector::Node(id) => subject.node_id == *id,
            Selector::SameNode => subject.node_id == other.node_id,
            Selector::Group(id) => self
                .groups
                .get(id)
                .is_some_and(|ids| ids.contains(&subject.id)),
        }
    }

    /// None means default denial; it is distinct from an explicit denial for reply grants.
    pub fn decision(&self, actor: &Agent, peer: &Agent, permission: Permission) -> Option<Effect> {
        if actor.revoked || peer.revoked {
            return Some(Effect::Deny);
        }
        let mut decision = None;
        for rule in &self.rules {
            if rule.permission == permission
                && self.matches(&rule.actor, actor, peer)
                && self.matches(&rule.peer, peer, actor)
            {
                if rule.effect == Effect::Deny {
                    return Some(Effect::Deny);
                }
                decision = Some(Effect::Allow);
            }
        }
        decision
    }

    pub fn visible(&self, actor: &Agent, peer: &Agent) -> bool {
        self.decision(actor, peer, Permission::Enumerate) == Some(Effect::Allow)
    }

    pub fn can_open(&self, sender: &Agent, recipient: &Agent) -> bool {
        self.visible(sender, recipient)
            && self.visible(recipient, sender)
            && self.decision(sender, recipient, Permission::Send) == Some(Effect::Allow)
            && self.decision(recipient, sender, Permission::Receive) == Some(Effect::Allow)
            && self.decision(sender, recipient, Permission::Receive) != Some(Effect::Deny)
    }

    /// Call only after verifying an accepted, unexpired exchange and its participants.
    pub fn can_reply(&self, sender: &Agent, recipient: &Agent) -> bool {
        self.visible(sender, recipient)
            && self.visible(recipient, sender)
            && self.decision(sender, recipient, Permission::Receive) != Some(Effect::Deny)
            && self.decision(recipient, sender, Permission::Receive) != Some(Effect::Deny)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilePart {
    pub name: String,
    pub media_type: String,
    pub data_base64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub id: String,
    pub exchange_id: String,
    pub sender: String,
    pub recipient: String,
    pub text: String,
    pub files: Vec<FilePart>,
    pub reply_to: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub acknowledged: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentOp {
    Register {
        name: String,
        provider: String,
    },
    Identity,
    Agents,
    Send {
        recipient: String,
        request_id: String,
        text: String,
        #[serde(default)]
        files: Vec<FilePart>,
    },
    Reply {
        message_id: String,
        request_id: String,
        text: String,
        #[serde(default)]
        files: Vec<FilePart>,
    },
    Inbox,
    Ack {
        message_id: String,
    },
    MessageStatus {
        message_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConfigurationEdit {
    Policy {
        policy: Policy,
    },
    Replace {
        cluster_name: String,
        node_name: String,
        policy: Policy,
    },
    RenameNode {
        name: String,
    },
    Renew,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerOp {
    Configure {
        request_id: String,
        edit: ConfigurationEdit,
    },
    ConfigurationRequests {
        request_id: Option<String>,
    },
    DelegateConfiguration {
        node_id: String,
        allow: bool,
    },
    Status,
    Nodes,
    Agents,
    Providers,
    SetPolicy {
        policy: Policy,
    },
    Renew,
    RenameNode {
        name: String,
    },
    Revoke {
        agent_id: String,
    },
    /// Owner-only bootstrap over an independently authenticated private channel.
    Pair {
        cluster_id: String,
        action: PairingOp,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum PairingOp {
    Snapshot,
    Enroll {
        request: String,
    },
    Configuration {
        request_id: String,
        peer: String,
        key_package: String,
    },
    History {
        revision: u64,
        digest: [u8; 32],
    },
    Data {
        request_id: String,
        peer: String,
        key_package: String,
        legacy_agents: Vec<String>,
    },
    AcceptData {
        peer: String,
        packet: String,
        outgoing_group: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Agent { credential: String, action: AgentOp },
    Owner { credential: String, action: OwnerOp },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum Response {
    Ok(serde_json::Value),
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    fn agent(id: &str, node: &str) -> Agent {
        Agent {
            id: id.into(),
            node_id: node.into(),
            name: id.into(),
            provider: "anything".into(),
            last_seen: 0,
            revoked: false,
        }
    }
    fn allow(policy: &mut Policy, a: &str, b: &str, permission: Permission) {
        policy.rules.push(Rule {
            actor: Selector::Agent(a.into()),
            peer: Selector::Agent(b.into()),
            permission,
            effect: Effect::Allow,
        });
    }
    #[test]
    fn default_deny_and_scoped_reply() {
        let (a, b) = (agent("a", "node"), agent("b", "node"));
        let mut p = Policy::default();
        assert!(!p.can_open(&a, &b));
        allow(&mut p, "a", "b", Permission::Enumerate);
        allow(&mut p, "b", "a", Permission::Enumerate);
        allow(&mut p, "a", "b", Permission::Send);
        allow(&mut p, "b", "a", Permission::Receive);
        assert!(p.can_open(&a, &b));
        assert!(!p.can_open(&b, &a));
        assert!(p.can_reply(&b, &a));
        p.rules.push(Rule {
            actor: Selector::Agent("b".into()),
            peer: Selector::Agent("a".into()),
            permission: Permission::Send,
            effect: Effect::Deny,
        });
        assert!(p.can_reply(&b, &a));
        p.rules.push(Rule {
            actor: Selector::Agent("a".into()),
            peer: Selector::Agent("b".into()),
            permission: Permission::Receive,
            effect: Effect::Deny,
        });
        assert!(!p.can_reply(&b, &a));
        assert!(!p.can_open(&a, &b));
    }
    #[test]
    fn denials_override_same_node_grants_and_location_changes() {
        let (a, mut b) = (agent("a", "one"), agent("b", "one"));
        let mut p = Policy::default();
        for permission in [Permission::Enumerate, Permission::Send, Permission::Receive] {
            p.rules.push(Rule {
                actor: Selector::All,
                peer: Selector::SameNode,
                permission,
                effect: Effect::Allow,
            });
        }
        assert!(p.can_open(&a, &b));
        b.node_id = "two".into();
        assert!(!p.can_open(&a, &b));
        b.node_id = "one".into();
        p.rules.insert(
            0,
            Rule {
                actor: Selector::Agent("a".into()),
                peer: Selector::All,
                permission: Permission::Enumerate,
                effect: Effect::Deny,
            },
        );
        assert!(!p.can_open(&a, &b));
        assert!(!p.can_reply(&a, &b));
    }
    #[test]
    fn authenticated_groups_and_revocation() {
        let (a, mut b) = (agent("a", "one"), agent("b", "two"));
        let mut p = Policy::default();
        p.groups.insert("team".into(), vec!["a".into(), "b".into()]);
        for permission in [Permission::Enumerate, Permission::Send, Permission::Receive] {
            p.rules.push(Rule {
                actor: Selector::Group("team".into()),
                peer: Selector::Group("team".into()),
                permission,
                effect: Effect::Allow,
            });
        }
        assert!(p.can_open(&a, &b));
        b.revoked = true;
        assert!(!p.can_open(&a, &b));
        assert!(!p.can_reply(&b, &a));
    }
}
