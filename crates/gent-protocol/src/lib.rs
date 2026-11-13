//! Portable identities, local RPC types, and endpoint permission semantics.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub mod file_objects;
pub mod service;

pub const MAX_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_FRAME_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_EXCHANGE_MESSAGES: u32 = 32;
pub const EXCHANGE_TTL_SECONDS: i64 = 24 * 60 * 60;
pub const MAX_RELAY_GRANT_LIFETIME: u64 = 7 * 24 * 60 * 60;

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
    /// Explicit owner authorization to select a target for user relay work.
    /// Messaging permissions still apply. Empty maps preserve old signed bytes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub relay_grants: BTreeMap<String, RelayGrant>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayGrant {
    pub intermediary: String,
    pub target: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAttachment {
    pub id: String,
    pub intermediary: String,
    pub target: String,
    pub grant_id: String,
    pub security_mode: RelaySecurityMode,
    pub created_at: u64,
    pub expires_at: u64,
    pub detached: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelaySecurityMode {
    LocalDaemon,
    EncryptedDaemonLink,
}

/// Authenticated relay context inside the encrypted message, never inferred
/// from text. The grant delegates relay access, not human authorship.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayMessage {
    pub attachment_id: String,
    pub grant_id: String,
    pub turn_id: String,
    pub kind: RelayMessageKind,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayMessageKind {
    Request,
    Progress,
    Complete,
    Cancel,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayResponseKind {
    Progress,
    Complete,
    Cancelled,
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

/// Agent-visible attachment metadata. Decryption keys are a separate private
/// wire type and must never be serialized into an agent RPC or MCP response.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileDescriptor {
    pub id: String,
    pub name: String,
    pub media_type: String,
    pub byte_length: u64,
    pub sha256: String,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<FileDescriptor>,
    pub reply_to: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub acknowledged: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayMessage>,
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
    RequestIds {
        #[serde(default = "one_request_id")]
        count: u32,
    },
    FilePaths,
    FileImport {
        request_id: String,
        name: String,
        media_type: String,
    },
    FileStatus {
        file_id: String,
    },
    FileExport {
        file_id: String,
    },
    Send {
        recipient: String,
        request_id: String,
        text: String,
        #[serde(default)]
        files: Vec<FilePart>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        file_ids: Vec<String>,
    },
    Reply {
        message_id: String,
        request_id: String,
        text: String,
        #[serde(default)]
        files: Vec<FilePart>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        file_ids: Vec<String>,
    },
    Inbox,
    Ack {
        message_id: String,
    },
    MessageStatus {
        message_id: String,
    },
    RelayAttach {
        target: String,
        request_id: String,
    },
    RelayStatus {
        attachment_id: Option<String>,
    },
    RelayDetach {
        attachment_id: String,
    },
    RelaySend {
        attachment_id: String,
        request_id: String,
        text: String,
        #[serde(default)]
        files: Vec<FilePart>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        file_ids: Vec<String>,
    },
    RelayTurnStatus {
        turn_id: String,
        after_message_id: Option<String>,
    },
    RelayTurns {
        after_turn_id: Option<String>,
    },
    RelayNext,
    RelayRespond {
        turn_id: String,
        request_id: String,
        text: String,
        #[serde(default)]
        files: Vec<FilePart>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        file_ids: Vec<String>,
        outcome: RelayResponseKind,
    },
    RelayCancel {
        turn_id: String,
        request_id: String,
    },
}

fn one_request_id() -> u32 {
    1
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
    GrantRelay {
        grant_id: String,
        intermediary: String,
        target: String,
        lifetime_seconds: u64,
    },
    RevokeRelay {
        grant_id: String,
    },
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
    FilesStatus,
    HistoryStatus,
    HistoryClean {
        dry_run: bool,
    },
    TransportStatus,
    TransportClean {
        dry_run: bool,
    },
    FilesClean {
        dry_run: bool,
    },
    RelayGrants,
    RelayAttachments,
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
    /// Local owner administration; private invitation material is never an agent tool.
    Invitation {
        action: InvitationOp,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvitationOp {
    Create {
        request_id: String,
        can_configure: bool,
        continuation: Option<String>,
    },
    Activate {
        id: String,
    },
    Revoke {
        id: String,
    },
    List,
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
