//! Portable identities, local RPC types, and endpoint permission semantics.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub mod administration;
pub mod configuration_log;
pub mod directory;
pub mod file_objects;
pub mod history;
pub mod hosted_mcp;
pub mod owner_transfer;
pub mod permissions;
pub mod service;
pub mod transport_batch;
pub mod transport_exchange;
pub mod transport_sweep;
pub mod transport_watch;
pub mod transport_wss;
pub mod wake;
pub mod web_failover;
pub mod work;

pub const MAX_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_FRAME_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_EXCHANGE_MESSAGES: u32 = 32;
pub const EXCHANGE_TTL_SECONDS: i64 = 24 * 60 * 60;
pub const MAX_RELAY_GRANT_LIFETIME: u64 = 7 * 24 * 60 * 60;
pub const MAX_REGISTRATION_GENERATION: u64 = (1 << 53) - 1;

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
    #[serde(alias = "chat")]
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
    /// Signed membership, changed by the owner or a separately delegated chat.
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    /// Legacy relay authorizations, retained to verify existing signed state.
    /// New relay selections use ordinary messaging permissions alone.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub relay_grants: BTreeMap<String, RelayGrant>,
    /// Editing authority is separate from message permissions. Empty maps keep
    /// previously signed policy bytes unchanged.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub admin_grants: BTreeMap<String, administration::AdminGrant>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub group_admin_grants: BTreeMap<String, administration::GroupAdminGrant>,
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
    /// Present only on selections created by older daemons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    pub security_mode: RelaySecurityMode,
    pub created_at: u64,
    /// New selections last until detached; legacy selections retain their expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub detached: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelaySecurityMode {
    LocalDaemon,
    EncryptedDaemonLink,
}

/// Authenticated relay context inside the encrypted message, never inferred
/// from text. Relay access follows messaging policy, not asserted human authorship.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayMessage {
    pub attachment_id: String,
    /// Retained on legacy turns so their original restrictions and retries survive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
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
        for (_, rule) in self.matching_rules(actor, peer, permission) {
            if rule.effect == Effect::Deny {
                return Some(Effect::Deny);
            }
            decision = Some(Effect::Allow);
        }
        decision
    }

    pub fn visible(&self, actor: &Agent, peer: &Agent) -> bool {
        self.decision(actor, peer, Permission::Enumerate) == Some(Effect::Allow)
    }

    pub fn can_open(&self, sender: &Agent, recipient: &Agent) -> bool {
        self.open_checks(sender, recipient)
            .all(|(_, allowed)| allowed)
    }

    /// Call only after verifying an accepted, unexpired exchange and its participants.
    pub fn can_reply(&self, sender: &Agent, recipient: &Agent) -> bool {
        self.reply_checks(sender, recipient)
            .all(|(_, allowed)| allowed)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilePart {
    pub name: String,
    pub media_type: String,
    pub data_base64: String,
}

/// Chat-visible attachment metadata. Decryption keys are a separate private
/// wire type and must never be serialized into a chat RPC or MCP response.
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
    /// Rename only this authenticated registration, preserving its identity.
    Rename {
        name: String,
        expected_generation: u64,
    },
    /// Current relationship with one visible peer; never exposes raw policy.
    PermissionCheck {
        peer: String,
    },
    PermissionAdminCheck {
        actor: String,
        peer: String,
    },
    PermissionPreview {
        changes: Vec<administration::PermissionChange>,
    },
    PermissionApply {
        request_id: String,
        changes: Vec<administration::PermissionChange>,
    },
    PermissionRequest {
        request_id: String,
    },
    PermissionRuleScopes,
    GroupAdminScopes,
    GroupMembers {
        group: String,
    },
    GroupPreview {
        changes: Vec<administration::GroupChange>,
    },
    GroupApply {
        request_id: String,
        changes: Vec<administration::GroupChange>,
    },
    GroupRequest {
        request_id: String,
    },
    PermissionRulePreview {
        changes: Vec<administration::PermissionRuleChange>,
    },
    PermissionRuleApply {
        request_id: String,
        changes: Vec<administration::PermissionRuleChange>,
    },
    Agents,
    Resolve {
        name: String,
        node: Option<String>,
        provider: Option<String>,
    },
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
    /// Private local RPC preflight; absent from the MCP tool surface.
    FileReceiveStatus {
        file: file_objects::IncomingFile,
    },
    /// Header for a bounded binary body after the daemon's ready response.
    FileReceive {
        file: file_objects::IncomingFile,
        byte_length: u64,
        sha256: String,
    },
    /// Constructed only by the local transport after receiving the whole body.
    #[serde(skip)]
    FileReceiveData {
        file: file_objects::IncomingFile,
        bytes: zeroize::Zeroizing<Vec<u8>>,
    },
    FileRead {
        file_id: String,
        chunk_index: u32,
    },
    FileView {
        file_id: String,
    },
    /// Local historical imports explicitly assigned to this authenticated chat.
    HistoryImports,
    HistoryMessages {
        import_id: String,
        #[serde(default)]
        after: u64,
    },
    HistoryFileRead {
        import_id: String,
        message_id: String,
        file_index: u32,
        chunk_index: u32,
    },
    HistoryFileView {
        import_id: String,
        message_id: String,
        file_index: u32,
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
    /// Response-required send; uses an isolated relay turn without changing the
    /// chat's persistent relay selection. MCP waits outside the daemon lock.
    RequestReply {
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
    /// Local host adapter operations; not exposed as model-callable MCP tools.
    WakePending,
    WakeClaim {
        message_id: String,
        attempt_id: String,
        target: wake::WakeTarget,
    },
    /// Recheck an existing claim without creating or renewing submission rights.
    WakeCheck {
        message_id: String,
        attempt_id: String,
        target: wake::WakeTarget,
    },
    WakeSubmitted {
        message_id: String,
        attempt_id: String,
        submission_id: String,
    },
    /// Native adapter APIs, deliberately absent from model-callable MCP tools.
    WakeDirectClaim {
        message_id: String,
        attempt_id: String,
        target: wake::WakeTarget,
    },
    WakeDirectPending {
        target: wake::WakeTarget,
    },
    WakeDirectRead {
        message_id: String,
        attempt_id: String,
        target: wake::WakeTarget,
    },
    WakeDirectObserve {
        message_id: String,
        attempt_id: String,
        target: wake::WakeTarget,
        turn_id: String,
    },
    WakeDirectComplete {
        message_id: String,
        attempt_id: String,
        target: wake::WakeTarget,
        turn_id: String,
        text: String,
    },
    WorkStatus {
        message_id: String,
    },
    WorkBegin {
        message_id: String,
        #[serde(default)]
        expect_revision: u64,
        description: String,
    },
    WorkComplete {
        message_id: String,
        expect_revision: u64,
        note: String,
    },
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
    EnrollNode {
        request: String,
        can_configure: bool,
        invitation: Option<String>,
    },
    RemoveNode {
        node_id: String,
    },
    DelegateNode {
        node_id: String,
        allow: bool,
    },
    /// Administrator-approved chat transport delegation; does not grant configuration access.
    HostNode {
        node_id: String,
        parent: String,
    },
    CreateGroup {
        name: String,
    },
    DeleteGroup {
        name: String,
    },
    GroupMembers {
        group: String,
        members: Vec<String>,
        action: administration::GroupAction,
    },
    GrantGroupAdmin {
        grant_id: String,
        administrator: String,
        group: String,
        members: Selector,
        actions: Vec<administration::GroupAction>,
        lifetime_seconds: u64,
    },
    RevokeGroupAdmin {
        grant_id: String,
    },
    AgentGroups {
        administrator: String,
        request_id: String,
        changes: Vec<administration::GroupChange>,
    },
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
    GrantPermissionAdmin {
        grant_id: String,
        administrator: String,
        actor: Selector,
        peer: Selector,
        permissions: Vec<Permission>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        selector_rules: bool,
        lifetime_seconds: u64,
    },
    RevokePermissionAdmin {
        grant_id: String,
    },
    /// Internal authenticated proposal; MCP supplies neither administrator nor
    /// origin node. The owner rechecks both and every grant before accepting it.
    AgentPermissions {
        administrator: String,
        request_id: String,
        changes: Vec<administration::PermissionChange>,
    },
    AgentPermissionRules {
        administrator: String,
        request_id: String,
        changes: Vec<administration::PermissionRuleChange>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerOp {
    /// Scoped proof for the hosted checkpoint service; never exports a signing key.
    WebAdmission {
        node_id: String,
        body_hash: [u8; 32],
    },
    WebCheckpoint {
        node_id: String,
    },
    WebCommit {
        node_id: String,
        revision: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epoch: Option<u64>,
    },
    WebLease {
        node_id: String,
        seconds: u64,
    },
    /// Absolute Unix deadline bounded by the start of the authority request.
    /// Zero closes the epoch and fences delayed grants for the same session.
    WebGrant {
        node_id: String,
        epoch: u64,
        expires_at: u64,
    },
    RestoreWebNode {
        node_id: String,
        home: std::path::PathBuf,
        checkpoint: std::path::PathBuf,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epoch: Option<u64>,
    },
    PreparePeerConfiguration,
    Groups {
        name: Option<String>,
    },
    GroupAdmins,
    GroupAdminHistory {
        administrator: Option<String>,
        before: Option<u64>,
    },
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
    /// Local signing-owner administration, never exposed as a chat tool.
    RemoveNode {
        node_id: String,
    },
    NodeRemovals {
        after: Option<String>,
        pending_only: bool,
    },
    ConfirmNodeRemoval {
        node_id: String,
        revision: u64,
    },
    Status,
    /// Move a stopped, locally owned web node's retained state into this daemon.
    PrepareHostedNode {
        node_id: String,
        home: std::path::PathBuf,
    },
    /// Read-only local-owner diagnostics; never advances clocks or projects files.
    Diagnose,
    PermissionExplain {
        actor: String,
        peer: String,
    },
    PermissionAdmins,
    PermissionAdminHistory {
        administrator: Option<String>,
        before: Option<u64>,
    },
    Nodes,
    RefreshNodes,
    Agents,
    ObserveActivity {
        agent_id: String,
        last_activity_at: i64,
    },
    ClearRetiredAgents {
        dry_run: bool,
    },
    Resolve {
        name: String,
        node: Option<String>,
        provider: Option<String>,
    },
    Agent {
        agent_id: String,
    },
    RenameAgent {
        agent_id: String,
        name: String,
        expected_generation: u64,
    },
    Providers,
    FilesStatus,
    HistoryStatus,
    /// Private recovery evidence. These operations grant no replacement authority.
    RecoveryChallenge,
    OwnerHandoffStatus,
    OwnerTransfer {
        action: owner_transfer::OwnerTransferOp,
    },
    RecoveryObserve {
        challenge: String,
    },
    WorkList {
        after_message_id: Option<String>,
    },
    WakeList {
        after_message_id: Option<String>,
    },
    WakeStatus,
    /// Owner-only pending recipient IDs; does not expose message content.
    WakePendingAgents {
        after: Option<String>,
    },
    WakeClean {
        dry_run: bool,
    },
    WakeShow {
        message_id: String,
    },
    WorkShow {
        message_id: String,
    },
    WorkReconcile {
        message_id: String,
        expect_revision: u64,
        resolution: work::WorkResolution,
        note: String,
    },
    HistoryImports,
    AgentRecover {
        directory: String,
        manifest_sha256: String,
        source_agent: String,
        agent_credential: String,
        name: String,
        provider: String,
    },
    HistoryImport {
        directory: String,
        manifest_sha256: String,
        source_agent: String,
        target_agent: String,
        restore_revision: Option<u64>,
    },
    HistoryRemove {
        import_id: String,
        expected_revision: u64,
    },
    HistoryClean {
        dry_run: bool,
    },
    TransportStatus,
    WebDeliveryDemand {
        node_id: String,
    },
    WebDeliveryChecked {
        node_id: String,
        message_id: String,
    },
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
    /// Local owner administration; private invitation material is never a chat tool.
    Invitation {
        action: InvitationOp,
    },
    /// Local administrator request, forwarded over authenticated node streams.
    NodeInvite {
        request_id: String,
        name: String,
        can_configure: bool,
        activate: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvitationOp {
    Create {
        request_id: String,
        can_configure: bool,
        continuation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        replace_node: Option<String>,
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
    Agent {
        credential: String,
        action: AgentOp,
    },
    Owner {
        credential: String,
        action: OwnerOp,
    },
    /// Private gateway-to-daemon RPC. The node scope is never supplied by MCP.
    HostedAgent {
        node_id: String,
        gateway_credential: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epoch: Option<u64>,
        credential: String,
        action: AgentOp,
    },
    HostedStatus {
        node_id: String,
        gateway_credential: String,
    },
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
