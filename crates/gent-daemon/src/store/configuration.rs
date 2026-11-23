//! Durable owner and scoped-agent proposals, serialized by the active signing owner.
use super::*;
use crate::messages::{EditResult, Event};
use gent_crypto::{SignedConfigurationGrant, SignedState, scoped_id};
use uuid::Uuid;

pub(super) mod pending;
pub(super) mod routing;
pub(super) mod storage;
#[cfg(test)]
mod tests;

pub(super) fn schema(db: &Connection) -> Result<()> {
    storage::schema(db)
}
fn validate(edit: &ConfigurationEdit) -> Result<()> {
    match edit {
        ConfigurationEdit::EnrollNode {
            request,
            invitation,
            ..
        } => {
            ensure!(request.len() <= 8192, "enrollment request too large");
            gent_crypto::SignedEnrollment::decode(&STANDARD.decode(request)?)?.fingerprint()?;
            ensure!(
                invitation
                    .as_deref()
                    .is_none_or(gent_protocol::configuration_log::valid_id),
                "invalid enrollment invitation"
            );
        }
        ConfigurationEdit::RemoveNode { node_id }
        | ConfigurationEdit::DelegateNode { node_id, .. } => {
            ensure!(
                gent_protocol::configuration_log::valid_id(node_id),
                "invalid node identity"
            );
        }
        ConfigurationEdit::HostNode { node_id, parent } => {
            ensure!(
                gent_protocol::configuration_log::valid_id(node_id)
                    && gent_protocol::configuration_log::valid_id(parent)
                    && node_id != parent,
                "hosting requires distinct valid node identities"
            );
        }
        ConfigurationEdit::CreateGroup { name } | ConfigurationEdit::DeleteGroup { name } => {
            config::label(name)?
        }
        ConfigurationEdit::GroupMembers { group, members, .. } => {
            administration::groups::validate_members(group, members)?
        }
        ConfigurationEdit::GrantGroupAdmin {
            grant_id,
            administrator,
            group,
            members,
            actions,
            lifetime_seconds,
        } => {
            let mut policy = Policy::default();
            policy.groups.insert(group.clone(), vec![]);
            if let Selector::Group(name) = members {
                policy.groups.insert(name.clone(), vec![]);
            }
            policy.group_admin_grants.insert(
                grant_id.clone(),
                gent_protocol::administration::GroupAdminGrant {
                    administrator: administrator.clone(),
                    group: group.clone(),
                    members: members.clone(),
                    actions: actions.clone(),
                    issued_at: 0,
                    expires_at: *lifetime_seconds,
                },
            );
            gent_crypto::validate_policy(&policy)?;
        }
        ConfigurationEdit::RevokeGroupAdmin { grant_id } => {
            let id = Uuid::parse_str(grant_id)?;
            ensure!(
                !id.is_nil() && id.to_string() == *grant_id,
                "invalid group administration grant ID"
            );
        }
        ConfigurationEdit::AgentGroups {
            administrator,
            request_id,
            changes,
        } => {
            administration::request_id(administrator, request_id)?;
            administration::groups::validate_changes(changes)?;
        }
        ConfigurationEdit::SetPermissionRule {
            actor,
            peer,
            permission,
            effect,
        } => {
            let mut policy = Policy::default();
            for selector in [actor, peer] {
                if let Selector::Group(name) = selector {
                    policy.groups.insert(name.clone(), vec![]);
                }
            }
            policy.rules.push(gent_protocol::Rule {
                actor: actor.clone(),
                peer: peer.clone(),
                permission: *permission,
                effect: effect.unwrap_or(gent_protocol::Effect::Allow),
            });
            gent_crypto::validate_policy(&policy)?;
        }
        ConfigurationEdit::Policy { policy } => gent_crypto::validate_policy(policy)?,
        ConfigurationEdit::Replace {
            cluster_name,
            node_name,
            policy,
        } => {
            config::label(cluster_name)?;
            config::label(node_name)?;
            gent_crypto::validate_policy(policy)?;
        }
        ConfigurationEdit::RenameNode { name } => config::label(name)?,
        ConfigurationEdit::Renew => {}
        ConfigurationEdit::GrantRelay {
            grant_id,
            intermediary,
            target,
            lifetime_seconds,
        } => {
            let policy = Policy {
                relay_grants: [(
                    grant_id.clone(),
                    RelayGrant {
                        intermediary: intermediary.clone(),
                        target: target.clone(),
                        issued_at: 0,
                        expires_at: *lifetime_seconds,
                    },
                )]
                .into(),
                ..Default::default()
            };
            gent_crypto::validate_policy(&policy)?;
        }
        ConfigurationEdit::RevokeRelay { grant_id }
        | ConfigurationEdit::RevokePermissionAdmin { grant_id } => {
            let id = Uuid::parse_str(grant_id).context("relay grant ID must be a UUID")?;
            ensure!(
                !id.is_nil() && id.to_string() == *grant_id,
                "invalid relay grant ID"
            );
        }
        ConfigurationEdit::GrantPermissionAdmin {
            grant_id,
            administrator,
            actor,
            peer,
            permissions,
            selector_rules,
            lifetime_seconds,
        } => {
            let mut policy = Policy::default();
            // Validate input shape before queuing. Actual group existence is
            // checked against signed policy when the owner accepts the edit.
            for selector in [actor, peer] {
                if let Selector::Group(name) = selector {
                    policy.groups.insert(name.clone(), vec![]);
                }
            }
            policy.admin_grants.insert(
                grant_id.clone(),
                gent_protocol::administration::AdminGrant {
                    administrator: administrator.clone(),
                    actor: actor.clone(),
                    peer: peer.clone(),
                    permissions: permissions.clone(),
                    selector_rules: *selector_rules,
                    issued_at: 0,
                    expires_at: *lifetime_seconds,
                },
            );
            gent_crypto::validate_policy(&policy)?;
        }
        ConfigurationEdit::AgentPermissions {
            administrator,
            request_id,
            changes,
        } => {
            administration::request_id(administrator, request_id)?;
            administration::validate_changes(changes)?;
        }
        ConfigurationEdit::AgentPermissionRules {
            administrator,
            request_id,
            changes,
        } => {
            administration::request_id(administrator, request_id)?;
            administration::rules::validate_changes(changes)?;
        }
    }
    ensure!(
        serde_json::to_vec(edit)?.len() < crate::messages::MAX_RECORD_BYTES - 4096,
        "configuration proposal exceeds transport limit"
    );
    Ok(())
}
pub(super) fn fingerprint(edit: &ConfigurationEdit) -> Result<String> {
    Ok(hash(&serde_json::to_string(edit)?))
}
impl StoreSession<'_> {
    pub(super) fn configuration_writer(&self) -> Result<String> {
        if self.state.state().peer.is_some() {
            return self
                .state
                .state()
                .nodes
                .iter()
                .find(|(_, n)| n.can_configure && n.hosted_by.is_none())
                .map(|(id, _)| id.clone())
                .context("no configuration administrator");
        }
        if let Some(successor) = self
            .state
            .state()
            .owner_transitions
            .last()
            .and_then(|t| t.transition.successor.as_ref())
        {
            // The signed handoff pins the new writer even before its replacement
            // configuration streams arrive. Old streams remain recovery history.
            ensure!(
                self.state
                    .state()
                    .nodes
                    .get(&successor.node.id)
                    .is_some_and(|n| n.signing_key == successor.node.signing_key),
                "configuration writer is no longer enrolled"
            );
            return Ok(successor.node.id.clone());
        }
        ensure!(
            self.state.owner_epoch() == 0,
            "owner epoch has no runtime writer binding"
        );
        let mut writers = std::collections::BTreeSet::new();
        let mut query = self.db.prepare("SELECT grant FROM configuration_streams")?;
        for grant in query.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            let grant = SignedConfigurationGrant::decode(&grant?)?;
            grant.verify(self.state.anchor())?;
            let grant = grant.grant;
            if grant.owner_candidate.is_none()
                && grant.reader == self.identity.node.id()
                && grant.reader_key == self.identity.node.public_key()
                && self
                    .state
                    .state()
                    .nodes
                    .get(&grant.writer)
                    .is_some_and(|n| n.signing_key == grant.writer_key)
            {
                writers.insert(grant.writer);
            }
        }
        ensure!(
            writers.len() == 1,
            "configuration writer is unavailable or ambiguous"
        );
        Ok(writers.into_iter().next().unwrap())
    }
    pub(super) fn submit_configuration(
        &mut self,
        id: &str,
        edit: ConfigurationEdit,
    ) -> Result<Value> {
        let request = Uuid::parse_str(id).context("configuration request_id must be a UUID")?;
        ensure!(
            !request.is_nil() && request.to_string() == id,
            "invalid configuration request_id"
        );
        let origin = self.identity.node.id().to_owned();
        let previous: Option<String> = self
            .db
            .query_row(
                "SELECT fingerprint FROM configuration_edits WHERE origin=?1 AND id=?2",
                params![origin, id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(previous) = previous {
            ensure!(
                previous == fingerprint(&edit)?,
                "configuration request_id already used with another edit"
            );
            pending::retain(self.db, &origin, id, &edit)?;
            return self.configuration_status(id);
        }
        validate(&edit)?;
        if let Some((administrator, request_id)) = administration::edit_identity(&edit) {
            ensure!(
                administration::request_id(administrator, request_id)? == request,
                "invalid chat configuration request identity"
            );
            requests::admit(request_id, self.timestamp)?;
            self.validate_agent_configuration(&origin, &edit)?;
        }
        if matches!(&edit, ConfigurationEdit::Replace { .. }) {
            let disk = config::load_for_runtime(self.home)?;
            ensure!(
                disk.node.id == self.config.node.id && disk.cluster.id == self.config.cluster.id,
                "cannot change active identities while daemon runs"
            );
        }
        if self.state.state().peer.is_some() && self.identity.can_administer(&self.state) {
            ensure!(
                self.state
                    .state()
                    .nodes
                    .get(&origin)
                    .is_some_and(|n| n.can_configure),
                "this node cannot administer configuration"
            );
            storage::insert(
                self.db,
                &origin,
                id,
                &origin,
                &fingerprint(&edit)?,
                &edit,
                None,
            )?;
            pending::retain(self.db, &origin, id, &edit)?;
        } else if self.identity.is_current_owner(&self.state) {
            if handoff::frozen(self.db, &self.state)? {
                // The source cannot decide new work after issuing a handoff.
                // Keep its own edits durably, like other origins, without
                // inventing a self-addressed data stream. Epoch reconciliation
                // routes the retained input once the successor is accepted.
                storage::insert(
                    self.db,
                    &origin,
                    id,
                    &origin,
                    &fingerprint(&edit)?,
                    &edit,
                    None,
                )?;
                pending::retain(self.db, &origin, id, &edit)?;
            } else {
                self.accept_configuration(&origin, request, edit)?;
            }
        } else {
            ensure!(
                administration::edit_identity(&edit).is_some()
                    || self
                        .state
                        .state()
                        .nodes
                        .get(&origin)
                        .is_some_and(|n| n.can_configure),
                "node lacks configuration-management grant; grant it on the owner node"
            );
            let writer = self.configuration_writer()?;
            storage::insert(
                self.db,
                &origin,
                id,
                &writer,
                &fingerprint(&edit)?,
                &edit,
                None,
            )?;
            pending::retain(self.db, &origin, id, &edit)?;
            self.queue_configuration(&origin, request, &writer, edit)?;
        }
        self.configuration_status(id)
    }
    fn revision_for_edit(&self, origin: &str, edit: &ConfigurationEdit) -> Result<SignedState> {
        let owner = &*self.identity.signing_owner(self.db)?;
        self.revision_for_edit_with(origin, edit, owner)
    }
    pub(in crate::store) fn revision_for_edit_with(
        &self,
        origin: &str,
        edit: &ConfigurationEdit,
        owner: &dyn gent_crypto::peer::ConfigurationSigner,
    ) -> Result<SignedState> {
        validate(edit)?;
        if origin != self.identity.node.id() && administration::edit_identity(edit).is_none() {
            self.state.require_fresh(self.timestamp as u64)?;
            ensure!(
                self.state
                    .state()
                    .nodes
                    .get(origin)
                    .is_some_and(|n| n.can_configure),
                "configuration-management grant is absent or revoked"
            );
        }
        let timestamp = self.timestamp as u64;
        match edit {
            ConfigurationEdit::EnrollNode {
                request,
                can_configure,
                invitation,
            } => {
                let request = gent_crypto::SignedEnrollment::decode(&STANDARD.decode(request)?)?;
                if let Some(id) = invitation {
                    invitations::validate_queued_enrollment(
                        self.db,
                        &self.state,
                        self.identity,
                        id,
                        &request,
                        *can_configure,
                        timestamp,
                    )?;
                }
                let fingerprint = request.fingerprint()?;
                if request.request.replaces.is_some() {
                    self.state
                        .replace_node(owner, &request, fingerprint, *can_configure, timestamp)
                } else if *can_configure {
                    self.state
                        .enroll_configurator(owner, &request, fingerprint, timestamp)
                } else {
                    self.state.enroll(owner, &request, fingerprint, timestamp)
                }
            }
            ConfigurationEdit::RemoveNode { node_id } => {
                ensure!(
                    node_id != self.identity.node.id(),
                    "cannot remove this node from itself; use another enrolled node"
                );
                self.state.revoke_node(owner, node_id, timestamp)
            }
            ConfigurationEdit::DelegateNode { node_id, allow } => self
                .state
                .delegate_configuration(owner, node_id, *allow, timestamp),
            ConfigurationEdit::HostNode { node_id, parent } => {
                // Epoch-zero owner state has no signed owner/node binding.
                // Its runtime writer must reject hosting itself before signing.
                ensure!(
                    self.state.state().peer.is_some() || node_id != self.identity.node.id(),
                    "active owner node must remain native until another handoff"
                );
                self.state.host_node(owner, node_id, parent, timestamp)
            }
            ConfigurationEdit::CreateGroup { name } => {
                let mut policy = self.config.policy.clone();
                ensure!(!policy.groups.contains_key(name), "group already exists");
                policy.groups.insert(name.clone(), vec![]);
                self.state.set_policy(owner, policy, timestamp)
            }
            ConfigurationEdit::DeleteGroup { name } => {
                let mut policy = self.config.policy.clone();
                ensure!(policy.groups.remove(name).is_some(), "unknown group");
                self.state
                    .set_policy(owner, policy, timestamp)
                    .context("cannot delete a group still referenced by a rule or grant")
            }
            ConfigurationEdit::GroupMembers {
                group,
                members,
                action,
            } => {
                let mut policy = self.config.policy.clone();
                for member in members {
                    if *action == gent_protocol::administration::GroupAction::Add {
                        ensure!(!self.get_agent(member)?.revoked, UNAVAILABLE);
                    }
                    administration::groups::change_member(&mut policy, group, member, *action)?;
                }
                self.state.set_policy(owner, policy, timestamp)
            }
            ConfigurationEdit::GrantGroupAdmin {
                grant_id,
                administrator,
                group,
                members,
                actions,
                lifetime_seconds,
            } => {
                ensure!(!self.get_agent(administrator)?.revoked, UNAVAILABLE);
                let mut policy = self.config.policy.clone();
                ensure!(
                    !policy.group_admin_grants.contains_key(grant_id)
                        && !policy.admin_grants.contains_key(grant_id),
                    "administration grant ID already exists"
                );
                policy.group_admin_grants.insert(
                    grant_id.clone(),
                    gent_protocol::administration::GroupAdminGrant {
                        administrator: administrator.clone(),
                        group: group.clone(),
                        members: members.clone(),
                        actions: actions.clone(),
                        issued_at: timestamp,
                        expires_at: timestamp
                            .checked_add(*lifetime_seconds)
                            .context("administration expiry overflow")?,
                    },
                );
                self.state.set_policy(owner, policy, timestamp)
            }
            ConfigurationEdit::RevokeGroupAdmin { grant_id } => {
                let mut policy = self.config.policy.clone();
                ensure!(
                    policy.group_admin_grants.remove(grant_id).is_some()
                        || self.state.state().retired_admin_grants.contains(grant_id),
                    "unknown group administration grant ID"
                );
                self.state.set_policy(owner, policy, timestamp)
            }
            ConfigurationEdit::SetPermissionRule {
                actor,
                peer,
                permission,
                effect,
            } => {
                let mut policy = self.state.state().policy.clone();
                policy.rules.retain(|r| {
                    r.actor != *actor || r.peer != *peer || r.permission != *permission
                });
                if let Some(effect) = effect {
                    policy.rules.push(gent_protocol::Rule {
                        actor: actor.clone(),
                        peer: peer.clone(),
                        permission: *permission,
                        effect: *effect,
                    });
                }
                self.state.set_policy(owner, policy, timestamp)
            }
            ConfigurationEdit::Policy { policy } => {
                self.state.set_policy(owner, policy.clone(), timestamp)
            }
            ConfigurationEdit::Replace {
                cluster_name,
                node_name,
                policy,
            } => self.state.configure(
                owner,
                cluster_name,
                (origin, node_name),
                policy.clone(),
                timestamp,
            ),
            ConfigurationEdit::RenameNode { name } => self.state.configure(
                owner,
                &self.state.state().name,
                (origin, name),
                self.state.state().policy.clone(),
                timestamp,
            ),
            ConfigurationEdit::Renew => self.state.renew(owner, timestamp),
            ConfigurationEdit::GrantRelay {
                grant_id,
                intermediary,
                target,
                lifetime_seconds,
            } => {
                let actor = self.get_agent(intermediary)?;
                let peer = self.get_agent(target)?;
                ensure!(!actor.revoked && !peer.revoked, "relay endpoint is revoked");
                let mut policy = self.state.state().policy.clone();
                ensure!(
                    !policy.relay_grants.contains_key(grant_id),
                    "relay grant ID already exists"
                );
                policy.relay_grants.insert(
                    grant_id.clone(),
                    RelayGrant {
                        intermediary: intermediary.clone(),
                        target: target.clone(),
                        issued_at: timestamp,
                        expires_at: timestamp
                            .checked_add(*lifetime_seconds)
                            .context("relay expiry overflow")?,
                    },
                );
                self.state.set_policy(owner, policy, timestamp)
            }
            ConfigurationEdit::RevokeRelay { grant_id } => {
                let mut policy = self.state.state().policy.clone();
                ensure!(
                    policy.relay_grants.remove(grant_id).is_some()
                        || self.state.state().retired_relay_grants.contains(grant_id),
                    "unknown relay grant ID"
                );
                self.state.set_policy(owner, policy, timestamp)
            }
            ConfigurationEdit::GrantPermissionAdmin {
                grant_id,
                administrator,
                actor,
                peer,
                permissions,
                selector_rules,
                lifetime_seconds,
            } => {
                let admin = self.get_agent(administrator)?;
                ensure!(!admin.revoked, UNAVAILABLE);
                let mut policy = self.config.policy.clone();
                ensure!(
                    !policy.admin_grants.contains_key(grant_id),
                    "administration grant ID already exists"
                );
                policy.admin_grants.insert(
                    grant_id.clone(),
                    gent_protocol::administration::AdminGrant {
                        administrator: administrator.clone(),
                        actor: actor.clone(),
                        peer: peer.clone(),
                        permissions: permissions.clone(),
                        selector_rules: *selector_rules,
                        issued_at: timestamp,
                        expires_at: timestamp
                            .checked_add(*lifetime_seconds)
                            .context("administration expiry overflow")?,
                    },
                );
                self.state.set_policy(owner, policy, timestamp)
            }
            ConfigurationEdit::RevokePermissionAdmin { grant_id } => {
                let mut policy = self.config.policy.clone();
                ensure!(
                    policy.admin_grants.remove(grant_id).is_some()
                        || self.state.state().retired_admin_grants.contains(grant_id),
                    "unknown administration grant ID"
                );
                self.state.set_policy(owner, policy, timestamp)
            }
            ConfigurationEdit::AgentPermissions { .. }
            | ConfigurationEdit::AgentPermissionRules { .. }
            | ConfigurationEdit::AgentGroups { .. } => {
                let policy = self.validate_agent_configuration(origin, edit)?;
                self.state.set_policy(owner, policy, timestamp)
            }
        }
    }
    pub(super) fn accept_configuration(
        &mut self,
        origin: &str,
        request: Uuid,
        edit: ConfigurationEdit,
    ) -> Result<()> {
        ensure!(!request.is_nil(), "invalid configuration request identity");
        let id = request.to_string();
        if self.state.state().peer.is_none()
            && !self.identity.is_current_owner(&self.state)
            && self.identity.was_owner(&self.state)
        {
            return self.retain_retired_request(origin, request, &edit);
        }
        if let Some((administrator, request_id)) = administration::edit_identity(&edit) {
            validate(&edit)?;
            // Do not attribute audit records or charge an agent's quota to a
            // proposal from a different hosting node, even when rejecting it.
            ensure!(
                self.state
                    .transport_host(&self.get_agent(administrator)?.node_id)?
                    == origin,
                UNAVAILABLE
            );
            ensure!(
                administration::request_id(administrator, request_id)? == request,
                "invalid chat configuration request identity"
            );
        }
        if self.state.state().peer.is_some() {
            if !self.identity.can_administer(&self.state) {
                return Ok(());
            }
            return self.accept_peer_request(origin, &id, &edit);
        }
        let fingerprint = fingerprint(&edit)?;
        let saved: Option<(String, Option<Vec<u8>>, String)> = self
            .db
            .query_row(
                "SELECT fingerprint,result,writer FROM configuration_edits WHERE origin=?1 AND id=?2",
                params![origin, id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((previous, _, _)) = &saved {
            ensure!(
                *previous == fingerprint,
                "conflicting configuration request"
            );
        }
        let (result, decided_by) = if let Some((_, Some(result), writer)) = &saved {
            (
                serde_json::from_slice::<EditResult>(result)?,
                writer.clone(),
            )
        } else {
            // A handoff pauses new decisions. Propagate the pause without
            // recording a terminal rejection; the same request must survive it.
            // Already committed decisions can still return their exact result.
            self.identity.signing_owner(self.db)?;
            let result = match self.revision_for_edit(origin, &edit) {
                Ok(update) => {
                    // Storage failures propagate and roll back the entire import,
                    // including authority, result, and outgoing response.
                    self.state = self.identity.apply(self.db, update)?;
                    EditResult::Applied {
                        checkpoint: self.state.checkpoint().clone(),
                    }
                }
                Err(error) => EditResult::Rejected {
                    reason: storage::rejection_reason(error.to_string()),
                },
            };
            if saved.is_some() {
                let encoded = serde_json::to_vec(&result)?;
                storage::result_size(&encoded)?;
                self.db.execute(
                    "UPDATE configuration_edits SET writer=?1,result=?2 WHERE origin=?3 AND id=?4",
                    params![self.identity.node.id(), encoded, origin, id],
                )?;
                pending::release(self.db, origin, &id)?;
            } else {
                storage::insert(
                    self.db,
                    origin,
                    &id,
                    self.identity.node.id(),
                    &fingerprint,
                    &edit,
                    Some(&serde_json::to_vec(&result)?),
                )?;
            }
            (result, self.identity.node.id().to_owned())
        };
        if origin != self.identity.node.id() {
            self.queue(
                origin,
                routing::event_id(
                    true,
                    self.state.owner_epoch(),
                    origin,
                    request,
                    self.identity.node.id(),
                ),
                Event::ConfigurationResult {
                    request_id: request,
                    fingerprint,
                    result,
                    decided_by: (decided_by != self.identity.node.id()).then_some(decided_by),
                },
                None,
            )?;
        }
        Ok(())
    }
    pub(super) fn import_configuration_result(
        &self,
        peer: &str,
        request: Uuid,
        fingerprint: &str,
        result: EditResult,
    ) -> Result<()> {
        self.import_routed_configuration_result(peer, request, fingerprint, result, None)
    }
    pub(super) fn import_routed_configuration_result(
        &self,
        peer: &str,
        request: Uuid,
        fingerprint: &str,
        result: EditResult,
        decided_by: Option<&str>,
    ) -> Result<()> {
        if self.state.state().peer.is_some() {
            return Ok(());
        }
        let (writer, expected, previous): (String, String, Option<Vec<u8>>) = self.db.query_row(
            "SELECT writer,fingerprint,result FROM configuration_edits WHERE origin=?1 AND id=?2",
            params![self.identity.node.id(), request.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure!(
            (writer == peer
                || routing::known_route(
                    self.db,
                    self.identity.node.id(),
                    &request.to_string(),
                    peer
                )?)
                && expected == fingerprint,
            "configuration result belongs to another request or writer"
        );
        let decided_by = decided_by.unwrap_or(peer);
        ensure!(
            Uuid::parse_str(decided_by)
                .is_ok_and(|id| !id.is_nil() && id.to_string() == decided_by),
            "invalid deciding writer"
        );
        if let Some(previous) = &previous {
            ensure!(
                writer == decided_by && *previous == serde_json::to_vec(&result)?,
                "configuration result changed"
            );
            return Ok(());
        }
        if self.state.owner_epoch() > 0 && peer != self.configuration_writer()? {
            return Ok(());
        }
        ensure!(
            writer == peer
                && (decided_by == peer
                    || routing::known_route(
                        self.db,
                        self.identity.node.id(),
                        &request.to_string(),
                        decided_by
                    )?),
            "configuration decision has no matching delivery route"
        );
        match &result {
            EditResult::Applied { checkpoint } => {
                ensure!(
                    encrypted::history::checkpoint(
                        self.db,
                        checkpoint.revision,
                        self.state.anchor()
                    )? == *checkpoint,
                    "configuration result does not match signed authority"
                );
            }
            EditResult::Rejected { reason } => {
                ensure!(
                    reason.len() <= storage::MAX_REASON_BYTES,
                    "configuration rejection too large"
                )
            }
        }
        let encoded = serde_json::to_vec(&result)?;
        storage::result_size(&encoded)?;
        ensure!(
            previous.is_none_or(|saved| saved == encoded),
            "configuration result changed"
        );
        self.db.execute(
            "UPDATE configuration_edits SET result=?1,writer=?4 WHERE origin=?2 AND id=?3",
            params![
                encoded,
                self.identity.node.id(),
                request.to_string(),
                decided_by
            ],
        )?;
        pending::release(self.db, self.identity.node.id(), &request.to_string())?;
        Ok(())
    }
    pub(super) fn configuration_status(&self, id: &str) -> Result<Value> {
        self.configuration_status_for(self.identity.node.id(), id)
    }
    fn validate_agent_configuration(
        &self,
        origin: &str,
        edit: &ConfigurationEdit,
    ) -> Result<Policy> {
        match edit {
            ConfigurationEdit::AgentGroups {
                administrator,
                changes,
                ..
            } => self.agent_group_policy(origin, administrator, changes),
            ConfigurationEdit::AgentPermissions {
                administrator,
                changes,
                ..
            } => self.agent_permission_policy(origin, administrator, changes),
            ConfigurationEdit::AgentPermissionRules {
                administrator,
                changes,
                ..
            } => self.agent_permission_rule_policy(origin, administrator, changes),
            _ => anyhow::bail!("not a chat configuration edit"),
        }
    }
    pub(super) fn configuration_status_for(&self, origin: &str, id: &str) -> Result<Value> {
        let (writer, edit, result, compact): (String, Vec<u8>, Option<Vec<u8>>, bool) = self
            .db
            .query_row(
                "SELECT writer,edit,result,compact FROM configuration_edits WHERE origin=?1 AND id=?2",
                params![origin, id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .context("unknown configuration request")?;
        let mut status = json!({"request_id":id,"writer":writer,"state":"queued","applied":false});
        if result.is_none() {
            status["payload_retained"] = pending::ready(self.db, origin, id)?.into();
        }
        if let Some(result) = result {
            match serde_json::from_slice(&result)? {
                EditResult::Applied { checkpoint } => {
                    status["state"] = "applied".into();
                    status["applied"] = true.into();
                    status["revision"] = checkpoint.revision.into();
                }
                EditResult::Rejected { reason } => {
                    status["state"] = "rejected".into();
                    status["reason"] = reason.into();
                }
            }
        }
        storage::describe(&edit, compact, &mut status)?;
        Ok(status)
    }
    pub(super) fn configuration_requests(&self) -> Result<Value> {
        let ids = self
            .db
            .prepare(
                "SELECT id FROM configuration_edits WHERE origin=?1 ORDER BY rowid DESC LIMIT 100",
            )?
            .query_map([self.identity.node.id()], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Value::Array(
            ids.iter()
                .map(|id| self.configuration_status(id))
                .collect::<Result<Vec<_>>>()?,
        ))
    }
}
