//! Durable owner and scoped-agent proposals, serialized by the active signing owner.
use super::*;
use crate::messages::{EditResult, Event};
use gent_crypto::{SignedConfigurationGrant, SignedState, scoped_id};
use uuid::Uuid;

pub(super) mod storage;

pub(super) fn schema(db: &Connection) -> Result<()> {
    storage::schema(db)
}
fn validate(edit: &ConfigurationEdit) -> Result<()> {
    match edit {
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
fn fingerprint(edit: &ConfigurationEdit) -> Result<String> {
    Ok(hash(&serde_json::to_string(edit)?))
}
impl StoreSession<'_> {
    pub(super) fn configuration_writer(&self) -> Result<String> {
        let mut writers = std::collections::BTreeSet::new();
        let mut query = self.db.prepare("SELECT grant FROM configuration_streams")?;
        for grant in query.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            let grant = SignedConfigurationGrant::decode(&grant?)?;
            grant.verify(self.state.anchor())?;
            let grant = grant.grant;
            if grant.reader == self.identity.node.id()
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
            return self.configuration_status(id);
        }
        validate(&edit)?;
        if let Some((administrator, request_id)) = administration::edit_identity(&edit) {
            ensure!(
                administration::request_id(administrator, request_id)? == request,
                "invalid agent configuration request identity"
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
        if self.identity.owner.is_some() {
            self.accept_configuration(&origin, request, edit)?;
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
            self.queue(
                &writer,
                scoped_id(
                    b"gent/configuration-request/v1\0",
                    &[origin.as_bytes(), request.as_bytes()],
                ),
                Event::ConfigurationRequest {
                    request_id: request,
                    edit: Box::new(edit),
                },
                None,
            )?;
        }
        self.configuration_status(id)
    }
    fn revision_for_edit(&self, origin: &str, edit: &ConfigurationEdit) -> Result<SignedState> {
        let owner = self.identity.signing_owner()?;
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
            | ConfigurationEdit::AgentPermissionRules { .. } => {
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
        self.identity.signing_owner()?;
        ensure!(!request.is_nil(), "invalid configuration request identity");
        let id = request.to_string();
        if let Some((administrator, request_id)) = administration::edit_identity(&edit) {
            validate(&edit)?;
            // Do not attribute audit records or charge an agent's quota to a
            // proposal from a different hosting node, even when rejecting it.
            ensure!(
                self.get_agent(administrator)?.node_id == origin,
                UNAVAILABLE
            );
            ensure!(
                administration::request_id(administrator, request_id)? == request,
                "invalid agent configuration request identity"
            );
        }
        let fingerprint = fingerprint(&edit)?;
        let saved: Option<(String, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT fingerprint,result FROM configuration_edits WHERE origin=?1 AND id=?2",
                params![origin, id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let result = if let Some((previous, result)) = saved {
            ensure!(previous == fingerprint, "conflicting configuration request");
            serde_json::from_slice::<EditResult>(&result)?
        } else {
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
            storage::insert(
                self.db,
                origin,
                &id,
                self.identity.node.id(),
                &fingerprint,
                &edit,
                Some(&serde_json::to_vec(&result)?),
            )?;
            result
        };
        if origin != self.identity.node.id() {
            self.queue(
                origin,
                scoped_id(
                    b"gent/configuration-result/v1\0",
                    &[origin.as_bytes(), request.as_bytes()],
                ),
                Event::ConfigurationResult {
                    request_id: request,
                    fingerprint,
                    result,
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
        let (writer, expected, previous): (String, String, Option<Vec<u8>>) = self.db.query_row(
            "SELECT writer,fingerprint,result FROM configuration_edits WHERE origin=?1 AND id=?2",
            params![self.identity.node.id(), request.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure!(
            writer == peer && expected == fingerprint,
            "configuration result belongs to another request or writer"
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
            "UPDATE configuration_edits SET result=?1 WHERE origin=?2 AND id=?3",
            params![encoded, self.identity.node.id(), request.to_string()],
        )?;
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
            _ => anyhow::bail!("not an agent configuration edit"),
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
