//! Agent-scoped edits use the same encrypted, durable owner proposal path.
use super::*;
use gent_protocol::administration::{MAX_PERMISSION_CHANGES, PermissionChange};
use uuid::Uuid;
pub(super) mod rules;

pub(super) fn edit_identity(edit: &ConfigurationEdit) -> Option<(&str, &str)> {
    match edit {
        ConfigurationEdit::AgentPermissions {
            administrator,
            request_id,
            ..
        }
        | ConfigurationEdit::AgentPermissionRules {
            administrator,
            request_id,
            ..
        } => Some((administrator, request_id)),
        _ => None,
    }
}

pub(super) fn request_id(administrator: &str, request: &str) -> Result<Uuid> {
    ensure!(
        requests::issued(request).is_some(),
        "request_id must be UUIDv7; use gent_request_ids"
    );
    Ok(gent_crypto::scoped_id(
        b"gent/agent-permissions/v1\0",
        &[
            administrator.as_bytes(),
            Uuid::parse_str(request)?.as_bytes(),
        ],
    ))
}

pub(super) fn validate_changes(changes: &[PermissionChange]) -> Result<()> {
    ensure!(
        !changes.is_empty() && changes.len() <= MAX_PERMISSION_CHANGES,
        "permission batch must contain 1 to 32 changes"
    );
    for (i, change) in changes.iter().enumerate() {
        for id in [&change.actor, &change.peer, &change.grant_id] {
            let parsed = Uuid::parse_str(id).context(UNAVAILABLE)?;
            ensure!(!parsed.is_nil() && parsed.to_string() == *id, UNAVAILABLE);
        }
        ensure!(
            !changes[..i].iter().any(|other| other.actor == change.actor
                && other.peer == change.peer
                && other.permission == change.permission),
            "duplicate permission change"
        );
    }
    Ok(())
}

impl StoreSession<'_> {
    pub(super) fn permission_admin_history(
        &self,
        administrator: Option<&str>,
        before: Option<u64>,
    ) -> Result<Value> {
        let rows = self.db.prepare("SELECT rowid,origin,id FROM configuration_edits WHERE
            CASE WHEN json_valid(edit) THEN json_extract(edit,'$.op') END IN ('agent_permissions','agent_permission_rules')
            AND (?1 IS NULL OR json_extract(edit,'$.administrator')=?1) AND rowid<?2 ORDER BY rowid DESC LIMIT 100")?
            .query_map(params![administrator,before.unwrap_or(i64::MAX as u64)],|r| Ok((r.get::<_,u64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let next = (rows.len() == 100).then(|| rows.last().unwrap().0);
        let mut entries = Vec::new();
        for (row, origin, id) in rows {
            let mut value = self.configuration_status_for(&origin, &id)?;
            value["audit_id"] = row.into();
            value["origin"] = origin.into();
            entries.push(value);
        }
        Ok(json!({"entries":entries,"next_before":next}))
    }
    fn admin_peer(&self, administrator: &Agent, id: &str) -> Result<Agent> {
        let peer = self.get_agent(id)?;
        ensure!(
            !peer.revoked
                && (peer.id == administrator.id
                    || self.config.policy.visible(administrator, &peer)),
            UNAVAILABLE
        );
        Ok(peer)
    }

    pub(super) fn permission_admin_check(
        &self,
        administrator: &Agent,
        actor: &str,
        peer: &str,
    ) -> Result<Value> {
        let actor = self.admin_peer(administrator, actor)?;
        let peer = self.admin_peer(administrator, peer)?;
        ensure!(actor.id != peer.id, UNAVAILABLE);
        let grants: Vec<_> = self.config.policy.admin_grants.iter().filter_map(|(id, grant)| {
            let permissions: Vec<_> = grant.permissions.iter().copied().filter(|p|
                self.config.policy.admin_allows(grant, administrator, &actor, &peer, *p, self.timestamp as u64)).collect();
            (!permissions.is_empty()).then(|| json!({"grant_id":id,"permissions":permissions,"expires_at":grant.expires_at}))
        }).collect();
        Ok(
            json!({"administrator":administrator.id,"actor":actor.id,"peer":peer.id,"grants":grants,
            "max_changes":MAX_PERMISSION_CHANGES,"decisions":["allow","deny","inherit"],
            "scope":"changes replace exact agent-pair rules only; broader rules still apply"}),
        )
    }

    pub(super) fn agent_permission_policy(
        &self,
        origin: &str,
        administrator: &str,
        changes: &[PermissionChange],
    ) -> Result<Policy> {
        validate_changes(changes)?;
        self.state.require_fresh(self.timestamp as u64)?;
        let admin = self.get_agent(administrator)?;
        ensure!(!admin.revoked && admin.node_id == origin, UNAVAILABLE);
        // Validate ALL scope/visibility checks against the pre-edit policy.
        // An earlier change in this batch cannot authorize a later one.
        for change in changes {
            let actor = self.admin_peer(&admin, &change.actor)?;
            let peer = self.admin_peer(&admin, &change.peer)?;
            let grant = self
                .config
                .policy
                .admin_grants
                .get(&change.grant_id)
                .context(UNAVAILABLE)?;
            ensure!(
                self.config.policy.admin_allows(
                    grant,
                    &admin,
                    &actor,
                    &peer,
                    change.permission,
                    self.timestamp as u64
                ),
                UNAVAILABLE
            );
        }
        let mut policy = self.config.policy.clone();
        policy.apply_permission_changes(changes);
        gent_crypto::validate_policy(&policy)?;
        Ok(policy)
    }

    pub(super) fn permission_preview(
        &self,
        administrator: &Agent,
        changes: &[PermissionChange],
    ) -> Result<Value> {
        let policy =
            self.agent_permission_policy(&administrator.node_id, &administrator.id, changes)?;
        let pairs: std::collections::BTreeSet<_> =
            changes.iter().map(|c| (&c.actor, &c.peer)).collect();
        let mut relationships = Vec::new();
        for (actor, peer) in pairs {
            relationships.push(json!({"actor":actor,"peer":peer,
                "policy":policy.relationship(&self.get_agent(actor)?, &self.get_agent(peer)?)}));
        }
        Ok(
            json!({"administrator":administrator.id,"changes":changes,"relationships":relationships,
            "scope":"preview only; apply rechecks all grants and visibility at acceptance; no reservation"}),
        )
    }

    pub(super) fn permission_apply(
        &mut self,
        administrator: &Agent,
        request: &str,
        changes: Vec<PermissionChange>,
    ) -> Result<Value> {
        let id = request_id(&administrator.id, request)?;
        self.submit_configuration(
            &id.to_string(),
            ConfigurationEdit::AgentPermissions {
                administrator: administrator.id.clone(),
                request_id: request.into(),
                changes,
            },
        )?;
        self.permission_request(administrator, request)
    }

    pub(super) fn permission_request(&self, administrator: &Agent, request: &str) -> Result<Value> {
        let id = request_id(&administrator.id, request)?;
        let value = self
            .configuration_status(&id.to_string())
            .map_err(|_| anyhow::anyhow!(UNAVAILABLE))?;
        ensure!(
            value["administrator"] == administrator.id && value["agent_request_id"] == request,
            UNAVAILABLE
        );
        let mut result = json!({"request_id":request,"administrator":administrator.id,
            "state":value["state"],"applied":value["applied"]});
        if value["state"] == "rejected" {
            result["reason"] = "permission change unavailable or no longer authorized".into();
        }
        // No global revision, writer identity, raw rejection or unrelated status.
        Ok(result)
    }
}
