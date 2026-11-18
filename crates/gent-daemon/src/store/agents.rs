//! Registration labels use the hosting node's existing ordered generations.
//! Renaming never replaces credentials, identity, policy or conversation state.
use super::*;
use gent_protocol::MAX_REGISTRATION_GENERATION;

impl StoreSession<'_> {
    pub(super) fn visible_agents(&self, who: &Agent) -> Result<Value> {
        Ok(serde_json::to_value(self.directory(Some(who))?)?)
    }

    fn registration_generation(&self, agent: &Agent) -> Result<u64> {
        let saved: Option<u64> = self
            .db
            .query_row(
                "SELECT generation FROM network_origins WHERE agent=?1",
                [&agent.id],
                |r| r.get(0),
            )
            .optional()?;
        // Legacy local registrations acquire generation one when first
        // announced. Reading their labels must not require a signing key.
        let generation = match saved {
            Some(generation) => generation,
            None if agent.node_id == self.identity.node.id() => 1,
            None => anyhow::bail!("missing remote registration generation"),
        };
        ensure!(
            (1..=MAX_REGISTRATION_GENERATION).contains(&generation),
            "invalid registration generation"
        );
        Ok(generation)
    }

    pub(super) fn agent_details(&self, id: &str) -> Result<Value> {
        let agent = self.get_agent(id)?;
        let generation = self.registration_generation(&agent)?;
        let mut details = serde_json::to_value(agent)?;
        details["registration_generation"] = json!(generation);
        Ok(details)
    }

    pub(super) fn agent_identity(&self, id: &str) -> Result<Value> {
        let agent = self.get_agent(id)?;
        let generation = self.registration_generation(&agent)?;
        Ok(json!({"agent":agent,"registration_generation":generation,
            "cluster_id":self.config.cluster.id,"node_name":self.config.node.name,
            "delivery":"polling","remote_ready":self.remote_ready()?}))
    }

    pub(super) fn rename_agent(&self, id: &str, name: &str, expected: u64) -> Result<()> {
        config::label(name)?;
        ensure!(
            (1..MAX_REGISTRATION_GENERATION).contains(&expected),
            "invalid expected registration generation"
        );
        self.state.authorize_node(
            self.identity.node.id(),
            &self.identity.node.public_key(),
            self.timestamp as u64,
        )?;
        let agent = self.get_agent(id)?;
        ensure!(
            agent.node_id == self.identity.node.id(),
            "rename on the agent's hosting node, or use gent_rename in that conversation"
        );
        ensure!(!agent.revoked, "registration revoked");
        let generation = self.registration_generation(&agent)?;
        if generation != expected {
            // An uncertain reply may be retried exactly, but cannot undo a
            // later rename, including a change away from and back to this name.
            ensure!(
                generation == expected + 1 && agent.name == name,
                "registration changed; inspect its current name and generation before renaming"
            );
            return Ok(());
        }
        if agent.name == name {
            return Ok(());
        }
        // Reserve the final valid generation for revocation.
        ensure!(
            generation < MAX_REGISTRATION_GENERATION - 1,
            "registration generation exhausted"
        );
        self.ensure_local_origin(id)?;
        self.db
            .execute("UPDATE agents SET name=?1 WHERE id=?2", params![name, id])?;
        self.db.execute(
            "UPDATE network_origins SET generation=generation+1 WHERE agent=?1",
            [id],
        )?;
        // In particular, a legacy certificate from a retired owner epoch must
        // not turn a label edit into an invalid record blocking the peer stream.
        self.registration(id)?
            .verify(&self.state, self.identity.node.id())?;
        // Publication and both local updates share the enclosing transaction.
        self.announce(id)
    }
}
