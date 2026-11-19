//! Logical web identities share the hosting daemon's directory and queues.
//! Hosting authenticates a chat carrier, never a configuration signer.
use super::*;
mod import;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS hosted_nodes (
        node TEXT PRIMARY KEY,home TEXT NOT NULL UNIQUE,gateway_hash TEXT NOT NULL);",
    )?;
    Ok(())
}

impl Store {
    pub(crate) fn reconcile_hosted_routes(&mut self) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        let routes: BTreeMap<_, _> = state
            .state()
            .nodes
            .iter()
            .filter_map(|(node, member)| {
                member
                    .hosted_by
                    .as_ref()
                    .map(|parent| (node.clone(), parent.clone()))
            })
            .collect();
        let fingerprint = serde_json::to_string(&routes)?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT value FROM metadata WHERE key='hosted_routes'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if previous.as_deref() == Some(&fingerprint) {
            return Ok(());
        }
        state.require_fresh(now() as u64)?;
        let session = StoreSession {
            db: &tx,
            home: &self.home,
            config: self.config.clone(),
            identity: &self.identity,
            state,
            timestamp: now(),
        };
        for agent in session.all_agents()? {
            if session.local_node(&agent.node_id) {
                session.announce(&agent.id)?;
                session.announce_activity(&agent.id)?;
            }
        }
        // Routing changes must retain the original request/message identities.
        // Re-enqueueing uses deterministic queue IDs and never repeats work.
        let ids = tx
            .prepare("SELECT id,request_id FROM messages ORDER BY rowid")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, request) in ids {
            let message = session.message(&id)?;
            if message.expires_at <= session.timestamp {
                continue;
            }
            let sender = session.get_agent(&message.sender)?;
            let recipient = session.get_agent(&message.recipient)?;
            if !session.state.state().nodes.contains_key(&sender.node_id)
                || !session.state.state().nodes.contains_key(&recipient.node_id)
            {
                continue;
            }
            if session.local_node(&sender.node_id)
                && !session.local_node(&recipient.node_id)
                && !message.acknowledged
            {
                session.queue_message(
                    session.state.transport_host(&recipient.node_id)?,
                    &request,
                    &message,
                )?;
            } else if session.local_node(&recipient.node_id)
                && !session.local_node(&sender.node_id)
                && message.acknowledged
            {
                session.receipt(
                    session.state.transport_host(&sender.node_id)?,
                    &id,
                    true,
                    message.expires_at,
                )?;
            }
        }
        tx.execute("INSERT INTO metadata VALUES('hosted_routes',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[fingerprint])?;
        tx.commit()?;
        self.sync_wakeup.notify_one();
        Ok(())
    }

    pub(super) fn prepare_hosted_node(&mut self, node: &str, home: &Path) -> Result<Value> {
        let home = std::fs::canonicalize(home)?;
        ensure!(home != self.home, "a node cannot host itself");
        config::private_dir(&home)?;
        let _lock = config::state_lock(&home, "daemon.lock")?;
        let mut child = config::load_for_runtime(&home)?;
        ensure!(
            child.node.id == node && child.cluster.id == self.config.cluster.id,
            "hosted node belongs to another identity or cluster"
        );
        if let Some(parent) = child.hosted_parent()? {
            ensure!(
                parent.node_id == self.identity.node.id()
                    && std::fs::canonicalize(parent.home)? == std::fs::canonicalize(&self.home)?,
                "web node belongs to another host"
            );
        }
        let gateway_hash = hash(&config::read_private(&home.join("owner.key"))?);
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        state.require_fresh(now() as u64)?;
        let member = state
            .state()
            .nodes
            .get(node)
            .context("web node is no longer enrolled")?;
        ensure!(
            member
                .hosted_by
                .as_deref()
                .is_none_or(|p| p == self.identity.node.id()),
            "web node belongs to another host"
        );
        ensure!(
            state.transport_host(self.identity.node.id())? == self.identity.node.id(),
            "hosted nodes cannot host other nodes"
        );
        let path = home.to_str().context("invalid hosted state path")?;
        let saved: Option<(String, String)> = tx
            .query_row(
                "SELECT home,gateway_hash FROM hosted_nodes WHERE node=?1",
                [node],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((saved_home, saved_key)) = saved {
            ensure!(
                saved_home == path && saved_key == gateway_hash,
                "hosted node migration identity changed"
            );
        } else {
            import::import(&tx, &home, &state, node, self.identity.node.id())?;
            tx.execute(
                "INSERT INTO hosted_nodes VALUES(?1,?2,?3)",
                params![node, path, gateway_hash],
            )?;
        }
        tx.commit()?;
        // This required local feature also fences older binaries: they reject
        // the unknown feature instead of starting a second independent writer.
        child.set_hosted_parent(config::HostedParent {
            home: std::fs::canonicalize(&self.home)?,
            node_id: self.identity.node.id().into(),
        })?;
        config::save(&home, &child)?;
        Ok(json!({"prepared":true,"node_id":node,"hosted_by":self.identity.node.id()}))
    }
}

impl StoreSession<'_> {
    pub(super) fn local_node(&self, node: &str) -> bool {
        self.state
            .transport_host(node)
            .is_ok_and(|host| host == self.identity.node.id())
    }

    pub(super) fn check_hosted(&self, node: &str, gateway: &str) -> Result<()> {
        self.state.authorize_node(
            self.identity.node.id(),
            &self.identity.node.public_key(),
            self.timestamp as u64,
        )?;
        ensure!(
            node != self.identity.node.id() && self.local_node(node),
            "hosted node unavailable"
        );
        ensure!(
            gateway.len() == 64 && gateway.bytes().all(|b| b.is_ascii_hexdigit()),
            "hosted node unavailable"
        );
        let saved: Option<String> = self
            .db
            .query_row(
                "SELECT gateway_hash FROM hosted_nodes WHERE node=?1",
                [node],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            saved.as_deref() == Some(hash(gateway).as_str()),
            "hosted node unavailable"
        );
        Ok(())
    }

    pub(super) fn hosted_status(&self, node: &str) -> Result<Value> {
        let member = self
            .state
            .state()
            .nodes
            .get(node)
            .context("hosted node unavailable")?;
        Ok(json!({"node":{"id":node,"name":member.name},
            "cluster":{"id":self.config.cluster.id,"name":self.state.state().name},
            "hosted_by":self.identity.node.id(),"remote_ready":self.remote_ready()?,
            "directory_chats":self.all_agents()?.len(),"config_saved":true,
            "authority":{"fresh":true,"revision":self.state.checkpoint().revision}}))
    }
}
