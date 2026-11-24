use super::*;
use gent_protocol::web_failover::Admission;

impl StoreSession<'_> {
    pub(in crate::store) fn obsolete_web_event(
        &self,
        peer: &str,
        event: &crate::messages::Event,
        revision: u64,
    ) -> Result<bool> {
        use crate::messages::Event;
        if revision >= self.state.checkpoint().revision {
            return Ok(false);
        }
        let moved = |node: &str, carrier: &str| {
            self.state
                .state()
                .nodes
                .get(node)
                .is_some_and(|n| n.hosted_by.as_deref().is_some_and(|host| host != carrier))
        };
        let obsolete = match event {
            Event::Dashboard { agent, .. }
            | Event::Registration { agent }
            | Event::ConversationActivity { agent, .. } => moved(&agent.node, peer),
            Event::Message {
                sender, message, ..
            } => {
                moved(&sender.node, peer)
                    || self
                        .get_agent(&message.recipient)
                        .is_ok_and(|a| moved(&a.node_id, self.identity.node.id()))
            }
            Event::Receipt { message_id, .. } => self.message(message_id).is_ok_and(|m| {
                self.get_agent(&m.recipient)
                    .is_ok_and(|a| moved(&a.node_id, peer))
                    || self
                        .get_agent(&m.sender)
                        .is_ok_and(|a| moved(&a.node_id, self.identity.node.id()))
            }),
            Event::Directory { envelope } => matches!(envelope.as_ref(),
                crate::messages::directory::Envelope::Reply {
                    result: crate::messages::directory::Reply::Leaves { chats }, ..
                } if chats.iter().any(|chat| moved(&chat.node, peer))),
            _ => false,
        };
        if obsolete && matches!(event, Event::Directory { .. }) {
            self.db.execute("UPDATE directory_sync SET progress=NULL,state='changed',next_check=?2 WHERE peer=?1",
                params![peer,self.timestamp])?;
        }
        Ok(obsolete)
    }
    pub(in crate::store) fn dirty_web(&self, node: &str, action: &AgentOp) -> Result<()> {
        if matches!(
            action,
            AgentOp::Register { .. }
                | AgentOp::Rename { .. }
                | AgentOp::Send { .. }
                | AgentOp::RequestReply { .. }
                | AgentOp::Reply { .. }
                | AgentOp::Ack { .. }
                | AgentOp::RelayAttach { .. }
                | AgentOp::RelayDetach { .. }
                | AgentOp::RelaySend { .. }
                | AgentOp::RelayRespond { .. }
                | AgentOp::RelayCancel { .. }
                | AgentOp::WorkBegin { .. }
                | AgentOp::WorkComplete { .. }
                | AgentOp::FileReceiveData { .. }
        ) {
            self.web_state_changed(node)?;
        }
        Ok(())
    }

    // Incoming messages and delivery receipts are native work. They can arrive
    // after the local web grant expires and must wake checkpoint publication.
    pub(in crate::store) fn web_state_changed(&self, node: &str) -> Result<()> {
        if node != self.identity.node.id() && self.local_node(node) {
            self.db.execute(
                "UPDATE hosted_checkpoints SET revision=revision+1 WHERE node=?1",
                [node],
            )?;
        }
        Ok(())
    }

    pub(in crate::store) fn record_web_demand(&self, node: &str, message: &str) -> Result<()> {
        if self
            .state
            .state()
            .nodes
            .get(node)
            .is_some_and(|n| n.hosted_by.is_some())
        {
            self.db.execute(
                "INSERT INTO web_delivery_demand (node,message) VALUES (?1,?2)
                 ON CONFLICT(node) DO UPDATE SET message=excluded.message",
                params![node, message],
            )?;
        }
        Ok(())
    }

    pub(in crate::store) fn web_delivery_demand(&self, node: &str) -> Result<Value> {
        let remote = self
            .state
            .state()
            .nodes
            .get(node)
            .and_then(|n| n.hosted_by.as_deref())
            .is_some_and(|host| host != self.identity.node.id());
        let message: Option<String> = if remote {
            self.db
                .query_row(
                    "SELECT m.id FROM web_delivery_demand d JOIN messages m ON m.id=d.message
                 JOIN exchanges e ON e.id=json_extract(m.payload,'$.exchange_id')
                 WHERE d.node=?1 AND m.acknowledged=0 AND e.expires_at>?2
                 AND NOT EXISTS(SELECT 1 FROM network_rejections WHERE message=m.id)",
                    params![node, self.timestamp],
                    |r| r.get(0),
                )
                .optional()?
        } else {
            None
        };
        Ok(json!({"message_id":message}))
    }

    pub(in crate::store) fn gate_web_event(
        &self,
        id: &str,
        event: &crate::messages::Event,
    ) -> Result<()> {
        use crate::messages::Event;
        let node = match event {
            Event::Dashboard { agent, .. }
            | Event::Registration { agent }
            | Event::ConversationActivity { agent, .. } => Some(agent.node.clone()),
            Event::Message { sender, .. } => Some(sender.node.clone()),
            // Rejected incoming messages need negative receipts even when no
            // message row was admitted. Database failures still propagate.
            Event::Receipt { message_id, .. } => self.db.query_row(
                "SELECT a.node_id FROM messages m JOIN agents a ON a.id=m.recipient WHERE m.id=?1",
                [message_id], |r|r.get(0)).optional()?,
            _ => None,
        };
        if let Some(node) = node {
            self.db.execute("INSERT INTO hosted_event_gates SELECT ?1,node,revision FROM hosted_checkpoints
                WHERE node=?2 AND revision>durable ON CONFLICT(id) DO UPDATE SET revision=MAX(revision,excluded.revision)", params![id,node])?;
        }
        Ok(())
    }

    pub(in crate::store) fn gate_web_message(&self, message: &Message) -> Result<()> {
        self.db.execute(
            "INSERT INTO hosted_message_gates SELECT ?1,c.node,c.revision FROM hosted_checkpoints c
            JOIN agents a ON a.node_id=c.node WHERE a.id=?2 AND c.revision>c.durable
            ON CONFLICT(id) DO NOTHING",
            params![message.id, message.sender],
        )?;
        Ok(())
    }
    pub(in crate::store) fn web_admission(&self, node: &str, body_hash: [u8; 32]) -> Result<Value> {
        require_pro(self.home, &self.config, "Hosted node admission")?;
        self.state.require_fresh(self.timestamp as u64)?;
        ensure!(
            self.identity.can_administer(&self.state),
            "web hosting requires configuration authority"
        );
        let member = self
            .state
            .state()
            .nodes
            .get(node)
            .context("web node unavailable")?;
        ensure!(
            member.hosted_by.is_some() && node != self.identity.node.id(),
            "node is not hosted"
        );
        let (head, key): (Vec<u8>, Vec<u8>) = self.db.query_row(
            "SELECT head,capability FROM peer_configuration WHERE singleton=1 AND active=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let key = zeroize::Zeroizing::new(key);
        let proof = gent_crypto::web_failover::sign(
            key.as_slice().try_into()?,
            Admission {
                version: 1,
                cluster: self.config.cluster.id.clone(),
                node: self.identity.node.id().into(),
                web: node.into(),
                head: serde_json::from_slice(&head)?,
                expires_at: self.timestamp as u64 + 45,
                body_hash,
                signature: Vec::new(),
            },
        )?;
        Ok(serde_json::to_value(proof)?)
    }

    pub(in crate::store) fn web_checkpoint(&self, node: &str) -> Result<Value> {
        let (revision, durable, lease_until, epoch): (u64, u64, i64, Option<u64>) =
            self.db.query_row(
                "SELECT c.revision,c.durable,c.lease_until,g.epoch FROM hosted_checkpoints c
             LEFT JOIN hosted_work_grants g USING(node) WHERE c.node=?1",
                [node],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
        let hosting_here = self
            .state
            .transport_host(node)
            .is_ok_and(|host| host == self.identity.node.id());
        Ok(
            json!({"revision":revision,"durable":durable,"lease_until":lease_until,"epoch":epoch,"hosting_here":hosting_here}),
        )
    }

    pub(in crate::store) fn web_lease(&self, node: &str, seconds: u64) -> Result<Value> {
        if seconds > 0 {
            require_pro(self.home, &self.config, "Hosting another node")?;
        }
        super::check_epoch(self.db, node, None)?;
        ensure!(seconds <= 25, "invalid local web lease");
        self.save_web_deadline(node, self.timestamp + seconds as i64)
    }

    pub(in crate::store) fn web_grant(
        &self,
        node: &str,
        epoch: u64,
        expires_at: u64,
    ) -> Result<Value> {
        ensure!(
            (1..(1u64 << 53)).contains(&epoch),
            "invalid web carrier epoch"
        );
        if expires_at > 0 {
            require_pro(self.home, &self.config, "Hosting another node")?;
        }
        let deadline = i64::try_from(expires_at)?;
        let current = super::grant_now().max(self.timestamp);
        ensure!(
            deadline == 0 || (deadline > current && deadline <= current.saturating_add(25)),
            "web carrier grant expired or too long"
        );
        // Zero is a tombstone. A fresh signed grant may resume an idle epoch
        // after natural expiry, but cannot reopen a released or restarted one.
        ensure!(self.db.execute(
            "INSERT INTO hosted_work_grants(node,epoch) VALUES(?1,?2)
             ON CONFLICT(node) DO UPDATE SET epoch=excluded.epoch,
             restored=CASE WHEN epoch=excluded.epoch THEN restored ELSE 0 END
             WHERE excluded.epoch>epoch OR (excluded.epoch=epoch AND
                 (?3=0 OR EXISTS(SELECT 1 FROM hosted_checkpoints WHERE node=?1 AND lease_until>0)))",
            params![node, epoch, deadline],
        )? == 1, "web carrier epoch changed or closed");
        self.save_web_deadline(node, deadline)
    }

    fn save_web_deadline(&self, node: &str, deadline: i64) -> Result<Value> {
        ensure!(
            self.state
                .state()
                .nodes
                .get(node)
                .is_some_and(|n| n.hosted_by.is_some()),
            "unknown web node"
        );
        let exists: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM hosted_checkpoints WHERE node=?1)",
            [node],
            |r| r.get(0),
        )?;
        self.db.execute(
            "INSERT INTO hosted_checkpoints VALUES(?1,1,0,?2)
            ON CONFLICT(node) DO UPDATE SET lease_until=excluded.lease_until",
            params![node, deadline],
        )?;
        if !exists && self.local_node(node) {
            for chat in self.all_agents()?.into_iter().filter(|a| a.node_id == node) {
                self.record_web_registration(&self.registration(&chat.id)?)?;
            }
        }
        self.web_checkpoint(node)
    }

    pub(in crate::store) fn web_commit(
        &self,
        node: &str,
        revision: u64,
        epoch: Option<u64>,
    ) -> Result<Value> {
        super::check_epoch(self.db, node, epoch)?;
        ensure!(
            epoch.is_none() || self.local_node(node),
            "web hosting route changed"
        );
        ensure!(
            self.db.execute(
                "UPDATE hosted_checkpoints SET durable=MAX(durable,?2)
            WHERE node=?1 AND revision>=?2 AND lease_until>?3",
                params![node, revision, self.timestamp]
            )? == 1,
            "web checkpoint lease or revision changed"
        );
        self.db.execute(
            "DELETE FROM hosted_event_gates WHERE node=?1 AND revision<=?2",
            params![node, revision],
        )?;
        self.db.execute(
            "DELETE FROM hosted_message_gates WHERE node=?1 AND revision<=?2",
            params![node, revision],
        )?;
        self.db.execute(
            "DELETE FROM hosted_dashboard_gates WHERE node=?1 AND revision<=?2",
            params![node, revision],
        )?;
        self.db.execute("DELETE FROM hosted_directory AS old WHERE node=?1 AND revision < (
            SELECT MAX(new.revision) FROM hosted_directory new WHERE new.agent=old.agent AND new.revision<=?2)", params![node,revision])?;
        if epoch.is_some() {
            super::check_epoch(self.db, node, epoch)?;
        }
        self.web_checkpoint(node)
    }

    pub(in crate::store) fn record_web_registration(
        &self,
        registration: &crate::messages::Registration,
    ) -> Result<()> {
        let payload = serde_json::to_vec(registration)?;
        let previous: Option<Vec<u8>> = self.db.query_row("SELECT payload FROM hosted_directory WHERE agent=?1 ORDER BY revision DESC LIMIT 1", [&registration.id], |r|r.get(0)).optional()?;
        if previous.as_ref() == Some(&payload) {
            return Ok(());
        }
        // Owner-side renames also need a new checkpoint revision.
        self.db.execute(
            "UPDATE hosted_checkpoints SET revision=revision+1 WHERE node=?1 AND revision<=durable",
            [&registration.node],
        )?;
        self.db.execute("INSERT INTO hosted_directory SELECT ?1,node,revision,?3 FROM hosted_checkpoints WHERE node=?2
            ON CONFLICT(agent,revision) DO UPDATE SET payload=excluded.payload",
            params![registration.id,registration.node,payload])?;
        Ok(())
    }

    /// A local web registration is publishable only at its committed generation.
    /// Remote copies are already committed by their carrier.
    pub(in crate::store) fn published_registration(
        &self,
        id: &str,
        node: &str,
    ) -> Result<Option<crate::messages::Registration>> {
        let portable: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM hosted_checkpoints WHERE node=?1)",
            [node],
            |r| r.get(0),
        )?;
        let retained: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM hosted_directory WHERE agent=?1)",
            [id],
            |r| r.get(0),
        )?;
        if !portable || (!self.local_node(node) && !retained) {
            return self.stored_registration(id).map(Some);
        }
        let bytes: Option<Vec<u8>> = self.db.query_row("SELECT d.payload FROM hosted_directory d JOIN hosted_checkpoints c ON c.node=d.node
            WHERE d.agent=?1 AND d.revision<=c.durable ORDER BY d.revision DESC LIMIT 1", [id], |r|r.get(0)).optional()?;
        bytes
            .map(|b| serde_json::from_slice(&b).map_err(Into::into))
            .transpose()
    }

    /// A former carrier may retain a speculative rename. Reset it to the last
    /// committed generation before comparing the new carrier's registration.
    pub(in crate::store) fn retire_web_registration(&self, id: &str, node: &str) -> Result<()> {
        let retained: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM hosted_directory WHERE agent=?1 AND node=?2)",
            params![id, node],
            |r| r.get(0),
        )?;
        if !retained {
            return Ok(());
        }
        if let Some(saved) = self.published_registration(id, node)? {
            self.db.execute(
                "UPDATE agents SET name=?2,provider=?3,revoked=?4 WHERE id=?1",
                params![id, saved.name, saved.provider, saved.revoked],
            )?;
            self.db.execute(
                "UPDATE network_origins SET generation=?2 WHERE agent=?1",
                params![id, saved.generation],
            )?;
        } else {
            self.db
                .execute("UPDATE agents SET revoked=0 WHERE id=?1", [id])?;
            self.db.execute(
                "UPDATE network_origins SET generation=0 WHERE agent=?1",
                [id],
            )?;
        }
        self.db
            .execute("DELETE FROM hosted_directory WHERE agent=?1", [id])?;
        Ok(())
    }

    pub(in crate::store) fn web_message_ready(&self, message: &Message) -> Result<bool> {
        let pending: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM hosted_message_gates g
            JOIN hosted_checkpoints c ON c.node=g.node WHERE g.id=?1 AND c.durable<g.revision)",
            [&message.id],
            |r| r.get(0),
        )?;
        Ok(!pending)
    }
}
