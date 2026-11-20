use super::*;
use crate::{
    encrypted::ordered::OrderedEndpoint,
    messages::{self, Event, FRAGMENT_BYTES, Frame, MAX_RECORD_BYTES, Record, Registration},
};
use gent_crypto::{SignedLegacyAgentBinding, scoped_id};
use uuid::Uuid;

mod queue;
pub(super) mod retention;
#[cfg(test)]
mod tests;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS network_links(peer TEXT PRIMARY KEY,peer_key BLOB NOT NULL,outgoing BLOB UNIQUE NOT NULL,incoming BLOB UNIQUE NOT NULL);
      CREATE TABLE IF NOT EXISTS network_origins(agent TEXT PRIMARY KEY,nonce TEXT,legacy BLOB,generation INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS legacy_agent_bindings(agent TEXT PRIMARY KEY,node TEXT NOT NULL,certificate BLOB NOT NULL);
      CREATE TABLE IF NOT EXISTS network_events(id TEXT PRIMARY KEY,peer TEXT NOT NULL,body BLOB NOT NULL,offset INTEGER NOT NULL DEFAULT 0,cancelled INTEGER NOT NULL DEFAULT 0,subject TEXT);
      CREATE TABLE IF NOT EXISTS network_sent(id TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS network_partial(group_id BLOB PRIMARY KEY,id TEXT NOT NULL,digest BLOB NOT NULL,total INTEGER NOT NULL,body BLOB NOT NULL);
      CREATE TABLE IF NOT EXISTS network_rejections(message TEXT PRIMARY KEY);")?;
    db.execute_batch("CREATE INDEX IF NOT EXISTS messages_exchange_sender ON messages(json_extract(payload,'$.exchange_id'),sender);")?;
    retention::schema(db)?;
    Ok(())
}

fn active_peer(state: &VerifiedState, peer: &str, key: &[u8], timestamp: i64) -> Result<()> {
    ensure!(
        state.transport_host(peer)? == peer,
        "web node uses its hosting node's transport"
    );
    state.authorize_node(
        peer,
        key.try_into().context("invalid peer key")?,
        timestamp as u64,
    )?;
    Ok(())
}

/// Recheck the selected queue position in the encryption transaction. A stale
/// selection must not allocate another ID after a completed request was pruned.
fn check_cursor(db: &Connection, group: &[u8], fragment: (Uuid, usize, bool)) -> Result<()> {
    let peer: String = db.query_row(
        "SELECT peer FROM network_links WHERE outgoing=?1",
        [group],
        |r| r.get(0),
    )?;
    ensure!(
        queue::next_id(db, &peer)?.as_deref() == Some(fragment.0.to_string().as_str()),
        "outgoing fragment selection changed before encryption"
    );
    let current: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM network_events e
        JOIN network_links l ON l.peer=e.peer WHERE l.outgoing=?1 AND e.id=?2
        AND e.offset=?3 AND e.cancelled=?4)",
        params![group, fragment.0.to_string(), fragment.1, fragment.2],
        |r| r.get(0),
    )?;
    ensure!(
        current,
        "outgoing fragment cursor changed before encryption"
    );
    Ok(())
}

impl StoreSession<'_> {
    pub(super) fn remote_ready(&self) -> Result<bool> {
        if self.config.relay.is_none() {
            return Ok(false);
        }
        let mut query = self.db.prepare("SELECT peer,peer_key FROM network_links")?;
        for row in query.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })? {
            let (peer, key) = row?;
            if active_peer(&self.state, &peer, &key, self.timestamp).is_ok() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub(super) fn ensure_local_origin(&self, id: &str) -> Result<()> {
        let agent = self.get_agent(id)?;
        ensure!(
            self.local_node(&agent.node_id),
            "chat belongs to another node"
        );
        if self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_origins WHERE agent=?1)",
            [id],
            |r| r.get::<_, bool>(0),
        )? {
            return Ok(());
        }
        let certificate = self.certify_legacy(id, &agent.node_id)?;
        self.db.execute(
            "INSERT INTO network_origins VALUES(?1,NULL,?2,1)",
            params![id, serde_json::to_vec(&certificate)?],
        )?;
        Ok(())
    }
    pub(super) fn certify_legacy(&self, id: &str, node: &str) -> Result<SignedLegacyAgentBinding> {
        if let Some((saved_node, certificate)) = self
            .db
            .query_row(
                "SELECT node,certificate FROM legacy_agent_bindings WHERE agent=?1",
                [id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
        {
            ensure!(
                saved_node == node,
                "legacy chat already belongs to another node"
            );
            let certificate: SignedLegacyAgentBinding = serde_json::from_slice(&certificate)?;
            certificate.verify_current(&self.state, id, node)?;
            return Ok(certificate);
        }
        let existing: Option<String> = self
            .db
            .query_row("SELECT node_id FROM agents WHERE id=?1", [id], |r| r.get(0))
            .optional()?;
        ensure!(
            existing.is_none_or(|existing| existing == node),
            "chat ID already belongs to another node"
        );
        let certificate = self.identity.signing_owner(self.db)?.bind_legacy_agent(
            &self.state,
            id,
            node,
            self.timestamp as u64,
        )?;
        self.db.execute(
            "INSERT INTO legacy_agent_bindings VALUES(?1,?2,?3)",
            params![id, node, serde_json::to_vec(&certificate)?],
        )?;
        Ok(certificate)
    }
    pub(super) fn registration(&self, id: &str) -> Result<Registration> {
        self.ensure_local_origin(id)?;
        self.stored_registration(id)
    }
    pub(super) fn stored_registration(&self, id: &str) -> Result<Registration> {
        let agent = self.get_agent(id)?;
        let (nonce, legacy, generation): (Option<String>, Option<Vec<u8>>, u64) =
            self.db.query_row(
                "SELECT nonce,legacy,generation FROM network_origins WHERE agent=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
        Ok(Registration {
            id: agent.id,
            node: agent.node_id,
            nonce: nonce.map(|n| Uuid::parse_str(&n)).transpose()?,
            legacy: legacy.map(|b| serde_json::from_slice(&b)).transpose()?,
            generation,
            name: agent.name,
            provider: agent.provider,
            revoked: agent.revoked,
        })
    }
    pub(super) fn queue(
        &self,
        peer: &str,
        id: Uuid,
        event: Event,
        subject: Option<&str>,
    ) -> Result<()> {
        self.queue_expiring(peer, id, event, subject, None)
    }
    fn queue_expiring(
        &self,
        peer: &str,
        id: Uuid,
        event: Event,
        subject: Option<&str>,
        receipt_expires: Option<i64>,
    ) -> Result<()> {
        let key: Vec<u8> = self
            .db
            .query_row(
                "SELECT peer_key FROM network_links WHERE peer=?1",
                [peer],
                |r| r.get(0),
            )
            .optional()?
            .context("node is not connected; establish its encrypted data streams")?;
        if matches!(&event, Event::ConfigurationRequest { .. }) {
            // A local owner may queue an edit while offline/expired. Publication
            // still requires fresh authority; acceptance rechecks delegation.
            ensure!(
                self.state
                    .state()
                    .nodes
                    .get(peer)
                    .is_some_and(|n| n.signing_key.as_slice() == key),
                "configuration writer key changed"
            );
        } else {
            active_peer(&self.state, peer, &key, self.timestamp)?;
        }
        self.gate_web_event(&id.to_string(), &event)?;
        self.enqueue_event(peer, id, event, subject, receipt_expires)
    }
    pub(super) fn announce(&self, id: &str) -> Result<()> {
        let registration = self.registration(id)?;
        self.record_web_registration(&registration)?;
        let peers = self
            .db
            .prepare("SELECT peer,peer_key FROM network_links ORDER BY peer")?
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if peers.is_empty() {
            return Ok(());
        }
        for (peer, key) in peers {
            // A revoked peer cannot block an otherwise local registration change.
            if active_peer(&self.state, &peer, &key, self.timestamp).is_err() {
                continue;
            }
            let event = scoped_id(
                b"gent/registration-event/v1\0",
                &[
                    peer.as_bytes(),
                    id.as_bytes(),
                    &registration.generation.to_be_bytes(),
                ],
            );
            self.queue(
                &peer,
                event,
                Event::Registration {
                    agent: registration.clone(),
                },
                None,
            )?;
        }
        Ok(())
    }
    pub(super) fn queue_message(&self, peer: &str, request: &str, message: &Message) -> Result<()> {
        let id = scoped_id(
            b"gent/message-event/v1\0",
            &[peer.as_bytes(), message.id.as_bytes()],
        );
        self.queue(
            peer,
            id,
            Event::Message {
                sender: Box::new(self.registration(&message.sender)?),
                request_id: request.into(),
                message: message.clone(),
                attachments: self.private_attachments(message)?,
            },
            Some(&message.id),
        )
    }
    pub(super) fn receipt(
        &self,
        peer: &str,
        message: &str,
        delivered: bool,
        expires: i64,
    ) -> Result<()> {
        let timestamp = requests::clock(self.db, self.timestamp)?;
        if expires
            .checked_add(history::RETENTION)
            .context("receipt retention overflow")?
            <= timestamp
        {
            return Ok(());
        }
        let id = scoped_id(
            b"gent/receipt-event/v1\0",
            &[peer.as_bytes(), message.as_bytes(), &[u8::from(delivered)]],
        );
        self.queue_expiring(
            peer,
            id,
            Event::Receipt {
                message_id: message.into(),
                delivered,
            },
            None,
            Some(expires),
        )
    }
    pub(super) fn import_registration(&self, node: &str, incoming: &Registration) -> Result<()> {
        incoming.verify(&self.state, &incoming.node)?;
        // Production imports pass data_peer's exact key and wall-clock
        // freshness check in this transaction. The retention clock can be
        // ahead; it must not be used to recheck authority freshness here.
        self.state.authorize_chat_carrier(&incoming.node, node)?;
        self.import_directory_registration(incoming)
    }

    /// Registration merging is shared by carrier announcements and V4 trusted
    /// replica repair. Message senders still require their actual carrier.
    pub(in crate::store) fn import_directory_registration(
        &self,
        incoming: &Registration,
    ) -> Result<()> {
        let node = incoming.node.as_str();
        ensure!(!self.local_node(node), "remote node claimed local identity");
        self.retire_web_registration(&incoming.id, node)?;
        if let Some(existing) = self
            .db
            .query_row(
                "SELECT node_id,revoked FROM agents WHERE id=?1",
                [&incoming.id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)),
            )
            .optional()?
        {
            ensure!(
                existing.0 == node,
                "chat ID already belongs to another node"
            );
            let (nonce, legacy, generation): (Option<String>, Option<Vec<u8>>, u64) =
                self.db.query_row(
                    "SELECT nonce,legacy,generation FROM network_origins WHERE agent=?1",
                    [&incoming.id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
            ensure!(
                nonce == incoming.nonce.map(|n| n.to_string())
                    && legacy
                        == incoming
                            .legacy
                            .as_ref()
                            .map(serde_json::to_vec)
                            .transpose()?,
                "chat binding changed"
            );
            if incoming.generation < generation {
                return Ok(());
            }
            if incoming.generation == generation {
                let previous = self.get_agent(&incoming.id)?;
                ensure!(
                    previous.name == incoming.name
                        && previous.provider == incoming.provider
                        && previous.revoked == incoming.revoked,
                    "conflicting chat generation"
                );
                return Ok(());
            }
            ensure!(
                !existing.1 || incoming.revoked,
                "revoked chat cannot be restored"
            );
            self.db.execute(
                "UPDATE agents SET name=?1,provider=?2,revoked=?3,last_seen=?4 WHERE id=?5",
                params![
                    incoming.name,
                    incoming.provider,
                    incoming.revoked,
                    self.timestamp,
                    incoming.id
                ],
            )?;
            self.db.execute(
                "UPDATE network_origins SET generation=?1 WHERE agent=?2",
                params![incoming.generation, incoming.id],
            )?;
        } else {
            let count: usize = self
                .db
                .query_row("SELECT COUNT(*) FROM agents", [], |r| r.get(0))?;
            ensure!(count < 16384, "chat directory limit reached");
            self.db.execute(
                "INSERT INTO agents VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    incoming.id,
                    format!("remote:{}", incoming.id),
                    node,
                    incoming.name,
                    incoming.provider,
                    self.timestamp,
                    incoming.revoked
                ],
            )?;
            self.db.execute(
                "INSERT INTO network_origins VALUES(?1,?2,?3,?4)",
                params![
                    incoming.id,
                    incoming.nonce.map(|n| n.to_string()),
                    incoming
                        .legacy
                        .as_ref()
                        .map(serde_json::to_vec)
                        .transpose()?,
                    incoming.generation
                ],
            )?;
        }
        Ok(())
    }
    fn import_event(&mut self, peer: &str, event: Event) -> Result<()> {
        self.timestamp = requests::clock(self.db, self.timestamp)?;
        match event {
            Event::Direct { address } => self.receive_direct(peer, address),
            Event::Directory { envelope } => self.receive_directory(peer, *envelope),
            Event::NodeInvite { envelope } => self.receive_node_invite(peer, *envelope),
            Event::Presence { challenge, reply } => self.presence_receive(peer, challenge, reply),
            Event::OwnerPreparation { envelope } => self.import_owner_preparation(peer, &envelope),
            Event::Mesh { envelope } => self.import_mesh(peer, envelope),
            Event::ConfigurationRequest { request_id, edit } => {
                self.accept_configuration(peer, request_id, *edit)
            }
            Event::ConfigurationResult {
                request_id,
                fingerprint,
                result,
                decided_by,
            } => match decided_by {
                None => self.import_configuration_result(peer, request_id, &fingerprint, result),
                Some(writer) => self.import_routed_configuration_result(
                    peer,
                    request_id,
                    &fingerprint,
                    result,
                    Some(&writer),
                ),
            },
            Event::Registration { agent } => self.import_registration(peer, &agent),
            Event::ConversationActivity { agent, timestamp } => {
                self.import_activity(peer, &agent, timestamp)
            }
            Event::Receipt {
                message_id,
                delivered,
            } => {
                // A late receipt for retired history has no state to change.
                // Existing messages still enforce their exact recipient node.
                if !self.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM messages WHERE id=?1)",
                    [&message_id],
                    |r| r.get::<_, bool>(0),
                )? {
                    return Ok(());
                }
                let message = self.message(&message_id)?;
                ensure!(
                    self.local_node(&self.get_agent(&message.sender)?.node_id)
                        && self
                            .state
                            .transport_host(&self.get_agent(&message.recipient)?.node_id)?
                            == peer,
                    "receipt belongs to another exchange"
                );
                if delivered {
                    self.db.execute(
                        "UPDATE messages SET acknowledged=1 WHERE id=?1",
                        [message_id],
                    )?;
                } else {
                    self.db.execute(
                        "INSERT OR IGNORE INTO network_rejections VALUES(?1)",
                        [message_id],
                    )?;
                }
                Ok(())
            }
            Event::Message {
                sender,
                request_id,
                message,
                attachments,
            } => {
                self.import_registration(peer, &sender)?;
                ensure!(
                    message.sender == sender.id
                        && message.id == messages::message_id(&sender.id, &request_id)?
                        && !message.acknowledged,
                    "invalid remote message identity"
                );
                validate_contents(&message.text, &message.files, message.attachments.len())?;
                ensure!(
                    message.created_at >= 0
                        && message.created_at <= self.timestamp + 60
                        && message.expires_at > message.created_at
                        && message.expires_at <= message.created_at + EXCHANGE_TTL_SECONDS,
                    "invalid message lifetime"
                );
                let recipient = self.get_agent(&message.recipient)?;
                ensure!(
                    self.local_node(&recipient.node_id) && sender.id != recipient.id,
                    "message belongs to another recipient node"
                );
                let payload = serde_json::to_string(&message)?;
                let previous: Option<String> = self
                    .db
                    .query_row(
                        "SELECT payload FROM messages WHERE id=?1",
                        [&message.id],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(previous) = previous {
                    ensure!(previous == payload, "conflicting remote message");
                    self.bind_attachments(&message, &attachments)?;
                    return Ok(());
                }
                if !requests::remote(
                    self.db,
                    &request_id,
                    message.created_at,
                    message.expires_at,
                    self.timestamp,
                )? {
                    // An inadmissible ID must not create fresh receipt work;
                    // otherwise rewritten timestamps could extend its lifetime.
                    return Ok(());
                }
                if !self.deliverable(&message)? {
                    let expires = if requests::issued(&request_id).is_none() {
                        // Legacy IDs contain no admission timestamp. A denied
                        // old message can be rewritten during the fixed upgrade
                        // grace; retain its receipt beyond that entire window.
                        let until: i64 = self.db.query_row(
                            "SELECT legacy_until FROM request_clock WHERE singleton=1",
                            [],
                            |r| r.get(0),
                        )?;
                        message.expires_at.max(until)
                    } else {
                        message.expires_at
                    };
                    return self.receipt(peer, &message.id, false, expires);
                }
                self.validate_relay_message(&message)?;
                if let Some(parent_id) = &message.reply_to {
                    let parent = self.message(parent_id)?;
                    let cancellation = message
                        .relay
                        .as_ref()
                        .is_some_and(|r| r.kind == RelayMessageKind::Cancel);
                    ensure!(
                        (if cancellation {
                            parent.sender == message.sender && parent.recipient == message.recipient
                        } else {
                            parent.sender == message.recipient && parent.recipient == message.sender
                        }) && parent.exchange_id == message.exchange_id
                            && parent.expires_at == message.expires_at,
                        "reply does not match an accepted exchange"
                    );
                } else {
                    ensure!(
                        message.exchange_id == message.id,
                        "invalid initial exchange ID"
                    );
                    self.db.execute(
                        "INSERT INTO exchanges VALUES(?1,?2,?3,?4,0)",
                        params![
                            message.exchange_id,
                            message.sender,
                            message.recipient,
                            message.expires_at
                        ],
                    )?;
                }
                let sent: u32 = self.db.query_row(
                    "SELECT COUNT(*) FROM messages WHERE json_extract(payload,'$.exchange_id')=?1 AND sender=?2",
                    params![message.exchange_id, message.sender],
                    |r| r.get(0),
                )?;
                ensure!(
                    sent < MAX_EXCHANGE_MESSAGES / 2,
                    "remote exchange sender limit exceeded"
                );
                ensure!(self.db.execute("UPDATE exchanges SET count=count+1 WHERE id=?1 AND count<?2 AND expires_at=?3 AND ((a=?4 AND b=?5) OR (a=?5 AND b=?4))", params![message.exchange_id,MAX_EXCHANGE_MESSAGES,message.expires_at,message.sender,message.recipient])? == 1, "invalid or exhausted remote exchange");
                let fingerprint = message_fingerprint(
                    &message.recipient,
                    &message.text,
                    &message.files,
                    &message.reply_to,
                    &message.relay,
                    &[],
                )?;
                history::message_capacity(self.db, payload.len())?;
                self.db.execute("INSERT INTO messages(id,sender,recipient,request_id,fingerprint,payload) VALUES(?1,?2,?3,?4,?5,?6)",params![message.id,message.sender,message.recipient,request_id,fingerprint,payload])?;
                self.bind_attachments(&message, &attachments)?;
                self.record_relay_message(&message)?;
                Ok(())
            }
        }
    }
}

pub(super) fn validate_contents(text: &str, files: &[FilePart], attachments: usize) -> Result<()> {
    ensure!(
        text.len() <= MAX_TEXT_BYTES && (!text.is_empty() || !files.is_empty() || attachments != 0),
        "invalid message text"
    );
    ensure!(
        files.len() + attachments <= 4,
        "at most four files per message"
    );
    let mut total = 0;
    for file in files {
        config::label(&file.name)?;
        config::label(&file.media_type)?;
        ensure!(
            !file.name.contains(['/', '\\']) && file.name != "." && file.name != "..",
            "filename must be a basename"
        );
        total += STANDARD.decode(&file.data_base64)?.len();
        ensure!(total <= MAX_FILE_BYTES, "combined files exceed 1 MiB");
    }
    Ok(())
}

impl Store {
    pub(super) fn network_session<'a>(
        &'a self,
        db: &'a Connection,
        state: VerifiedState,
    ) -> StoreSession<'a> {
        let mut config = self.config.clone();
        config.policy = state.state().policy.clone();
        StoreSession {
            db,
            home: &self.home,
            config,
            identity: &self.identity,
            state,
            timestamp: now(),
        }
    }
    pub(crate) fn pairing_node(&self) -> Result<gent_crypto::NodeIdentity> {
        gent_crypto::NodeIdentity::from_secret_bytes(
            self.identity.node.id(),
            &self.identity.node.expose_secret(),
        )
    }
    pub(crate) fn needs_data_pairing(&self) -> Result<bool> {
        Ok(!self
            .identity
            .is_current_owner(&self.identity.state(&self.db)?)
            && !self
                .db
                .query_row("SELECT EXISTS(SELECT 1 FROM network_links)", [], |r| {
                    r.get::<_, bool>(0)
                })?)
    }
    pub(crate) fn legacy_registrations(&self) -> Result<Vec<String>> {
        Ok(self.db.prepare("SELECT id FROM agents WHERE node_id=?1 AND id NOT IN (SELECT agent FROM network_origins) ORDER BY id")?.query_map([self.identity.node.id()], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// Install a previously authenticated pair of two-node directional streams.
    pub fn install_data_link(
        &mut self,
        peer: &str,
        outgoing: &[u8],
        incoming: &[u8],
        legacy: &[SignedLegacyAgentBinding],
    ) -> Result<()> {
        let tx = self.db.unchecked_transaction()?;
        let state = self.identity.state(&tx)?;
        let key = state
            .state()
            .nodes
            .get(peer)
            .context("unknown peer")?
            .signing_key;
        active_peer(&state, peer, &key, now())?;
        ensure!(
            peer != self.identity.node.id(),
            "data link requires a different node"
        );
        for (group, writer) in [(outgoing, self.identity.node.id()), (incoming, peer)] {
            let (purpose, saved_writer, roster, writer_key): (String, String, Vec<u8>, Vec<u8>) =
                tx.query_row(
                    "SELECT purpose,writer,roster_hash,writer_key FROM streams WHERE group_id=?1",
                    [group],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )?;
            let mut members = vec![peer, self.identity.node.id()];
            members.sort();
            ensure!(
                purpose == "data"
                    && saved_writer == writer
                    && state
                        .state()
                        .nodes
                        .get(writer)
                        .is_some_and(|n| n.signing_key.as_slice() == writer_key)
                    && roster == Sha256::digest(serde_json::to_vec(&members)?).as_slice(),
                "data link has an unexpected roster or writer"
            );
        }
        if let Some((saved_out, saved_in, saved_key)) = tx
            .query_row(
                "SELECT outgoing,incoming,peer_key FROM network_links WHERE peer=?1",
                [peer],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?
        {
            ensure!(
                saved_out == outgoing && saved_in == incoming && saved_key == key,
                "peer already has different data streams"
            );
        } else {
            tx.execute(
                "INSERT INTO network_links VALUES(?1,?2,?3,?4)",
                params![peer, key.as_slice(), outgoing, incoming],
            )?;
        }
        for certificate in legacy {
            let id = &certificate.binding.agent;
            certificate.verify_current(&state, id, self.identity.node.id())?;
            let node: String =
                tx.query_row("SELECT node_id FROM agents WHERE id=?1", [id], |r| r.get(0))?;
            ensure!(
                node == self.identity.node.id(),
                "legacy binding is not for a local registration"
            );
            tx.execute(
                "INSERT OR IGNORE INTO network_origins VALUES(?1,NULL,?2,1)",
                params![id, serde_json::to_vec(certificate)?],
            )?;
        }
        let session = self.network_session(&tx, state);
        for agent in session
            .all_agents()?
            .into_iter()
            .filter(|a| session.local_node(&a.node_id))
        {
            session.announce(&agent.id)?;
        }
        tx.commit()?;
        self.sync_wakeup.notify_one();
        Ok(())
    }

    pub(crate) fn data_streams(&self) -> Result<Vec<crate::sync::Stream>> {
        let state = self.identity.state(&self.db)?;
        if state.require_fresh(now() as u64).is_err() {
            return Ok(vec![]);
        }
        let mut streams = Vec::new();
        let mut query = self.db.prepare(
            "SELECT peer,peer_key,outgoing,incoming FROM network_links ORDER BY peer LIMIT 1024",
        )?;
        for row in query.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })? {
            let (peer, key, outgoing, incoming) = row?;
            if active_peer(&state, &peer, &key, now()).is_ok() {
                streams.push(crate::sync::Stream {
                    group: outgoing,
                    outgoing: true,
                    configuration: false,
                });
                streams.push(crate::sync::Stream {
                    group: incoming,
                    outgoing: false,
                    configuration: false,
                });
            }
        }
        Ok(streams)
    }

    pub(super) fn data_peer(
        &self,
        db: &Connection,
        group: &[u8],
        outgoing: bool,
    ) -> Result<String> {
        let column = if outgoing { "outgoing" } else { "incoming" };
        let (peer, key): (String, Vec<u8>) = db.query_row(
            &format!("SELECT peer,peer_key FROM network_links WHERE {column}=?1"),
            [group],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        active_peer(&self.identity.state(db)?, &peer, &key, now())?;
        Ok(peer)
    }
    pub(crate) fn data_prepare(&mut self, group: &[u8]) -> Result<()> {
        let peer = self.data_peer(&self.db, group, true)?;
        let Some(queue::ReadyEvent {
            id,
            subject,
            cancelled,
        }) = queue::ready_event(self, &peer)?
        else {
            return Ok(());
        };
        let (body, offset, control, compress): (Vec<u8>, usize, bool, bool) = self.db.query_row(
            "SELECT body,offset,traffic<>'data',compress FROM network_events WHERE id=?1",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        let id = Uuid::parse_str(&id)?;
        if cancelled {
            let tx = self.db.unchecked_transaction()?;
            tx.execute(
                "UPDATE network_events SET cancelled=1 WHERE id=?1",
                [id.to_string()],
            )?;
            if let Some(subject) = &subject {
                tx.execute(
                    "INSERT OR IGNORE INTO network_rejections VALUES(?1)",
                    [subject],
                )?;
            }
            tx.commit()?;
        }
        let end = (offset + FRAGMENT_BYTES).min(body.len());
        let frame = if cancelled {
            Frame::Cancel { version: 1, id }
        } else {
            ensure!(offset < body.len(), "invalid outgoing fragment cursor");
            Frame::Part {
                version: 1,
                id,
                digest: Sha256::digest(&body).into(),
                total: body.len(),
                offset,
                data: STANDARD.encode(&body[offset..end]),
            }
        };
        let mut endpoint = OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?;
        let packet = endpoint.send_checked(
            group,
            (id, offset, cancelled),
            &serde_json::to_vec(&frame)?,
            compress,
            now() as u64,
            |db, state| {
                self.data_peer(db, group, true)?;
                check_cursor(db, group, (id, offset, cancelled))?;
                if !cancelled && let Some(subject) = &subject {
                    let session = self.network_session(db, state.clone());
                    ensure!(
                        session.deliverable(&session.message(subject)?)?,
                        "message permission changed before encryption"
                    );
                }
                Ok(())
            },
        )?;
        // Ciphertext and its request ID already committed together. If this
        // cursor write fails, retrying returns that exact packet without a ratchet step.
        let tx = self.db.unchecked_transaction()?;
        let confirmed: Option<u64> = if cancelled || end == body.len() {
            if !cancelled && control {
                configuration::pending::capture_record(&tx, self.identity.node.id(), &body)?;
            }
            retention::finish(&tx, id)?;
            tx.query_row(
                "DELETE FROM network_events WHERE id=?1 AND offset=?2 AND cancelled=?3
                 RETURNING (SELECT sequence FROM stream_confirmed WHERE group_id=?4)",
                params![id.to_string(), offset, cancelled, group],
                |row| row.get(0),
            )?
        } else {
            tx.query_row(
                "UPDATE network_events SET offset=?1 WHERE id=?2 AND offset=?3 AND cancelled=0
                 RETURNING (SELECT sequence FROM stream_confirmed WHERE group_id=?4)",
                params![end, id.to_string(), offset, group],
                |row| row.get(0),
            )?
        };
        // The usual new fragment is ahead of the signed floor. A cursor
        // recovered after a lost write may release already acknowledged bytes.
        if confirmed.is_some_and(|head| head > 0 && (head >= packet.sequence() || cancelled)) {
            encrypted::ordered::confirmation::retire_released_fragment(&tx, group, id, offset)?;
        }
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn data_outgoing(
        &self,
        group: &[u8],
        next: u64,
    ) -> Result<Option<gent_crypto::stream::Packet>> {
        self.data_peer(&self.db, group, true)?;
        let mut endpoint = OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?;
        ensure!(
            next <= endpoint.status(group, now() as u64)?.next,
            "relay position exceeds local history"
        );
        Ok(endpoint
            .outbox(group, next.checked_sub(1), 1, now() as u64)?
            .pop())
    }
    pub(crate) fn data_next(&mut self, group: &[u8]) -> Result<u64> {
        self.data_peer(&self.db, group, false)?;
        self.process_data(group)?;
        let mut endpoint = OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?;
        endpoint.drain(group, 1, now() as u64)?;
        let next = endpoint.status(group, now() as u64)?.next;
        drop(endpoint);
        self.process_data(group)?;
        Ok(next)
    }
    pub(crate) fn data_receive(&mut self, packet: &gent_crypto::stream::Packet) -> Result<()> {
        self.data_peer(&self.db, packet.group(), false)?;
        self.process_data(packet.group())?;
        let mut endpoint = OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?;
        endpoint.stage(packet, now() as u64)?;
        endpoint.drain(packet.group(), 1, now() as u64)?;
        drop(endpoint);
        self.process_data(packet.group())
    }
    fn process_data(&mut self, group: &[u8]) -> Result<()> {
        for _ in 0..32 {
            let tx = self.db.unchecked_transaction()?;
            let peer = self.data_peer(&tx, group, false)?;
            let Some((sequence,sender,body)) = tx.query_row("SELECT sequence,sender,body FROM inbox WHERE group_id=?1 ORDER BY sequence LIMIT 1", [group], |r| Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?))).optional()? else { return Ok(()); };
            ensure!(sender == peer, "node record sender mismatch");
            let frame: Frame = serde_json::from_slice(&body)?;
            match frame {
                Frame::Cancel { version, id } => {
                    ensure!(version == 1 && !id.is_nil(), "invalid cancellation");
                    tx.execute(
                        "DELETE FROM network_partial WHERE group_id=?1 AND id=?2",
                        params![group, id.to_string()],
                    )?;
                }
                Frame::Part {
                    version,
                    id,
                    digest,
                    total,
                    offset,
                    data,
                } => {
                    ensure!(
                        version == 1
                            && !id.is_nil()
                            && total > 0
                            && total <= MAX_RECORD_BYTES
                            && offset < total,
                        "invalid node record fragment"
                    );
                    let bytes = STANDARD.decode(data)?;
                    ensure!(
                        bytes.len() == (total - offset).min(FRAGMENT_BYTES),
                        "invalid fragment length"
                    );
                    let saved: Option<(String, Vec<u8>, usize, Vec<u8>)> = tx
                        .query_row(
                            "SELECT id,digest,total,body FROM network_partial WHERE group_id=?1",
                            [group],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                        )
                        .optional()?;
                    let mut record =
                        if let Some((saved_id, saved_digest, saved_total, body)) = saved {
                            ensure!(
                                saved_id == id.to_string()
                                    && saved_digest == digest
                                    && saved_total == total
                                    && body.len() == offset,
                                "node record gap or fork"
                            );
                            body
                        } else {
                            ensure!(offset == 0, "missing node record prefix");
                            let reserved: usize = tx.query_row(
                                "SELECT COALESCE(SUM(total),0) FROM network_partial",
                                [],
                                |r| r.get(0),
                            )?;
                            ensure!(
                                reserved + total <= 8 * 1024 * 1024,
                                "node record reconstruction limit reached"
                            );
                            Vec::new()
                        };
                    record.extend_from_slice(&bytes);
                    if record.len() == total {
                        ensure!(
                            Sha256::digest(&record).as_slice() == digest,
                            "node record digest mismatch"
                        );
                        let record: Record = serde_json::from_slice(&record)?;
                        let state = self.identity.state(&tx)?;
                        if record.authority.revision > state.checkpoint().revision {
                            return Ok(());
                        }
                        ensure!(
                            encrypted::history::checkpoint(
                                &tx,
                                record.authority.revision,
                                state.anchor()
                            )? == record.authority,
                            "node record authority fork"
                        );
                        let mut session = self.network_session(&tx, state);
                        if !session.obsolete_web_event(
                            &peer,
                            &record.event,
                            record.authority.revision,
                        )? {
                            session.import_event(&peer, record.event)?;
                        }
                        if let Some(snapshot) = record.directory {
                            session.confirm_wire_version(&peer, record.version)?;
                            session.receive_directory_snapshot(&peer, snapshot)?;
                        }
                        tx.execute("DELETE FROM network_partial WHERE group_id=?1", [group])?;
                    } else {
                        tx.execute("INSERT INTO network_partial VALUES(?1,?2,?3,?4,?5) ON CONFLICT(group_id) DO UPDATE SET body=excluded.body",params![group,id.to_string(),digest.as_slice(),total,record])?;
                    }
                }
            }
            tx.execute("DELETE FROM inbox WHERE sequence=?1", [sequence])?;
            tx.commit()?;
            let _ = self.project_config();
            self.sync_wakeup.notify_one();
        }
        Ok(())
    }
}
