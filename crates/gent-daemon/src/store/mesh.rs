//! Automatic two-node streams. Only bootstrap metadata passes through the owner;
//! neither the owner nor the service receives the peers' application group keys.
use super::*;
use crate::{
    encrypted::ordered::OrderedEndpoint,
    messages::{Event, MeshEnvelope, MeshSignal},
};
use gent_crypto::{scoped_id, stream::Packet};
use uuid::Uuid;

const BATCH: usize = 8;
mod direct;
pub(super) mod storage;

#[cfg(test)]
mod tests;

pub(super) fn schema(db: &Connection) -> Result<()> {
    storage::schema(db)?;
    direct::schema(db)
}

fn link_id(state: &VerifiedState, a: &str, b: &str) -> Result<Uuid> {
    ensure!(a != b, "mesh requires distinct nodes");
    let mut ids = [a, b];
    ids.sort();
    let keys: Vec<_> = ids
        .iter()
        .map(|id| {
            state
                .state()
                .nodes
                .get(*id)
                .map(|n| n.signing_key)
                .context("mesh peer is not enrolled")
        })
        .collect::<Result<_>>()?;
    Ok(scoped_id(
        b"gent/mesh-link/v1\0",
        &[
            state.anchor().cluster_id.as_bytes(),
            ids[0].as_bytes(),
            &keys[0],
            ids[1].as_bytes(),
            &keys[1],
        ],
    ))
}

impl MeshEnvelope {
    fn id(&self) -> Uuid {
        let step = match self.signal {
            MeshSignal::Offer { .. } => b"offer".as_slice(),
            MeshSignal::Welcome { .. } => b"welcome".as_slice(),
        };
        scoped_id(
            b"gent/mesh-signal/v1\0",
            &[
                self.link.as_bytes(),
                self.origin.as_bytes(),
                self.target.as_bytes(),
                step,
            ],
        )
    }
    fn current(&self, state: &VerifiedState) -> Result<bool> {
        let (Some(origin), Some(target)) = (
            state.state().nodes.get(&self.origin),
            state.state().nodes.get(&self.target),
        ) else {
            return Ok(false);
        };
        if origin.signing_key != self.origin_key || target.signing_key != self.target_key {
            return Ok(false);
        }
        ensure!(
            self.link == link_id(state, &self.origin, &self.target)?,
            "invalid mesh link identity"
        );
        Ok(true)
    }
    fn validate_size(&self) -> Result<()> {
        match &self.signal {
            MeshSignal::Offer { key_package } => {
                ensure!(key_package.len() <= 24 * 1024, "mesh key package too large")
            }
            MeshSignal::Welcome { packet } => {
                ensure!(packet.len() <= 512 * 1024, "mesh Welcome too large")
            }
        }
        Ok(())
    }
}

impl StoreSession<'_> {
    pub(super) fn import_mesh(&self, sender: &str, envelope: MeshEnvelope) -> Result<()> {
        envelope.validate_size()?;
        if self.state.state().peer.is_some() {
            return Ok(());
        }
        if self.identity.is_current_owner(&self.state) {
            ensure!(
                envelope.origin == sender && envelope.target != self.identity.node.id(),
                "mesh forwarding origin or target mismatch"
            );
        } else {
            ensure!(
                sender == self.configuration_writer()?
                    && envelope.target == self.identity.node.id()
                    && envelope.origin != sender,
                "mesh bootstrap requires the configured owner route"
            );
        }
        // Revocation/key replacement may overtake queued bootstrap traffic. Drop
        // that work without stalling unrelated traffic on the shared owner link.
        if !envelope.current(&self.state)? {
            return Ok(());
        }
        storage::admit(self.db, &envelope)
    }
    fn queue_mesh(&self, route: &str, envelope: MeshEnvelope) -> Result<()> {
        if self.state.state().peer.is_some() {
            return self.queue_direct_mesh(envelope);
        }
        let id = scoped_id(
            b"gent/mesh-hop/v1\0",
            &[envelope.id().as_bytes(), route.as_bytes()],
        );
        self.queue(route, id, Event::Mesh { envelope }, None)
    }
}

impl Store {
    /// One bounded maintenance pass. Cryptographic operations have durable,
    /// deterministic request IDs; subsequent job/outbox transactions can retry
    /// after a crash without consuming another key package or creating a group.
    pub(crate) fn mesh_tick(&mut self) -> Result<bool> {
        let state = self.identity.state(&self.db)?;
        if self.config.relay.is_none() || state.require_fresh(now() as u64).is_err() {
            return Ok(false);
        }
        state.authorize_node(
            self.identity.node.id(),
            &self.identity.node.public_key(),
            now() as u64,
        )?;
        let writer = if state.state().peer.is_some() {
            Some(String::new())
        } else if self.identity.is_current_owner(&state) {
            None
        } else {
            // Configuration-only fixtures and interrupted enrollment may not yet
            // have an owner route. Ordinary configuration recovery still runs.
            match self
                .network_session(&self.db, state.clone())
                .configuration_writer()
            {
                Ok(writer) => Some(writer),
                Err(_) => return Ok(false),
            }
        };
        let mut more = false;
        if let Some(writer) = &writer {
            let ready: bool = self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM network_links WHERE peer=?1)",
                [writer],
                |r| r.get(0),
            )?;
            if !ready && state.state().peer.is_none() {
                return Ok(false);
            }
            let mut candidates = Vec::new();
            for peer in state
                .state()
                .nodes
                .keys()
                .filter(|p| *p != self.identity.node.id() && *p != writer)
            {
                let known: bool = if state.state().peer.is_some() {
                    self.db.query_row("SELECT EXISTS(SELECT 1 FROM network_links WHERE peer=?1) OR EXISTS(SELECT 1 FROM mesh_direct_outbox WHERE peer=?1)", [peer], |r| r.get(0))?
                } else {
                    self.db.query_row("SELECT EXISTS(SELECT 1 FROM network_links WHERE peer=?1) OR EXISTS(SELECT 1 FROM mesh_peers WHERE peer=?1)", [peer], |r| r.get(0))?
                };
                if !known {
                    candidates.push(peer.clone());
                }
            }
            more = candidates.len() > BATCH;
            for peer in candidates.into_iter().take(BATCH) {
                self.offer_mesh(&state, writer, &peer)?;
            }
        }
        let jobs = self.db.prepare("SELECT id,body,attempts,error,fingerprint FROM mesh_jobs WHERE done=0 AND retry_at<=?1 ORDER BY retry_at,rowid LIMIT ?2")?
            .query_map(params![now(),BATCH], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,u32>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,Option<Vec<u8>>>(4)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, body, attempts, previous, fingerprint) in jobs {
            let result = storage::decode(&id, &body, fingerprint.as_deref())
                .and_then(|envelope| self.process_mesh(&id, envelope));
            if let Err(error) = result {
                let error = storage::error_text(error.to_string());
                if previous.as_ref() != Some(&error) {
                    eprintln!("Gent peer setup waiting: {error}");
                }
                let delay = 1i64 << attempts.min(5);
                self.db.execute("UPDATE mesh_jobs SET attempts=MIN(attempts+1,32),retry_at=?1,error=?2 WHERE id=?3", params![now()+delay,error,id])?;
            }
        }
        // Incomplete local pairs also need a pass after the second stream's job
        // commits. Installing the link and announcing registrations is atomic.
        let peers = self.db.prepare("SELECT peer,peer_key,outgoing,incoming FROM mesh_peers WHERE outgoing IS NOT NULL AND incoming IS NOT NULL AND peer NOT IN (SELECT peer FROM network_links) ORDER BY rowid")?
            .query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,Vec<u8>>(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut ready = peers.into_iter().filter(|(peer, key, _, _)| {
            state
                .state()
                .nodes
                .get(peer)
                .is_some_and(|n| n.signing_key.as_slice() == key)
        });
        for (peer, _, outgoing, incoming) in ready.by_ref().take(BATCH) {
            self.install_data_link(&peer, &outgoing, &incoming, &[])?;
        }
        more |= ready.next().is_some();
        let pending: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM mesh_jobs WHERE done=0)",
            [],
            |r| r.get(0),
        )?;
        Ok(more || pending)
    }

    fn offer_mesh(&self, state: &VerifiedState, writer: &str, peer: &str) -> Result<()> {
        let link = link_id(state, self.identity.node.id(), peer)?;
        let request = scoped_id(
            b"gent/mesh-package/v1\0",
            &[link.as_bytes(), self.identity.node.id().as_bytes()],
        );
        let package = OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?
            .key_package(request, now() as u64)?;
        let tx = self.db.unchecked_transaction()?;
        let current = self.identity.state(&tx)?;
        ensure!(
            link_id(&current, self.identity.node.id(), peer)? == link,
            "mesh authority changed"
        );
        let key = current.state().nodes[peer].signing_key;
        tx.execute(
            "INSERT INTO mesh_peers(peer,peer_key,link) VALUES(?1,?2,?3) ON CONFLICT(peer) DO NOTHING",
            params![peer, key.as_slice(), link.to_string()],
        )?;
        self.network_session(&tx, current).queue_mesh(
            writer,
            MeshEnvelope {
                origin: self.identity.node.id().into(),
                target: peer.into(),
                origin_key: self.identity.node.public_key(),
                target_key: key,
                link,
                signal: MeshSignal::Offer {
                    key_package: STANDARD.encode(package),
                },
            },
        )?;
        tx.commit()?;
        self.sync_wakeup.notify_one();
        Ok(())
    }

    fn process_mesh(&mut self, id: &str, envelope: MeshEnvelope) -> Result<()> {
        let state = self.identity.state(&self.db)?;
        state.require_fresh(now() as u64)?;
        if !envelope.current(&state)? {
            let tx = self.db.unchecked_transaction()?;
            storage::finish(&tx, id, Some("peer revoked or key replaced"))?;
            tx.commit()?;
            return Ok(());
        }
        if state.state().peer.is_some() && envelope.target != self.identity.node.id() {
            let tx = self.db.unchecked_transaction()?;
            storage::finish(
                &tx,
                id,
                Some("legacy forwarding replaced by direct bootstrap"),
            )?;
            tx.commit()?;
            return Ok(());
        }
        if self.identity.is_current_owner(&state) {
            let tx = self.db.unchecked_transaction()?;
            let target = envelope.target.clone();
            self.network_session(&tx, self.identity.state(&tx)?)
                .queue_mesh(&target, envelope)?;
            storage::finish(&tx, id, None)?;
            tx.commit()?;
            self.sync_wakeup.notify_one();
            return Ok(());
        }
        let peer = &envelope.origin;
        let saved: (Vec<u8>, String) = self.db.query_row(
            "SELECT peer_key,link FROM mesh_peers WHERE peer=?1",
            [peer],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            saved.0 == envelope.origin_key && saved.1 == envelope.link.to_string(),
            "mesh attempt belongs to another peer key"
        );
        let mut endpoint = OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?;
        match &envelope.signal {
            MeshSignal::Offer { key_package } => {
                let request = scoped_id(
                    b"gent/mesh-stream/v1\0",
                    &[envelope.link.as_bytes(), self.identity.node.id().as_bytes()],
                );
                let packet = endpoint.create(
                    request,
                    &[(peer, &STANDARD.decode(key_package)?)],
                    now() as u64,
                )?;
                drop(endpoint);
                let tx = self.db.unchecked_transaction()?;
                let session = self.network_session(&tx, self.identity.state(&tx)?);
                ensure!(envelope.current(&session.state)?, "mesh authority changed");
                let writer = if state.state().peer.is_some() {
                    String::new()
                } else {
                    session.configuration_writer()?
                };
                session.queue_mesh(
                    &writer,
                    MeshEnvelope {
                        origin: self.identity.node.id().into(),
                        target: peer.clone(),
                        origin_key: self.identity.node.public_key(),
                        target_key: envelope.origin_key,
                        link: envelope.link,
                        signal: MeshSignal::Welcome {
                            packet: STANDARD.encode(packet.encode()?),
                        },
                    },
                )?;
                save_group(&tx, peer, "outgoing", packet.group())?;
                storage::finish(&tx, id, None)?;
                tx.commit()?;
            }
            MeshSignal::Welcome { packet } => {
                let packet = Packet::decode(&STANDARD.decode(packet)?)?;
                endpoint.join(
                    &packet,
                    peer,
                    &[self.identity.node.id(), peer],
                    now() as u64,
                )?;
                drop(endpoint);
                let tx = self.db.unchecked_transaction()?;
                ensure!(
                    envelope.current(&self.identity.state(&tx)?)?,
                    "mesh authority changed"
                );
                save_group(&tx, peer, "incoming", packet.group())?;
                storage::finish(&tx, id, None)?;
                tx.commit()?;
            }
        }
        self.sync_wakeup.notify_one();
        Ok(())
    }
}

fn save_group(db: &Connection, peer: &str, column: &str, group: &[u8]) -> Result<()> {
    // The column is selected only by the two static call sites above.
    let saved: Option<Vec<u8>> = db.query_row(
        &format!("SELECT {column} FROM mesh_peers WHERE peer=?1"),
        [peer],
        |r| r.get(0),
    )?;
    ensure!(
        saved.as_deref().is_none_or(|saved| saved == group),
        "conflicting mesh stream"
    );
    db.execute(
        &format!("UPDATE mesh_peers SET {column}=?1 WHERE peer=?2"),
        params![group, peer],
    )?;
    Ok(())
}
