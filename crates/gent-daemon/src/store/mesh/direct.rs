//! Durable direct bootstrap mailboxes. These contain encrypted MLS setup only;
//! ordinary agent messages continue over their existing MLS links.
use super::*;
use gent_crypto::{peer::direct as crypto, stream::Receipt};

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS mesh_direct_outbox(id BLOB PRIMARY KEY,peer TEXT NOT NULL,fingerprint BLOB NOT NULL,packet BLOB,last_attempt INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS mesh_direct_inbox(id BLOB PRIMARY KEY,receipt BLOB NOT NULL,published INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS mesh_direct_probes(id BLOB PRIMARY KEY,last_attempt INTEGER NOT NULL);")?;
    Ok(())
}

impl StoreSession<'_> {
    pub(super) fn queue_direct_mesh(&self, envelope: MeshEnvelope) -> Result<()> {
        ensure!(
            envelope.origin == self.identity.node.id() && envelope.current(&self.state)?,
            "invalid local mesh origin"
        );
        envelope.validate_size()?;
        let id = envelope.id();
        let bytes = serde_json::to_vec(&envelope)?;
        let fingerprint: [u8; 32] = Sha256::digest(&bytes).into();
        if let Some(saved) = self
            .db
            .query_row(
                "SELECT fingerprint FROM mesh_direct_outbox WHERE id=?1",
                [id.as_bytes().as_slice()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            ensure!(saved == fingerprint, "direct mesh retry changed");
            return Ok(());
        }
        let (count, used): (usize, usize) = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(packet)),0) FROM mesh_direct_outbox",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let packet = crypto::seal(
            &self.identity.node,
            &envelope.target_key,
            id.as_bytes(),
            &bytes,
        )?
        .encode()?;
        ensure!(
            count < 65536 && used.saturating_add(packet.len()) <= 64 * 1024 * 1024,
            "direct mesh capacity reached"
        );
        self.db.execute(
            "INSERT INTO mesh_direct_outbox(id,peer,fingerprint,packet) VALUES(?1,?2,?3,?4)",
            params![
                id.as_bytes().as_slice(),
                envelope.target,
                fingerprint.as_slice(),
                packet
            ],
        )?;
        Ok(())
    }
}

impl Store {
    pub(crate) fn direct_mesh_outgoing(&self) -> Result<Vec<Packet>> {
        let state = self.identity.state(&self.db)?;
        if state.state().peer.is_none() || state.require_fresh(now() as u64).is_err() {
            return Ok(vec![]);
        }
        let rows = self.db.prepare("SELECT id,peer,packet FROM mesh_direct_outbox WHERE packet IS NOT NULL ORDER BY last_attempt,rowid LIMIT 8")?
            .query_map([], |r| Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut packets = Vec::new();
        for (id, peer, bytes) in rows {
            if state.transport_host(&peer).is_ok_and(|host| host == peer) {
                packets.push(Packet::decode(&bytes)?);
            } else {
                self.db.execute(
                    "UPDATE mesh_direct_outbox SET packet=NULL WHERE id=?1",
                    [&id],
                )?;
            }
            self.db.execute(
                "UPDATE mesh_direct_outbox SET last_attempt=?1 WHERE id=?2",
                params![now(), id],
            )?;
        }
        Ok(packets)
    }

    pub(crate) fn direct_mesh_confirm(&self, receipt: &Receipt) -> Result<()> {
        let (peer, bytes): (String, Option<Vec<u8>>) = self.db.query_row(
            "SELECT peer,packet FROM mesh_direct_outbox WHERE id=?1",
            [receipt.group()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let state = self.identity.state(&self.db)?;
        let member = state
            .state()
            .nodes
            .get(&peer)
            .context("mesh peer no longer enrolled")?;
        receipt.verify(&member.signing_key)?;
        if let Some(bytes) = bytes {
            let packet = Packet::decode(&bytes)?;
            ensure!(
                receipt.sequence() == 0 && receipt.digest() == packet.digest()?,
                "direct mesh receipt mismatch"
            );
        }
        Ok(())
    }

    pub(crate) fn direct_mesh_finished(&self, receipt: &Receipt) -> Result<()> {
        self.direct_mesh_confirm(receipt)?;
        self.db.execute(
            "UPDATE mesh_direct_outbox SET packet=NULL WHERE id=?1",
            [receipt.group()],
        )?;
        Ok(())
    }

    pub(crate) fn direct_mesh_incoming(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let state = self.identity.state(&self.db)?;
        if state.state().peer.is_none() || state.require_fresh(now() as u64).is_err() {
            return Ok(vec![]);
        }
        let mut groups = Vec::new();
        for origin in state.state().nodes.keys().filter(|p| {
            *p != self.identity.node.id()
                && state.transport_host(p).is_ok_and(|host| host == p.as_str())
        }) {
            let link = link_id(&state, origin, self.identity.node.id())?;
            for step in [b"offer".as_slice(), b"welcome".as_slice()] {
                let id = scoped_id(
                    b"gent/mesh-signal/v1\0",
                    &[
                        link.as_bytes(),
                        origin.as_bytes(),
                        self.identity.node.id().as_bytes(),
                        step,
                    ],
                );
                let last: Option<i64> = self
                    .db
                    .query_row(
                        "SELECT last_attempt FROM mesh_direct_probes WHERE id=?1",
                        [id.as_bytes().as_slice()],
                        |r| r.get(0),
                    )
                    .optional()?;
                let linked: bool = self.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM network_links WHERE peer=?1)",
                    [origin],
                    |r| r.get(0),
                )?;
                // Once both sides have links, retained receipts still answer any
                // sender retry. Established pre-migration links need no probes.
                let published: Option<bool> = self
                    .db
                    .query_row(
                        "SELECT published FROM mesh_direct_inbox WHERE id=?1",
                        [id.as_bytes().as_slice()],
                        |r| r.get(0),
                    )
                    .optional()?;
                if published == Some(false) || (published.is_none() && !linked) {
                    groups.push((last.unwrap_or(0), origin.clone(), id.as_bytes().to_vec()));
                }
            }
        }
        groups.sort();
        let mut selected = Vec::new();
        for (_, peer, id) in groups.into_iter().take(8) {
            self.db.execute("INSERT INTO mesh_direct_probes VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET last_attempt=excluded.last_attempt", params![id,now()])?;
            selected.push((peer, id));
        }
        Ok(selected)
    }

    pub(crate) fn direct_mesh_receipt(&self, group: &[u8]) -> Result<Option<Receipt>> {
        self.db
            .query_row(
                "SELECT receipt FROM mesh_direct_inbox WHERE id=?1",
                [group],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|b| Receipt::decode(&b))
            .transpose()
    }

    pub(crate) fn direct_mesh_receipt_published(&self, group: &[u8]) -> Result<()> {
        self.db.execute(
            "UPDATE mesh_direct_inbox SET published=1 WHERE id=?1",
            [group],
        )?;
        Ok(())
    }

    pub(crate) fn receive_direct_mesh(&self, peer: &str, packet: &Packet) -> Result<Receipt> {
        let tx = self.db.unchecked_transaction()?;
        let state = self.identity.state(&tx)?;
        let member = state
            .state()
            .nodes
            .get(peer)
            .context("mesh peer unavailable")?;
        state.authorize_node(peer, &member.signing_key, now() as u64)?;
        let body = crypto::open(&self.identity.node, &member.signing_key, packet)?;
        let envelope: MeshEnvelope = serde_json::from_slice(&body)?;
        envelope.validate_size()?;
        ensure!(
            envelope.origin == peer
                && envelope.target == self.identity.node.id()
                && envelope.current(&state)?
                && envelope.id().as_bytes() == packet.group(),
            "direct mesh scope mismatch"
        );
        storage::admit(&tx, &envelope)?;
        let receipt =
            self.identity
                .node
                .sign_stream_receipt(packet.group(), 0, packet.digest()?)?;
        if let Some(previous) = self.direct_mesh_receipt(packet.group())? {
            ensure!(previous == receipt, "direct mesh history fork");
        }
        tx.execute(
            "INSERT INTO mesh_direct_inbox(id,receipt) VALUES(?1,?2) ON CONFLICT DO NOTHING",
            params![packet.group(), receipt.encode()?],
        )?;
        tx.commit()?;
        self.sync_wakeup.notify_one();
        Ok(receipt)
    }
}
