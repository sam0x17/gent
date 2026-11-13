//! Directional MLS streams: one writer, authenticated ordering, durable gaps.
//! Replies use another stream. These APIs are for trusted daemon code only.
use super::*;
use gent_crypto::{Digest, PublicKey, stream::Packet};

pub const MAX_PENDING_DISTANCE: u64 = 128;
pub const MAX_PENDING_BYTES: usize = 16 * 1024 * 1024;
const MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;

pub struct OrderedEndpoint<'a> {
    inner: EncryptedEndpoint<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Staged {
    Queued,
    Duplicate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamStatus {
    pub head: u64,
    pub digest: Digest,
    pub pending: usize,
    /// Fetch starting at this position when later packets are buffered.
    pub next: u64,
}

struct Stream {
    writer: String,
    key: PublicKey,
    head: u64,
    digest: Digest,
    origin: Digest,
    roster: Digest,
}

impl<'a> OrderedEndpoint<'a> {
    pub fn open(home: &Path, identity: &'a NodeIdentity) -> Result<Self> {
        Ok(Self {
            inner: EncryptedEndpoint::open(home, identity)?,
        })
    }
    pub fn initialize(&mut self, state: &VerifiedState, now: u64) -> Result<()> {
        self.inner.initialize(state, now)
    }
    pub fn apply_authority(&mut self, updates: &[SignedState]) -> Result<()> {
        self.inner.apply_authority(updates)
    }
    pub fn key_package(&mut self, request: Uuid, now: u64) -> Result<Vec<u8>> {
        self.inner.key_package(request, now)
    }

    pub fn create(&mut self, request: Uuid, peers: &[(&str, &[u8])], now: u64) -> Result<Packet> {
        self.inner.transact(now, |session| {
            // A low-level proof group cannot be converted after it has emitted
            // unsequenced traffic. A genuine ordered retry already has its packet.
            let raw_exists: bool = session.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM outbox WHERE id=?1)",
                [request.to_string()],
                |row| row.get(0),
            )?;
            let saved = outgoing_request(session.db, request)?;
            ensure!(
                !raw_exists || saved.is_some(),
                "cannot adopt a raw MLS operation"
            );
            let welcome = session.create_group(request, peers)?;
            if let Some(saved) = saved {
                return Ok(saved);
            }
            let packet =
                session
                    .signer
                    .sign_stream_packet(&welcome.group_id, 0, [0; 32], &welcome.bytes)?;
            let ids: Vec<_> = std::iter::once(session.signer.id())
                .chain(peers.iter().map(|(node, _)| *node))
                .collect();
            initialize_stream(
                session,
                &packet,
                session.signer.id(),
                session.signer.public_key(),
                roster_hash(&ids)?,
            )?;
            save_outgoing(session.db, request, &packet)?;
            Ok(packet)
        })
    }

    /// Writer and roster must be independently approved locally. The outer packet
    /// signature and MLS Welcome creator must both authenticate that writer.
    pub fn join(
        &mut self,
        packet: &Packet,
        writer: &str,
        expected: &[&str],
        now: u64,
    ) -> Result<()> {
        ensure!(packet.sequence() == 0, "expected stream origin");
        let roster = roster_hash(expected)?;
        self.inner.transact(now, |session| {
            ensure!(
                writer != session.signer.id() && expected.contains(&writer),
                "invalid stream writer"
            );
            let key = session
                .state
                .state()
                .nodes
                .get(writer)
                .context("unknown writer")?
                .signing_key;
            session.state.authorize_node(writer, &key, now)?;
            packet.verify(&key)?;
            if let Some(saved) = stream(session.db, packet.group())? {
                ensure!(
                    saved.writer == writer
                        && saved.key == key
                        && saved.origin == packet.digest()?
                        && saved.roster == roster,
                    "conflicting stream origin"
                );
                return Ok(());
            }
            let invitation = Outgoing {
                id: Uuid::nil(),
                group_id: packet.group().into(),
                bytes: packet.ciphertext().into(),
            };
            session.join(&invitation, expected, Some(writer))?;
            initialize_stream(session, packet, writer, key, roster)
        })
    }

    pub fn send(&mut self, group: &[u8], id: Uuid, body: &[u8], now: u64) -> Result<Packet> {
        self.publish(group, now, |session| session.send(group, id, body))
    }
    pub fn rotate(&mut self, group: &[u8], id: Uuid, now: u64) -> Result<Packet> {
        self.publish(group, now, |session| session.rotate(group, id))
    }
    pub fn remove_revoked(&mut self, group: &[u8], id: Uuid, now: u64) -> Result<Packet> {
        self.publish(group, now, |session| session.remove_revoked(group, id))
    }

    fn publish(
        &mut self,
        group: &[u8],
        now: u64,
        operation: impl FnOnce(&Session<'_>) -> Result<Outgoing>,
    ) -> Result<Packet> {
        self.inner.transact(now, |session| {
            let saved = authorized_stream(session, group)?;
            ensure!(
                saved.writer == session.signer.id(),
                "only the stream writer can send or change epochs"
            );
            let outgoing = operation(session)?;
            if let Some(packet) = outgoing_request(session.db, outgoing.id)? {
                return Ok(packet);
            }
            let packet = session.signer.sign_stream_packet(
                group,
                saved.head.checked_add(1).context("stream exhausted")?,
                saved.digest,
                &outgoing.bytes,
            )?;
            save_outgoing(session.db, outgoing.id, &packet)?;
            advance(session.db, &packet)?;
            Ok(packet)
        })
    }

    /// Verify before buffering, including writer authority. No MLS keys advance
    /// here. Duplicate and conflicting sequence slots cannot overwrite each other.
    pub fn stage(&mut self, packet: &Packet, now: u64) -> Result<Staged> {
        self.inner.transact(now, |session| {
            let saved = authorized_stream(session, packet.group())?;
            ensure!(
                saved.writer != session.signer.id(),
                "writer cannot receive its own stream"
            );
            packet.verify(&saved.key)?;
            let digest = packet.digest()?;
            if let Some(seen) = seen(session.db, packet.group(), packet.sequence())? {
                ensure!(seen == digest, "conflicting accepted stream history");
                return Ok(Staged::Duplicate);
            }
            ensure!(
                packet.sequence() > saved.head
                    && packet.sequence() - saved.head <= MAX_PENDING_DISTANCE,
                "packet outside receive window"
            );
            if packet.sequence() == saved.head + 1 {
                ensure!(
                    packet.previous() == saved.digest,
                    "stream predecessor mismatch"
                );
            }
            let pending: Option<Vec<u8>> = session
                .db
                .query_row(
                    "SELECT digest FROM stream_pending WHERE group_id=?1 AND sequence=?2",
                    params![packet.group(), packet.sequence()],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(pending) = pending {
                ensure!(pending == digest, "conflicting buffered stream history");
                return Ok(Staged::Duplicate);
            }
            let wire = packet.encode()?;
            let used: usize = session.db.query_row(
                "SELECT COALESCE(SUM(length(packet)),0) FROM stream_pending",
                [],
                |row| row.get(0),
            )?;
            // Keep room for a missing predecessor even when later packets fill
            // the queue. Draining that contiguous prefix releases the reserve.
            let capacity = if packet.sequence() == saved.head + 1 {
                MAX_PENDING_BYTES
            } else {
                MAX_PENDING_BYTES - gent_crypto::stream::MAX_PACKET_BYTES
            };
            ensure!(
                used + wire.len() <= capacity,
                "pending stream storage limit reached"
            );
            session.db.execute(
                "INSERT INTO stream_pending VALUES(?1,?2,?3,?4)",
                params![packet.group(), packet.sequence(), digest.as_slice(), wire],
            )?;
            Ok(Staged::Queued)
        })
    }

    /// Apply at most `limit` contiguous packets. Each packet commits separately:
    /// a later invalid packet cannot roll back earlier accepted work. Errors leave
    /// the failing packet queued for diagnosis, never skip an authenticated gap.
    pub fn drain(&mut self, group: &[u8], limit: usize, now: u64) -> Result<Vec<Received>> {
        ensure!((1..=128).contains(&limit), "invalid drain limit");
        let mut applied = Vec::new();
        for _ in 0..limit {
            let result = self.inner.transact(now, |session| {
                let saved = authorized_stream(session, group)?;
                ensure!(
                    saved.writer != session.signer.id(),
                    "writer cannot receive its own stream"
                );
                let wire: Option<Vec<u8>> = session
                    .db
                    .query_row(
                        "SELECT packet FROM stream_pending WHERE group_id=?1 AND sequence=?2",
                        params![group, saved.head + 1],
                        |row| row.get(0),
                    )
                    .optional()?;
                let Some(wire) = wire else {
                    return Ok(None);
                };
                let packet = Packet::decode(&wire)?;
                packet.verify(&saved.key)?;
                ensure!(
                    packet.group() == group
                        && packet.sequence() == saved.head + 1
                        && packet.previous() == saved.digest,
                    "stream predecessor mismatch"
                );
                let received = session.receive(group, packet.ciphertext(), Some(&saved.writer))?;
                ensure!(
                    received != Received::Duplicate,
                    "MLS packet repeated at a new sequence"
                );
                advance(session.db, &packet)?;
                session.db.execute(
                    "DELETE FROM stream_pending WHERE group_id=?1 AND sequence=?2",
                    params![group, packet.sequence()],
                )?;
                Ok(Some(received))
            })?;
            match result {
                Some(received) => applied.push(received),
                None => break,
            }
        }
        Ok(applied)
    }

    pub fn status(&mut self, group: &[u8], now: u64) -> Result<StreamStatus> {
        self.inner.transact(now, |session| {
            let saved = authorized_stream(session, group)?;
            let pending = session.db.query_row(
                "SELECT COUNT(*) FROM stream_pending WHERE group_id=?1",
                [group],
                |row| row.get(0),
            )?;
            Ok(StreamStatus {
                head: saved.head,
                digest: saved.digest,
                pending,
                next: saved.head + 1,
            })
        })
    }

    /// Durable ciphertext packets; None includes the origin. Recipient transport
    /// authorization and encrypted acknowledgments remain a separate concern.
    pub fn outbox(
        &mut self,
        group: &[u8],
        after: Option<u64>,
        limit: usize,
        now: u64,
    ) -> Result<Vec<Packet>> {
        ensure!((1..=128).contains(&limit), "invalid outbox limit");
        self.inner.transact(now, |session| {
            let saved = authorized_stream(session, group)?;
            ensure!(saved.writer == session.signer.id(), "only the writer has an outbox");
            let after = after.map(i64::try_from).transpose()?.unwrap_or(-1);
            let mut query = session.db.prepare("SELECT packet FROM stream_outbox WHERE group_id=?1 AND sequence>?2 ORDER BY sequence LIMIT ?3")?;
            let mut result = Vec::new();
            let mut bytes = 0;
            for row in query.query_map(params![group,after,limit], |row| row.get::<_,Vec<u8>>(0))? {
                let wire = row?;
                if bytes + wire.len() > MAX_BATCH_BYTES { break; }
                bytes += wire.len();
                let packet = Packet::decode(&wire)?;
                packet.verify(&saved.key)?;
                result.push(packet);
            }
            Ok(result)
        })
    }

    /// Trusted endpoint inspection. Agent-level delivery still needs its policy check.
    pub fn inbox(
        &self,
        group: &[u8],
        after: i64,
        limit: usize,
    ) -> Result<Vec<(i64, InboxMessage)>> {
        self.inner.inbox(group, after, limit)
    }
}

fn roster_hash(expected: &[&str]) -> Result<Digest> {
    Ok(Sha256::digest(serde_json::to_vec(&roster(expected)?)?).into())
}

fn stream(db: &Connection, group: &[u8]) -> Result<Option<Stream>> {
    ensure!(!group.is_empty() && group.len() <= 256, "invalid group ID");
    Ok(db.query_row("SELECT writer,writer_key,head,head_hash,origin_hash,roster_hash FROM streams WHERE group_id=?1", [group], |row| Ok(Stream {
        writer:row.get(0)?,key:row.get(1)?,head:row.get(2)?,digest:row.get(3)?,origin:row.get(4)?,roster:row.get(5)?
    })).optional()?)
}

fn authorized_stream(session: &Session<'_>, group: &[u8]) -> Result<Stream> {
    let stream = stream(session.db, group)?.context("unknown ordered stream")?;
    session
        .state
        .authorize_node(&stream.writer, &stream.key, session.now)?;
    Ok(stream)
}

fn initialize_stream(
    session: &Session<'_>,
    packet: &Packet,
    writer: &str,
    key: PublicKey,
    roster: Digest,
) -> Result<()> {
    let digest = packet.digest()?;
    session.db.execute(
        "INSERT INTO streams VALUES(?1,?2,?3,0,?4,?4,?5)",
        params![
            packet.group(),
            writer,
            key.as_slice(),
            digest.as_slice(),
            roster.as_slice()
        ],
    )?;
    session.db.execute(
        "INSERT INTO stream_seen VALUES(?1,0,?2)",
        params![packet.group(), digest.as_slice()],
    )?;
    Ok(())
}

fn outgoing_request(db: &Connection, id: Uuid) -> Result<Option<Packet>> {
    let wire: Option<Vec<u8>> = db
        .query_row(
            "SELECT packet FROM stream_outbox WHERE id=?1",
            [id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    wire.map(|wire| Packet::decode(&wire)).transpose()
}

fn save_outgoing(db: &Connection, id: Uuid, packet: &Packet) -> Result<()> {
    db.execute(
        "INSERT INTO stream_outbox VALUES(?1,?2,?3,?4)",
        params![
            id.to_string(),
            packet.group(),
            packet.sequence(),
            packet.encode()?
        ],
    )?;
    Ok(())
}

fn seen(db: &Connection, group: &[u8], sequence: u64) -> Result<Option<Digest>> {
    Ok(db
        .query_row(
            "SELECT digest FROM stream_seen WHERE group_id=?1 AND sequence=?2",
            params![group, sequence],
            |row| row.get(0),
        )
        .optional()?)
}

fn advance(db: &Connection, packet: &Packet) -> Result<()> {
    let digest = packet.digest()?;
    db.execute(
        "UPDATE streams SET head=?1,head_hash=?2 WHERE group_id=?3",
        params![packet.sequence(), digest.as_slice(), packet.group()],
    )?;
    db.execute(
        "INSERT INTO stream_seen VALUES(?1,?2,?3)",
        params![packet.group(), packet.sequence(), digest.as_slice()],
    )?;
    Ok(())
}
