//! Directional MLS streams: one writer, authenticated ordering, durable gaps.
//! Replies use another stream. These APIs are for trusted daemon code only.
pub mod configuration;
pub mod confirmation;
pub mod storage;
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
    /// Older than retained digest evidence. Never queued or decrypted again;
    /// equality with an original packet is no longer asserted.
    Retired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamStatus {
    pub head: u64,
    pub digest: Digest,
    pub pending: usize,
    /// Fetch starting at this position when later packets are buffered.
    pub next: u64,
    /// Non-origin positions at or below this may have retired digest evidence.
    pub retired_through: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Data,
    Configuration,
}
impl Purpose {
    fn name(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Configuration => "configuration",
        }
    }
}

struct Stream {
    purpose: String,
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

    /// Attach trusted daemon code to the live RPC database. Configuration
    /// reception and RPC permission checks then share one authority checkpoint.
    pub fn open_runtime(home: &Path, identity: &'a NodeIdentity) -> Result<Self> {
        ensure!(
            home.join("state.sqlite3").exists(),
            "runtime is not initialized"
        );
        let db = open_database(home, "state.sqlite3")?;
        let initialized: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM metadata WHERE key='signed_authority')",
            [],
            |row| row.get(0),
        )?;
        ensure!(initialized, "runtime is not initialized");
        authority(&db, identity)?;
        Ok(Self {
            inner: EncryptedEndpoint { db, identity },
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
                ensure!(
                    stream(session.db, saved.group())?
                        .context("unknown stream")?
                        .purpose
                        == Purpose::Data.name(),
                    "wrong stream purpose"
                );
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
                    saved.purpose == Purpose::Data.name()
                        && saved.writer == writer
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
    /// Policy and encryption share the same immediate transaction, closing the
    /// race with a configuration change between queue inspection and encryption.
    pub(crate) fn send_checked(
        &mut self,
        group: &[u8],
        fragment: (Uuid, usize, bool),
        body: &[u8],
        compress: bool,
        now: u64,
        check: impl FnOnce(&Connection, &VerifiedState) -> Result<()>,
    ) -> Result<Packet> {
        self.inner.transact(now, |session| {
            check(session.db, &session.state)?;
            let id = requests::allocate(session.db, group, body, Some(fragment))?;
            publish_in(session, group, Purpose::Data, |session| {
                session.send_with_compression(group, id, body, compress)
            })
        })
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
            publish_in(session, group, Purpose::Data, operation)
        })
    }

    /// Verify before buffering, including writer authority. No MLS keys advance
    /// here. Duplicate and conflicting sequence slots cannot overwrite each other.
    pub fn stage(&mut self, packet: &Packet, now: u64) -> Result<Staged> {
        self.inner
            .transact(now, |session| stage_in(session, packet, Purpose::Data))
    }

    /// Apply at most `limit` contiguous packets. Each packet commits separately:
    /// a later invalid packet cannot roll back earlier accepted work. Errors leave
    /// the failing packet queued for diagnosis, never skip an authenticated gap.
    pub fn drain(&mut self, group: &[u8], limit: usize, now: u64) -> Result<Vec<Received>> {
        self.drain_mode(group, limit, now, Purpose::Data)
    }

    fn drain_mode(
        &mut self,
        group: &[u8],
        limit: usize,
        now: u64,
        purpose: Purpose,
    ) -> Result<Vec<Received>> {
        ensure!((1..=128).contains(&limit), "invalid drain limit");
        let mut applied = Vec::new();
        for _ in 0..limit {
            let result =
                self.inner
                    .transact_mode(now, purpose == Purpose::Configuration, |session| {
                        let saved = checked_stream(session, group, purpose)?;
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
                        let received = if purpose == Purpose::Configuration {
                            configuration::receive(
                                session,
                                group,
                                packet.ciphertext(),
                                &saved.writer,
                            )?
                        } else {
                            session.receive(group, packet.ciphertext(), Some(&saved.writer))?
                        };
                        ensure!(
                            received != Received::Duplicate,
                            "MLS packet repeated at a new sequence"
                        );
                        advance(session.db, &packet)?;
                        storage::received(session.db, &packet)?;
                        storage::trim_group(session.db, group, packet.sequence())?;
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
        self.status_mode(group, now, Purpose::Data)
    }

    fn status_mode(&mut self, group: &[u8], now: u64, purpose: Purpose) -> Result<StreamStatus> {
        self.inner
            .transact_mode(now, purpose == Purpose::Configuration, |session| {
                let saved = checked_stream(session, group, purpose)?;
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
                    retired_through: saved.head.saturating_sub(storage::RECENT_PACKETS),
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
        self.outbox_mode(group, after, limit, now, Purpose::Data)
    }

    fn outbox_mode(
        &mut self,
        group: &[u8],
        after: Option<u64>,
        limit: usize,
        now: u64,
        purpose: Purpose,
    ) -> Result<Vec<Packet>> {
        ensure!((1..=128).contains(&limit), "invalid outbox limit");
        self.inner.transact_mode(now, purpose == Purpose::Configuration, |session| {
            let saved = checked_stream(session, group, purpose)?;
            ensure!(saved.writer == session.signer.id(), "only the writer has an outbox");
            ensure!(after.is_none_or(|n| n < gent_crypto::stream::MAX_SEQUENCE), "invalid outbox position");
            let after = after.map(i64::try_from).transpose()?.unwrap_or(-1);
            ensure!((after+1) as u64 >= confirmation::next(session.db,group)?,"requested stream prefix was confirmed and retired; endpoint recovery is required for an older receiver");
            let mut query = session.db.prepare("SELECT packet FROM stream_outbox WHERE group_id=?1 AND sequence>?2 AND length(packet)>0 ORDER BY sequence LIMIT ?3")?;
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

    /// Trusted endpoint inspection. Chat-level delivery still needs its policy check.
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
    Ok(db.query_row("SELECT writer,writer_key,head,head_hash,origin_hash,roster_hash,purpose FROM streams WHERE group_id=?1", [group], |row| Ok(Stream {
        writer:row.get(0)?,key:row.get(1)?,head:row.get(2)?,digest:row.get(3)?,origin:row.get(4)?,roster:row.get(5)?,purpose:row.get(6)?
    })).optional()?)
}

fn checked_stream(session: &Session<'_>, group: &[u8], purpose: Purpose) -> Result<Stream> {
    let stream = stream(session.db, group)?.context("unknown ordered stream")?;
    ensure!(stream.purpose == purpose.name(), "wrong stream purpose");
    if purpose == Purpose::Configuration {
        configuration::authorize(session, group, &stream)?;
    } else {
        session
            .state
            .authorize_node(&stream.writer, &stream.key, session.now)?;
    }
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
        "INSERT INTO streams(group_id,writer,writer_key,head,head_hash,origin_hash,roster_hash) VALUES(?1,?2,?3,0,?4,?4,?5)",
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
    storage::received(session.db, packet)?;
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
    wire.map(|wire| {
        ensure!(
            !wire.is_empty(),
            "transport request was confirmed and retired; it cannot be submitted again"
        );
        Packet::decode(&wire)
    })
    .transpose()
}

fn save_outgoing(db: &Connection, id: Uuid, packet: &Packet) -> Result<()> {
    let wire = packet.encode()?;
    let saved = stream(db, packet.group())?.context("unknown stream")?;
    storage::capacity(db, &saved.purpose, wire.len())?;
    db.execute(
        "INSERT INTO stream_outbox VALUES(?1,?2,?3,?4)",
        params![id.to_string(), packet.group(), packet.sequence(), wire],
    )?;
    // Keep the request fingerprint but reconstruct retry bytes from the signed
    // ordered packet. Both copies and this update share the MLS transaction.
    ensure!(
        db.execute(
            "UPDATE outbox SET bytes=X'' WHERE id=?1 AND group_id=?2",
            params![id.to_string(), packet.group()]
        )? == 1,
        "missing MLS retry record"
    );
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

fn publish_in(
    session: &Session<'_>,
    group: &[u8],
    purpose: Purpose,
    operation: impl FnOnce(&Session<'_>) -> Result<Outgoing>,
) -> Result<Packet> {
    let saved = checked_stream(session, group, purpose)?;
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
    storage::trim_group(session.db, group, packet.sequence())?;
    Ok(packet)
}

fn stage_in(session: &Session<'_>, packet: &Packet, purpose: Purpose) -> Result<Staged> {
    let saved = checked_stream(session, packet.group(), purpose)?;
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
    if packet.sequence() > 0
        && packet.sequence() <= saved.head.saturating_sub(storage::RECENT_PACKETS)
    {
        return Ok(Staged::Retired);
    }
    ensure!(
        packet.sequence() > saved.head && packet.sequence() - saved.head <= MAX_PENDING_DISTANCE,
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
            "SELECT COALESCE(SUM(length(p.packet)),0) FROM stream_pending p JOIN streams s USING(group_id) WHERE s.purpose=?1",
            [purpose.name()],
            |row| row.get(0),
        )?;
    // Keep room for a missing predecessor even when later packets fill
    // the queue. Draining that contiguous prefix releases the reserve.
    let quota = if purpose == Purpose::Configuration {
        configuration::MAX_PENDING_CONFIGURATION_BYTES
    } else {
        MAX_PENDING_BYTES
    };
    let capacity = if packet.sequence() == saved.head + 1 {
        quota
    } else {
        quota - gent_crypto::stream::MAX_PACKET_BYTES
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
}
