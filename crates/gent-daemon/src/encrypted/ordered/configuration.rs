//! Owner-authorized configuration recovery. Only signed authority records enter
//! this channel; application messages never gain an expired-lease exemption.
use super::*;
use gent_crypto::{MAX_STATE_BYTES, OwnerKey, SignedConfigurationGrant};
pub mod standby;

pub const MAX_FRAGMENT_BYTES: usize = 256 * 1024;
pub const MAX_PENDING_CONFIGURATION_BYTES: usize = 8 * 1024 * 1024;
const MAX_REASSEMBLY_BYTES: usize = 8 * 1024 * 1024;

/// Contains private identity metadata. Exchange through protected pairing only.
#[derive(Clone)]
pub struct ConfigurationInvitation {
    pub packet: Packet,
    pub grant: SignedConfigurationGrant,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fragment {
    version: u8,
    revision: u64,
    digest: Digest,
    total: usize,
    offset: usize,
    data: String,
}

pub(super) struct Progress {
    pub(super) grant: SignedConfigurationGrant,
    revision: u64,
    hash: Digest,
    offset: usize,
}

#[derive(Clone)]
pub struct ConfigurationStream {
    pub group: Vec<u8>,
    pub outgoing: bool,
}

impl OrderedEndpoint<'_> {
    /// Only established, still-authorized configuration streams are eligible.
    /// Expiry alone does not hide the recovery route; known revocation does.
    pub fn configuration_streams(&mut self, now: u64) -> Result<Vec<ConfigurationStream>> {
        self.inner.transact_mode(now, true, |session| {
            let mut query = session.db.prepare(
                "SELECT group_id FROM configuration_streams ORDER BY group_id LIMIT 4097",
            )?;
            let groups = query
                .query_map([], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            ensure!(groups.len() <= 4096, "too many configuration streams");
            let mut streams = Vec::new();
            for group in groups {
                if let Ok(stream) = checked_stream(session, &group, Purpose::Configuration) {
                    if stream.writer == session.signer.id()
                        && !progress(session.db, &group)?
                            .grant
                            .can_publish(&session.state)?
                    {
                        continue;
                    }
                    streams.push(ConfigurationStream {
                        group,
                        outgoing: stream.writer == session.signer.id(),
                    });
                }
            }
            Ok(streams)
        })
    }

    pub fn authority_state(&self) -> Result<VerifiedState> {
        self.inner.authority_state()
    }

    /// Grants full configuration access to one trusted daemon. Both node keys
    /// and the exact initial checkpoint are signed by the separate owner key.
    pub fn create_configuration(
        &mut self,
        owner: &OwnerKey,
        request: Uuid,
        peer: (&str, &[u8]),
        now: u64,
    ) -> Result<ConfigurationInvitation> {
        self.inner.transact(now, |session| {
            ensure!(
                owner.public_key() == session.state.state().owner_key,
                "wrong owner authority"
            );
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
            if saved.is_none() {
                ensure!(
                    !crate::store::handoff::frozen(session.db, &session.state)?,
                    "owner handoff is issued; configuration grants are frozen"
                );
            }
            let welcome = session.create_group(request, &[peer])?;
            if let Some(packet) = saved {
                checked_stream(session, packet.group(), Purpose::Configuration)?;
                return Ok(ConfigurationInvitation {
                    grant: progress(session.db, packet.group())?.grant,
                    packet,
                });
            }
            let packet =
                session
                    .signer
                    .sign_stream_packet(&welcome.group_id, 0, [0; 32], &welcome.bytes)?;
            let grant = owner.authorize_configuration_stream(
                &session.state,
                packet.group(),
                packet.digest()?,
                (session.signer.id(), peer.0),
                now,
            )?;
            initialize_stream(
                session,
                &packet,
                session.signer.id(),
                session.signer.public_key(),
                roster_hash(&[session.signer.id(), peer.0])?,
            )?;
            initialize_configuration(session.db, &grant)?;
            save_outgoing(session.db, request, &packet)?;
            Ok(ConfigurationInvitation { packet, grant })
        })
    }

    pub fn join_configuration(
        &mut self,
        invitation: &ConfigurationInvitation,
        now: u64,
    ) -> Result<()> {
        let packet = &invitation.packet;
        let signed = &invitation.grant;
        self.inner.transact_mode(now, true, |session| {
            signed.verify(session.state.anchor())?;
            let grant = &signed.grant;
            ensure!(
                grant.reader == session.signer.id()
                    && grant.reader_key == session.signer.public_key(),
                "configuration grant belongs to another reader"
            );
            ensure!(
                packet.sequence() == 0
                    && packet.group() == grant.group
                    && packet.digest()? == grant.origin,
                "configuration grant does not match Welcome"
            );
            packet.verify(&grant.writer_key)?;
            if let Some(saved) = stream(session.db, packet.group())? {
                authorize(session, packet.group(), &saved)?;
                ensure!(
                    progress(session.db, packet.group())?.grant == *signed,
                    "conflicting configuration grant"
                );
                return Ok(());
            }
            signed.verify_initial(&session.state, now)?;
            let raw = Outgoing {
                id: Uuid::nil(),
                group_id: packet.group().into(),
                bytes: packet.ciphertext().into(),
            };
            session.join(&raw, &[&grant.writer, &grant.reader], Some(&grant.writer))?;
            initialize_stream(
                session,
                packet,
                &grant.writer,
                grant.writer_key,
                roster_hash(&[&grant.writer, &grant.reader])?,
            )?;
            initialize_configuration(session.db, signed)
        })
    }

    /// Publish the next bounded fragment of already accepted owner history.
    /// Applying a new local signed revision and its history is a separate owner
    /// transaction; this outbox then catches every configured peer up to it.
    pub fn next_configuration(
        &mut self,
        group: &[u8],
        request: Uuid,
        now: u64,
    ) -> Result<Option<Packet>> {
        ensure!(!request.is_nil(), "nil request ID");
        self.prepare_configuration(group, Some(request), now)
    }

    /// Daemon publication commits its allocated ID with the fragment and cursor.
    pub(crate) fn prepare_configuration(
        &mut self,
        group: &[u8],
        request: Option<Uuid>,
        now: u64,
    ) -> Result<Option<Packet>> {
        // Already accepted signed history must remain publishable after lease
        // expiry, including when its quota is preventing an owner renewal.
        // The recovery grant and current saved node/key membership still apply.
        self.inner.transact_mode(now, true, |session| {
            let saved = checked_stream(session, group, Purpose::Configuration)?;
            ensure!(saved.writer == session.signer.id(), "only the configuration writer can publish");
            if let Some(request) = request {
                let prior: Option<Vec<u8>> = session.db.query_row("SELECT group_id FROM configuration_requests WHERE id=?1", [request.to_string()], |row| row.get(0)).optional()?;
                if let Some(prior) = prior {
                    ensure!(prior == group, "conflicting configuration request ID");
                    return Ok(Some(outgoing_request(session.db, request)?.context("missing configuration packet")?));
                }
                ensure!(!requests::managed(request), "transport request is unallocated or retired; it cannot publish configuration");
            }
            let cursor = progress(session.db, group)?;
            ensure!(cursor.grant.can_publish(&session.state)?, "standby configuration candidate is not active");
            let revision = cursor.revision.checked_add(1).context("revision overflow")?;
            let Some(record) = history(session.db, revision)? else { return Ok(None); };
            let checkpoint = record.verified_checkpoint(session.state.anchor())?;
            ensure!(record.state.previous == Some(cursor.hash), "configuration publication history fork");
            let wire = record.encode()?;
            ensure!(cursor.offset < wire.len(), "invalid configuration cursor");
            let end = (cursor.offset + MAX_FRAGMENT_BYTES).min(wire.len());
            let fragment = Fragment { version:1, revision, digest:Sha256::digest(&wire).into(), total:wire.len(), offset:cursor.offset, data:STANDARD.encode(&wire[cursor.offset..end]) };
            let body = serde_json::to_vec(&fragment)?;
            let request = match request {
                Some(request) => request,
                None => requests::allocate(session.db, group, &body, None)?,
            };
            let packet = publish_in(session, group, Purpose::Configuration, |session| session.send(group, request, &body))?;
            let (revision,hash,offset) = if end == wire.len() { (revision, checkpoint.state_hash,0) } else { (cursor.revision,cursor.hash,end) };
            session.db.execute("UPDATE configuration_streams SET revision=?1,state_hash=?2,offset=?3 WHERE group_id=?4", params![revision,hash.as_slice(),offset,group])?;
            session.db.execute("INSERT INTO configuration_requests VALUES(?1,?2)", params![request.to_string(),group])?;
            Ok(Some(packet))
        })
    }

    pub fn rotate_configuration(
        &mut self,
        group: &[u8],
        request: Uuid,
        now: u64,
    ) -> Result<Packet> {
        self.inner.transact(now, |session| {
            ensure!(
                progress(session.db, group)?
                    .grant
                    .can_publish(&session.state)?,
                "standby configuration candidate is not active"
            );
            publish_in(session, group, Purpose::Configuration, |session| {
                session.rotate(group, request)
            })
        })
    }

    pub fn stage_configuration(&mut self, packet: &Packet, now: u64) -> Result<Staged> {
        self.inner.transact_mode(now, true, |session| {
            stage_in(session, packet, Purpose::Configuration)
        })
    }
    pub fn drain_configuration(
        &mut self,
        group: &[u8],
        limit: usize,
        now: u64,
    ) -> Result<Vec<Received>> {
        self.drain_mode(group, limit, now, Purpose::Configuration)
    }
    pub fn configuration_status(&mut self, group: &[u8], now: u64) -> Result<StreamStatus> {
        self.status_mode(group, now, Purpose::Configuration)
    }
    pub fn configuration_outbox(
        &mut self,
        group: &[u8],
        after: Option<u64>,
        limit: usize,
        now: u64,
    ) -> Result<Vec<Packet>> {
        self.outbox_mode(group, after, limit, now, Purpose::Configuration)
    }
}

fn initialize_configuration(db: &Connection, signed: &SignedConfigurationGrant) -> Result<()> {
    let grant = &signed.grant;
    ensure!(
        db.query_row("SELECT COUNT(*) FROM configuration_streams", [], |r| r
            .get::<_, usize>(0))?
            < 4096,
        "configuration stream capacity reached"
    );
    db.execute(
        "UPDATE streams SET purpose='configuration' WHERE group_id=?1",
        [&grant.group],
    )?;
    db.execute(
        "INSERT INTO configuration_streams VALUES(?1,?2,?3,?4,0)",
        params![
            grant.group,
            signed.encode()?,
            grant.base.revision,
            grant.base.state_hash.as_slice()
        ],
    )?;
    Ok(())
}

pub(super) fn progress(db: &Connection, group: &[u8]) -> Result<Progress> {
    let (grant, revision, hash, offset): (Vec<u8>, u64, Digest, usize) = db.query_row(
        "SELECT grant,revision,state_hash,offset FROM configuration_streams WHERE group_id=?1",
        [group],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(Progress {
        grant: SignedConfigurationGrant::decode(&grant)?,
        revision,
        hash,
        offset,
    })
}

pub(super) fn authorize(session: &Session<'_>, group: &[u8], stream: &Stream) -> Result<()> {
    ensure!(
        stream.purpose == Purpose::Configuration.name(),
        "wrong stream purpose"
    );
    let signed = progress(session.db, group)?.grant;
    signed.verify(session.state.anchor())?;
    let grant = &signed.grant;
    ensure!(
        grant.group == group
            && grant.origin == stream.origin
            && grant.writer == stream.writer
            && grant.writer_key == stream.key,
        "configuration stream pin mismatch"
    );
    ensure!(
        (session.signer.id() == grant.writer && session.signer.public_key() == grant.writer_key)
            || (session.signer.id() == grant.reader
                && session.signer.public_key() == grant.reader_key),
        "configuration grant belongs to other endpoints"
    );
    authorize_saved_node(&session.state, &grant.writer, &grant.writer_key)?;
    authorize_saved_node(&session.state, &grant.reader, &grant.reader_key)?;
    Ok(())
}

fn history(db: &Connection, revision: u64) -> Result<Option<SignedState>> {
    let wire: Option<Vec<u8>> = db
        .query_row(
            "SELECT state FROM authority_history WHERE revision=?1",
            [revision],
            |row| row.get(0),
        )
        .optional()?;
    wire.map(|wire| SignedState::decode(&wire)).transpose()
}

pub(super) fn receive(
    session: &Session<'_>,
    group: &[u8],
    wire: &[u8],
    writer: &str,
) -> Result<Received> {
    session.receive_with(group, wire, Some(writer), |_, _, body| {
        receive_fragment(session, group, &body)
    })
}

fn receive_fragment(session: &Session<'_>, group: &[u8], body: &[u8]) -> Result<Received> {
    let part: Fragment = serde_json::from_slice(body)?;
    let cursor = progress(session.db, group)?;
    ensure!(
        part.version == 1
            && part.revision == cursor.revision + 1
            && part.total > 0
            && part.total <= MAX_STATE_BYTES
            && part.offset < part.total,
        "invalid configuration fragment"
    );
    let bytes = STANDARD.decode(&part.data)?;
    ensure!(
        bytes.len() == (part.total - part.offset).min(MAX_FRAGMENT_BYTES),
        "invalid configuration fragment length"
    );
    let saved: Option<(u64, Digest, usize, Vec<u8>)> = session
        .db
        .query_row(
            "SELECT revision,digest,total,bytes FROM configuration_fragments WHERE group_id=?1",
            [group],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let mut wire = if let Some((revision, digest, total, wire)) = saved {
        ensure!(
            revision == part.revision
                && digest == part.digest
                && total == part.total
                && wire.len() == part.offset,
            "configuration fragment conflict or gap"
        );
        wire
    } else {
        ensure!(part.offset == 0, "missing configuration prefix");
        // Reserve the complete record up front. Already admitted partial records
        // must always have enough space to finish and release their reservation.
        if bytes.len() < part.total {
            let reserved: usize = session.db.query_row(
                "SELECT COALESCE(SUM(total),0) FROM configuration_fragments",
                [],
                |row| row.get(0),
            )?;
            ensure!(
                reserved + part.total <= MAX_REASSEMBLY_BYTES,
                "configuration reassembly limit reached"
            );
        }
        Vec::new()
    };
    wire.extend_from_slice(&bytes);
    if wire.len() < part.total {
        session.db.execute("INSERT INTO configuration_fragments VALUES(?1,?2,?3,?4,?5) ON CONFLICT(group_id) DO UPDATE SET bytes=excluded.bytes", params![group,part.revision,part.digest.as_slice(),part.total,wire])?;
        return Ok(Received::ConfigurationPart {
            revision: part.revision,
            complete: false,
        });
    }
    ensure!(
        Sha256::digest(&wire).as_slice() == part.digest,
        "configuration fragment digest mismatch"
    );
    let update = SignedState::decode(&wire)?;
    let checkpoint = update.verified_checkpoint(session.state.anchor())?;
    if cursor.grant.grant.owner_candidate.is_some() {
        let publication = VerifiedState::restore(
            session.state.anchor().clone(),
            checkpoint.clone(),
            update.clone(),
        )?;
        ensure!(
            cursor.grant.can_publish(&publication)?,
            "configuration update does not activate its standby candidate"
        );
    }
    ensure!(
        checkpoint.revision == part.revision && update.state.previous == Some(cursor.hash),
        "configuration history fork or gap"
    );
    if checkpoint.revision <= session.state.checkpoint().revision {
        let accepted = super::super::history::checkpoint(
            session.db,
            checkpoint.revision,
            session.state.anchor(),
        )?;
        ensure!(
            accepted == checkpoint,
            "conflicting accepted authority history"
        );
    } else {
        let mut next = session.state.clone();
        next.advance_history(std::slice::from_ref(&update))?;
        persist_authority(session.db, session.signer, &next, &[update])?;
    }
    session.db.execute(
        "UPDATE configuration_streams SET revision=?1,state_hash=?2 WHERE group_id=?3",
        params![checkpoint.revision, checkpoint.state_hash.as_slice(), group],
    )?;
    session.db.execute(
        "DELETE FROM configuration_fragments WHERE group_id=?1",
        [group],
    )?;
    Ok(Received::ConfigurationPart {
        revision: checkpoint.revision,
        complete: true,
    })
}
