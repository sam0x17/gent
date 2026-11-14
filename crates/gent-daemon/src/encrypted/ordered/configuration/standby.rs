//! Prepare the successor's MLS groups without sharing an owner signing key.
//! Grants are installed before handoff; publication waits for the signed choice.
use super::*;
use gent_crypto::succession::SignedOwnerCandidate;

const MAX_RECORDS: u64 = 4096;
const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Private pairing material for the current owner to authorize. The Welcome is
/// signed by the candidate node; the eventual grant binds every field below.
#[derive(Clone)]
pub struct ConfigurationPreparation {
    pub candidate: SignedOwnerCandidate,
    pub reader: String,
    pub reader_key: PublicKey,
    pub packet: Packet,
}

impl ConfigurationPreparation {
    pub fn verify_grant(&self, grant: &SignedConfigurationGrant) -> Result<()> {
        grant.verify_owner_candidate(&self.candidate)?;
        self.packet
            .verify(&self.candidate.candidate.node.signing_key)?;
        ensure!(
            self.packet.sequence() == 0
                && self.packet.group() == grant.grant.group
                && self.packet.digest()? == grant.grant.origin
                && self.reader == grant.grant.reader,
            "standby configuration grant does not match preparation"
        );
        ensure!(
            self.reader_key == grant.grant.reader_key,
            "standby reader key changed"
        );
        Ok(())
    }
}

pub(crate) fn schema(db: &Connection, previous: i64) -> Result<()> {
    let count: usize = db.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('configuration_preparations','owner_configuration_grants')", [], |r| r.get(0))?;
    if count == 0 && previous < 21 {
        db.execute_batch("CREATE TABLE configuration_preparations(
            id TEXT PRIMARY KEY CHECK(length(id)=36),candidate BLOB NOT NULL CHECK(length(candidate)<=8192),
            reader TEXT NOT NULL,reader_key BLOB NOT NULL CHECK(length(reader_key)=32),package_hash BLOB NOT NULL CHECK(length(package_hash)=32),
            group_id BLOB NOT NULL UNIQUE REFERENCES streams(group_id));
            CREATE TABLE owner_configuration_grants(group_id BLOB PRIMARY KEY,
            candidate BLOB NOT NULL CHECK(length(candidate)<=8192),grant BLOB NOT NULL CHECK(length(grant)<=139264));")?;
    } else {
        ensure!(count == 2, "standby configuration storage is missing");
        db.prepare("SELECT id,candidate,reader,reader_key,package_hash,group_id FROM configuration_preparations LIMIT 0")?;
        db.prepare("SELECT group_id,candidate,grant FROM owner_configuration_grants LIMIT 0")?;
    }
    Ok(())
}

pub(crate) fn usage(db: &Connection) -> Result<(u64, u64)> {
    Ok(db.query_row("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM (
        SELECT length(candidate)+length(reader)+length(reader_key)+length(package_hash)+length(group_id) AS bytes FROM configuration_preparations
        UNION ALL SELECT length(candidate)+length(grant)+length(group_id) FROM owner_configuration_grants)", [], |r| Ok((r.get(0)?,r.get(1)?)))?)
}

pub(crate) fn capacity(db: &Connection, bytes: usize) -> Result<()> {
    let (records, used) = usage(db)?;
    ensure!(
        records < MAX_RECORDS && used.saturating_add(bytes as u64) <= MAX_BYTES,
        "standby configuration preparation quota exhausted"
    );
    Ok(())
}

fn saved(db: &Connection, request: Uuid) -> Result<Option<(ConfigurationPreparation, Digest)>> {
    type PreparationRow = (Vec<u8>, String, PublicKey, Digest, Vec<u8>);
    let row: Option<PreparationRow> = db.query_row(
        "SELECT candidate,reader,reader_key,package_hash,group_id FROM configuration_preparations WHERE id=?1",
        [request.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional()?;
    row.map(|(candidate, reader, reader_key, hash, group)| {
        let candidate = SignedOwnerCandidate::decode(&candidate)?;
        let packet = outgoing_request(db, request)?.context("standby stream origin is missing")?;
        packet.verify(&candidate.candidate.node.signing_key)?;
        let stream = stream(db, &group)?.context("standby stream is missing")?;
        ensure!(
            packet.group() == group
                && packet.sequence() == 0
                && stream.purpose == Purpose::Configuration.name()
                && stream.writer == candidate.candidate.node.id
                && stream.key == candidate.candidate.node.signing_key
                && stream.origin == packet.digest()?
                && stream.roster == roster_hash(&[&stream.writer, &reader])?,
            "standby stream pins changed"
        );
        Ok((
            ConfigurationPreparation {
                candidate,
                reader,
                reader_key,
                packet,
            },
            hash,
        ))
    })
    .transpose()
}

impl OrderedEndpoint<'_> {
    /// Create only a configuration stream. Until its grant is installed it is
    /// unavailable to the dispatcher and cannot send application traffic.
    pub fn prepare_standby_configuration(
        &mut self,
        request: Uuid,
        candidate: &SignedOwnerCandidate,
        peer: (&str, &[u8]),
        now: u64,
    ) -> Result<ConfigurationPreparation> {
        ensure!(!request.is_nil(), "nil request ID");
        self.inner.transact_mode(now, true, |session| {
            ensure!(
                candidate.candidate.node.id == session.signer.id()
                    && candidate.candidate.node.signing_key == session.signer.public_key()
                    && &candidate.candidate.anchor == session.state.anchor(),
                "standby stream belongs to another candidate node"
            );
            let package_hash: Digest = Sha256::digest(peer.1).into();
            if let Some((previous, pinned_hash)) = saved(session.db, request)? {
                ensure!(
                    previous.candidate == *candidate
                        && previous.reader == peer.0
                        && package_hash == pinned_hash,
                    "standby configuration request changed"
                );
                authorize_saved_node(&session.state, peer.0, &previous.reader_key)?;
                return Ok(previous);
            }
            candidate.verify(&session.state, now)?;
            let reader_key = session
                .state
                .state()
                .nodes
                .get(peer.0)
                .context("unknown standby reader")?
                .signing_key;
            let exists: bool = session.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM outbox WHERE id=?1)",
                [request.to_string()],
                |r| r.get(0),
            )?;
            ensure!(
                !exists,
                "cannot adopt another MLS operation as a standby stream"
            );
            let welcome = session.create_group(request, &[peer])?;
            let packet =
                session
                    .signer
                    .sign_stream_packet(&welcome.group_id, 0, [0; 32], &welcome.bytes)?;
            let wire = candidate.encode()?;
            capacity(
                session.db,
                wire.len() + peer.0.len() + 64 + packet.group().len(),
            )?;
            initialize_stream(
                session,
                &packet,
                session.signer.id(),
                session.signer.public_key(),
                roster_hash(&[session.signer.id(), peer.0])?,
            )?;
            session.db.execute(
                "UPDATE streams SET purpose='configuration' WHERE group_id=?1",
                [packet.group()],
            )?;
            save_outgoing(session.db, request, &packet)?;
            session.db.execute(
                "INSERT INTO configuration_preparations VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    request.to_string(),
                    wire,
                    peer.0,
                    reader_key.as_slice(),
                    package_hash.as_slice(),
                    packet.group()
                ],
            )?;
            Ok(ConfigurationPreparation {
                candidate: candidate.clone(),
                reader: peer.0.into(),
                reader_key,
                packet,
            })
        })
    }

    /// Install the old owner's authorization without activating the candidate.
    /// Exact installed retries need neither a fresh candidate nor a fresh lease.
    pub fn install_standby_configuration(
        &mut self,
        request: Uuid,
        grant: &SignedConfigurationGrant,
        now: u64,
    ) -> Result<ConfigurationInvitation> {
        self.inner.transact_mode(now, true, |session| {
            let (preparation, _) =
                saved(session.db, request)?.context("unknown standby preparation")?;
            preparation.verify_grant(grant)?;
            ensure!(
                grant.grant.writer == session.signer.id()
                    && grant.grant.writer_key == session.signer.public_key(),
                "standby grant belongs to another writer"
            );
            let group = preparation.packet.group();
            let installed: bool = session.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM configuration_streams WHERE group_id=?1)",
                [group],
                |r| r.get(0),
            )?;
            if installed {
                checked_stream(session, group, Purpose::Configuration)?;
                ensure!(
                    progress(session.db, group)?.grant == *grant,
                    "standby grant changed"
                );
            } else {
                preparation.candidate.verify(&session.state, now)?;
                grant.verify_initial(&session.state, now)?;
                ensure!(
                    stream(session.db, group)?
                        .context("missing standby stream")?
                        .head
                        == 0,
                    "standby stream advanced before installation"
                );
                initialize_configuration(session.db, grant)?;
            }
            Ok(ConfigurationInvitation {
                packet: preparation.packet,
                grant: grant.clone(),
            })
        })
    }
}
