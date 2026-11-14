//! Owner-authenticated preparation for a later coordinated activation workflow.
//! Private successor keys stay on their node. Issuing authority durably fences
//! the source before any signature is returned. There is no activation/abort API.
use super::*;
use gent_crypto::{
    OwnerKey, SignedState,
    succession::{MAX_CANDIDATE_BYTES, SignedOwnerCandidate, SignedOwnerTransition},
};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const LIMIT: usize = 64;
const MAGIC: &[u8] = b"GENTOWN1";
mod journal;
mod streams;

pub(crate) fn schema(db: &Connection, previous: i64) -> Result<()> {
    let count: usize = db.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('owner_handoff_control','owner_handoffs','owner_candidates')", [], |r| r.get(0))?;
    if previous < 18 && count == 0 {
        db.execute_batch("CREATE TABLE owner_handoffs(id TEXT PRIMARY KEY CHECK(length(id)=36),baseline BLOB NOT NULL CHECK(length(baseline)<=2097152),candidate BLOB NOT NULL CHECK(length(candidate)<=8192),authorization BLOB NOT NULL CHECK(length(authorization)<=4096));
        CREATE TABLE owner_handoff_control(singleton INTEGER PRIMARY KEY CHECK(singleton=1),issued TEXT REFERENCES owner_handoffs(id));
        INSERT INTO owner_handoff_control VALUES(1,NULL);
        CREATE TABLE owner_candidates(id TEXT PRIMARY KEY CHECK(length(id)=36),baseline BLOB NOT NULL CHECK(length(baseline)<=2097152),candidate BLOB NOT NULL CHECK(length(candidate)<=8192),completed BLOB CHECK(length(completed)<=2097152));")?;
    } else {
        ensure!(
            count == 3,
            "owner handoff journal is missing; do not resume signing"
        );
        db.prepare("SELECT id,baseline,candidate,authorization FROM owner_handoffs LIMIT 0")?;
        db.prepare("SELECT id,baseline,candidate,completed FROM owner_candidates LIMIT 0")?;
        ensure!(
            db.query_row(
                "SELECT COUNT(*) FROM owner_handoff_control WHERE singleton=1",
                [],
                |r| r.get::<_, usize>(0)
            )? == 1,
            "owner handoff fence is missing; do not resume signing"
        );
    }
    journal::schema(db, previous)
}

fn restore(candidate: &SignedOwnerCandidate, baseline: &[u8]) -> Result<VerifiedState> {
    VerifiedState::restore(
        candidate.candidate.anchor.clone(),
        candidate.candidate.base.clone(),
        SignedState::decode(baseline)?,
    )
}

struct Issued {
    base: VerifiedState,
    candidate: SignedOwnerCandidate,
    authorization: SignedOwnerTransition,
}

fn issued(db: &Connection) -> Result<Option<Issued>> {
    let id: Option<String> = db.query_row(
        "SELECT issued FROM owner_handoff_control WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let count: usize = db.query_row("SELECT COUNT(*) FROM owner_handoffs", [], |r| r.get(0))?;
    let Some(id) = id else {
        ensure!(count == 0, "owner handoff fence lost its record pin");
        return Ok(None);
    };
    ensure!(count == 1, "owner handoff history is missing or ambiguous");
    let (baseline, candidate, authorization): (Vec<u8>, Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT baseline,candidate,authorization FROM owner_handoffs WHERE id=?1",
        [&id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let candidate = SignedOwnerCandidate::decode(&candidate)?;
    ensure!(
        candidate.candidate.id == id,
        "owner handoff request changed"
    );
    let base = restore(&candidate, &baseline)?;
    let authorization = SignedOwnerTransition::decode(&authorization)?;
    base.verify_owner_authorization(&candidate, &authorization)?;
    journal::check_source(db, &base, &candidate, &authorization)?;
    Ok(Some(Issued {
        base,
        candidate,
        authorization,
    }))
}

pub(crate) fn frozen(db: &Connection, state: &VerifiedState) -> Result<bool> {
    let Some(record) = issued(db)? else {
        return Ok(false);
    };
    ensure!(
        state.anchor() == record.base.anchor(),
        "owner handoff belongs to another cluster"
    );
    if state.owner_epoch() == record.base.owner_epoch() {
        ensure!(
            state.checkpoint() == record.base.checkpoint(),
            "owner signing advanced after handoff was issued"
        );
        return Ok(true);
    }
    ensure!(
        state.owner_epoch() > record.base.owner_epoch()
            && state
                .state()
                .owner_transitions
                .get(record.base.owner_epoch() as usize)
                == Some(&record.authorization),
        "accepted owner epoch conflicts with the issued handoff"
    );
    Ok(false)
}

pub(crate) fn check_state(db: &Connection, state: &VerifiedState) -> Result<()> {
    frozen(db, state)?;
    Ok(())
}

pub(super) fn status(db: &Connection, state: &VerifiedState) -> Result<Value> {
    let blocked = frozen(db, state)?;
    let issued = issued(db)?;
    let (stream_records, stream_bytes) = encrypted::ordered::configuration::standby::usage(db)?;
    let (candidates, completed): (u64, u64) = db.query_row(
        "SELECT COUNT(*),COUNT(completed) FROM owner_candidates",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(
        candidates <= LIMIT as u64,
        "owner candidate capacity exceeded"
    );
    Ok(
        json!({"owner_epoch":state.owner_epoch(),"signing_frozen":blocked,
        "issued_request":issued.as_ref().map(|r| &r.candidate.candidate.id),
        "successor_node":issued.as_ref().map(|r| &r.candidate.candidate.node.id),
        "prepared_candidates":candidates,"completed_candidates":completed,
        "journal_transfer":journal::usage(db)?,
        "configuration_preparation":{"records":stream_records,"stored_bytes":stream_bytes},
        "activation_supported":false}),
    )
}

fn candidate_path(home: &Path, id: &str) -> Result<PathBuf> {
    ensure!(
        Uuid::parse_str(id).is_ok_and(|u| !u.is_nil() && u.to_string() == id),
        "invalid owner candidate ID"
    );
    Ok(home.join("owner-candidates").join(format!("{id}.key")))
}

fn read_key(path: &Path) -> Result<(OwnerKey, SignedOwnerCandidate)> {
    let parent = fs::symlink_metadata(path.parent().context("candidate parent missing")?)?;
    ensure!(
        parent.is_dir()
            && parent.uid() == rustix::process::geteuid().as_raw()
            && parent.mode() & 0o077 == 0,
        "owner candidate directory must be private, owned and without symlinks"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.nlink() == 1
            && before.uid() == rustix::process::geteuid().as_raw()
            && before.mode() & 0o077 == 0,
        "owner candidate key must be a private owned file without links"
    );
    let file = fs::File::open(path)?;
    let stamp = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        stamp(&before) == stamp(&file.metadata()?),
        "owner candidate key changed while opening"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    (&file)
        .take((MAX_CANDIDATE_BYTES + 41) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        stamp(&before) == stamp(&file.metadata()?)
            && bytes.len() > 40
            && bytes.len() <= MAX_CANDIDATE_BYTES + 40
            && &bytes[..8] == MAGIC,
        "invalid or changed owner candidate key file"
    );
    let key = OwnerKey::from_secret_bytes(bytes[8..40].try_into()?);
    let candidate = SignedOwnerCandidate::decode(&bytes[40..])?;
    ensure!(
        key.public_key() == candidate.candidate.owner_key,
        "owner candidate signing key mismatch"
    );
    Ok((key, candidate))
}

fn save_key(path: &Path, key: &OwnerKey, candidate: &SignedOwnerCandidate) -> Result<()> {
    let parent = path.parent().context("candidate parent missing")?;
    config::private_dir(parent)?;
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir() && meta.uid() == rustix::process::geteuid().as_raw(),
        "owner candidate directory must be owned by this user"
    );
    ensure!(
        fs::read_dir(parent)?
            .take(LIMIT + 1)
            .collect::<std::io::Result<Vec<_>>>()?
            .len()
            < LIMIT,
        "owner candidate key capacity reached"
    );
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(MAGIC)?;
    file.write_all(key.expose_secret().as_ref())?;
    file.write_all(&candidate.encode()?)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

impl Store {
    /// Local-owner preparation API for the future handoff coordinator. No MCP
    /// operation invokes it, and it changes no active signing authority.
    pub fn prepare_owner_handoff(
        &mut self,
        credential: &str,
        id: &str,
    ) -> Result<SignedOwnerCandidate> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let path = candidate_path(&self.home, id)?;
        let _lock = config::state_lock(&self.home, "owner-handoff.lock")?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        ensure!(
            self.identity
                .owner
                .as_ref()
                .is_none_or(|k| k.public_key() != state.state().owner_key),
            "prepare the successor on a different enrolled node"
        );
        let previous: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT baseline,candidate FROM owner_candidates WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((baseline, wire)) = previous {
            let (key, candidate) = read_key(&path)?;
            ensure!(
                candidate.encode()? == wire
                    && candidate.candidate.node.id == self.identity.node.id()
                    && candidate.candidate.node.signing_key == self.identity.node.public_key(),
                "owner candidate identity changed"
            );
            let pinned = restore(&candidate, &baseline)?;
            candidate.verify(&pinned, candidate.candidate.issued_at)?;
            ensure!(
                pinned.anchor() == state.anchor()
                    && key.public_key() == candidate.candidate.owner_key,
                "candidate cluster changed"
            );
            return Ok(candidate);
        }
        ensure!(
            tx.query_row("SELECT COUNT(*) FROM owner_candidates", [], |r| r
                .get::<_, usize>(0))?
                < LIMIT,
            "owner candidate capacity reached"
        );
        let timestamp = requests::clock(&tx, now())? as u64;
        let candidate = match fs::symlink_metadata(&path) {
            Ok(_) => read_key(&path)?.1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = OwnerKey::generate()?;
                let candidate = self
                    .identity
                    .node
                    .prepare_owner_candidate(&state, &key, id, timestamp)?;
                save_key(&path, &key, &candidate)?;
                candidate
            }
            Err(e) => return Err(e.into()),
        };
        ensure!(
            candidate.candidate.id == id
                && candidate.candidate.node.id == self.identity.node.id()
                && candidate.candidate.node.signing_key == self.identity.node.public_key(),
            "owner candidate file belongs to another request or node"
        );
        candidate.verify(&state, timestamp)?;
        tx.execute(
            "INSERT INTO owner_candidates VALUES(?1,?2,?3,NULL)",
            params![id, state.signed().encode()?, candidate.encode()?],
        )?;
        tx.commit()?;
        Ok(candidate)
    }

    /// Irrevocable once returned or committed: no timeout clears this fence.
    /// The coordinator must finish activation, never resume the old writer.
    pub fn authorize_owner_handoff(
        &mut self,
        credential: &str,
        candidate: &SignedOwnerCandidate,
    ) -> Result<SignedOwnerTransition> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let _lock = config::state_lock(&self.home, "owner-handoff.lock")?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        if let Some(previous) = issued(&tx)? {
            ensure!(
                previous.candidate == *candidate,
                "a different owner handoff is already issued"
            );
            return Ok(previous.authorization);
        }
        ensure!(
            candidate.candidate.node.id != self.identity.node.id(),
            "owner handoff requires another node"
        );
        let owner = self.identity.signing_owner(&tx)?;
        let timestamp = requests::clock(&tx, now())? as u64;
        let (manifest, body) = journal::capture(&tx, &state, candidate)?;
        let authorization = state.authorize_owner_candidate_with_journal(
            owner,
            candidate,
            manifest.digest()?,
            timestamp,
        )?;
        tx.execute(
            "INSERT INTO owner_handoffs VALUES(?1,?2,?3,?4)",
            params![
                candidate.candidate.id,
                state.signed().encode()?,
                candidate.encode()?,
                authorization.encode()?
            ],
        )?;
        tx.execute(
            "UPDATE owner_handoff_control SET issued=?1 WHERE singleton=1",
            [&candidate.candidate.id],
        )?;
        journal::save_source(&tx, candidate, &authorization, &manifest, &body)?;
        tx.commit()?;
        Ok(authorization)
    }

    /// Save the successor's signature without installing its key or activating
    /// the state. Retries preserve the same result, including after expiry.
    pub fn accept_owner_handoff(
        &mut self,
        credential: &str,
        id: &str,
        authorization: &SignedOwnerTransition,
    ) -> Result<SignedState> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let path = candidate_path(&self.home, id)?;
        let _lock = config::state_lock(&self.home, "owner-handoff.lock")?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        let (baseline, wire, completed): (Vec<u8>, Vec<u8>, Option<Vec<u8>>) = tx.query_row(
            "SELECT baseline,candidate,completed FROM owner_candidates WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let (key, candidate) = read_key(&path)?;
        ensure!(
            candidate.encode()? == wire
                && candidate.candidate.id == id
                && candidate.candidate.node.id == self.identity.node.id()
                && candidate.candidate.node.signing_key == self.identity.node.public_key(),
            "owner candidate changed"
        );
        let pinned = restore(&candidate, &baseline)?;
        ensure!(
            state.anchor() == pinned.anchor() && state.checkpoint() == pinned.checkpoint(),
            "local state changed since owner preparation"
        );
        let timestamp = requests::clock(&tx, now())? as u64;
        if authorization
            .transition
            .successor
            .as_ref()
            .is_some_and(|s| s.journal.is_some())
        {
            journal::require_complete(&tx, &pinned, &candidate, authorization)?;
        }
        let result =
            pinned.accept_owner_authorization(&key, &candidate, authorization, timestamp)?;
        if let Some(previous) = completed {
            ensure!(
                previous == result.encode()?,
                "owner authorization changed after completion"
            );
            return Ok(result);
        }
        tx.execute(
            "UPDATE owner_candidates SET completed=?1 WHERE id=?2",
            params![result.encode()?, id],
        )?;
        tx.commit()?;
        Ok(result)
    }
}
