//! Durable readiness evidence, required before issuing a new signing stop.
use super::*;
use gent_crypto::{SignedConfigurationGrant, succession::readiness::SignedReadiness};

const MAX_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn schema(db: &Connection, previous: i64) -> Result<()> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='owner_readiness')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        ensure!(previous < 23, "owner readiness storage is missing");
        db.execute_batch("CREATE TABLE owner_readiness(id TEXT PRIMARY KEY CHECK(length(id)=36),local INTEGER NOT NULL CHECK(local IN (0,1)),candidate BLOB NOT NULL CHECK(length(candidate)<=8192),baseline BLOB NOT NULL CHECK(length(baseline)<=2097152),report BLOB NOT NULL CHECK(length(report)<=1572864));")?;
    } else {
        db.prepare("SELECT id,local,candidate,baseline,report FROM owner_readiness LIMIT 0")?;
    }
    Ok(())
}

pub(super) fn usage(db: &Connection) -> Result<Value> {
    let (reports, bytes) = size(db)?;
    ensure!(
        reports <= LIMIT && bytes <= MAX_BYTES,
        "owner readiness storage exceeds budget"
    );
    Ok(json!({"reports":reports,"stored_bytes":bytes,"max_reports":LIMIT,"max_bytes":MAX_BYTES}))
}

fn size(db: &Connection) -> Result<(usize, usize)> {
    Ok(db.query_row("SELECT COUNT(*),COALESCE(SUM(length(candidate)+length(baseline)+length(report)),0) FROM owner_readiness", [], |r| Ok((r.get(0)?, r.get(1)?)))?)
}

fn grants(
    db: &Connection,
    report: &SignedReadiness,
    candidate: &SignedOwnerCandidate,
    local: bool,
) -> Result<Vec<SignedConfigurationGrant>> {
    let mut grants = Vec::new();
    for peer in &report.readiness.peers {
        let wire: Vec<u8> = if local {
            db.query_row(
                "SELECT grant FROM configuration_streams WHERE group_id=?1",
                [peer.receipt.group()],
                |r| r.get(0),
            )?
        } else {
            let (pinned, grant): (Vec<u8>, Vec<u8>) = db.query_row(
                "SELECT candidate,grant FROM owner_configuration_grants WHERE group_id=?1",
                [peer.receipt.group()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            ensure!(
                pinned == candidate.encode()?,
                "readiness grant belongs to another candidate"
            );
            grant
        };
        grants.push(SignedConfigurationGrant::decode(&wire)?);
    }
    Ok(grants)
}

fn load(
    db: &Connection,
    candidate: &SignedOwnerCandidate,
    local: bool,
) -> Result<Option<SignedReadiness>> {
    type Saved = (bool, Vec<u8>, Vec<u8>, Vec<u8>);
    let saved: Option<Saved> = db
        .query_row(
            "SELECT local,candidate,baseline,report FROM owner_readiness WHERE id=?1",
            [&candidate.candidate.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((role, pinned, baseline, wire)) = saved else {
        return Ok(None);
    };
    ensure!(
        role == local && pinned == candidate.encode()?,
        "owner readiness candidate or role changed"
    );
    let report = SignedReadiness::decode(&wire)?;
    let state = restore(candidate, &baseline)?;
    report.verify(
        &state,
        candidate,
        &grants(db, &report, candidate, local)?,
        report.readiness.issued_at,
    )?;
    Ok(Some(report))
}

fn save(
    db: &Connection,
    candidate: &SignedOwnerCandidate,
    state: &VerifiedState,
    report: &SignedReadiness,
    local: bool,
) -> Result<()> {
    let candidate_wire = candidate.encode()?;
    let baseline = state.signed().encode()?;
    let report_wire = report.encode()?;
    let (rows, bytes) = size(db)?;
    ensure!(
        rows < LIMIT
            && bytes
                .checked_add(candidate_wire.len() + baseline.len() + report_wire.len())
                .is_some_and(|n| n <= MAX_BYTES),
        "owner readiness storage budget exhausted"
    );
    db.execute(
        "INSERT INTO owner_readiness VALUES(?1,?2,?3,?4,?5)",
        params![
            candidate.candidate.id,
            local,
            candidate_wire,
            baseline,
            report_wire
        ],
    )?;
    Ok(())
}

pub(super) fn require(
    db: &Connection,
    state: &VerifiedState,
    candidate: &SignedOwnerCandidate,
    now: u64,
) -> Result<()> {
    let report = load(db, candidate, false)?
        .context("successor readiness must be recorded before authorizing a handoff")?;
    report.verify(
        state,
        candidate,
        &grants(db, &report, candidate, false)?,
        now,
    )
}

impl Store {
    /// Signs only after checking the successor's protected key, installed streams,
    /// durable reader confirmations and local bidirectional data links.
    pub fn owner_handoff_readiness(
        &mut self,
        credential: &str,
        id: &str,
    ) -> Result<SignedReadiness> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let _lock = config::state_lock(&self.home, "owner-handoff.lock")?;
        let (key, candidate) = read_key(&candidate_path(&self.home, id)?)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (wire, baseline): (Vec<u8>, Vec<u8>) = tx.query_row(
            "SELECT candidate,baseline FROM owner_candidates WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            wire == candidate.encode()?
                && candidate.candidate.node.id == self.identity.node.id()
                && candidate.candidate.node.signing_key == self.identity.node.public_key(),
            "readiness candidate belongs to another node"
        );
        self.identity.state(&tx)?;
        if let Some(report) = load(&tx, &candidate, true)? {
            return Ok(report);
        }
        let pinned = restore(&candidate, &baseline)?;
        let state = self.identity.state(&tx)?;
        ensure!(
            state.checkpoint() == pinned.checkpoint(),
            "authority changed since handoff preparation"
        );
        let timestamp = requests::clock(&tx, now())? as u64;
        candidate.verify(&state, timestamp)?;
        let connections = activation::readiness(&tx, &self.identity.node, &state, &candidate)?;
        let report = self.identity.node.sign_owner_readiness(
            &state,
            &key,
            &candidate,
            &connections,
            timestamp,
        )?;
        save(&tx, &candidate, &state, &report, true)?;
        tx.commit()?;
        Ok(report)
    }

    /// Records evidence on the source without freezing it. New authorization
    /// verifies the same evidence again at the decision's current checkpoint.
    pub fn record_owner_readiness(
        &mut self,
        credential: &str,
        candidate: &SignedOwnerCandidate,
        report: &SignedReadiness,
    ) -> Result<()> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        report.encode()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        if let Some(previous) = load(&tx, candidate, false)? {
            ensure!(previous == *report, "owner readiness report changed");
            return Ok(());
        }
        self.identity.signing_owner(&tx)?;
        ensure!(
            candidate.candidate.node.id != self.identity.node.id(),
            "owner handoff requires another node"
        );
        let timestamp = requests::clock(&tx, now())? as u64;
        report.verify(
            &state,
            candidate,
            &grants(&tx, report, candidate, false)?,
            timestamp,
        )?;
        save(&tx, candidate, &state, report, false)?;
        tx.commit()?;
        Ok(())
    }
}
