//! Commit successor selection, key reference and completed decisions together.
use super::*;
use gent_crypto::{NodeIdentity, SignedConfigurationGrant, stream::Receipt};

pub(super) fn schema(db: &Connection, previous: i64) -> Result<()> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='owner_epochs')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        ensure!(previous < 22, "accepted owner epoch storage is missing");
        db.execute_batch("CREATE TABLE owner_epochs(epoch INTEGER PRIMARY KEY CHECK(epoch BETWEEN 1 AND 64),transition BLOB NOT NULL CHECK(length(transition)<=4096),local_candidate TEXT REFERENCES owner_candidates(id));")?;
    } else {
        db.prepare("SELECT epoch,transition,local_candidate FROM owner_epochs LIMIT 0")?;
    }
    Ok(())
}

fn local(signed: &SignedOwnerTransition, node: &NodeIdentity) -> Result<bool> {
    let successor = signed.transition.successor.as_ref().context(
        "owner succession requires coordinated daemon activation with a node-bound candidate",
    )?;
    ensure!(
        successor.journal.is_some(),
        "owner succession requires coordinated daemon activation with a decision journal"
    );
    Ok(successor.node.id == node.id() && successor.node.signing_key == node.public_key())
}

pub(crate) fn check_epochs(
    db: &Connection,
    node: &NodeIdentity,
    state: &VerifiedState,
) -> Result<()> {
    for signed in &state.state().owner_transitions {
        let own = local(signed, node)?;
        let (wire, id): (Vec<u8>, Option<String>) = db.query_row(
            "SELECT transition,local_candidate FROM owner_epochs WHERE epoch=?1",
            [signed.transition.epoch],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            wire == signed.encode()? && own == id.is_some(),
            "accepted owner epoch or local signer reference changed"
        );
        if let Some(id) = id {
            let wire: Vec<u8> = db.query_row(
                "SELECT candidate FROM owner_candidates WHERE id=?1",
                [&id],
                |r| r.get(0),
            )?;
            let candidate = SignedOwnerCandidate::decode(&wire)?;
            ensure!(
                candidate.candidate.id == id
                    && candidate.digest()?
                        == signed.transition.successor.as_ref().unwrap().candidate
                    && candidate.candidate.owner_key == signed.transition.owner_key,
                "active owner candidate changed"
            );
        }
    }
    Ok(())
}

/// Initial enrollment is independently pinned through the trusted pairing API.
/// An existing peer requires its prepared incoming stream before accepting a new
/// epoch. Selecting this node as signer always requires the activation API.
pub(crate) fn admit_epochs(
    db: &Connection,
    node: &NodeIdentity,
    state: &VerifiedState,
    initial: bool,
    channel: Option<&SignedConfigurationGrant>,
) -> Result<()> {
    for signed in &state.state().owner_transitions {
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM owner_epochs WHERE epoch=?1)",
            [signed.transition.epoch],
            |r| r.get(0),
        )?;
        let own = local(signed, node)?;
        if exists {
            continue;
        }
        ensure!(
            !own,
            "local owner succession requires coordinated activation"
        );
        if !initial {
            let channel = channel
                .context("owner succession must arrive through its prepared successor stream")?;
            let mut ready = false;
            let mut query = db.prepare("SELECT c.grant,s.writer,s.writer_key,s.origin_hash,c.group_id FROM configuration_streams c JOIN streams s USING(group_id) WHERE s.purpose='configuration'")?;
            for row in query.query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, gent_crypto::PublicKey>(2)?,
                    r.get::<_, gent_crypto::Digest>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                ))
            })? {
                let (wire, writer, key, origin, group) = row?;
                let grant = SignedConfigurationGrant::decode(&wire)?;
                let g = &grant.grant;
                if grant == *channel
                    && g.group == group
                    && g.owner_candidate
                        == Some(signed.transition.successor.as_ref().unwrap().candidate)
                    && g.reader == node.id()
                    && g.reader_key == node.public_key()
                    && g.writer == writer
                    && g.writer_key == key
                    && g.origin == origin
                    && g.base == signed.transition.base
                    && grant.can_publish(state)?
                {
                    ready = true;
                }
            }
            ensure!(
                ready,
                "owner succession requires a prepared incoming configuration stream"
            );
        }
        db.execute(
            "INSERT INTO owner_epochs VALUES(?1,?2,NULL)",
            params![signed.transition.epoch, signed.encode()?],
        )?;
    }
    check_epochs(db, node, state)
}

pub(crate) fn active_key(
    home: &Path,
    db: &Connection,
    state: &VerifiedState,
    node: &NodeIdentity,
) -> Result<OwnerKey> {
    check_epochs(db, node, state)?;
    let id: String = db.query_row(
        "SELECT local_candidate FROM owner_epochs WHERE epoch=?1",
        [state.owner_epoch()],
        |r| r.get(0),
    )?;
    let (key, candidate) = read_key(&candidate_path(home, &id)?)?;
    let signed = state
        .state()
        .owner_transitions
        .last()
        .context("missing successor epoch")?;
    ensure!(
        key.public_key() == state.state().owner_key
            && candidate.candidate.id == id
            && candidate.digest()?
                == signed
                    .transition
                    .successor
                    .as_ref()
                    .context("missing successor")?
                    .candidate
            && candidate.candidate.node.id == node.id()
            && candidate.candidate.node.signing_key == node.public_key(),
        "active successor key changed"
    );
    Ok(key)
}

pub(super) fn readiness(
    db: &Connection,
    node: &NodeIdentity,
    baseline: &VerifiedState,
    candidate: &SignedOwnerCandidate,
) -> Result<Vec<(SignedConfigurationGrant, Receipt)>> {
    let digest = candidate.digest()?;
    let mut ready = std::collections::BTreeMap::new();
    let mut query = db.prepare("SELECT c.grant,c.group_id,s.writer,s.writer_key,s.origin_hash,s.head FROM configuration_streams c JOIN streams s USING(group_id) WHERE s.purpose='configuration' ORDER BY c.group_id")?;
    for row in query.query_map([], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, gent_crypto::PublicKey>(3)?,
            r.get::<_, gent_crypto::Digest>(4)?,
            r.get::<_, u64>(5)?,
        ))
    })? {
        let (wire, group, writer, key, origin, head) = row?;
        let grant = SignedConfigurationGrant::decode(&wire)?;
        if grant.grant.owner_candidate != Some(digest) {
            continue;
        }
        grant.verify_owner_candidate(candidate)?;
        grant.verify_initial(baseline, candidate.candidate.issued_at)?;
        let g = &grant.grant;
        ensure!(
            writer == node.id()
                && key == node.public_key()
                && group == g.group
                && origin == g.origin
                && head == 0,
            "standby stream changed before activation"
        );
        let (reader, reader_key, sequence, saved_digest, receipt): (String,gent_crypto::PublicKey,u64,gent_crypto::Digest,Vec<u8>) = db.query_row("SELECT reader,reader_key,sequence,digest,receipt FROM stream_confirmed WHERE group_id=?1", [&group], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
        let receipt = Receipt::decode(&receipt)?;
        receipt.verify(&g.reader_key)?;
        ensure!(
            reader == g.reader
                && reader_key == g.reader_key
                && sequence == 0
                && saved_digest == origin
                && receipt.group() == group
                && receipt.sequence() == 0
                && receipt.digest() == origin,
            "standby reader readiness changed"
        );
        let data: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM network_links l JOIN streams o ON o.group_id=l.outgoing JOIN streams i ON i.group_id=l.incoming
            WHERE l.peer=?1 AND l.peer_key=?2 AND o.purpose='data' AND i.purpose='data' AND o.writer=?3 AND o.writer_key=?4 AND i.writer=?1 AND i.writer_key=?2)",
            params![reader,reader_key.as_slice(),node.id(),node.public_key().as_slice()], |r| r.get(0))?;
        ensure!(
            data,
            "successor needs an established data link to each peer"
        );
        ready.insert(reader, (grant, receipt));
    }
    ensure!(
        baseline
            .state()
            .nodes
            .keys()
            .filter(|id| id.as_str() != node.id())
            .all(|id| ready.contains_key(id)),
        "successor configuration streams are not ready for every enrolled peer"
    );
    Ok(ready.into_values().collect())
}

impl Store {
    /// Trusted local-owner activation. All imported decisions, the durable key
    /// reference and accepted handoff commit together. No source process is used.
    pub fn activate_owner_handoff(&mut self, credential: &str, id: &str) -> Result<SignedState> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let _lock = config::state_lock(&self.home, "owner-handoff.lock")?;
        let (key, candidate) = read_key(&candidate_path(&self.home, id)?)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (baseline, wire, completed): (Vec<u8>, Vec<u8>, Option<Vec<u8>>) = tx.query_row(
            "SELECT baseline,candidate,completed FROM owner_candidates WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure!(
            wire == candidate.encode()?
                && candidate.candidate.node.id == self.identity.node.id()
                && candidate.candidate.node.signing_key == self.identity.node.public_key(),
            "activation belongs to another candidate or node"
        );
        let pinned = restore(&candidate, &baseline)?;
        let completed = SignedState::decode(&completed.context("owner handoff is not completed")?)?;
        let authorization = completed
            .state
            .owner_transitions
            .last()
            .context("missing handoff authorization")?;
        pinned.verify_owner_authorization(&candidate, authorization)?;
        ensure!(
            pinned
                .accept_owner_authorization(&key, &candidate, authorization, now() as u64)?
                .encode()?
                == completed.encode()?,
            "completed owner handoff changed"
        );
        let state = self.identity.state(&tx)?;
        if state.owner_epoch() >= authorization.transition.epoch {
            ensure!(
                state
                    .state()
                    .owner_transitions
                    .get(authorization.transition.epoch as usize - 1)
                    == Some(authorization),
                "another owner handoff was accepted"
            );
            check_epochs(&tx, &self.identity.node, &state)?;
        } else {
            ensure!(
                state.checkpoint() == pinned.checkpoint(),
                "authority changed since handoff preparation"
            );
            readiness(&tx, &self.identity.node, &pinned, &candidate)?;
            let (entries, body) =
                journal::require_complete(&tx, &pinned, &candidate, authorization)?;
            configuration::storage::handoff::adopt(&tx, pinned.checkpoint(), entries, &body)?;
            tx.execute(
                "INSERT INTO owner_epochs VALUES(?1,?2,?3)",
                params![authorization.transition.epoch, authorization.encode()?, id],
            )?;
            let accepted = self.identity.apply(&tx, completed.clone())?;
            let timestamp = requests::clock(&tx, now())? as u64;
            if accepted.state().expires_at.saturating_sub(timestamp) <= 6 * 60 * 60 {
                self.identity.apply(&tx, accepted.renew(&key, timestamp)?)?;
            }
        }
        tx.commit()?;
        self.sync_wakeup.notify_one();
        self.project_config()?;
        self.reconcile_configuration()?;
        Ok(completed)
    }
}
