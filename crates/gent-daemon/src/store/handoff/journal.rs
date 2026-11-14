//! Transfer of decision history precedes successor signing and activation.
use super::*;
use gent_crypto::succession::journal::{MAX_BYTES, MAX_MANIFEST_BYTES, Manifest, PAGE_BYTES};

const MAX_RESERVED_BYTES: usize = 2 * MAX_BYTES;
const MAX_SNAPSHOTS: usize = LIMIT + 1;

pub(super) fn schema(db: &Connection, previous: i64) -> Result<()> {
    let count: usize = db.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('owner_journals','owner_journal_pages')", [], |r| r.get(0))?;
    if previous < 19 && count == 0 {
        db.execute_batch("CREATE TABLE owner_journals(id TEXT PRIMARY KEY CHECK(length(id)=36),source INTEGER NOT NULL CHECK(source IN (0,1)),manifest BLOB NOT NULL CHECK(length(manifest)<=131072),authorization BLOB NOT NULL CHECK(length(authorization)<=4096),bytes INTEGER NOT NULL CHECK(bytes>0 AND bytes<=83886080));
        CREATE TABLE owner_journal_pages(id TEXT NOT NULL REFERENCES owner_journals(id),page INTEGER NOT NULL CHECK(page>=0 AND page<320),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=262144),PRIMARY KEY(id,page));")?;
    } else {
        ensure!(count == 2, "owner decision transfer journal is missing");
        db.prepare("SELECT id,source,manifest,authorization,bytes FROM owner_journals LIMIT 0")?;
        db.prepare("SELECT id,page,body FROM owner_journal_pages LIMIT 0")?;
    }
    Ok(())
}

pub(super) fn usage(db: &Connection) -> Result<Value> {
    let (count, bytes): (usize, usize) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM owner_journals",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(
        count <= MAX_SNAPSHOTS && bytes <= MAX_RESERVED_BYTES,
        "owner journal transfer budget exceeded"
    );
    Ok(json!({"snapshots":count,"reserved_bytes":bytes,"max_reserved_bytes":MAX_RESERVED_BYTES}))
}

fn load(db: &Connection, id: &str, source: bool) -> Result<(Manifest, SignedOwnerTransition)> {
    let (wire, auth, bytes): (Vec<u8>, Vec<u8>, usize) = db.query_row(
        "SELECT manifest,authorization,bytes FROM owner_journals WHERE id=?1 AND source=?2",
        params![id, source],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    ensure!(
        wire.len() <= MAX_MANIFEST_BYTES,
        "owner journal manifest exceeds limit"
    );
    let manifest = Manifest::decode(&wire)?;
    ensure!(manifest.bytes == bytes, "owner journal reservation changed");
    Ok((manifest, SignedOwnerTransition::decode(&auth)?))
}

fn reserve(
    db: &Connection,
    candidate: &SignedOwnerCandidate,
    source: bool,
    authorization: &SignedOwnerTransition,
    manifest: &Manifest,
) -> Result<()> {
    let prior: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM owner_journals WHERE id=?1)",
        [&candidate.candidate.id],
        |r| r.get(0),
    )?;
    if prior {
        let (saved, auth) = load(db, &candidate.candidate.id, source)?;
        ensure!(
            saved == *manifest && auth == *authorization,
            "owner journal request changed"
        );
        return Ok(());
    }
    let (count, bytes): (usize, usize) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM owner_journals",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(
        count < MAX_SNAPSHOTS
            && bytes
                .checked_add(manifest.bytes)
                .is_some_and(|n| n <= MAX_RESERVED_BYTES),
        "owner journal transfer budget exhausted"
    );
    db.execute(
        "INSERT INTO owner_journals VALUES(?1,?2,?3,?4,?5)",
        params![
            candidate.candidate.id,
            source,
            manifest.encode()?,
            authorization.encode()?,
            manifest.bytes
        ],
    )?;
    Ok(())
}

pub(super) fn capture(
    db: &Connection,
    state: &VerifiedState,
    candidate: &SignedOwnerCandidate,
) -> Result<(Manifest, Vec<u8>)> {
    let (count, body) = configuration::storage::handoff::snapshot(db, state.checkpoint())?;
    configuration::storage::handoff::verify_snapshot(db, state.checkpoint(), count, &body)?;
    let manifest = Manifest::new(candidate, count, &body)?;
    Ok((manifest, body))
}

pub(super) fn save_source(
    db: &Connection,
    candidate: &SignedOwnerCandidate,
    authorization: &SignedOwnerTransition,
    manifest: &Manifest,
    body: &[u8],
) -> Result<()> {
    reserve(db, candidate, true, authorization, manifest)?;
    for (page, body) in body.chunks(PAGE_BYTES).enumerate() {
        manifest.verify_page(page, body)?;
        db.execute(
            "INSERT INTO owner_journal_pages VALUES(?1,?2,?3)",
            params![candidate.candidate.id, page, body],
        )?;
    }
    Ok(())
}

pub(super) fn check_source(
    db: &Connection,
    state: &VerifiedState,
    candidate: &SignedOwnerCandidate,
    authorization: &SignedOwnerTransition,
) -> Result<()> {
    if authorization
        .transition
        .successor
        .as_ref()
        .is_some_and(|s| s.journal.is_some())
    {
        let (manifest, auth) = load(db, &candidate.candidate.id, true)?;
        ensure!(
            auth == *authorization,
            "owner decision journal authorization changed"
        );
        manifest.verify(state, candidate, authorization)?;
    }
    Ok(())
}

fn incoming(
    db: &Connection,
    id: &str,
) -> Result<(
    VerifiedState,
    SignedOwnerCandidate,
    Manifest,
    SignedOwnerTransition,
)> {
    let (baseline, candidate): (Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT baseline,candidate FROM owner_candidates WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let candidate = SignedOwnerCandidate::decode(&candidate)?;
    ensure!(
        candidate.candidate.id == id,
        "owner journal candidate identity changed"
    );
    let baseline = restore(&candidate, &baseline)?;
    let (manifest, authorization) = load(db, id, false)?;
    manifest.verify(&baseline, &candidate, &authorization)?;
    Ok((baseline, candidate, manifest, authorization))
}

fn page(db: &Connection, id: &str, manifest: &Manifest, index: usize) -> Result<Vec<u8>> {
    ensure!(
        index < manifest.pages.len(),
        "owner journal page outside manifest"
    );
    let body: Vec<u8> = db.query_row(
        "SELECT body FROM owner_journal_pages WHERE id=?1 AND page=?2",
        params![id, index],
        |r| r.get(0),
    )?;
    manifest.verify_page(index, &body)?;
    Ok(body)
}

fn progress(db: &Connection, id: &str, manifest: &Manifest) -> Result<Value> {
    let indices = db
        .prepare("SELECT page FROM owner_journal_pages WHERE id=?1 ORDER BY page")?
        .query_map([id], |r| r.get::<_, usize>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        indices.len() <= manifest.pages.len() && indices.iter().all(|i| *i < manifest.pages.len()),
        "owner journal page inventory changed"
    );
    let missing: Vec<usize> = (0..manifest.pages.len())
        .filter(|i| indices.binary_search(i).is_err())
        .collect();
    let activated: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM owner_epochs WHERE local_candidate=?1)",
        [id],
        |r| r.get(0),
    )?;
    Ok(
        json!({"request_id":id,"pages":manifest.pages.len(),"received":indices.len(),
        "missing":missing,"pages_complete":missing.is_empty(),"entries":manifest.entries,"bytes":manifest.bytes,"activated":activated}),
    )
}

pub(super) fn require_complete(
    db: &Connection,
    baseline: &VerifiedState,
    candidate: &SignedOwnerCandidate,
    authorization: &SignedOwnerTransition,
) -> Result<(usize, Vec<u8>)> {
    let (manifest, saved) = load(db, &candidate.candidate.id, false)?;
    ensure!(
        saved == *authorization,
        "owner journal authorization changed"
    );
    manifest.verify(baseline, candidate, authorization)?;
    ensure!(
        progress(db, &candidate.candidate.id, &manifest)?["pages_complete"] == true,
        "owner decision journal transfer is incomplete"
    );
    let mut body = Vec::with_capacity(manifest.bytes);
    for index in 0..manifest.pages.len() {
        body.extend(page(db, &candidate.candidate.id, &manifest, index)?);
    }
    configuration::storage::handoff::verify_snapshot(
        db,
        baseline.checkpoint(),
        manifest.entries,
        &body,
    )?;
    Ok((manifest.entries, body))
}

impl Store {
    /// Owner-only private export. Contains decision summaries, never signing keys.
    pub fn owner_handoff_manifest(&self, credential: &str, id: &str) -> Result<Manifest> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let tx = self.db.unchecked_transaction()?;
        self.identity.state(&tx)?;
        issued_for(&tx, id)?;
        Ok(load(&tx, id, true)?.0)
    }

    pub fn owner_handoff_page(&self, credential: &str, id: &str, index: usize) -> Result<Vec<u8>> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let tx = self.db.unchecked_transaction()?;
        self.identity.state(&tx)?;
        issued_for(&tx, id)?;
        page(&tx, id, &load(&tx, id, true)?.0, index)
    }

    pub fn begin_owner_handoff_import(
        &mut self,
        credential: &str,
        id: &str,
        authorization: &SignedOwnerTransition,
        manifest: &Manifest,
    ) -> Result<Value> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        let (baseline, wire): (Vec<u8>, Vec<u8>) = tx.query_row(
            "SELECT baseline,candidate FROM owner_candidates WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let candidate = SignedOwnerCandidate::decode(&wire)?;
        ensure!(
            candidate.candidate.id == id
                && candidate.candidate.node.id == self.identity.node.id()
                && candidate.candidate.node.signing_key == self.identity.node.public_key(),
            "owner journal belongs to another node or request"
        );
        let pinned = restore(&candidate, &baseline)?;
        ensure!(
            pinned.anchor() == state.anchor() && pinned.checkpoint() == state.checkpoint(),
            "owner journal checkpoint changed"
        );
        manifest.verify(&pinned, &candidate, authorization)?;
        reserve(&tx, &candidate, false, authorization, manifest)?;
        let status = progress(&tx, id, manifest)?;
        tx.commit()?;
        Ok(status)
    }

    pub fn import_owner_handoff_page(
        &mut self,
        credential: &str,
        id: &str,
        index: usize,
        body: &[u8],
    ) -> Result<Value> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        ensure!(body.len() <= PAGE_BYTES, "owner journal page exceeds limit");
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        let (baseline, candidate, manifest, authorization) = incoming(&tx, id)?;
        ensure!(
            baseline.anchor() == state.anchor()
                && baseline.checkpoint() == state.checkpoint()
                && candidate.candidate.node.id == self.identity.node.id()
                && candidate.candidate.node.signing_key == self.identity.node.public_key(),
            "owner journal local authority changed"
        );
        manifest.verify_page(index, body)?;
        let saved: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM owner_journal_pages WHERE id=?1 AND page=?2",
                params![id, index],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(saved) = saved {
            ensure!(saved == body, "owner journal page changed after receipt");
        } else {
            tx.execute(
                "INSERT INTO owner_journal_pages VALUES(?1,?2,?3)",
                params![id, index, body],
            )?;
        }
        let status = progress(&tx, id, &manifest)?;
        if status["pages_complete"] == true {
            require_complete(&tx, &baseline, &candidate, &authorization)?;
        }
        tx.commit()?;
        Ok(status)
    }

    pub fn owner_handoff_import_status(&self, credential: &str, id: &str) -> Result<Value> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let tx = self.db.unchecked_transaction()?;
        let (_, candidate, manifest, _) = incoming(&tx, id)?;
        ensure!(
            candidate.candidate.node.id == self.identity.node.id()
                && candidate.candidate.node.signing_key == self.identity.node.public_key(),
            "owner journal belongs to another node"
        );
        progress(&tx, id, &manifest)
    }
}
