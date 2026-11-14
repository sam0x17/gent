use super::*;

const MAX_JOBS: u64 = 65536;
const MAX_PENDING: u64 = 8192;
const MAX_BYTES: u64 = 128 * 1024 * 1024;

pub(in crate::store::handoff) fn schema(db: &Connection, previous: i64) -> Result<()> {
    let count: usize = db.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('owner_preparation_plans','owner_preparation_jobs')", [], |r| r.get(0))?;
    if count == 0 && previous < 25 {
        db.execute_batch("CREATE TABLE owner_preparation_plans(
            id TEXT PRIMARY KEY CHECK(length(id)=36),plan BLOB NOT NULL CHECK(length(plan)<=8192),
            candidate BLOB CHECK(length(candidate)<=8192),ready INTEGER NOT NULL DEFAULT 0 CHECK(ready IN (0,1)),
            error TEXT CHECK(length(CAST(error AS BLOB))<=1024));
            CREATE TABLE owner_preparation_jobs(
            id TEXT PRIMARY KEY CHECK(length(id)=36),plan TEXT NOT NULL REFERENCES owner_preparation_plans(id),
            body BLOB NOT NULL CHECK(length(body)<=2097152),fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
            done INTEGER NOT NULL DEFAULT 0 CHECK(done IN (0,1)),attempts INTEGER NOT NULL DEFAULT 0,
            retry_at INTEGER NOT NULL DEFAULT 0,error TEXT CHECK(length(CAST(error AS BLOB))<=1024));
            CREATE INDEX owner_preparation_pending ON owner_preparation_jobs(done,retry_at);")?;
    } else {
        ensure!(
            count == 2,
            "owner preparation coordination storage is missing"
        );
        db.prepare("SELECT id,plan,candidate,ready,error FROM owner_preparation_plans LIMIT 0")?;
        db.prepare("SELECT id,plan,body,fingerprint,done,attempts,retry_at,error FROM owner_preparation_jobs LIMIT 0")?;
    }
    Ok(())
}

pub(in crate::store::handoff) fn usage(db: &Connection) -> Result<Value> {
    let (records, pending, bytes): (u64,u64,u64) = db.query_row("SELECT COUNT(*),COALESCE(SUM(done=0),0),COALESCE(SUM(length(body)+length(id)+length(plan)+32+1024),0) FROM owner_preparation_jobs", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    let (plans, plan_bytes): (u64, u64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(plan)+8192+1024+36),0) FROM owner_preparation_plans",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(
        json!({"plans":plans,"records":records,"pending":pending,"reserved_bytes":bytes+plan_bytes,
        "max_plans":LIMIT,"max_records":MAX_JOBS,"max_pending":MAX_PENDING,"max_reserved_bytes":MAX_BYTES}),
    )
}

fn capacity(db: &Connection, bytes: usize) -> Result<()> {
    let used = usage(db)?;
    ensure!(
        used["reserved_bytes"]
            .as_u64()
            .unwrap()
            .saturating_add(bytes as u64)
            <= MAX_BYTES,
        "owner preparation storage quota exhausted"
    );
    Ok(())
}

pub(super) fn save_plan(db: &Connection, plan: &Plan) -> Result<()> {
    let wire = serde_json::to_vec(plan)?;
    ensure!(wire.len() <= 8192, "owner preparation plan too large");
    if let Some(previous) = load_plan(db, plan.id)? {
        ensure!(previous == *plan, "owner preparation request changed");
        return Ok(());
    }
    let used = usage(db)?;
    ensure!(
        used["plans"].as_u64().unwrap() < LIMIT as u64,
        "owner preparation plan limit reached"
    );
    capacity(db, wire.len() + 8192 + 1024 + 36)?;
    db.execute(
        "INSERT INTO owner_preparation_plans(id,plan) VALUES(?1,?2)",
        params![plan.id.to_string(), wire],
    )?;
    Ok(())
}

pub(in crate::store::handoff) fn load_plan(db: &Connection, id: Uuid) -> Result<Option<Plan>> {
    let wire: Option<Vec<u8>> = db
        .query_row(
            "SELECT plan FROM owner_preparation_plans WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    wire.map(|wire| {
        let plan: Plan = serde_json::from_slice(&wire)?;
        ensure!(
            plan.id == id && serde_json::to_vec(&plan)? == wire,
            "saved owner preparation plan changed"
        );
        Ok(plan)
    })
    .transpose()
}

pub(in crate::store::handoff) fn candidate(
    db: &Connection,
    id: Uuid,
) -> Result<Option<SignedOwnerCandidate>> {
    let wire: Option<Vec<u8>> = db.query_row(
        "SELECT candidate FROM owner_preparation_plans WHERE id=?1",
        [id.to_string()],
        |r| r.get(0),
    )?;
    wire.map(|wire| SignedOwnerCandidate::decode(&wire))
        .transpose()
}

pub(super) fn pin(db: &Connection, plan: &Plan, candidate: &SignedOwnerCandidate) -> Result<()> {
    if let Some(saved) = self::candidate(db, plan.id)? {
        ensure!(saved == *candidate, "owner preparation candidate changed");
    } else {
        ensure!(
            db.execute(
                "UPDATE owner_preparation_plans SET candidate=?1 WHERE id=?2",
                params![candidate.encode()?, plan.id.to_string()]
            )? == 1,
            "owner preparation plan missing"
        );
    }
    Ok(())
}

pub(super) fn duplicate(db: &Connection, envelope: &Envelope) -> Result<bool> {
    let previous: Option<Vec<u8>> = db
        .query_row(
            "SELECT fingerprint FROM owner_preparation_jobs WHERE id=?1",
            [envelope.id().to_string()],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(previous) = previous {
        ensure!(
            previous == Sha256::digest(serde_json::to_vec(envelope)?).as_slice(),
            "conflicting owner preparation signal"
        );
        return Ok(true);
    }
    Ok(false)
}

pub(super) fn admit(db: &Connection, envelope: &Envelope) -> Result<()> {
    if duplicate(db, envelope)? {
        return Ok(());
    }
    let body = serde_json::to_vec(envelope)?;
    ensure!(
        body.len() <= crate::messages::MAX_RECORD_BYTES,
        "owner preparation signal too large"
    );
    let used = usage(db)?;
    ensure!(
        used["records"].as_u64().unwrap() < MAX_JOBS
            && used["pending"].as_u64().unwrap() < MAX_PENDING,
        "owner preparation job limit reached"
    );
    capacity(db, body.len() + 36 + 36 + 32 + 1024)?;
    db.execute(
        "INSERT INTO owner_preparation_jobs(id,plan,body,fingerprint) VALUES(?1,?2,?3,?4)",
        params![
            envelope.id().to_string(),
            envelope.plan.id.to_string(),
            body,
            Sha256::digest(&body).as_slice()
        ],
    )?;
    Ok(())
}

pub(super) fn decode(id: &str, body: &[u8], fingerprint: &[u8]) -> Result<Envelope> {
    let envelope: Envelope = serde_json::from_slice(body)?;
    ensure!(
        envelope.id().to_string() == id
            && Sha256::digest(body).as_slice() == fingerprint
            && serde_json::to_vec(&envelope)? == body,
        "saved owner preparation job changed"
    );
    Ok(envelope)
}

pub(super) fn finish(db: &Connection, id: &str) -> Result<()> {
    ensure!(
        db.execute(
            "UPDATE owner_preparation_jobs SET done=1,body=X'',error=NULL WHERE id=?1 AND done=0",
            [id]
        )? == 1,
        "owner preparation job changed before completion"
    );
    Ok(())
}

pub(super) fn error_text(mut text: String) -> String {
    let mut end = text.len().min(1024);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text
}
