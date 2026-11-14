//! Private, canonical decision snapshots for an authenticated owner handoff.
use super::*;
use gent_crypto::{Checkpoint, succession::journal};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    origin: String,
    id: String,
    writer: String,
    fingerprint: String,
    summary: Value,
    result: EditResult,
}

type SavedDecision = (String, String, Vec<u8>, Option<Vec<u8>>, bool);

fn summary(body: &[u8], compact: bool, expected: &str) -> Result<Value> {
    let value: Summary = if compact {
        serde_json::from_slice(body)?
    } else {
        let edit: ConfigurationEdit = serde_json::from_slice(body)?;
        ensure!(
            fingerprint(&edit)? == expected,
            "legacy configuration edit fingerprint mismatch"
        );
        Summary::from(&edit)
    };
    Ok(serde_json::to_value(value)?)
}

impl Decision {
    fn validate(&self, base: &Checkpoint) -> Result<()> {
        for id in [&self.origin, &self.id, &self.writer] {
            ensure!(
                Uuid::parse_str(id).is_ok_and(|u| !u.is_nil() && u.to_string() == *id),
                "invalid handoff decision identity"
            );
        }
        ensure!(
            self.fingerprint.len() == 64
                && self
                    .fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid handoff decision fingerprint"
        );
        let _: Summary = serde_json::from_value(self.summary.clone())?;
        result_size(&serde_json::to_vec(&self.result)?)?;
        match &self.result {
            EditResult::Applied { checkpoint } => ensure!(
                checkpoint.revision <= base.revision && checkpoint.state_hash != [0; 32],
                "handoff decision is ahead of its checkpoint"
            ),
            EditResult::Rejected { reason } => ensure!(
                reason.len() <= MAX_REASON_BYTES,
                "handoff rejection exceeds limit"
            ),
        }
        ensure!(
            serde_jcs::to_vec(self)?.len() <= crate::messages::MAX_RECORD_BYTES + RESULT_RESERVE,
            "handoff decision exceeds record limit"
        );
        Ok(())
    }
}

pub(in crate::store) fn snapshot(db: &Connection, base: &Checkpoint) -> Result<(usize, Vec<u8>)> {
    let mut stmt = db.prepare("SELECT origin,id,writer,fingerprint,edit,result,compact FROM configuration_edits WHERE result IS NOT NULL ORDER BY origin,id LIMIT 65537")?;
    let mut rows = stmt.query([])?;
    let mut decisions = Vec::new();
    let mut size: usize = 2;
    while let Some(row) = rows.next()? {
        ensure!(
            decisions.len() < journal::MAX_ENTRIES,
            "owner decision count exceeds limit"
        );
        let fingerprint: String = row.get(3)?;
        let decision = Decision {
            origin: row.get(0)?,
            id: row.get(1)?,
            writer: row.get(2)?,
            summary: summary(&row.get::<_, Vec<u8>>(4)?, row.get(6)?, &fingerprint)?,
            fingerprint,
            result: serde_json::from_slice(&row.get::<_, Vec<u8>>(5)?)?,
        };
        decision.validate(base)?;
        size = size
            .checked_add(serde_jcs::to_vec(&decision)?.len() + 1)
            .context("journal size overflow")?;
        ensure!(
            size <= journal::MAX_BYTES,
            "owner decision journal exceeds limit"
        );
        decisions.push(decision);
    }
    Ok((decisions.len(), serde_jcs::to_vec(&decisions)?))
}

/// Validates the complete authenticated snapshot and its overlap with this
/// node's retry history. It neither applies edits nor imports authority hashes.
pub(in crate::store) fn verify_snapshot(
    db: &Connection,
    base: &Checkpoint,
    entries: usize,
    body: &[u8],
) -> Result<()> {
    ensure!(
        body.len() <= journal::MAX_BYTES && entries <= journal::MAX_ENTRIES,
        "owner decision journal exceeds limit"
    );
    let decisions: Vec<Decision> = serde_json::from_slice(body)?;
    ensure!(
        decisions.len() == entries && serde_jcs::to_vec(&decisions)? == body,
        "owner decision journal count or canonical encoding changed"
    );
    let mut previous: Option<(&str, &str)> = None;
    for decision in &decisions {
        decision.validate(base)?;
        let key = (decision.origin.as_str(), decision.id.as_str());
        ensure!(
            previous.is_none_or(|p| p < key),
            "owner decision journal is duplicated or unordered"
        );
        previous = Some(key);
        let saved: Option<SavedDecision> = db.query_row(
            "SELECT writer,fingerprint,edit,result,compact FROM configuration_edits WHERE origin=?1 AND id=?2",
            params![decision.origin, decision.id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).optional()?;
        if let Some((writer, fingerprint, edit, result, compact)) = saved {
            ensure!(
                (writer == decision.writer
                    || (result.is_none()
                        && super::super::routing::known_route(
                            db,
                            &decision.origin,
                            &decision.id,
                            &decision.writer
                        )?))
                    && fingerprint == decision.fingerprint
                    && summary(&edit, compact, &fingerprint)? == decision.summary,
                "owner decision conflicts with local request history"
            );
            if let Some(result) = result {
                let result: EditResult = serde_json::from_slice(&result)?;
                ensure!(
                    serde_json::to_value(result)? == serde_json::to_value(&decision.result)?,
                    "owner decision conflicts with local result history"
                );
            }
        }
        if let EditResult::Applied { checkpoint } = &decision.result {
            // A new node may not retain pre-enrollment digests. Existing accepted
            // evidence must agree; the signed snapshot never overwrites it.
            let known: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_digests WHERE revision=?1) OR EXISTS(SELECT 1 FROM authority_history WHERE revision=?1)",
                [checkpoint.revision], |r| r.get(0),
            )?;
            if known {
                let anchor: Vec<u8> =
                    db.query_row("SELECT anchor FROM authority WHERE singleton=1", [], |r| {
                        r.get(0)
                    })?;
                ensure!(
                    encrypted::history::checkpoint(
                        db,
                        checkpoint.revision,
                        &serde_json::from_slice(&anchor)?
                    )? == *checkpoint,
                    "owner decision conflicts with accepted authority"
                );
            }
        }
    }
    Ok(())
}

/// Authenticated migration can exceed ordinary admission quotas. Existing
/// decisions and pending inputs survive; ordinary admission then remains closed
/// until capacity is available. The incoming journal has its own strict bound.
pub(in crate::store) fn adopt(
    db: &Connection,
    base: &Checkpoint,
    entries: usize,
    body: &[u8],
) -> Result<()> {
    verify_snapshot(db, base, entries, body)?;
    for decision in serde_json::from_slice::<Vec<Decision>>(body)? {
        let summary = serde_json::to_vec(&decision.summary)?;
        let result = serde_json::to_vec(&decision.result)?;
        db.execute("INSERT INTO configuration_edits(origin,id,writer,fingerprint,edit,result,compact) VALUES(?1,?2,?3,?4,?5,?6,1)
            ON CONFLICT(origin,id) DO UPDATE SET writer=excluded.writer,edit=excluded.edit,result=excluded.result,compact=1",
            params![decision.origin,decision.id,decision.writer,decision.fingerprint,summary,result])?;
        super::super::pending::release(db, &decision.origin, &decision.id)?;
        super::super::routing::cancel_requests(db, &decision.origin, &decision.id)?;
    }
    Ok(())
}
