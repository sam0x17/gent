//! Retention never grants another dispatch. A missing message, closed legacy
//! admission and an elapsed replay horizon make its old claim unnecessary.
use super::*;

const RETENTION: i64 = history::RETENTION;
const BATCH: usize = 128;

// An imported message may be created one skew interval ahead of receipt; its
// request UUID may be another interval ahead of creation. Even rewritten
// timestamps cannot extend that UUID's delivery past this bound after a claim.
const _: () =
    assert!(RETENTION > requests::LIFETIME + EXCHANGE_TTL_SECONDS + 2 * requests::CLOCK_SKEW);

#[derive(Default)]
struct Inspection {
    records: u64,
    uncertain: u64,
    submitted_without_inbox_observation: u64,
    submitted_and_observed: u64,
    eligible: u64,
    candidates: Vec<String>,
}

fn inspect(db: &Connection, timestamp: i64) -> Result<Inspection> {
    let legacy_until: i64 = db.query_row(
        "SELECT legacy_until FROM request_clock WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let mut statement = db.prepare(
        "SELECT message_id,EXISTS(SELECT 1 FROM messages WHERE id=w.message_id)
         FROM wake_dispatches w ORDER BY claimed_at,message_id",
    )?;
    let rows = statement.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)))?;
    let mut result = Inspection::default();
    for row in rows {
        let (message_id, message_retained) = row?;
        // Use the same strict decoder as claim retries. Never delete malformed
        // evidence, even if its unchecked JSON would appear eligible.
        let record = record(db, &message_id)?.context("wake record disappeared")?;
        result.records += 1;
        if record.state == WakeState::Uncertain {
            result.uncertain += 1;
        } else if record.inbox_seen_at.is_none() {
            result.submitted_without_inbox_observation += 1;
        } else {
            result.submitted_and_observed += 1;
            if !message_retained
                && timestamp >= legacy_until
                && record.updated_at <= timestamp - RETENTION
            {
                result.eligible += 1;
                if result.candidates.len() < BATCH {
                    result.candidates.push(message_id);
                }
            }
        }
    }
    Ok(result)
}

pub(in crate::store) fn status(db: &Connection, timestamp: i64) -> Result<Value> {
    let inspection = inspect(db, timestamp)?;
    Ok(json!({"records":inspection.records,
        "uncertain":inspection.uncertain,
        "submitted_without_inbox_observation":inspection.submitted_without_inbox_observation,
        "submitted_and_observed":inspection.submitted_and_observed,
        "eligible":inspection.eligible,
        "available_records":MAX_RECORDS.saturating_sub(inspection.records),
        "limits":limits(),"cleanup_batch_limit":BATCH,
        "retention_after_update_seconds":RETENTION,"request_clock":timestamp}))
}

// Callers hold an immediate transaction and use its persisted request clock.
pub(in crate::store) fn clean(db: &Connection, timestamp: i64, dry_run: bool) -> Result<Value> {
    let inspection = inspect(db, timestamp)?;
    if !dry_run {
        for message_id in &inspection.candidates {
            ensure!(
                db.execute(
                    "DELETE FROM wake_dispatches WHERE message_id=?1",
                    [message_id]
                )? == 1,
                "wake record changed during cleanup"
            );
        }
    }
    let removed = inspection.candidates.len() as u64;
    Ok(json!({"dry_run":dry_run,"records_removed":removed,
        "more_due":inspection.eligible - removed,"batch_limit":BATCH,
        "uncertain_retained":inspection.uncertain,
        "unobserved_submissions_retained":inspection.submitted_without_inbox_observation}))
}

impl Store {
    pub(in crate::store) fn clean_wake(&mut self) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let timestamp = requests::clock(&tx, now())?;
        clean(&tx, timestamp, false)?;
        tx.commit()?;
        Ok(())
    }
}
