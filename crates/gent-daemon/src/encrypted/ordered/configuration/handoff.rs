//! Bounded, candidate-bound journal records on the configuration recovery route.
//! Delivery never activates an owner or relaxes the ordinary message lease.
use super::*;
use crate::store::handoff::{self as owner, journal};
use gent_crypto::succession::{SignedOwnerCandidate, SignedOwnerTransition, journal::Manifest};

#[cfg(test)]
pub(crate) mod test_packets;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    version: u8,
    handoff: Artifact,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Artifact {
    Manifest {
        id: String,
        authorization: Box<SignedOwnerTransition>,
        manifest: Manifest,
    },
    Page {
        id: String,
        index: usize,
        data: String,
    },
}

pub(crate) fn schema(db: &Connection, previous: i64) -> Result<()> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='owner_deliveries')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        ensure!(previous < 24, "owner delivery storage is missing");
        db.execute_batch("CREATE TABLE owner_deliveries(id TEXT PRIMARY KEY REFERENCES owner_handoffs(id),group_id BLOB UNIQUE NOT NULL CHECK(length(group_id) BETWEEN 1 AND 256),next INTEGER NOT NULL CHECK(next>=0 AND next<=parts),parts INTEGER NOT NULL CHECK(parts BETWEEN 2 AND 321));")?;
    } else {
        db.prepare("SELECT id,group_id,next,parts FROM owner_deliveries LIMIT 0")?;
    }
    Ok(())
}

pub(crate) fn usage(db: &Connection) -> Result<serde_json::Value> {
    let (jobs, pending): (usize, usize) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(next<parts),0) FROM owner_deliveries",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(jobs <= 64, "owner delivery capacity exceeded");
    Ok(serde_json::json!({"jobs":jobs,"pending_publication":pending,"max_jobs":64}))
}

fn route(
    signed: &SignedConfigurationGrant,
    baseline: &VerifiedState,
    candidate: &SignedOwnerCandidate,
) -> Result<()> {
    signed.verify(baseline.anchor())?;
    let grant = &signed.grant;
    let epoch = grant.owner_transitions.len() + usize::from(grant.owner_candidate.is_some());
    ensure!(
        epoch == baseline.owner_epoch() as usize
            && baseline
                .state()
                .owner_transitions
                .starts_with(&grant.owner_transitions)
            && signed.can_publish(baseline)?
            && grant.base.revision <= baseline.checkpoint().revision
            && grant.reader == candidate.candidate.node.id
            && grant.reader_key == candidate.candidate.node.signing_key,
        "owner delivery requires a predecessor configuration stream to the candidate"
    );
    Ok(())
}

fn at_baseline(cursor: &Progress, baseline: &VerifiedState) -> Result<()> {
    ensure!(
        cursor.revision == baseline.checkpoint().revision
            && cursor.hash == baseline.checkpoint().state_hash
            && cursor.offset == 0,
        "owner delivery must follow configuration history through its baseline"
    );
    Ok(())
}

fn status(db: &Connection, id: &str) -> Result<serde_json::Value> {
    let (next, parts): (usize, usize) = db.query_row(
        "SELECT next,parts FROM owner_deliveries WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(
        serde_json::json!({"request_id":id,"published_parts":next,"parts":parts,"publication_complete":next==parts}),
    )
}

impl OrderedEndpoint<'_> {
    pub(crate) fn queue_owner_handoff(&mut self, id: &str, now: u64) -> Result<serde_json::Value> {
        self.inner.transact_mode(now, true, |session| {
            owner::check_state(session.db, &session.state)?;
            let issued = owner::issued_for(session.db, id)?;
            let (manifest, _) = journal::load(session.db, id, true)?;
            let saved: Option<(Vec<u8>, usize)> = session
                .db
                .query_row(
                    "SELECT group_id,parts FROM owner_deliveries WHERE id=?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((group, parts)) = saved {
                let stream = checked_stream(session, &group, Purpose::Configuration)?;
                ensure!(
                    stream.writer == session.signer.id(),
                    "owner delivery belongs to another writer"
                );
                route(
                    &progress(session.db, &group)?.grant,
                    &issued.base,
                    &issued.candidate,
                )?;
                ensure!(
                    parts == manifest.pages.len() + 1,
                    "owner delivery manifest changed"
                );
                return status(session.db, id);
            }
            let count: usize =
                session
                    .db
                    .query_row("SELECT COUNT(*) FROM owner_deliveries", [], |r| r.get(0))?;
            ensure!(count < 64, "owner delivery capacity exhausted");
            let mut query = session.db.prepare(
                "SELECT group_id FROM configuration_streams ORDER BY group_id LIMIT 4097",
            )?;
            let groups = query
                .query_map([], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            ensure!(groups.len() <= 4096, "too many configuration streams");
            let mut selected = None;
            for group in groups {
                let Ok(stream) = checked_stream(session, &group, Purpose::Configuration) else {
                    continue;
                };
                if stream.writer != session.signer.id() {
                    continue;
                }
                if route(
                    &progress(session.db, &group)?.grant,
                    &issued.base,
                    &issued.candidate,
                )
                .is_ok()
                {
                    selected = Some(group);
                    break;
                }
            }
            let group =
                selected.context("no approved predecessor configuration route to successor")?;
            session.db.execute(
                "INSERT INTO owner_deliveries VALUES(?1,?2,0,?3)",
                params![id, group, manifest.pages.len() + 1],
            )?;
            status(session.db, id)
        })
    }

    /// The caller first drains ordinary signed history. Publication, its
    /// managed request ID, MLS ratchet and job cursor commit together.
    pub(crate) fn prepare_owner_handoff(
        &mut self,
        group: &[u8],
        now: u64,
    ) -> Result<Option<Packet>> {
        self.inner.transact_mode(now, true, |session| {
            let job: Option<(String, usize, usize)> = session
                .db
                .query_row(
                    "SELECT id,next,parts FROM owner_deliveries WHERE group_id=?1 AND next<parts",
                    [group],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((id, next, parts)) = job else {
                return Ok(None);
            };
            let saved = checked_stream(session, group, Purpose::Configuration)?;
            ensure!(
                saved.writer == session.signer.id(),
                "only the configuration writer can publish"
            );
            let issued = owner::issued_for(session.db, &id)?;
            let cursor = progress(session.db, group)?;
            route(&cursor.grant, &issued.base, &issued.candidate)?;
            at_baseline(&cursor, &issued.base)?;
            let (manifest, _) = journal::load(session.db, &id, true)?;
            ensure!(
                parts == manifest.pages.len() + 1,
                "owner delivery manifest changed"
            );
            let handoff = if next == 0 {
                Artifact::Manifest {
                    id: id.clone(),
                    authorization: Box::new(issued.authorization),
                    manifest,
                }
            } else {
                let body = journal::page(session.db, &id, &manifest, next - 1)?;
                Artifact::Page {
                    id: id.clone(),
                    index: next - 1,
                    data: STANDARD.encode(body),
                }
            };
            let body = serde_json::to_vec(&Record {
                version: 1,
                handoff,
            })?;
            let request = requests::allocate(session.db, group, &body, None)?;
            let packet = publish_in(session, group, Purpose::Configuration, |session| {
                session.send(group, request, &body)
            })?;
            session.db.execute(
                "INSERT INTO configuration_requests VALUES(?1,?2)",
                params![request.to_string(), group],
            )?;
            session
                .db
                .execute("UPDATE owner_deliveries SET next=next+1 WHERE id=?1", [&id])?;
            Ok(Some(packet))
        })
    }
}

pub(super) fn receive(session: &Session<'_>, group: &[u8], record: Record) -> Result<Received> {
    ensure!(record.version == 1, "unsupported owner delivery record");
    let id = match &record.handoff {
        Artifact::Manifest { id, .. } | Artifact::Page { id, .. } => id,
    };
    let (baseline, candidate) = journal::candidate(session.db, id)?;
    let cursor = progress(session.db, group)?;
    route(&cursor.grant, &baseline, &candidate)?;
    at_baseline(&cursor, &baseline)?;
    match record.handoff {
        Artifact::Manifest {
            id,
            authorization,
            manifest,
        } => {
            journal::begin_import(
                session.db,
                &session.state,
                session.signer,
                &id,
                &authorization,
                &manifest,
            )?;
        }
        Artifact::Page { id, index, data } => {
            ensure!(
                data.len() <= 4 * gent_crypto::succession::journal::PAGE_BYTES.div_ceil(3),
                "owner journal page exceeds limit"
            );
            journal::import_page(
                session.db,
                &session.state,
                session.signer,
                &id,
                index,
                &STANDARD.decode(data)?,
            )?;
        }
    }
    Ok(Received::OwnerHandoff)
}
