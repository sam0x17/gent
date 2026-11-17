use super::*;
use crate::messages::EditResult;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    origin: String,
    id: String,
    fingerprint: String,
    result: EditResult,
}

pub(super) fn snapshot(db: &Connection) -> Result<Vec<u8>> {
    let mut records = Vec::new();
    let mut query = db.prepare(
        "SELECT origin,id,fingerprint,result FROM peer_configuration_decisions ORDER BY origin,id",
    )?;
    let mut rows = query.query([])?;
    let mut size = 2usize;
    while let Some(row) = rows.next()? {
        let record = Saved {
            origin: row.get(0)?,
            id: row.get(1)?,
            fingerprint: row.get(2)?,
            result: serde_json::from_slice(&row.get::<_, Vec<u8>>(3)?)?,
        };
        size = size.saturating_add(serde_json::to_vec(&record)?.len() + 1);
        ensure!(
            size <= 1024 * 1024,
            "configuration decision snapshot exceeds enrollment capacity"
        );
        records.push(record);
    }
    Ok(serde_json::to_vec(&records)?)
}

pub(super) fn install(db: &Connection, state: &VerifiedState, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= 1024 * 1024,
        "configuration decision snapshot too large"
    );
    for record in serde_json::from_slice::<Vec<Saved>>(bytes)? {
        ensure!(
            gent_protocol::configuration_log::valid_id(&record.origin)
                && gent_protocol::configuration_log::valid_id(&record.id)
                && record.fingerprint.len() == 64
                && record.fingerprint.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid configuration decision identity"
        );
        match &record.result {
            EditResult::Applied { checkpoint } => ensure!(
                checkpoint.revision <= state.checkpoint().revision
                    && checkpoint.state_hash != [0; 32],
                "decision is ahead of enrollment checkpoint"
            ),
            EditResult::Rejected { reason } => {
                ensure!(reason.len() <= 1024, "decision reason too large")
            }
        }
        db.execute(
            "INSERT INTO peer_configuration_decisions VALUES(?1,?2,?3,?4)",
            params![
                record.origin,
                record.id,
                record.fingerprint,
                serde_json::to_vec(&record.result)?
            ],
        )?;
    }
    Ok(())
}

impl Store {
    pub(crate) fn configuration_decisions(&self) -> Result<Vec<u8>> {
        snapshot(&self.db)
    }
}

pub(super) fn accept(db: &Connection, state: &VerifiedState) -> Result<()> {
    let Some(request) = state.state().peer.as_ref().and_then(|p| p.request.as_ref()) else {
        return Ok(());
    };
    let result = if let Some(reason) = &request.rejection {
        EditResult::Rejected {
            reason: reason.clone(),
        }
    } else {
        EditResult::Applied {
            checkpoint: state.checkpoint().clone(),
        }
    };
    ensure!(
        !db.query_row(
            "SELECT EXISTS(SELECT 1 FROM peer_configuration_decisions WHERE origin=?1 AND id=?2)",
            params![request.origin, request.id],
            |r| r.get::<_, bool>(0)
        )?,
        "configuration request committed twice"
    );
    let encoded = serde_json::to_vec(&result)?;
    db.execute(
        "INSERT INTO peer_configuration_decisions VALUES(?1,?2,?3,?4)",
        params![request.origin, request.id, request.fingerprint, encoded],
    )?;
    let known: Option<(String, Option<Vec<u8>>)> = db
        .query_row(
            "SELECT fingerprint,result FROM configuration_edits WHERE origin=?1 AND id=?2",
            params![request.origin, request.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((fingerprint, previous)) = known {
        ensure!(
            fingerprint == request.fingerprint && previous.as_ref().is_none_or(|p| p == &encoded),
            "configuration decision conflicts with local request"
        );
        db.execute(
            "UPDATE configuration_edits SET result=?1 WHERE origin=?2 AND id=?3",
            params![encoded, request.origin, request.id],
        )?;
        configuration::pending::release(db, &request.origin, &request.id)?;
        configuration::routing::cancel_requests(db, &request.origin, &request.id)?;
        db.execute(
            "UPDATE peer_configuration_requests SET candidate=NULL WHERE origin=?1 AND id=?2",
            params![request.origin, request.id],
        )?;
    }
    Ok(())
}

impl StoreSession<'_> {
    pub(in crate::store) fn accept_peer_request(
        &self,
        origin: &str,
        id: &str,
        edit: &ConfigurationEdit,
    ) -> Result<()> {
        self.identity.require_administrator(self.db)?;
        let fingerprint = configuration::fingerprint(edit)?;
        let decided: Option<(String,Vec<u8>)> = self.db.query_row("SELECT fingerprint,result FROM peer_configuration_decisions WHERE origin=?1 AND id=?2",params![origin,id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let old: Option<String> = self
            .db
            .query_row(
                "SELECT fingerprint FROM configuration_edits WHERE origin=?1 AND id=?2",
                params![origin, id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            ensure!(old == fingerprint, "configuration request changed");
        } else {
            if let Some((expected, _)) = &decided {
                ensure!(
                    expected == &fingerprint,
                    "configuration retry changed intent"
                );
            }
            configuration::storage::insert(
                self.db,
                origin,
                id,
                self.identity.node.id(),
                &fingerprint,
                edit,
                decided.as_ref().map(|d| d.1.as_slice()),
            )?;
        }
        configuration::pending::retain(self.db, origin, id, edit)
    }
}
