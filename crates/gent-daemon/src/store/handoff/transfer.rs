//! Explicit source commit, durable publication and opt-in successor activation.
//! Maintenance may finish an issued transfer, but can never issue a new one.
use super::coordination::storage::{candidate, load_plan};
use super::*;
use gent_crypto::NodeIdentity;
use gent_protocol::owner_transfer::OwnerTransferOp;

const BATCH: usize = 8;

pub(super) fn schema(db: &Connection, previous: i64) -> Result<()> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='owner_transfers')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        ensure!(previous < 26, "owner transfer control storage is missing");
        db.execute_batch(
            "CREATE TABLE owner_transfers(
            id TEXT PRIMARY KEY REFERENCES owner_preparation_plans(id),
            role TEXT NOT NULL CHECK(role IN ('source','successor')),
            done INTEGER NOT NULL DEFAULT 0 CHECK(done IN (0,1)),
            attempts INTEGER NOT NULL DEFAULT 0,retry_at INTEGER NOT NULL DEFAULT 0,
            error TEXT CHECK(length(CAST(error AS BLOB))<=1024));",
        )?;
    } else {
        db.prepare("SELECT id,role,done,attempts,retry_at,error FROM owner_transfers LIMIT 0")?;
    }
    Ok(())
}

pub(super) fn usage(db: &Connection) -> Result<Value> {
    let (records, pending): (u64, u64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(done=0),0) FROM owner_transfers",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(
        records <= LIMIT as u64,
        "owner transfer history exceeds limit"
    );
    Ok(json!({"records":records,"pending":pending,"max_records":LIMIT}))
}

fn request_id(id: &str) -> Result<Uuid> {
    let parsed = Uuid::parse_str(id)?;
    ensure!(
        !parsed.is_nil() && parsed.to_string() == id,
        "invalid owner transfer request ID"
    );
    Ok(parsed)
}

fn arm(db: &Connection, id: Uuid, role: &str) -> Result<()> {
    if let Some(previous) = db
        .query_row(
            "SELECT role FROM owner_transfers WHERE id=?1",
            [id.to_string()],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    {
        ensure!(previous == role, "owner transfer role changed");
        return Ok(());
    }
    ensure!(
        usage(db)?["records"].as_u64().unwrap() < LIMIT as u64,
        "owner transfer history is full"
    );
    db.execute(
        "INSERT INTO owner_transfers(id,role) VALUES(?1,?2)",
        params![id.to_string(), role],
    )?;
    Ok(())
}

/// Runs in the exact transaction which records the signing stop. Publication
/// therefore remains recoverable even if no response or ciphertext is sent.
pub(super) fn arm_source(
    db: &Connection,
    node: &NodeIdentity,
    state: &VerifiedState,
    proposal: &SignedOwnerCandidate,
    fresh: bool,
) -> Result<()> {
    let id = request_id(&proposal.candidate.id)?;
    let plan = load_plan(db, id)?.context("owner transfer was not prepared through the CLI")?;
    ensure!(
        plan.auto_activate
            && plan.source == node.id()
            && plan.successor == proposal.candidate.node.id
            && candidate(db, id)?.as_ref() == Some(proposal),
        "owner transfer does not match the prepared plan"
    );
    ensure!(
        db.query_row(
            "SELECT ready FROM owner_preparation_plans WHERE id=?1",
            [id.to_string()],
            |r| r.get::<_, bool>(0)
        )?,
        "owner transfer readiness is not recorded"
    );
    if fresh {
        plan.current(state, requests::clock(db, now())? as u64)?;
    }
    arm(db, id, "source")
}

fn accepted(state: &VerifiedState, proposal: Option<&SignedOwnerCandidate>) -> Result<Option<u32>> {
    let Some(proposal) = proposal else {
        return Ok(None);
    };
    let digest = proposal.digest()?;
    Ok(state
        .state()
        .owner_transitions
        .iter()
        .find(|t| {
            t.transition
                .successor
                .as_ref()
                .is_some_and(|s| s.candidate == digest && s.node == proposal.candidate.node)
        })
        .map(|t| t.transition.epoch))
}

impl Store {
    pub(in crate::store) fn owner_transfer(
        &mut self,
        credential: &str,
        action: OwnerTransferOp,
    ) -> Result<Value> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        match action {
            OwnerTransferOp::Prepare {
                request_id: id,
                node_id,
            } => {
                let id = request_id(&id)?;
                self.start_owner_preparation_mode(credential, id, &node_id, true)?;
                self.owner_transfer_status(credential, Some(id))
            }
            OwnerTransferOp::Status { request_id: id } => {
                self.owner_transfer_status(credential, id.as_deref().map(request_id).transpose()?)
            }
            OwnerTransferOp::Commit { request_id: id } => {
                let id = request_id(&id)?;
                let proposal =
                    candidate(&self.db, id)?.context("owner transfer candidate is not prepared")?;
                self.issue_owner_handoff(credential, &proposal, true)?;
                // Any failure after commitment is retained as pending progress.
                self.resume_owner_transfer(credential, id)
            }
            OwnerTransferOp::Resume { request_id: id } => {
                self.resume_owner_transfer(credential, request_id(&id)?)
            }
        }
    }

    fn resume_owner_transfer(&mut self, credential: &str, id: Uuid) -> Result<Value> {
        let plan = load_plan(&self.db, id)?.context("unknown owner transfer")?;
        ensure!(
            plan.auto_activate,
            "this legacy plan requires manual owner activation"
        );
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "UPDATE owner_transfers SET retry_at=0 WHERE id=?1 AND done=0",
            [id.to_string()],
        )?;
        tx.execute(
            "UPDATE owner_preparation_jobs SET retry_at=0 WHERE plan=?1 AND done=0",
            [id.to_string()],
        )?;
        tx.commit()?;
        // Wake the normal worker; it handles publication even after expiry.
        // Resume must never call the signing-stop operation.
        self.sync_wakeup.notify_one();
        self.owner_transfer_status(credential, Some(id))
    }

    fn owner_transfer_status(&self, credential: &str, id: Option<Uuid>) -> Result<Value> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let state = self.identity.state(&self.db)?;
        if let Some(id) = id {
            return self.transfer_detail(&state, id);
        }
        let writer = if self.identity.is_current_owner(&state) {
            Some(self.identity.node.id().to_owned())
        } else {
            self.network_session(&self.db, state.clone())
                .configuration_writer()
                .ok()
        };
        let ids = self
            .db
            .prepare("SELECT id FROM owner_preparation_plans ORDER BY rowid DESC LIMIT 64")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let transfers = ids
            .iter()
            .map(|id| self.transfer_detail(&state, request_id(id)?))
            .collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"owner_node":writer,"owner_epoch":state.owner_epoch(),"local_node":self.identity.node.id(),
            "signing_frozen":frozen(&self.db,&state)?,"transfers":transfers}),
        )
    }

    fn transfer_detail(&self, state: &VerifiedState, id: Uuid) -> Result<Value> {
        let plan = load_plan(&self.db, id)?.context("unknown owner transfer")?;
        let proposal = candidate(&self.db, id)?;
        let epoch = accepted(state, proposal.as_ref())?;
        let (ready, preparation_error): (bool, Option<String>) = self.db.query_row(
            "SELECT ready,error FROM owner_preparation_plans WHERE id=?1",
            [id.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let control: Option<(bool, Option<String>)> = self
            .db
            .query_row(
                "SELECT done,error FROM owner_transfers WHERE id=?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let source = plan.source == self.identity.node.id();
        let successor = plan.successor == self.identity.node.id();
        let issued: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM owner_handoffs WHERE id=?1)",
            [id.to_string()],
            |r| r.get(0),
        )?;
        let importing: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM owner_journals WHERE id=?1 AND source=0)",
            [id.to_string()],
            |r| r.get(0),
        )?;
        let delivery: Option<(usize, usize)> = self
            .db
            .query_row(
                "SELECT next,parts FROM owner_deliveries WHERE id=?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let pending: u64 = self.db.query_row(
            "SELECT COUNT(*) FROM owner_preparation_jobs WHERE plan=?1 AND done=0",
            [id.to_string()],
            |r| r.get(0),
        )?;
        let errors=self.db.prepare("SELECT id,error FROM owner_preparation_jobs WHERE plan=?1 AND error IS NOT NULL ORDER BY rowid LIMIT 8")?.query_map([id.to_string()],|r|Ok(json!({"job":r.get::<_,String>(0)?,"error":r.get::<_,String>(1)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let current = plan.current(state, now() as u64).and_then(|()| {
            if let Some(proposal) = &proposal {
                proposal.verify(state, now() as u64)?;
            }
            Ok(())
        });
        let committed = issued || importing || epoch.is_some();
        let phase = if epoch.is_some() {
            if successor && control.as_ref().is_some_and(|(done, _)| !done) {
                "finishing"
            } else {
                "complete"
            }
        } else if source && issued {
            match delivery {
                None => "committed",
                Some((next, parts)) if next < parts => "publishing",
                _ => "awaiting_successor",
            }
        } else if successor && importing {
            "receiving"
        } else if current.is_err() {
            "stale"
        } else if ready {
            "prepared"
        } else {
            "preparing"
        };
        let error = if phase == "complete" {
            None
        } else if committed {
            control.and_then(|(_, error)| error)
        } else {
            current.err().map(|e| e.to_string()).or(preparation_error)
        };
        Ok(
            json!({"id":id,"source":plan.source,"successor":plan.successor,
            "source_name":state.state().nodes.get(&plan.source).map(|n|&n.name),
            "successor_name":state.state().nodes.get(&plan.successor).map(|n|&n.name),
            "role":if source {"source"} else if successor {"successor"} else {"reader"},
            "state":phase,"committed":committed,"auto_activate":plan.auto_activate,
            "readiness_recorded":ready,"expires_at":plan.expires_at,"accepted_epoch":epoch,
            "published_parts":delivery.map(|d|d.0),"parts":delivery.map(|d|d.1),
            "pending_preparation_jobs":pending,"preparation_errors":errors,"error":error,
            "signing_frozen":frozen(&self.db,state)?}),
        )
    }

    /// Runs regardless of lease freshness. Only existing explicit source
    /// commitments or verified received authorizations can create work here.
    pub(crate) fn owner_transfer_tick(&mut self) -> Result<bool> {
        let tx = self.db.unchecked_transaction()?;
        let received=tx.prepare("SELECT p.id FROM owner_preparation_plans p JOIN owner_journals j ON j.id=p.id WHERE j.source=0 AND p.ready=1 AND json_extract(p.plan,'$.auto_activate')=1 AND json_extract(p.plan,'$.successor')=?1 AND NOT EXISTS(SELECT 1 FROM owner_transfers t WHERE t.id=p.id) LIMIT ?2")?.query_map(params![self.identity.node.id(),BATCH],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        for id in received {
            arm(&tx, request_id(&id)?, "successor")?;
        }
        tx.commit()?;
        let jobs=self.db.prepare("SELECT id,role,attempts FROM owner_transfers WHERE done=0 AND retry_at<=?1 ORDER BY retry_at,rowid LIMIT ?2")?.query_map(params![now(),BATCH],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,u32>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, role, attempts) in jobs {
            if let Err(error) = self.advance_owner_transfer(&id, &role) {
                let mut error = error.to_string();
                let mut end = error.len().min(1024);
                while !error.is_char_boundary(end) {
                    end -= 1;
                }
                error.truncate(end);
                self.db.execute("UPDATE owner_transfers SET attempts=MIN(attempts+1,32),retry_at=?1,error=?2 WHERE id=?3",params![now()+(1i64<<attempts.min(5)),error,id])?;
            }
        }
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM owner_transfers WHERE done=0)",
            [],
            |r| r.get(0),
        )?)
    }

    fn advance_owner_transfer(&mut self, id: &str, role: &str) -> Result<()> {
        let parsed = request_id(id)?;
        let plan = load_plan(&self.db, parsed)?.context("owner transfer plan is missing")?;
        ensure!(
            plan.auto_activate,
            "owner transfer lacks automatic activation consent"
        );
        let credential = Zeroizing::new(config::read_private(&self.home.join("owner.key"))?);
        let complete = match role {
            "source" => {
                ensure!(
                    plan.source == self.identity.node.id(),
                    "owner transfer source changed"
                );
                let issued = issued_for(&self.db, id)?;
                ensure!(
                    candidate(&self.db, parsed)?.as_ref() == Some(&issued.candidate),
                    "owner transfer candidate changed"
                );
                let state = self.identity.state(&self.db)?;
                if let Some(epoch) = accepted(&state, Some(&issued.candidate))? {
                    ensure!(
                        state.state().owner_transitions.get(epoch as usize - 1)
                            == Some(&issued.authorization),
                        "owner transfer authorization changed"
                    );
                    true
                } else {
                    self.queue_owner_handoff_delivery(&credential, id)?;
                    false
                }
            }
            "successor" => {
                ensure!(
                    plan.successor == self.identity.node.id(),
                    "owner transfer successor changed"
                );
                if self.owner_handoff_import_status(&credential, id)?["pages_complete"] != true {
                    return Ok(());
                }
                let wire: Vec<u8> = self.db.query_row(
                    "SELECT authorization FROM owner_journals WHERE id=?1 AND source=0",
                    [id],
                    |r| r.get(0),
                )?;
                let authorization = SignedOwnerTransition::decode(&wire)?;
                self.accept_owner_handoff(&credential, id, &authorization)?;
                self.activate_owner_handoff(&credential, id)?;
                true
            }
            _ => anyhow::bail!("invalid owner transfer role"),
        };
        self.db.execute(
            "UPDATE owner_transfers SET done=?1,error=NULL,retry_at=?2 WHERE id=?3",
            params![complete, now() + 1, id],
        )?;
        self.sync_wakeup.notify_one();
        Ok(())
    }
}
