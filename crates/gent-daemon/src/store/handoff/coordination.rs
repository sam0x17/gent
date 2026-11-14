//! Resumable preparation over authenticated encrypted data links. Only the
//! source's local owner can start a plan. Network jobs never issue or activate it.
use super::*;
use crate::{
    encrypted::ordered::{
        OrderedEndpoint,
        configuration::{ConfigurationInvitation, standby::ConfigurationPreparation},
    },
    messages::{
        Event,
        owner_preparation::{Envelope, Plan, Step},
    },
};
use gent_crypto::{scoped_id, stream::Packet};

pub(super) mod storage;
pub(super) use storage::{schema, usage};
const BATCH: usize = 8;

impl Plan {
    pub(super) fn current(&self, state: &VerifiedState, timestamp: u64) -> Result<()> {
        ensure!(
            !self.id.is_nil() && self.source != self.successor,
            "invalid owner preparation plan"
        );
        ensure!(
            &self.anchor == state.anchor() && &self.base == state.checkpoint(),
            "owner preparation checkpoint changed"
        );
        state.require_fresh(timestamp)?;
        ensure!(
            timestamp < self.expires_at && self.expires_at <= timestamp.saturating_add(900),
            "owner preparation window expired or invalid"
        );
        ensure!(
            state.state().nodes.contains_key(&self.source)
                && state.state().nodes.contains_key(&self.successor),
            "owner preparation endpoint is no longer enrolled"
        );
        Ok(())
    }
    fn request(&self, domain: &[u8], reader: &str) -> Uuid {
        scoped_id(domain, &[self.id.as_bytes(), reader.as_bytes()])
    }
}

impl Envelope {
    fn validate(&self, sender: &str, local: &str) -> Result<()> {
        ensure!(
            self.version == 1 && self.origin == sender && self.target == local,
            "owner preparation route mismatch"
        );
        let source = &self.plan.source;
        let successor = &self.plan.successor;
        let valid = match &self.step {
            Step::Begin => {
                &self.origin == source && &self.target == successor && self.candidate.is_none()
            }
            Step::Candidate | Step::Ready { .. } | Step::Prepared { .. } => {
                &self.origin == successor && &self.target == source
            }
            Step::Offer => &self.origin == source && &self.target != successor,
            Step::Package { .. } | Step::Confirmed { .. } => {
                &self.origin != successor && &self.target == successor
            }
            Step::Grant { .. } => &self.origin == source && &self.target == successor,
            Step::Invitation { .. } => &self.origin == successor && &self.target != successor,
        };
        ensure!(valid, "owner preparation role mismatch");
        ensure!(
            matches!(self.step, Step::Begin) == self.candidate.is_none(),
            "owner preparation candidate missing or unexpected"
        );
        match &self.step {
            Step::Package { package } => ensure!(
                package.len() <= 24 * 1024,
                "owner preparation key package too large"
            ),
            Step::Prepared { packet, .. } | Step::Invitation { packet, .. } => ensure!(
                packet.len() <= 512 * 1024,
                "owner preparation Welcome too large"
            ),
            Step::Ready { report } => {
                report.encode()?;
            }
            _ => (),
        }
        Ok(())
    }
    fn verify_candidate(&self, state: &VerifiedState, timestamp: u64) -> Result<()> {
        if let Some(candidate) = &self.candidate {
            candidate.verify(state, timestamp)?;
            ensure!(
                candidate.candidate.id == self.plan.id.to_string()
                    && candidate.candidate.node.id == self.plan.successor,
                "owner preparation candidate belongs to another plan"
            );
        }
        Ok(())
    }
    fn response(&self, origin: &str, target: &str, step: Step) -> Self {
        Self {
            version: 1,
            plan: self.plan.clone(),
            origin: origin.into(),
            target: target.into(),
            candidate: self.candidate.clone(),
            step,
        }
    }
}

impl StoreSession<'_> {
    fn preparation_plan(&self, plan: &Plan) -> Result<()> {
        plan.current(&self.state, self.timestamp as u64)?;
        if self.identity.node.id() == plan.source {
            ensure!(
                self.identity.is_current_owner(&self.state),
                "owner preparation source is not the current writer"
            );
        } else {
            ensure!(
                self.configuration_writer()? == plan.source,
                "owner preparation requires the current owner route"
            );
        }
        Ok(())
    }

    pub(in crate::store) fn import_owner_preparation(
        &self,
        sender: &str,
        envelope: &Envelope,
    ) -> Result<()> {
        envelope.validate(sender, self.identity.node.id())?;
        if storage::duplicate(self.db, envelope)? {
            return Ok(());
        }
        // Configuration changes can overtake queued preparation. Obsolete work
        // must drain without blocking the ordinary shared data stream.
        if envelope.plan.anchor != *self.state.anchor()
            || envelope.plan.base != *self.state.checkpoint()
            || self.timestamp as u64 >= envelope.plan.expires_at
        {
            return Ok(());
        }
        self.preparation_plan(&envelope.plan)?;
        envelope.verify_candidate(&self.state, self.timestamp as u64)?;
        if let Some(plan) = storage::load_plan(self.db, envelope.plan.id)? {
            ensure!(plan == envelope.plan, "owner preparation request changed");
        } else {
            ensure!(
                self.identity.node.id() != envelope.plan.source
                    && matches!(envelope.step, Step::Begin | Step::Offer),
                "unsolicited owner preparation step"
            );
            storage::save_plan(self.db, &envelope.plan)?;
        }
        if let Some(candidate) = &envelope.candidate {
            if storage::candidate(self.db, envelope.plan.id)?.is_none() {
                ensure!(
                    matches!(envelope.step, Step::Candidate | Step::Offer),
                    "owner preparation candidate was not approved"
                );
            }
            storage::pin(self.db, &envelope.plan, candidate)?;
        }
        storage::admit(self.db, envelope)
    }

    fn queue_preparation(&self, envelope: Envelope) -> Result<()> {
        ensure!(
            envelope.origin == self.identity.node.id(),
            "owner preparation cannot impersonate another node"
        );
        if envelope.target == self.identity.node.id() {
            self.import_owner_preparation(self.identity.node.id(), &envelope)
        } else {
            let id = envelope.id();
            let target = envelope.target.clone();
            self.queue(
                &target,
                id,
                Event::OwnerPreparation {
                    envelope: Box::new(envelope),
                },
                None,
            )
        }
    }
}

impl Store {
    /// Prepare streams and collect readiness only. This never stops signing;
    /// issuing a handoff remains a separate explicitly authorized local action.
    pub fn start_owner_preparation(
        &mut self,
        credential: &str,
        id: Uuid,
        successor: &str,
    ) -> Result<Value> {
        self.start_owner_preparation_mode(credential, id, successor, false)
    }

    pub(super) fn start_owner_preparation_mode(
        &mut self,
        credential: &str,
        id: Uuid,
        successor: &str,
        auto_activate: bool,
    ) -> Result<Value> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        if let Some(plan) = storage::load_plan(&self.db, id)? {
            ensure!(
                plan.source == self.identity.node.id()
                    && plan.successor == successor
                    && plan.auto_activate == auto_activate,
                "owner preparation request changed"
            );
            return self.owner_preparation_status(credential, id);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.identity.signing_owner(&tx)?;
        let state = self.identity.state(&tx)?;
        let timestamp = requests::clock(&tx, now())? as u64;
        let plan = Plan {
            id,
            anchor: state.anchor().clone(),
            base: state.checkpoint().clone(),
            source: self.identity.node.id().into(),
            successor: successor.into(),
            expires_at: timestamp + 900,
            auto_activate,
        };
        plan.current(&state, timestamp)?;
        storage::save_plan(&tx, &plan)?;
        // No self-referential borrow of Store while its connection is mutable.
        let session = StoreSession {
            db: &tx,
            home: &self.home,
            config: self.config.clone(),
            identity: &self.identity,
            state,
            timestamp: timestamp as i64,
        };
        session.queue_preparation(Envelope {
            version: 1,
            origin: plan.source.clone(),
            target: plan.successor.clone(),
            plan,
            candidate: None,
            step: Step::Begin,
        })?;
        tx.commit()?;
        self.sync_wakeup.notify_one();
        self.owner_preparation_status(credential, id)
    }

    pub fn owner_preparation_status(&self, credential: &str, id: Uuid) -> Result<Value> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let plan = storage::load_plan(&self.db, id)?.context("unknown owner preparation")?;
        let state = self.identity.state(&self.db)?;
        let candidate = storage::candidate(&self.db, id)?;
        let current = plan.current(&state, now() as u64).and_then(|()| {
            if let Some(candidate) = &candidate {
                candidate.verify(&state, now() as u64)?;
            }
            Ok(())
        });
        let (ready, error): (bool, Option<String>) = self.db.query_row(
            "SELECT ready,error FROM owner_preparation_plans WHERE id=?1",
            [id.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let jobs=self.db.prepare("SELECT id,done,error FROM owner_preparation_jobs WHERE plan=?1 ORDER BY rowid")?.query_map([id.to_string()],|r|Ok(json!({"id":r.get::<_,String>(0)?,"done":r.get::<_,bool>(1)?,"error":r.get::<_,Option<String>>(2)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(
            json!({"id":id,"source":plan.source,"successor":plan.successor,"expires_at":plan.expires_at,
            "candidate_prepared":candidate.is_some(),"readiness_recorded":ready,"current":current.is_ok(),
            "error":current.err().map(|e|e.to_string()).or(error),"jobs":jobs,"signing_frozen":frozen(&self.db,&state)?}),
        )
    }

    pub(crate) fn owner_preparation_tick(&mut self) -> Result<bool> {
        if self.config.relay.is_none()
            || self
                .identity
                .state(&self.db)?
                .require_fresh(now() as u64)
                .is_err()
        {
            return Ok(false);
        }
        let jobs=self.db.prepare("SELECT id,body,fingerprint,attempts FROM owner_preparation_jobs WHERE done=0 AND retry_at<=?1 ORDER BY retry_at,rowid LIMIT ?2")?.query_map(params![now(),BATCH],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,u32>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, body, digest, attempts) in jobs {
            let result = storage::decode(&id, &body, &digest)
                .and_then(|envelope| self.process_owner_preparation(&id, envelope));
            if let Err(error) = result {
                self.db.execute("UPDATE owner_preparation_jobs SET attempts=MIN(attempts+1,32),retry_at=?1,error=?2 WHERE id=?3",params![now()+(1i64<<attempts.min(5)),storage::error_text(error.to_string()),id])?;
            }
        }
        let plans=self.db.prepare("SELECT id FROM owner_preparation_plans WHERE candidate IS NOT NULL AND ready=0 ORDER BY rowid")?.query_map([],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        for id in plans {
            let id = Uuid::parse_str(&id)?;
            let plan =
                storage::load_plan(&self.db, id)?.context("owner preparation plan missing")?;
            if plan.successor != self.identity.node.id() {
                continue;
            }
            if let Err(error) = self.publish_owner_readiness(&plan) {
                self.db.execute(
                    "UPDATE owner_preparation_plans SET error=?1 WHERE id=?2",
                    params![storage::error_text(error.to_string()), id.to_string()],
                )?;
            }
        }
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM owner_preparation_jobs WHERE done=0)",
            [],
            |r| r.get(0),
        )?)
    }

    fn process_owner_preparation(&mut self, id: &str, mut envelope: Envelope) -> Result<()> {
        let state = self.identity.state(&self.db)?;
        let session = self.network_session(&self.db, state.clone());
        envelope.validate(&envelope.origin, self.identity.node.id())?;
        session.preparation_plan(&envelope.plan)?;
        envelope.verify_candidate(&state, now() as u64)?;
        ensure!(
            storage::load_plan(&self.db, envelope.plan.id)?.as_ref() == Some(&envelope.plan),
            "owner preparation plan changed"
        );
        if let Some(candidate) = &envelope.candidate {
            ensure!(
                storage::candidate(&self.db, envelope.plan.id)?.as_ref() == Some(candidate),
                "owner preparation candidate changed"
            );
        }
        let credential = Zeroizing::new(config::read_private(&self.home.join("owner.key"))?);
        let local = self.identity.node.id().to_owned();
        let plan = envelope.plan.clone();
        let mut outputs = Vec::new();
        match &envelope.step {
            Step::Begin => {
                let candidate = self.prepare_owner_handoff(&credential, &plan.id.to_string())?;
                envelope.candidate = Some(candidate);
                envelope.verify_candidate(&state, now() as u64)?;
                outputs.push(envelope.response(&local, &plan.source, Step::Candidate));
            }
            Step::Candidate => {
                for reader in state
                    .state()
                    .nodes
                    .keys()
                    .filter(|id| *id != &plan.successor)
                {
                    outputs.push(envelope.response(&local, reader, Step::Offer));
                }
            }
            Step::Offer => {
                let request = plan.request(b"gent/owner-preparation-package/v1\0", &local);
                let package = OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?
                    .key_package(request, now() as u64)?;
                outputs.push(envelope.response(
                    &local,
                    &plan.successor,
                    Step::Package {
                        package: STANDARD.encode(package),
                    },
                ));
            }
            Step::Package { package } => {
                let request = plan.request(b"gent/owner-preparation-stream/v1\0", &envelope.origin);
                let preparation = self.prepare_owner_configuration(
                    &credential,
                    &plan.id.to_string(),
                    request,
                    (&envelope.origin, &STANDARD.decode(package)?),
                )?;
                outputs.push(envelope.response(
                    &local,
                    &plan.source,
                    Step::Prepared {
                        reader: envelope.origin.clone(),
                        packet: STANDARD.encode(preparation.packet.encode()?),
                    },
                ));
            }
            Step::Prepared { reader, packet } => {
                let preparation = ConfigurationPreparation {
                    candidate: envelope.candidate.clone().context("missing candidate")?,
                    reader: reader.clone(),
                    reader_key: state
                        .state()
                        .nodes
                        .get(reader)
                        .context("reader is not enrolled")?
                        .signing_key,
                    packet: Packet::decode(&STANDARD.decode(packet)?)?,
                };
                let grant = self.authorize_owner_configuration(&credential, &preparation)?;
                outputs.push(envelope.response(
                    &local,
                    &plan.successor,
                    Step::Grant {
                        reader: reader.clone(),
                        grant: Box::new(grant),
                    },
                ));
            }
            Step::Grant { reader, grant } => {
                ensure!(
                    grant.grant.reader == *reader,
                    "owner preparation reader changed"
                );
                grant.verify_owner_candidate(
                    envelope.candidate.as_ref().context("missing candidate")?,
                )?;
                let request = plan.request(b"gent/owner-preparation-stream/v1\0", reader);
                let invitation = self.install_owner_configuration(&credential, request, grant)?;
                outputs.push(envelope.response(
                    &local,
                    reader,
                    Step::Invitation {
                        packet: STANDARD.encode(invitation.packet.encode()?),
                        grant: grant.clone(),
                    },
                ));
            }
            Step::Invitation { packet, grant } => {
                ensure!(
                    grant.grant.reader == local,
                    "owner preparation reader changed"
                );
                grant.verify_owner_candidate(
                    envelope.candidate.as_ref().context("missing candidate")?,
                )?;
                let invitation = ConfigurationInvitation {
                    packet: Packet::decode(&STANDARD.decode(packet)?)?,
                    grant: *grant.clone(),
                };
                let receipt = self.receive_owner_configuration(&credential, &invitation)?;
                outputs.push(envelope.response(
                    &local,
                    &plan.successor,
                    Step::Confirmed { receipt },
                ));
            }
            Step::Confirmed { receipt } => {
                let wire: Vec<u8> = self.db.query_row(
                    "SELECT grant FROM configuration_streams WHERE group_id=?1",
                    [receipt.group()],
                    |r| r.get(0),
                )?;
                let grant = gent_crypto::SignedConfigurationGrant::decode(&wire)?;
                grant.verify_owner_candidate(
                    envelope.candidate.as_ref().context("missing candidate")?,
                )?;
                ensure!(
                    grant.grant.reader == envelope.origin,
                    "owner preparation receipt belongs to another reader"
                );
                self.confirm_owner_configuration(&credential, receipt)?;
            }
            Step::Ready { report } => {
                self.record_owner_readiness(
                    &credential,
                    envelope.candidate.as_ref().context("missing candidate")?,
                    report,
                )?;
            }
        }
        let tx = self.db.unchecked_transaction()?;
        let session = self.network_session(&tx, self.identity.state(&tx)?);
        session.preparation_plan(&plan)?;
        envelope.verify_candidate(&session.state, now() as u64)?;
        if let Some(candidate) = &envelope.candidate {
            storage::pin(&tx, &plan, candidate)?;
        }
        for output in outputs {
            session.queue_preparation(output)?;
        }
        if matches!(envelope.step, Step::Ready { .. }) {
            tx.execute(
                "UPDATE owner_preparation_plans SET ready=1,error=NULL WHERE id=?1",
                [plan.id.to_string()],
            )?;
        }
        storage::finish(&tx, id)?;
        tx.commit()?;
        self.sync_wakeup.notify_one();
        Ok(())
    }

    fn publish_owner_readiness(&mut self, plan: &Plan) -> Result<()> {
        let state = self.identity.state(&self.db)?;
        self.network_session(&self.db, state)
            .preparation_plan(plan)?;
        let credential = Zeroizing::new(config::read_private(&self.home.join("owner.key"))?);
        let report = self.owner_handoff_readiness(&credential, &plan.id.to_string())?;
        let tx = self.db.unchecked_transaction()?;
        let session = self.network_session(&tx, self.identity.state(&tx)?);
        session.preparation_plan(plan)?;
        session.queue_preparation(Envelope {
            version: 1,
            plan: plan.clone(),
            origin: plan.successor.clone(),
            target: plan.source.clone(),
            candidate: storage::candidate(&tx, plan.id)?,
            step: Step::Ready { report },
        })?;
        tx.execute(
            "UPDATE owner_preparation_plans SET ready=1,error=NULL WHERE id=?1",
            [plan.id.to_string()],
        )?;
        tx.commit()?;
        self.sync_wakeup.notify_one();
        Ok(())
    }
}
