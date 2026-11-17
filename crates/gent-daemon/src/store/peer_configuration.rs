//! Durable endpoint state for the ordered configuration log. Network I/O must
//! happen outside the Store lock; each method commits its local work first.
use super::*;
use gent_crypto::{
    configuration_log::{self as crypto, WriteCapability},
    peer::{NodeSigner, envelope},
};
use gent_protocol::configuration_log::{Bootstrap, Commit, Head, Header, Receipt};
use zeroize::Zeroizing;
mod enrollment;
pub(crate) use enrollment::install_checkpoint;
mod decisions;
mod maintenance;
mod migration;
mod proposals;
#[cfg(test)]
mod tests;

struct SavedProposal {
    salt: Zeroizing<Vec<u8>>,
    intent: Vec<u8>,
    candidate: Option<Vec<u8>>,
}

#[derive(Clone)]
pub(crate) struct Queued {
    pub origin: String,
    pub id: String,
    pub operation: String,
}

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS peer_configuration (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),bootstrap BLOB NOT NULL,
        head BLOB NOT NULL,capability BLOB CHECK(capability IS NULL OR length(capability)=32),
        migration BLOB,active INTEGER NOT NULL CHECK(active IN (0,1)));
        CREATE TABLE IF NOT EXISTS peer_configuration_requests (
        origin TEXT NOT NULL,id TEXT NOT NULL,salt BLOB NOT NULL CHECK(length(salt)=32),
        intent BLOB NOT NULL CHECK(length(intent)=32),candidate BLOB,
        PRIMARY KEY(origin,id),FOREIGN KEY(origin,id) REFERENCES configuration_edits(origin,id));
        CREATE TABLE IF NOT EXISTS peer_configuration_history (
        sequence INTEGER PRIMARY KEY,receipt BLOB NOT NULL,body BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS peer_configuration_decisions (
        origin TEXT NOT NULL,id TEXT NOT NULL,fingerprint TEXT NOT NULL,result BLOB NOT NULL,
        PRIMARY KEY(origin,id));
        CREATE TABLE IF NOT EXISTS peer_configuration_routes (
        origin TEXT NOT NULL,id TEXT NOT NULL,writer TEXT NOT NULL,event TEXT NOT NULL,PRIMARY KEY(origin,id,writer));",
    )?;
    Ok(())
}

pub(super) fn check_state(db: &Connection, state: &VerifiedState) -> Result<()> {
    if state.state().peer.is_none() {
        return Ok(());
    }
    let head: Vec<u8> = db
        .query_row(
            "SELECT head FROM peer_configuration WHERE singleton=1 AND active=1",
            [],
            |r| r.get(0),
        )
        .optional()?
        .context("peer configuration checkpoint is missing; restore this node's state")?;
    let head: Head = serde_json::from_slice(&head)?;
    let receipt: Vec<u8> = db.query_row(
        "SELECT receipt FROM peer_configuration_history WHERE sequence=?1",
        [head.sequence],
        |r| r.get(0),
    )?;
    ensure!(
        head.sequence == state.checkpoint().revision
            && serde_json::from_slice::<Receipt>(&receipt)?.head == head,
        "peer configuration checkpoint mismatch"
    );
    Ok(())
}

fn random_salt() -> [u8; 32] {
    Sha256::digest(config::secret().as_bytes()).into()
}

fn header(
    state: &VerifiedState,
    head: Head,
    node: &str,
    operation: &str,
    intent: [u8; 32],
    next: &WriteCapability,
) -> Header {
    Header {
        version: 1,
        cluster: state.anchor().cluster_id.clone(),
        origin: node.into(),
        operation: operation.into(),
        intent,
        previous: head,
        next_write_key: next.public_key(),
    }
}

impl Store {
    pub(crate) fn configuration_proposals(&self) -> Result<Vec<Queued>> {
        let state = self.identity.state(&self.db)?;
        let administrator = self.identity.can_administer(&state);
        let rows = self.db.prepare("SELECT e.origin,e.id,p.body FROM configuration_edits e JOIN configuration_pending p USING(origin,id) WHERE e.result IS NULL ORDER BY e.rowid")?
            .query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut result = Vec::new();
        for (origin, id, body) in rows {
            if !administrator
                && (origin != self.identity.node.id()
                    || administration::edit_identity(&serde_json::from_slice(&body)?).is_some())
            {
                continue;
            }
            let operation = if origin == self.identity.node.id() {
                id.clone()
            } else {
                gent_crypto::scoped_id(
                    b"gent/delegated-configuration/v1\0",
                    &[origin.as_bytes(), id.as_bytes()],
                )
                .to_string()
            };
            result.push(Queued {
                origin,
                id,
                operation,
            });
            if result.len() == 8 {
                break;
            }
        }
        Ok(result)
    }
    pub(crate) fn begin_configuration_discovery(&mut self) {
        if self.config.service.is_some() {
            self.configuration_discovery(false);
        }
    }
    pub(crate) fn configuration_discovery(&mut self, legacy_allowed: bool) {
        self.identity.legacy_service_checked = legacy_allowed;
    }
    pub fn pending_configuration_proposals(&self) -> Result<Vec<String>> {
        Ok(self.db.prepare("SELECT e.id FROM configuration_edits e JOIN configuration_pending p USING(origin,id) WHERE e.origin=?1 AND e.result IS NULL ORDER BY e.rowid LIMIT 8")?
            .query_map([self.identity.node.id()], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn configuration_proposal_intent(&self, id: &str) -> Result<Option<[u8; 32]>> {
        self.configuration_intent_for(self.identity.node.id(), id)
    }
    pub(crate) fn configuration_intent_for(
        &self,
        origin: &str,
        id: &str,
    ) -> Result<Option<[u8; 32]>> {
        let value: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT intent FROM peer_configuration_requests WHERE origin=?1 AND id=?2",
                params![origin, id],
                |r| r.get(0),
            )
            .optional()?;
        value
            .map(|value| value.as_slice().try_into().map_err(Into::into))
            .transpose()
    }

    /// Trusted local administration, not an MCP operation. The runtime must
    /// finish migration acceptance before exposing this through the CLI.
    pub fn prepare_configuration_log(&mut self, credential: &str) -> Result<Bootstrap> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        if let Some(bytes) = self
            .db
            .query_row(
                "SELECT bootstrap FROM peer_configuration WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            self.sync_wakeup.notify_one();
            return Ok(serde_json::from_slice(&bytes)?);
        }
        let state = self.identity.state(&self.db)?;
        let key = self.identity.migration_owner(&self.db)?;
        let admission = WriteCapability::generate()?;
        let next = WriteCapability::generate()?;
        let bootstrap = Bootstrap {
            cluster: state.anchor().cluster_id.clone(),
            head: Head {
                sequence: state.checkpoint().revision,
                digest: state.checkpoint().state_hash,
                write_key: admission.public_key(),
            },
        };
        let archive = migration::Archive::capture(&self.db, &state)?;
        let salt = random_salt();
        let proposal = header(
            &state,
            bootstrap.head.clone(),
            self.identity.node.id(),
            &uuid::Uuid::new_v4().to_string(),
            crypto::intent(&salt, &archive),
            &next,
        );
        let candidate = state.migrate_to_peers(
            &key,
            &self.identity.node,
            proposal.clone(),
            (now() as u64).max(state.state().issued_at),
        )?;
        let commit = admission.seal(
            proposal,
            &envelope::seal_migration(&candidate, &next, salt, &archive)?,
        )?;
        drop(key);
        self.identity.fence_peer_authority()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure!(
            self.identity.state(&tx)?.checkpoint() == state.checkpoint(),
            "migration checkpoint changed"
        );
        tx.execute(
            "INSERT INTO peer_configuration VALUES(1,?1,?2,NULL,?3,0)",
            params![
                serde_json::to_vec(&bootstrap)?,
                serde_json::to_vec(&bootstrap.head)?,
                serde_json::to_vec(&commit)?
            ],
        )?;
        tx.commit()?;
        self.sync_wakeup.notify_one();
        Ok(bootstrap)
    }

    pub fn configuration_log_head(&self) -> Result<Option<Head>> {
        let bytes: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT head FROM peer_configuration WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
            .transpose()
    }

    pub fn configuration_log_migration(&self) -> Result<Option<Commit>> {
        let bytes: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT migration FROM peer_configuration WHERE singleton=1 AND active=0",
                [],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        bytes
            .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
            .transpose()
    }

    /// Called with bytes fetched from the authenticated ordering service. A
    /// locally prepared proposal is never passed here before service commitment.
    pub fn accept_configuration_commit(&mut self, commit: &Commit) -> Result<Receipt> {
        let receipt = crypto::verify(commit)?;
        let previous = self
            .db
            .query_row(
                "SELECT receipt FROM peer_configuration_history WHERE sequence=?1",
                [receipt.head.sequence],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if let Some(previous) = previous {
            ensure!(
                serde_json::from_slice::<Receipt>(&previous)? == receipt,
                "configuration history fork"
            );
            return Ok(receipt);
        }
        let original = self.identity.state(&self.db)?;
        let decrypted = envelope::decrypt(&self.identity.node, commit)?;
        let archive = decrypted
            .migration
            .as_ref()
            .map(|m| -> Result<migration::Archive> {
                Ok(serde_json::from_slice(&STANDARD.decode(&m.archive)?)?)
            })
            .transpose()?;
        let state = if original.state().peer.is_none() {
            archive
                .as_ref()
                .context("migration archive is missing")?
                .verify_history(&original)?
        } else {
            ensure!(archive.is_none(), "migration archive after activation");
            original.clone()
        };
        let saved = self.configuration_log_head()?;
        ensure!(
            saved.is_some() || state.state().peer.is_none(),
            "peer configuration checkpoint is missing"
        );
        let head = saved.unwrap_or_else(|| commit.header.previous.clone());
        if state.state().peer.is_none() {
            ensure!(
                head.sequence == state.checkpoint().revision
                    && head.digest == state.checkpoint().state_hash,
                "migration bootstrap does not match pinned authority"
            );
        }
        let mut updated = state.clone();
        let updated_head = updated.advance_committed(decrypted.state, commit, &head)?;
        self.identity.fence_peer_authority()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure!(
            self.identity.state(&tx)?.checkpoint() == original.checkpoint(),
            "local configuration changed"
        );
        let mut history = archive
            .as_ref()
            .map(|a| {
                a.history
                    .iter()
                    .filter(|s| s.state.revision > original.checkpoint().revision)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        history.push(updated.signed().clone());
        encrypted::persist_authority(&tx, &self.identity.node, &updated, &history)?;
        if let Some(archive) = &archive {
            archive.adopt(&tx)?;
            tx.execute("INSERT INTO peer_configuration_decisions(origin,id,fingerprint,result) SELECT origin,id,fingerprint,result FROM configuration_edits WHERE result IS NOT NULL ON CONFLICT DO NOTHING", [])?;
        }
        // Every surviving administrator retains service cleanup intent. The
        // creating node is not needed to revoke a retired transport identity.
        let session = StoreSession {
            db: &tx,
            home: &self.home,
            config: self.config.clone(),
            identity: &self.identity,
            state: updated.clone(),
            timestamp: now(),
        };
        for (id, member) in &state.state().nodes {
            if !updated.state().nodes.contains_key(id) {
                let known: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM node_removals WHERE node=?1)",
                    [id],
                    |r| r.get(0),
                )?;
                if !known {
                    session.record_removal(id, &member.signing_key, None)?;
                }
            }
        }
        let capability = decrypted.capability.as_ref().map(WriteCapability::secret);
        let bootstrap = Bootstrap {
            cluster: state.anchor().cluster_id.clone(),
            head,
        };
        tx.execute("INSERT INTO peer_configuration VALUES(1,?1,?2,?3,NULL,1) ON CONFLICT(singleton) DO UPDATE SET head=excluded.head,capability=excluded.capability,migration=NULL,active=1", params![serde_json::to_vec(&bootstrap)?, serde_json::to_vec(&updated_head)?, capability.as_ref().map(|v| v.as_slice())])?;
        tx.execute(
            "INSERT INTO peer_configuration_history VALUES(?1,?2,?3)",
            params![
                receipt.head.sequence,
                serde_json::to_vec(&receipt)?,
                serde_json::to_vec(commit)?
            ],
        )?;
        decisions::accept(&tx, &updated)?;
        tx.commit()?;
        let _ = self.project_config();
        self.sync_wakeup.notify_one();
        Ok(receipt)
    }
}
