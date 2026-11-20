//! Logical web identities share the hosting daemon's directory and queues.
//! Hosting authenticates a chat carrier, never a configuration signer.
use super::*;
mod import;
mod portable;
#[cfg(test)]
mod portable_tests;
pub(crate) mod snapshot;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub(super) fn schema(db: &Connection) -> Result<()> {
    grant_now();
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS hosted_nodes (
        node TEXT PRIMARY KEY,home TEXT NOT NULL UNIQUE,gateway_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS hosted_checkpoints (
        node TEXT PRIMARY KEY,revision INTEGER NOT NULL,durable INTEGER NOT NULL,
        lease_until INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS hosted_work_grants (
        node TEXT PRIMARY KEY,epoch INTEGER NOT NULL,restored INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS hosted_event_gates (id TEXT PRIMARY KEY,node TEXT NOT NULL,revision INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS web_delivery_demand (
        node TEXT PRIMARY KEY,message TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS hosted_directory (
        agent TEXT NOT NULL,node TEXT NOT NULL,revision INTEGER NOT NULL,payload BLOB NOT NULL,
        PRIMARY KEY(agent,revision));
        CREATE TABLE IF NOT EXISTS hosted_message_gates (id TEXT PRIMARY KEY,node TEXT NOT NULL,revision INTEGER NOT NULL);",
    )?;
    Ok(())
}

// Grants use Unix deadlines across local IPC. Advance the observed wall time
// by monotonic elapsed time as well, so a wall-clock correction cannot revive
// an expiring grant. Startup seals all previously installed grants.
fn grant_now() -> i64 {
    use std::{
        sync::{Mutex, OnceLock},
        time::{Instant, SystemTime, UNIX_EPOCH},
    };
    static CLOCK: OnceLock<Mutex<(SystemTime, Instant)>> = OnceLock::new();
    let mut clock = CLOCK
        .get_or_init(|| Mutex::new((SystemTime::now(), Instant::now())))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let instant = Instant::now();
    let wall = SystemTime::now().max(clock.0 + instant.duration_since(clock.1));
    *clock = (wall, instant);
    wall.duration_since(UNIX_EPOCH)
        .map_or(i64::MAX, |d| d.as_secs() as i64)
}

impl Store {
    pub(super) fn restore_web_node(
        &mut self,
        node: &str,
        home: &Path,
        checkpoint: &Path,
        epoch: Option<u64>,
    ) -> Result<Value> {
        let home = std::fs::canonicalize(home)?;
        ensure!(home != self.home, "invalid web home");
        config::private_dir(&home)?;
        let child = config::load_for_runtime(&home)?;
        ensure!(
            child.node.id == node && child.cluster.id == self.config.cluster.id,
            "web restore identity mismatch"
        );
        let snapshot = snapshot::read(checkpoint)?;
        let gateway = hash(&config::read_private(&home.join("owner.key"))?);
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_epoch(&tx, node, epoch)?;
        if let Some(epoch) = epoch {
            ensure!(tx.execute(
                "UPDATE hosted_work_grants SET restored=1 WHERE node=?1 AND epoch=?2 AND restored=0",
                params![node, epoch],
            )? == 1, "web carrier already restored this epoch");
        }
        let state = self.identity.state(&tx)?;
        state.require_fresh(now() as u64)?;
        ensure!(
            self.identity.can_administer(&state),
            "web restore requires configuration authority"
        );
        ensure!(
            state
                .state()
                .nodes
                .get(node)
                .is_some_and(|n| n.hosted_by.is_some()),
            "web node unavailable"
        );
        snapshot::restore(&tx, &snapshot, state.anchor(), node)?;
        tx.execute(
            "INSERT INTO hosted_nodes VALUES(?1,?2,?3) ON CONFLICT(node)
            DO UPDATE SET home=excluded.home,gateway_hash=excluded.gateway_hash",
            params![node, home.to_str().context("invalid web home")?, gateway],
        )?;
        tx.execute(
            "INSERT INTO hosted_checkpoints VALUES(?1,?2,?2,0) ON CONFLICT(node)
            DO UPDATE SET revision=excluded.revision,durable=excluded.durable,
            lease_until=CASE WHEN ?3 IS NULL THEN 0 ELSE hosted_checkpoints.lease_until END",
            params![node, snapshot.revision, epoch],
        )?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT value FROM metadata WHERE key='hosted_routes'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(previous) = previous {
            let mut routes: BTreeMap<String, String> = serde_json::from_str(&previous)?;
            routes.remove(node);
            tx.execute(
                "UPDATE metadata SET value=?1 WHERE key='hosted_routes'",
                [serde_json::to_string(&routes)?],
            )?;
        }
        check_epoch(&tx, node, epoch)?;
        tx.commit()?;
        Ok(json!({"restored":true,"revision":snapshot.revision}))
    }

    pub(crate) fn reconcile_hosted_routes(&mut self) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        let routes: BTreeMap<_, _> = state
            .state()
            .nodes
            .iter()
            .filter_map(|(node, member)| {
                member
                    .hosted_by
                    .as_ref()
                    .map(|parent| (node.clone(), parent.clone()))
            })
            .collect();
        let fingerprint = serde_json::to_string(&routes)?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT value FROM metadata WHERE key='hosted_routes'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if previous.as_deref() == Some(&fingerprint) {
            return Ok(());
        }
        let previous: BTreeMap<String, String> = previous
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?
            .unwrap_or_default();
        let changed = |node: &str| routes.get(node) != previous.get(node);
        state.require_fresh(now() as u64)?;
        let session = StoreSession {
            db: &tx,
            home: &self.home,
            config: self.config.clone(),
            identity: &self.identity,
            state,
            timestamp: now(),
        };
        for agent in session.all_agents()? {
            if session.local_node(&agent.node_id) {
                session.announce(&agent.id)?;
                session.announce_activity(&agent.id)?;
            }
        }
        // Routing changes must retain the original request/message identities.
        // Re-enqueueing uses deterministic queue IDs and never repeats work.
        let ids = tx
            .prepare("SELECT id,request_id FROM messages ORDER BY rowid")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, request) in ids {
            let message = session.message(&id)?;
            if message.expires_at <= session.timestamp {
                continue;
            }
            let sender = session.get_agent(&message.sender)?;
            let recipient = session.get_agent(&message.recipient)?;
            if !session.state.state().nodes.contains_key(&sender.node_id)
                || !session.state.state().nodes.contains_key(&recipient.node_id)
            {
                continue;
            }
            if session.local_node(&sender.node_id)
                && !session.local_node(&recipient.node_id)
                && !message.acknowledged
            {
                if changed(&sender.node_id) || changed(&recipient.node_id) {
                    let id = gent_crypto::scoped_id(
                        b"gent/message-event/v1\0",
                        &[
                            session.state.transport_host(&recipient.node_id)?.as_bytes(),
                            message.id.as_bytes(),
                        ],
                    );
                    tx.execute("DELETE FROM network_sent WHERE id=?1", [id.to_string()])?;
                }
                session.queue_message(
                    session.state.transport_host(&recipient.node_id)?,
                    &request,
                    &message,
                )?;
            } else if session.local_node(&recipient.node_id)
                && !session.local_node(&sender.node_id)
                && message.acknowledged
            {
                if changed(&sender.node_id) || changed(&recipient.node_id) {
                    let id = gent_crypto::scoped_id(
                        b"gent/receipt-event/v1\0",
                        &[
                            session.state.transport_host(&sender.node_id)?.as_bytes(),
                            message.id.as_bytes(),
                            &[1],
                        ],
                    );
                    tx.execute("DELETE FROM network_sent WHERE id=?1", [id.to_string()])?;
                }
                session.receipt(
                    session.state.transport_host(&sender.node_id)?,
                    &id,
                    true,
                    message.expires_at,
                )?;
            }
        }
        tx.execute("INSERT INTO metadata VALUES('hosted_routes',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[fingerprint])?;
        tx.commit()?;
        self.sync_wakeup.notify_one();
        Ok(())
    }

    pub(super) fn prepare_hosted_node(&mut self, node: &str, home: &Path) -> Result<Value> {
        let home = std::fs::canonicalize(home)?;
        ensure!(home != self.home, "a node cannot host itself");
        config::private_dir(&home)?;
        let _lock = config::state_lock(&home, "daemon.lock")?;
        let mut child = config::load_for_runtime(&home)?;
        ensure!(
            child.node.id == node && child.cluster.id == self.config.cluster.id,
            "hosted node belongs to another identity or cluster"
        );
        if let Some(parent) = child.hosted_parent()? {
            ensure!(
                parent.node_id == self.identity.node.id()
                    && std::fs::canonicalize(parent.home)? == std::fs::canonicalize(&self.home)?,
                "web node belongs to another host"
            );
        }
        let gateway_hash = hash(&config::read_private(&home.join("owner.key"))?);
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        state.require_fresh(now() as u64)?;
        let member = state
            .state()
            .nodes
            .get(node)
            .context("web node is no longer enrolled")?;
        ensure!(
            member
                .hosted_by
                .as_deref()
                .is_none_or(|p| p == self.identity.node.id()),
            "web node belongs to another host"
        );
        ensure!(
            state.transport_host(self.identity.node.id())? == self.identity.node.id(),
            "hosted nodes cannot host other nodes"
        );
        let path = home.to_str().context("invalid hosted state path")?;
        let saved: Option<(String, String)> = tx
            .query_row(
                "SELECT home,gateway_hash FROM hosted_nodes WHERE node=?1",
                [node],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((saved_home, saved_key)) = saved {
            ensure!(
                saved_home == path && saved_key == gateway_hash,
                "hosted node migration identity changed"
            );
        } else {
            import::import(&tx, &home, &state, node, self.identity.node.id())?;
            tx.execute(
                "INSERT INTO hosted_nodes VALUES(?1,?2,?3)",
                params![node, path, gateway_hash],
            )?;
        }
        // This required local feature also fences older binaries: they reject
        // the unknown feature instead of starting a second independent writer.
        // Persist it before committing the journal, while the child lock is
        // held. A failed commit leaves a fenced source that retry can reimport;
        // a committed journal must never coexist with an unfenced child.
        child.set_hosted_parent(config::HostedParent {
            home: std::fs::canonicalize(&self.home)?,
            node_id: self.identity.node.id().into(),
        })?;
        config::save(&home, &child)?;
        tx.commit()?;
        Ok(json!({"prepared":true,"node_id":node,"hosted_by":self.identity.node.id()}))
    }
}

/// The marker survives restart and release. An unscoped legacy operation can
/// run only on a node that has never installed a fenced grant.
pub(super) fn check_epoch(db: &Connection, node: &str, epoch: Option<u64>) -> Result<()> {
    let current: Option<(u64, i64)> = db
        .query_row(
            "SELECT g.epoch,COALESCE(c.lease_until,0) FROM hosted_work_grants g
         LEFT JOIN hosted_checkpoints c USING(node) WHERE g.node=?1",
            [node],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    ensure!(
        current.map(|(id, _)| id) == epoch,
        "web carrier epoch changed"
    );
    if let Some((_, until)) = current {
        ensure!(until > grant_now(), "web carrier grant expired");
    }
    Ok(())
}

impl StoreSession<'_> {
    pub(super) fn local_node(&self, node: &str) -> bool {
        self.state
            .transport_host(node)
            .is_ok_and(|host| host == self.identity.node.id())
    }

    pub(super) fn check_hosted(&self, node: &str, gateway: &str) -> Result<()> {
        self.state.authorize_node(
            self.identity.node.id(),
            &self.identity.node.public_key(),
            self.timestamp as u64,
        )?;
        ensure!(
            node != self.identity.node.id() && self.local_node(node),
            "hosted node unavailable"
        );
        ensure!(
            gateway.len() == 64 && gateway.bytes().all(|b| b.is_ascii_hexdigit()),
            "hosted node unavailable"
        );
        let saved: Option<String> = self
            .db
            .query_row(
                "SELECT gateway_hash FROM hosted_nodes WHERE node=?1",
                [node],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            saved.as_deref() == Some(hash(gateway).as_str()),
            "hosted node unavailable"
        );
        Ok(())
    }

    pub(super) fn require_web_lease(&self, node: &str) -> Result<()> {
        if let Some(until) = self
            .db
            .query_row(
                "SELECT lease_until FROM hosted_checkpoints WHERE node=?1",
                [node],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
        {
            ensure!(
                until > self.timestamp,
                "web carrier lease expired; retry the same request"
            );
        }
        Ok(())
    }

    pub(super) fn hosted_status(&self, node: &str) -> Result<Value> {
        let member = self
            .state
            .state()
            .nodes
            .get(node)
            .context("hosted node unavailable")?;
        Ok(json!({"node":{"id":node,"name":member.name},
            "cluster":{"id":self.config.cluster.id,"name":self.state.state().name},
            "hosted_by":self.identity.node.id(),"remote_ready":self.remote_ready()?,
            "directory_chats":self.all_agents()?.len(),"config_saved":true,
            "authority":{"fresh":true,"revision":self.state.checkpoint().revision}}))
    }
}
