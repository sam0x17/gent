use crate::{
    config::{self, Config},
    encrypted,
    runtime::{self, Identity},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use gent_crypto::VerifiedState;
use gent_protocol::*;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;
mod activity;
mod administration;
mod agents;
mod babysitter;
mod configuration;
mod message_dates;
mod notifications;
mod wire;
pub(crate) use configuration::pending::schema as pending_configuration_schema;
pub(crate) use configuration::routing::schema as configuration_routing_schema;
mod dashboards;
mod diagnostics;
pub mod direct;
pub(crate) mod directory;
mod directory_sync;
mod files;
pub(crate) mod handoff;
mod history;
pub(crate) mod hosted;
pub mod invitations;
mod mesh;
mod network;
pub mod node_invites;
mod pairing;
pub(crate) mod peer_configuration;
mod permissions;
mod presence;
mod recovered;
mod relay;
pub(crate) mod removals;
mod requests;
#[cfg(test)]
mod storage_tests;
mod synchronization;
mod wake;
mod work;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
        .try_into()
        .expect("clock overflow")
}
fn hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
fn require_pro(home: &Path, cfg: &Config, feature: &str) -> Result<()> {
    ensure!(
        crate::entitlements::paid(home, cfg),
        "{feature} requires an active Gent Pro plan for this cluster. See https://gent.link/pricing"
    );
    Ok(())
}
const UNAVAILABLE: &str = "recipient or message unavailable";

pub struct Store {
    db: Connection,
    direct_certs: direct::CertificateCache,
    home: PathBuf,
    config: Config,
    identity: Identity,
    owner_hash: String,
    pub(crate) sync_wakeup: Arc<Notify>,
    pub(crate) sync_health: Arc<crate::sync::health::Health>,
}
impl Store {
    pub(crate) fn local_node_id(&self) -> &str {
        self.identity.node.id()
    }
    /// Called by offline owner provisioning while holding daemon.lock. Service
    /// registration cannot turn a joined node into a cryptographic owner.
    pub fn require_provisioning_owner(&self) -> Result<()> {
        self.identity.signing_owner(&self.db)?;
        self.require_provisioning_member()
    }

    pub fn require_provisioning_member(&self) -> Result<()> {
        let state = self.identity.state(&self.db)?;
        ensure!(
            state
                .state()
                .nodes
                .get(self.identity.node.id())
                .is_some_and(|n| n.signing_key == self.identity.node.public_key()),
            "this node is no longer enrolled in the cluster"
        );
        // Expired authority can still obtain ciphertext transport to recover its
        // latest signed configuration. RPC access continues to require freshness.
        Ok(())
    }
    pub fn require_provisioning_joined(&self) -> Result<()> {
        ensure!(
            !self
                .identity
                .is_current_owner(&self.identity.state(&self.db)?),
            "the existing owner cannot be replaced by a joined identity"
        );
        self.require_provisioning_member()
    }

    /// Service setup records describe enrollment history. A signed handoff can
    /// change the configuration writer without changing account ownership or
    /// removing either node's relay access.
    pub fn require_service_setup_role(&self, originally_owner: bool) -> Result<()> {
        let state = self.identity.state(&self.db)?;
        if state.owner_epoch() > 0 || state.state().peer.is_some() {
            self.require_provisioning_member()
        } else if originally_owner {
            self.require_provisioning_owner()
        } else {
            self.require_provisioning_joined()
        }
    }

    pub fn open(home: &Path) -> Result<Self> {
        let config = config::load_for_runtime(home)?;
        ensure!(
            config.hosted_parent()?.is_none(),
            "this web node is served by its native host daemon"
        );
        let replacement = crate::pairing::replacement::check_intent(home, &config, None)?;
        let owner_hash = hash(&config::read_private(&home.join("owner.key"))?);
        ensure!(
            home.join("state.sqlite3").exists() || !home.join(runtime::KEY_FILE).exists(),
            "authority database is missing; restore this node's state"
        );
        let mut db = encrypted::open_database(home, "state.sqlite3")?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, credential_hash TEXT UNIQUE NOT NULL, node_id TEXT NOT NULL, name TEXT NOT NULL, provider TEXT NOT NULL, last_seen INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS exchanges (id TEXT PRIMARY KEY, a TEXT NOT NULL REFERENCES agents(id), b TEXT NOT NULL REFERENCES agents(id), expires_at INTEGER NOT NULL, count INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, sender TEXT NOT NULL REFERENCES agents(id), recipient TEXT NOT NULL REFERENCES agents(id), request_id TEXT NOT NULL, fingerprint TEXT NOT NULL, payload TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0, UNIQUE(sender,request_id));
          CREATE INDEX IF NOT EXISTS messages_inbox ON messages(recipient,acknowledged);
          CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS stream_relay_upload (
            group_id BLOB PRIMARY KEY REFERENCES streams(group_id) ON DELETE CASCADE,
            next_sequence INTEGER NOT NULL CHECK(next_sequence >= 0)
          );")?;
        network::schema(&db)?;
        configuration::schema(&db)?;
        peer_configuration::schema(&db)?;
        mesh::schema(&db)?;
        relay::schema(&db)?;
        files::schema(&mut db)?;
        requests::schema(&db, now())?;
        history::schema(&db)?;
        recovered::schema(&db)?;
        work::schema(&db)?;
        wake::schema(&db)?;
        presence::schema(&db)?;
        directory::schema(&db)?;
        activity::schema(&db)?;
        wire::schema(&db)?;
        dashboards::schema(&db)?;
        babysitter::schema(&db)?;
        notifications::schema(&db)?;
        hosted::schema(&db)?;
        directory_sync::schema(&db)?;
        direct::schema(&db)?;
        db.execute("UPDATE hosted_checkpoints SET lease_until=0", [])?;
        let previous: Option<String> = db
            .query_row("SELECT value FROM metadata WHERE key='cluster'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(previous) = previous {
            ensure!(
                previous == config.cluster.id,
                "database belongs to another cluster"
            );
        } else {
            db.execute(
                "INSERT INTO metadata VALUES ('cluster',?1)",
                [&config.cluster.id],
            )?;
        }
        let previous_node: Option<String> = db
            .query_row("SELECT value FROM metadata WHERE key='node'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(previous_node) = previous_node {
            ensure!(
                previous_node == config.node.id,
                "database belongs to another node"
            );
        } else {
            db.execute("INSERT INTO metadata VALUES ('node',?1)", [&config.node.id])?;
        }
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let identity = Identity::load_or_create(home, &config, &tx, now() as u64)?;
        peer_configuration::check_state(&tx, &identity.state(&tx)?)?;
        directory::backfill_names(&tx, &identity.state(&tx)?)?;
        message_dates::migrate(&tx, identity.node.id())?;
        configuration::pending::recover(&tx, identity.node.id())?;
        if let Some(record) = replacement {
            record.verify_node(&identity.node)?;
            let target = record.replaces;
            let state = identity.state(&tx)?;
            ensure!(
                !state.state().nodes.contains_key(&target.id)
                    && state.state().retired_nodes.contains(&target.id)
                    && state.state().retired_keys.contains(&target.signing_key),
                "replacement record does not match signed retirement"
            );
        }
        if !identity.is_current_owner(&identity.state(&tx)?) {
            // Only the SSH owner can issue enrollment snapshots. Conservative
            // migration pins on a joined runtime cannot represent pending joins.
            tx.execute("DELETE FROM authority_join_pins", [])?;
        }
        tx.commit()?;
        let mut store = Self {
            direct_certs: Default::default(),
            db,
            home: home.into(),
            config,
            owner_hash,
            identity,
            sync_wakeup: Arc::new(Notify::new()),
            sync_health: Arc::default(),
        };
        // Projection failure must never replace committed authority with TOML.
        let _ = store.project_config();
        Ok(store)
    }

    pub fn handle(&mut self, request: Request) -> Response {
        match self.execute(request) {
            Ok(value) => Response::Ok(value),
            Err(error) => Response::Error(error.to_string()),
        }
    }

    fn execute(&mut self, request: Request) -> Result<Value> {
        if let Request::Agent {
            credential,
            action: AgentOp::FileExport { file_id },
        } = &request
        {
            // Persist capacity before creating plaintext, then persist the
            // completed inode before publication. Each step rechecks authority.
            for step in [
                files::ExportStep::Reserve,
                files::ExportStep::Write,
                files::ExportStep::Publish,
            ] {
                let value = self.execute_step(
                    Request::Agent {
                        credential: credential.clone(),
                        action: AgentOp::FileExport {
                            file_id: file_id.clone(),
                        },
                    },
                    step,
                )?;
                if !value.is_null() {
                    return Ok(value);
                }
            }
            anyhow::bail!("export did not finish");
        }
        self.execute_step(request, files::ExportStep::Reserve)
    }

    fn execute_step(&mut self, request: Request, export_step: files::ExportStep) -> Result<Value> {
        if let Request::Owner { credential, .. } = &request {
            ensure!(hash(credential) == self.owner_hash, "unauthorized");
        }
        if let Request::Owner {
            action:
                OwnerOp::RestoreWebNode {
                    node_id,
                    home,
                    checkpoint,
                    epoch,
                },
            ..
        } = &request
        {
            return self.restore_web_node(node_id, home, checkpoint, *epoch);
        }
        if let Request::Owner {
            action: OwnerOp::PrepareHostedNode { node_id, home },
            ..
        } = &request
        {
            return self.prepare_hosted_node(node_id, home);
        }
        if let Request::Owner {
            credential,
            action: OwnerOp::PreparePeerConfiguration,
        } = &request
        {
            return Ok(serde_json::to_value(
                self.prepare_configuration_log(credential)?,
            )?);
        }
        if matches!(
            &request,
            Request::Owner {
                action: OwnerOp::Diagnose,
                ..
            }
        ) {
            return self.diagnose();
        }
        if let Request::Owner {
            action: OwnerOp::Pair { cluster_id, action },
            ..
        } = request
        {
            return self.pair(&cluster_id, action);
        }
        if let Request::Owner {
            credential,
            action: OwnerOp::Invitation { action },
        } = request
        {
            return self.manage_invitation(&credential, action);
        }
        if let Request::Owner {
            credential,
            action: OwnerOp::OwnerTransfer { action },
        } = request
        {
            return self.owner_transfer(&credential, action);
        }
        // Idle service probes and removal polling must not force a disk flush
        // or wake the encrypted transport on every observation. Pending config
        // projection retains its usual repair path.
        let projection_pending = runtime::projection_pending(&self.db)?;
        let local_only = matches!(
            &request,
            Request::Agent {
                action: AgentOp::BabysitterClaim { .. }
                    | AgentOp::BabysitterCheck { .. }
                    | AgentOp::BabysitterSubmitted { .. },
                ..
            } | Request::Owner {
                action: OwnerOp::NotificationPut { .. }
                    | OwnerOp::NotificationSent { .. }
                    | OwnerOp::BabysitterVerifiedBlockedClaim { .. },
                ..
            }
        );
        let read_only = (matches!(
            &request,
            Request::Owner {
                action: OwnerOp::Status
                    | OwnerOp::Agents
                    | OwnerOp::Nodes
                    | OwnerOp::Dashboards { .. }
                    | OwnerOp::NotificationPending { .. }
                    | OwnerOp::WebCheckpoint { .. }
                    | OwnerOp::WebDeliveryDemand { .. }
                    | OwnerOp::NodeRemovals { .. }
                    | OwnerOp::WakePendingAgents { .. }
                    | OwnerOp::WakeDirectTurnEvidence { .. },
                ..
            }
        ) || matches!(&request, Request::HostedStatus { .. }))
            && !projection_pending;
        let tx = self.db.transaction_with_behavior(if read_only {
            TransactionBehavior::Deferred
        } else {
            TransactionBehavior::Immediate
        })?;
        let timestamp = if read_only {
            requests::diagnostic_clock(&tx, now())?
        } else {
            requests::clock(&tx, now())?
        };
        let state = self.identity.state(&tx)?;
        let mut config = self.config.clone();
        config.policy = state.state().policy.clone();
        config.cluster.name.clone_from(&state.state().name);
        if let Some(node) = state.state().nodes.get(self.identity.node.id()) {
            config.node.name.clone_from(&node.name);
        }
        config.applied_revision = Some(state.checkpoint().revision);
        let mut session = StoreSession {
            db: &tx,
            home: &self.home,
            config,
            identity: &self.identity,
            state,
            timestamp,
        };
        let owner_request = matches!(&request, Request::Owner { .. });
        let refresh_nodes = matches!(
            &request,
            Request::Owner {
                action: OwnerOp::RefreshNodes,
                ..
            }
        );
        let status_request = matches!(
            &request,
            Request::Owner {
                action: OwnerOp::Status,
                ..
            }
        );
        let mut value = match request {
            Request::Owner { action, .. } => session.owner(action, &self.sync_health)?,
            Request::Agent { credential, action } => {
                session.state.authorize_node(
                    self.identity.node.id(),
                    &self.identity.node.public_key(),
                    timestamp as u64,
                )?;
                session.agent(self.identity.node.id(), &credential, action, export_step)?
            }
            Request::HostedAgent {
                node_id,
                gateway_credential,
                credential,
                action,
                epoch,
            } => {
                session.check_hosted(&node_id, &gateway_credential)?;
                hosted::check_epoch(&tx, &node_id, epoch)?;
                session.require_web_lease(&node_id)?;
                session.dirty_web(&node_id, &action)?;
                ensure!(
                    !matches!(
                        action,
                        AgentOp::FilePaths
                            | AgentOp::FileImport { .. }
                            | AgentOp::FileExport { .. }
                    ),
                    "local filesystem tools are unavailable to hosted chats"
                );
                let value = session.agent(&node_id, &credential, action, export_step)?;
                if epoch.is_some() {
                    hosted::check_epoch(&tx, &node_id, epoch)?;
                }
                value
            }
            Request::HostedStatus {
                node_id,
                gateway_credential,
            } => {
                session.check_hosted(&node_id, &gateway_credential)?;
                session.hosted_status(&node_id)?
            }
        };
        tx.commit()?;
        if refresh_nodes
            && value.as_array().is_some_and(|nodes| {
                nodes
                    .iter()
                    .any(|n| n["presence"]["probe_started_at"].is_i64())
            })
            && self
                .sync_health
                .connected
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            self.sync_health.verify_watch.notify_one();
        }
        if status_request {
            value["sync"] = self.synchronization_status()?;
        }
        if read_only || (local_only && !projection_pending) {
            return Ok(value);
        }
        // Also wakes directory/message publication after a committed agent RPC.
        self.sync_wakeup.notify_one();
        // Filesystem projection is retryable after the authoritative commit.
        // A caller must not interpret a projection failure as an unapplied edit.
        let projected = self.project_config();
        if owner_request
            && (value.get("applied") == Some(&Value::Bool(true))
                || value.get("config_saved").is_some())
        {
            value["config_saved"] = json!(projected.is_ok());
            if let Err(error) = projected {
                value["config_error"] = json!(error.to_string());
            }
        }
        Ok(value)
    }

    fn project_config(&mut self) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        runtime::project(&self.home, &tx, &self.identity)?;
        tx.commit()?;
        Ok(())
    }

    /// The owner daemon renews its lease without requiring a chat turn.
    /// Chat RPCs never bypass expiry or trigger a renewal themselves.
    pub fn maintain(&mut self) -> Result<()> {
        // Local cleanup remains available after membership/lease loss.
        self.clean_invitations()?;
        self.clean_files()?;
        self.clean_history()?;
        self.clean_wake()?;
        {
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            configuration::pending::recover(&tx, self.identity.node.id())?;
            encrypted::ordered::storage::clean(&tx, false)?;
            tx.commit()?;
        }
        let timestamp = now() as u64;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        ensure!(
            state
                .state()
                .nodes
                .get(self.identity.node.id())
                .is_some_and(|n| n.signing_key == self.identity.node.public_key()),
            "local node is no longer enrolled"
        );
        crate::file_objects::Objects::new(&tx, timestamp)?.reap()?;
        let renew = !self.identity.legacy_signing_fenced()
            && self.identity.legacy_service_checked
            && self.identity.is_current_owner(&state)
            && !handoff::frozen(&tx, &state)?
            && state.state().expires_at.saturating_sub(timestamp) <= 6 * 60 * 60;
        if renew {
            let update = state.renew(&*self.identity.signing_owner(&tx)?, timestamp)?;
            self.identity.apply(&tx, update)?;
        }
        tx.commit()?;
        if renew {
            self.sync_wakeup.notify_one();
        }
        self.project_config()?;
        self.reconcile_configuration()
    }

    /// Trusted enrollment API. The supplied authority must already be verified
    /// through protected pairing. It installs no owner signing secret.
    pub fn install_joined(
        home: &Path,
        node: &gent_crypto::NodeIdentity,
        state: &VerifiedState,
    ) -> Result<()> {
        runtime::install_joined(home, node, state)
    }

    pub(crate) fn relay_settings(&self) -> Option<(config::RelayConfig, PathBuf)> {
        self.config
            .relay
            .clone()
            .map(|relay| (relay, self.home.clone()))
    }
    pub(crate) fn sync_streams(&self) -> Result<Vec<crate::sync::Stream>> {
        if self.identity.state(&self.db)?.state().peer.is_some() {
            return self.data_streams();
        }
        let mut streams: Vec<_> =
            encrypted::ordered::OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?
                .configuration_streams(now() as u64)?
                .into_iter()
                .map(|s| crate::sync::Stream {
                    group: s.group,
                    outgoing: s.outgoing,
                    configuration: true,
                })
                .collect();
        streams.extend(self.data_streams()?);
        Ok(streams)
    }
    pub(crate) fn sync_pending_groups(
        &self,
        streams: &[crate::sync::Stream],
    ) -> Result<crate::sync::MailboxWork> {
        let mut work = crate::sync::MailboxWork::default();
        let mut pending = self.db.prepare(
            "SELECT s.group_id,s.head>=COALESCE(u.next_sequence,0)
             FROM streams s LEFT JOIN stream_relay_upload u USING(group_id)
             LEFT JOIN stream_confirmed c USING(group_id)
             WHERE s.writer=?1 AND s.head>COALESCE(c.sequence,-1)",
        )?;
        let mut rows = pending.query([self.identity.node.id()])?;
        while let Some(row) = rows.next()? {
            let group: Vec<u8> = row.get(0)?;
            work.unconfirmed.insert(group.clone());
            if row.get::<_, bool>(1)? {
                work.ready.insert(group);
            }
        }
        let local = self
            .db
            .prepare(
                "SELECT group_id FROM owner_deliveries WHERE next<parts
             UNION SELECT s.group_id FROM streams s JOIN stream_pending p
               ON p.group_id=s.group_id AND p.sequence=s.head+1",
            )?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<Vec<u8>>>>()?;
        work.ready.extend(local);
        self.add_ready_network_groups(&mut work.ready)?;

        // An unpublished legacy configuration revision is work even before
        // its first fragment has a stream position. Old owner epochs stop at
        // their signed handoff baseline.
        let writers: BTreeSet<_> = streams
            .iter()
            .filter(|s| s.configuration && s.outgoing)
            .map(|s| s.group.as_slice())
            .collect();
        if writers.is_empty() {
            return Ok(work);
        }
        let state = self.identity.state(&self.db)?;
        let mut query = self.db.prepare(
            "SELECT c.group_id,c.grant,h.revision FROM configuration_streams c
             JOIN streams s USING(group_id) JOIN authority_history h ON h.revision=c.revision+1
             WHERE s.writer=?1",
        )?;
        let mut rows = query.query([self.identity.node.id()])?;
        while let Some(row) = rows.next()? {
            let group: Vec<u8> = row.get(0)?;
            if !writers.contains(group.as_slice()) {
                continue;
            }
            let grant = gent_crypto::SignedConfigurationGrant::decode(&row.get::<_, Vec<u8>>(1)?)?;
            let limit = encrypted::ordered::configuration::publication_limit(&grant, &state);
            let revision: u64 = row.get(2)?;
            if limit.is_none_or(|last| revision <= last) {
                work.ready.insert(group);
            }
        }
        Ok(work)
    }

    /// A relay can roll back its queue or lose a successful PUT response.
    /// Replay from the lower position, excluding only the verified prefix.
    pub(crate) fn relay_upload_start(
        &self,
        group: &[u8],
        relay_next: u64,
        confirmed_next: u64,
    ) -> Result<u64> {
        let (local_next, uploaded): (u64, u64) = self.db.query_row(
            "SELECT s.head+1,COALESCE(u.next_sequence,0) FROM streams s
             LEFT JOIN stream_relay_upload u USING(group_id) WHERE s.group_id=?1 AND s.writer=?2",
            params![group, self.identity.node.id()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            relay_next <= local_next,
            "relay position exceeds local history"
        );
        if relay_next < uploaded {
            self.record_relay_upload(group, relay_next)?;
        }
        Ok(uploaded.min(relay_next).max(confirmed_next))
    }

    pub(crate) fn record_relay_upload(&self, group: &[u8], next: u64) -> Result<()> {
        self.db.execute(
            "INSERT INTO stream_relay_upload(group_id,next_sequence) VALUES(?1,?2)
             ON CONFLICT(group_id) DO UPDATE SET next_sequence=excluded.next_sequence",
            params![group, next],
        )?;
        Ok(())
    }
    pub(crate) fn sync_prepare(&self, group: &[u8]) -> Result<()> {
        let mut endpoint =
            encrypted::ordered::OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?;
        let timestamp = now() as u64;
        if endpoint
            .prepare_configuration(group, None, timestamp)?
            .is_none()
        {
            endpoint.prepare_owner_handoff(group, timestamp)?;
        }
        Ok(())
    }

    pub(crate) fn transport_receipt(
        &self,
        group: &[u8],
        configuration: bool,
    ) -> Result<gent_crypto::stream::Receipt> {
        if !configuration {
            self.data_peer(&self.db, group, false)?;
        }
        encrypted::ordered::OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?
            .receipt(group, now() as u64)
    }

    pub(crate) fn transport_confirm(
        &self,
        group: &[u8],
        configuration: bool,
        receipt: Option<&gent_crypto::stream::Receipt>,
    ) -> Result<Option<gent_crypto::stream::Receipt>> {
        Ok(self
            .transport_confirmation(group, configuration, receipt)?
            .0)
    }

    /// The flag records a newly advanced durable checkpoint, excluding cached or replayed ACKs.
    pub(crate) fn transport_confirmation(
        &self,
        group: &[u8],
        configuration: bool,
        receipt: Option<&gent_crypto::stream::Receipt>,
    ) -> Result<(Option<gent_crypto::stream::Receipt>, bool)> {
        let mut endpoint =
            encrypted::ordered::OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?;
        let reader = if configuration {
            endpoint.configuration_reader(group)?
        } else {
            self.data_peer(&self.db, group, true)?
        };
        if let Some(receipt) = receipt {
            ensure!(
                receipt.group() == group,
                "checkpoint belongs to another stream"
            );
            return endpoint
                .confirm_and_get(receipt, &reader, now() as u64)
                .map(|(receipt, advanced)| (Some(receipt), advanced));
        }
        Ok((endpoint.confirmed_receipt(group, now() as u64)?, false))
    }
    pub(crate) fn sync_outgoing(
        &self,
        group: &[u8],
        next: u64,
    ) -> Result<Option<gent_crypto::stream::Packet>> {
        let mut endpoint =
            encrypted::ordered::OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?;
        let timestamp = now() as u64;
        let status = endpoint.configuration_status(group, timestamp)?;
        ensure!(next <= status.next, "relay position exceeds local history");
        Ok(endpoint
            .configuration_outbox(group, next.checked_sub(1), 1, timestamp)?
            .pop())
    }
    pub(crate) fn sync_next(&mut self, group: &[u8]) -> Result<u64> {
        let mut endpoint =
            encrypted::ordered::OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?;
        let timestamp = now() as u64;
        // A restart may find a packet committed to the receive buffer before
        // its authority transaction ran. Apply it without requiring the relay.
        let pending = endpoint.drain_configuration(group, 1, timestamp)?;
        let next = endpoint
            .configuration_status(group, timestamp)
            .map(|status| status.next);
        drop(endpoint);
        if !pending.is_empty() {
            self.project_config()?;
            self.reconcile_configuration()?;
            self.sync_wakeup.notify_one();
        }
        next
    }
    pub(crate) fn sync_receive(&mut self, packet: &gent_crypto::stream::Packet) -> Result<()> {
        let mut endpoint =
            encrypted::ordered::OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?;
        let timestamp = now() as u64;
        endpoint.stage_configuration(packet, timestamp)?;
        endpoint.drain_configuration(packet.group(), 1, timestamp)?;
        self.sync_wakeup.notify_one();
        self.project_config()?;
        self.reconcile_configuration()
    }
}

struct StoreSession<'a> {
    db: &'a Connection,
    home: &'a Path,
    config: Config,
    identity: &'a Identity,
    state: VerifiedState,
    timestamp: i64,
}

#[derive(Default)]
struct SendContext {
    parent: Option<Message>,
    relay: Option<RelayMessage>,
    file_ids: Vec<String>,
}

fn message_fingerprint(
    recipient: &str,
    text: &str,
    files: &[FilePart],
    reply_to: &Option<String>,
    relay: &Option<RelayMessage>,
    file_ids: &[String],
) -> Result<String> {
    let mut value = json!({"recipient":recipient,"text":text,"files":files,"reply_to":reply_to});
    // Preserve exact retry fingerprints for pre-relay messages.
    if let Some(relay) = relay {
        value["relay"] = json!(relay);
    }
    if !file_ids.is_empty() {
        value["file_ids"] = json!(file_ids);
    }
    Ok(hash(&serde_json::to_string(&value)?))
}
impl StoreSession<'_> {
    fn decode_agent(row: &rusqlite::Row<'_>) -> rusqlite::Result<Agent> {
        Ok(Agent {
            id: row.get(0)?,
            node_id: row.get(1)?,
            name: row.get(2)?,
            provider: row.get(3)?,
            last_seen: row.get(4)?,
            revoked: row.get(5)?,
        })
    }
    fn get_agent(&self, id: &str) -> Result<Agent> {
        let mut agent = self
            .db
            .query_row(
                "SELECT id,node_id,name,provider,last_seen,revoked FROM agents WHERE id=?1",
                [id],
                Self::decode_agent,
            )
            .optional()?
            .context(UNAVAILABLE)?;
        agent.revoked |= !self.state.state().nodes.contains_key(&agent.node_id);
        Ok(agent)
    }
    fn all_agents(&self) -> Result<Vec<Agent>> {
        let mut agents = self
            .db
            .prepare("SELECT id,node_id,name,provider,last_seen,revoked FROM agents ORDER BY id")?
            .query_map([], Self::decode_agent)?
            .collect::<Result<Vec<_>, _>>()?;
        for agent in &mut agents {
            agent.revoked |= !self.state.state().nodes.contains_key(&agent.node_id);
        }
        Ok(agents)
    }
    fn owner(&mut self, action: OwnerOp, health: &crate::sync::health::Health) -> Result<Value> {
        match action {
            OwnerOp::WebDeliveryDemand { node_id } => self.web_delivery_demand(&node_id),
            OwnerOp::WebDeliveryChecked {
                node_id,
                message_id,
            } => {
                let cleared = self.db.execute(
                    "DELETE FROM web_delivery_demand WHERE node=?1 AND message=?2",
                    params![node_id, message_id],
                )?;
                Ok(json!({"cleared":cleared==1}))
            }
            OwnerOp::WebAdmission { node_id, body_hash } => self.web_admission(&node_id, body_hash),
            OwnerOp::WebCheckpoint { node_id } => self.web_checkpoint(&node_id),
            OwnerOp::WebLease { node_id, seconds } => self.web_lease(&node_id, seconds),
            OwnerOp::WebGrant {
                node_id,
                epoch,
                expires_at,
            } => self.web_grant(&node_id, epoch, expires_at),
            OwnerOp::WebCommit {
                node_id,
                revision,
                epoch,
            } => self.web_commit(&node_id, revision, epoch),
            OwnerOp::RestoreWebNode { .. } => unreachable!("handled before session"),
            OwnerOp::NodeInvite {
                request_id,
                name,
                can_configure,
                activate,
            } => self.request_node_invite(&request_id, &name, can_configure, activate),
            OwnerOp::AgentRecover {
                directory,
                manifest_sha256,
                source_agent,
                agent_credential,
                name,
                provider,
            } => {
                let registered = self.agent(
                    self.identity.node.id(),
                    &agent_credential,
                    AgentOp::Register {
                        name: name.clone(),
                        provider: provider.clone(),
                    },
                    files::ExportStep::Reserve,
                )?;
                let id = registered["agent"]["id"]
                    .as_str()
                    .context("missing recovered chat identity")?;
                let agent = self.get_agent(id)?;
                ensure!(
                    agent.name == name && agent.provider == provider,
                    "recovery registration arguments changed"
                );
                let history = self.recovered_import(
                    Path::new(&directory),
                    &manifest_sha256,
                    &source_agent,
                    id,
                    None,
                )?;
                Ok(
                    json!({"agent":agent,"history":history,"source_agent":source_agent,
                    "scope":"fresh local registration with assigned history; old credentials, peer permissions and pending work are not restored"}),
                )
            }
            OwnerOp::HistoryImports => self.recovered_imports(None),
            OwnerOp::HistoryImport {
                directory,
                manifest_sha256,
                source_agent,
                target_agent,
                restore_revision,
            } => self.recovered_import(
                Path::new(&directory),
                &manifest_sha256,
                &source_agent,
                &target_agent,
                restore_revision,
            ),
            OwnerOp::HistoryRemove {
                import_id,
                expected_revision,
            } => self.recovered_remove(&import_id, expected_revision),
            OwnerOp::Pair { .. }
            | OwnerOp::Invitation { .. }
            | OwnerOp::Diagnose
            | OwnerOp::PreparePeerConfiguration => {
                anyhow::bail!("pairing must use its owner-authenticated entry point")
            }
            OwnerOp::Status => Ok(
                json!({"process_id":std::process::id(),"node":self.config.node,"cluster":self.config.cluster,"transport":"local_unix_socket","remote_ready":self.remote_ready()?,"authority":{"mode":if self.state.state().peer.is_some(){"peers"}else{"legacy"},"sequence":self.state.checkpoint().revision,"revision":self.state.checkpoint().revision,"expires_at":self.state.state().expires_at,"fresh":self.state.require_fresh(self.timestamp as u64).is_ok()},"config_saved":!runtime::projection_pending(self.db)?}),
            ),
            OwnerOp::Groups { name } => match name {
                Some(name) => Ok(
                    json!({"name":name,"members":self.config.policy.groups.get(&name).context("unknown group")?}),
                ),
                None => Ok(json!(self.config.policy.groups)),
            },
            OwnerOp::GroupAdmins => Ok(
                json!({"grants":self.config.policy.group_admin_grants,"retired":self.state.state().retired_admin_grants}),
            ),
            OwnerOp::GroupAdminHistory {
                administrator,
                before,
            } => self.administration_history(administrator.as_deref(), before, true),
            OwnerOp::NotificationPending { scope } => self.pending_notices(&scope),
            OwnerOp::NotificationPut { notice, scope } => self.enqueue_notice(&notice, scope),
            OwnerOp::NotificationSent { id } => {
                self.db
                    .execute("DELETE FROM account_outbox WHERE id=?1", [id.to_string()])?;
                Ok(json!({}))
            }
            OwnerOp::Dashboards { after } => self.dashboards(after.as_deref()),
            OwnerOp::DashboardClick {
                agent,
                revision,
                widget,
                request_id,
            } => self.dashboard_click(&agent, revision, &widget, &request_id),
            OwnerOp::PermissionRules => Ok(json!({"rules":self.state.state().policy.rules,
                "groups":self.state.state().policy.groups.keys().collect::<Vec<_>>()})),
            OwnerOp::PermissionExplain { actor, peer } => self.permission_explain(&actor, &peer),
            OwnerOp::PermissionAdmins => {
                Ok(json!({"grants":self.state.state().policy.admin_grants,
                "retired":self.state.state().retired_admin_grants,"revision":self.state.checkpoint().revision}))
            }
            OwnerOp::PermissionAdminHistory {
                administrator,
                before,
            } => self.permission_admin_history(administrator.as_deref(), before),
            OwnerOp::Nodes => self.nodes(health),
            OwnerOp::RefreshNodes => self.refresh_nodes(health),
            OwnerOp::Agents => Ok(serde_json::to_value(self.directory(None)?)?),
            OwnerOp::Resolve {
                name,
                node,
                provider,
            } => self.resolve_agent(None, &name, node.as_deref(), provider.as_deref()),
            OwnerOp::NativeMessageDates => self.local_native_message_dates(),
            OwnerOp::ObserveActivity {
                agent_id,
                last_activity_at,
                last_native_message_at,
            } => self.observe_activity(&agent_id, last_activity_at, last_native_message_at),
            OwnerOp::ClearRetiredAgents { dry_run } => self.clear_retired_agents(dry_run),
            OwnerOp::Agent { agent_id } => self.agent_details(&agent_id),
            OwnerOp::RenameAgent {
                agent_id,
                name,
                expected_generation,
            } => {
                self.rename_agent(&agent_id, &name, expected_generation)?;
                self.agent_details(&agent_id)
            }
            OwnerOp::FilesStatus => self.files_status(),
            OwnerOp::FilesClean { dry_run } => self.files_clean(dry_run),
            OwnerOp::HistoryStatus => self.history_status(),
            OwnerOp::OwnerHandoffStatus => handoff::status(self.db, &self.state),
            OwnerOp::OwnerTransfer { .. } => {
                anyhow::bail!("owner transfer requires the authenticated store entry point")
            }
            OwnerOp::RecoveryChallenge => Ok(serde_json::to_value(
                gent_crypto::recovery::RecoveryBaseline::new(&self.state, self.timestamp as u64)?,
            )?),
            OwnerOp::RecoveryObserve { challenge } => {
                let challenge =
                    gent_crypto::recovery::RecoveryChallenge::decode(challenge.as_bytes())?;
                Ok(serde_json::to_value(self.identity.node.observe_recovery(
                    &self.state,
                    &challenge,
                    self.timestamp as u64,
                )?)?)
            }
            OwnerOp::WorkList { after_message_id } => self.work_list(after_message_id.as_deref()),
            OwnerOp::WakeList { after_message_id } => self.wake_list(after_message_id.as_deref()),
            OwnerOp::WakeStatus => wake::retention::status(self.db, self.timestamp),
            OwnerOp::WakePendingAgents { after } => self.wake_pending_agents(after.as_deref()),
            OwnerOp::WakeDirectTurnEvidence {
                agent_credential,
                thread_id,
                turn,
            } => {
                let who = self.native_supervisor_agent(&agent_credential, thread_id)?;
                self.direct_turn_evidence(&who, thread_id, turn)
            }
            OwnerOp::BabysitterVerifiedBlockedClaim {
                agent_credential,
                thread_id,
                goal,
                turn,
                failed_at,
                reason,
            } => {
                let who = self.native_supervisor_agent(&agent_credential, thread_id)?;
                self.babysitter_claim(
                    &who,
                    &goal,
                    turn,
                    failed_at,
                    reason,
                    babysitter::Window::VerifiedBlocked,
                )
            }
            OwnerOp::WakeClean { dry_run } => {
                wake::retention::clean(self.db, self.timestamp, dry_run)
            }
            OwnerOp::WakeShow { message_id } => self.wake_show(&message_id),
            OwnerOp::WorkShow { message_id } => self.work_show(&message_id),
            OwnerOp::WorkReconcile {
                message_id,
                expect_revision,
                resolution,
                note,
            } => self.work_reconcile(&message_id, expect_revision, resolution, &note),
            OwnerOp::HistoryClean { dry_run } => self.history_clean(dry_run),
            OwnerOp::TransportStatus => encrypted::ordered::storage::status(self.db),
            OwnerOp::TransportClean { dry_run } => {
                encrypted::ordered::storage::clean(self.db, dry_run)
            }
            OwnerOp::Providers => {
                let mut providers = BTreeMap::<String, Vec<Agent>>::new();
                for agent in self.all_agents()? {
                    if !agent.revoked {
                        providers
                            .entry(agent.provider.clone())
                            .or_default()
                            .push(agent);
                    }
                }
                Ok(json!(providers))
            }
            OwnerOp::RelayGrants => Ok(json!({"grants":self.state.state().policy.relay_grants,
                "retired":self.state.state().retired_relay_grants,"revision":self.state.checkpoint().revision})),
            OwnerOp::RelayAttachments => self.relay_attachments(),
            OwnerOp::Configure { request_id, edit } => self.submit_configuration(&request_id, edit),
            OwnerOp::ConfigurationRequests { request_id } => match request_id {
                Some(id) => self.configuration_status(&id),
                None => self.configuration_requests(),
            },
            OwnerOp::DelegateConfiguration { node_id, allow } => {
                if self.state.state().peer.is_some() {
                    return self.submit_configuration(
                        &uuid::Uuid::new_v4().to_string(),
                        ConfigurationEdit::DelegateNode { node_id, allow },
                    );
                }
                let update = self.state.delegate_configuration(
                    &*self.identity.signing_owner(self.db)?,
                    &node_id,
                    allow,
                    self.timestamp as u64,
                )?;
                self.state = self.identity.apply(self.db, update)?;
                Ok(
                    json!({"applied":true,"revision":self.state.checkpoint().revision,"node_id":node_id,"can_configure":allow}),
                )
            }
            OwnerOp::RemoveNode { node_id } => self.remove_node(&node_id),
            OwnerOp::NodeRemovals {
                after,
                pending_only,
            } => self.node_removals(after.as_deref(), pending_only),
            OwnerOp::ConfirmNodeRemoval { node_id, revision } => {
                self.confirm_node_removal(&node_id, revision)
            }
            OwnerOp::SetPolicy { policy } => {
                let disk = config::load_for_runtime(self.home)?;
                ensure!(
                    disk.node.id == self.config.node.id
                        && disk.cluster.id == self.config.cluster.id,
                    "cannot change active identities while daemon runs"
                );
                self.submit_configuration(
                    &uuid::Uuid::new_v4().to_string(),
                    ConfigurationEdit::Replace {
                        cluster_name: disk.cluster.name,
                        node_name: disk.node.name,
                        policy,
                    },
                )
            }
            OwnerOp::Renew => self
                .submit_configuration(&uuid::Uuid::new_v4().to_string(), ConfigurationEdit::Renew),
            OwnerOp::RenameNode { name } => self.submit_configuration(
                &uuid::Uuid::new_v4().to_string(),
                ConfigurationEdit::RenameNode { name },
            ),
            OwnerOp::PrepareHostedNode { .. } => unreachable!("handled before session"),
            OwnerOp::Revoke { agent_id } => self.request_unregister(&agent_id),
        }
    }

    fn native_supervisor_agent(&self, credential: &str, thread: uuid::Uuid) -> Result<Agent> {
        ensure!(!thread.is_nil(), "invalid native thread");
        let node = self.identity.node.id();
        self.state.authorize_node(
            node,
            &self.identity.node.public_key(),
            self.timestamp as u64,
        )?;
        self.registered_agent(node, &hash(credential))
    }

    fn registered_agent(&self, node: &str, digest: &str) -> Result<Agent> {
        let who = self.db.query_row(
            "SELECT id,node_id,name,provider,last_seen,revoked FROM agents WHERE credential_hash=?1",
            [digest],
            Self::decode_agent,
        ).optional()?.context("register this connection first")?;
        ensure!(!who.revoked, "registration revoked");
        ensure!(
            who.node_id == node && self.local_node(node),
            "credential belongs to another node"
        );
        Ok(who)
    }

    fn agent(
        &mut self,
        node: &str,
        credential: &str,
        action: AgentOp,
        export_step: files::ExportStep,
    ) -> Result<Value> {
        ensure!(
            credential.len() == 64 && credential.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid registration credential"
        );
        let digest = hash(credential);
        if let AgentOp::Register { name, provider } = &action {
            config::label(name)?;
            config::label(provider)?;
            if !self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM agents WHERE credential_hash=?1)",
                [&digest],
                |r| r.get::<_, bool>(0),
            )? {
                let nonce = uuid::Uuid::new_v4();
                let agent = gent_crypto::agent_id(node, nonce)?;
                self.db.execute("INSERT INTO agents(id,credential_hash,node_id,name,provider,last_seen) VALUES (?1,?2,?3,?4,?5,?6)",params![agent,digest,node,name,provider,self.timestamp])?;
                self.db.execute("INSERT INTO network_origins(agent,nonce,legacy,generation) VALUES(?1,?2,NULL,1)",params![agent,nonce.to_string()])?;
                self.announce(&agent)?;
            }
        }
        let who = self.registered_agent(node, &digest)?;
        if !matches!(
            &action,
            AgentOp::BabysitterClaim { .. }
                | AgentOp::BabysitterCheck { .. }
                | AgentOp::BabysitterSubmitted { .. }
                | AgentOp::WakePending
                | AgentOp::WakeClaim { .. }
                | AgentOp::WakeCheck { .. }
                | AgentOp::WakeSubmitted { .. }
                | AgentOp::WakeDirectClaim { .. }
                | AgentOp::WakeDirectPending { .. }
                | AgentOp::WakeDirectRead { .. }
                | AgentOp::WakeDirectObserve { .. }
                | AgentOp::WakeDirectComplete { .. }
        ) {
            self.db.execute(
                "UPDATE agents SET last_seen=?1 WHERE id=?2",
                params![self.timestamp, who.id],
            )?;
        }
        match action {
            AgentOp::Register { .. } | AgentOp::Identity => self.agent_identity(&who.id),
            AgentOp::Rename {
                name,
                expected_generation,
            } => {
                self.rename_agent(&who.id, &name, expected_generation)?;
                self.agent_identity(&who.id)
            }
            AgentOp::Babysit { enabled } => self.babysit(&who, enabled),
            AgentOp::BabysitterClaim {
                goal,
                turn,
                failed_at,
                reason,
            } => self.babysitter_claim(
                &who,
                &goal,
                turn,
                failed_at,
                reason,
                babysitter::Window::Routine,
            ),
            AgentOp::BabysitterCheck { attempt } => {
                Ok(json!({"eligible":self.babysitter_check(&who,attempt)?}))
            }
            AgentOp::BabysitterSubmitted { attempt, scope } => {
                self.babysitter_submitted(&who, attempt, scope)
            }
            AgentOp::DashboardGet => self.dashboard_get(&who),
            op @ (AgentOp::DashboardDefine { .. }
            | AgentOp::DashboardUpdate { .. }
            | AgentOp::DashboardDelete { .. }) => self.dashboard_mutate(&who, op),
            AgentOp::Agents => self.visible_agents(&who),
            AgentOp::Resolve {
                name,
                node,
                provider,
            } => self.resolve_agent(Some(&who), &name, node.as_deref(), provider.as_deref()),
            AgentOp::HistoryImports => self.recovered_imports(Some(&who)),
            AgentOp::HistoryMessages { import_id, after } => {
                self.recovered_messages(&who, &import_id, after)
            }
            AgentOp::HistoryFileRead {
                import_id,
                message_id,
                file_index,
                chunk_index,
            } => self.recovered_file_read(&who, &import_id, &message_id, file_index, chunk_index),
            AgentOp::HistoryFileView {
                import_id,
                message_id,
                file_index,
            } => self.recovered_file_view(&who, &import_id, &message_id, file_index),
            AgentOp::PermissionCheck { peer } => self.permission_check(&who, &peer),
            AgentOp::PermissionAdminCheck { actor, peer } => {
                self.permission_admin_check(&who, &actor, &peer)
            }
            AgentOp::PermissionPreview { changes } => self.permission_preview(&who, &changes),
            AgentOp::PermissionApply {
                request_id,
                changes,
            } => self.permission_apply(&who, &request_id, changes),
            AgentOp::PermissionRequest { request_id } => self.permission_request(&who, &request_id),
            AgentOp::PermissionRuleScopes => self.permission_rule_scopes(&who),
            AgentOp::GroupAdminScopes => self.group_admin_scopes(&who),
            AgentOp::GroupMembers { group } => self.group_members(&who, &group),
            AgentOp::GroupPreview { changes } => self.group_preview(&who, &changes),
            AgentOp::GroupApply {
                request_id,
                changes,
            } => self.group_apply(&who, &request_id, changes),
            AgentOp::GroupRequest { request_id } => self.permission_request(&who, &request_id),
            AgentOp::PermissionRulePreview { changes } => {
                self.permission_rule_preview(&who, &changes)
            }
            AgentOp::PermissionRuleApply {
                request_id,
                changes,
            } => self.permission_rule_apply(&who, &request_id, changes),
            AgentOp::RequestIds { count } => self.request_ids(count),
            AgentOp::WorkStatus { message_id } => self.work_status(&who, &message_id),
            AgentOp::WakeDirectClaim {
                message_id,
                attempt_id,
                target,
            } => self.wake_direct_claim(&who, &message_id, &attempt_id, target),
            AgentOp::WakeDirectPending { target } => self.wake_direct_pending(&who, &target),
            AgentOp::WakeDirectRead {
                message_id,
                attempt_id,
                target,
            } => self.wake_direct_read(&who, &message_id, &attempt_id, &target),
            AgentOp::WakeDirectObserve {
                message_id,
                attempt_id,
                target,
                turn_id,
            } => self.wake_direct_observe(&who, &message_id, &attempt_id, &target, &turn_id),
            AgentOp::WakeDirectComplete {
                message_id,
                attempt_id,
                target,
                turn_id,
                text,
            } => {
                self.wake_direct_complete(&who, &message_id, &attempt_id, &target, (&turn_id, text))
            }
            AgentOp::WakePending => self.wake_pending(&who),
            AgentOp::WakeClaim {
                message_id,
                attempt_id,
                target,
            } => self.wake_claim(&who, &message_id, &attempt_id, target),
            AgentOp::WakeCheck {
                message_id,
                attempt_id,
                target,
            } => self.wake_check(&who, &message_id, &attempt_id, &target),
            AgentOp::WakeSubmitted {
                message_id,
                attempt_id,
                submission_id,
            } => self.wake_submitted(&who, &message_id, &attempt_id, &submission_id),
            AgentOp::WorkBegin {
                message_id,
                expect_revision,
                description,
            } => self.work_begin(&who, &message_id, expect_revision, &description),
            AgentOp::WorkComplete {
                message_id,
                expect_revision,
                note,
            } => self.work_complete(&who, &message_id, expect_revision, &note),
            AgentOp::FilePaths => self.file_paths(&who),
            AgentOp::FileImport {
                request_id,
                name,
                media_type,
            } => self.file_import(&who, &request_id, &name, &media_type),
            AgentOp::FileStatus { file_id } => self.file_status(&who, &file_id),
            AgentOp::FileReceiveStatus { file } => self.file_receive_status(&who, &file),
            AgentOp::FileReceive {
                file,
                byte_length,
                sha256,
            } => {
                ensure!(
                    byte_length <= gent_protocol::file_objects::MAX_FILE_BYTES as u64,
                    "file exceeds 32 MiB"
                );
                ensure!(
                    sha256.len() == 64
                        && sha256
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "invalid file digest"
                );
                let status = self.file_receive_status(&who, &file)?;
                ensure!(
                    status["state"] != "ready"
                        || (status["file"]["byte_length"] == byte_length
                            && status["file"]["sha256"] == sha256),
                    "request_id already used with different content"
                );
                Ok(status)
            }
            AgentOp::FileReceiveData { file, bytes } => self.file_receive(&who, &file, &bytes),
            AgentOp::FileRead {
                file_id,
                chunk_index,
            } => self.file_read(&who, &file_id, chunk_index),
            AgentOp::FileView { file_id } => self.file_view(&who, &file_id),
            AgentOp::FileExport { file_id } => self.file_export(&who, &file_id, export_step),
            AgentOp::RelayAttach { target, request_id } => {
                self.relay_attach(&who, &target, &request_id)
            }
            AgentOp::RelayStatus { attachment_id } => self.relay_status(&who, attachment_id),
            AgentOp::RelayDetach { attachment_id } => self.relay_detach(&who, &attachment_id),
            AgentOp::RelaySend {
                attachment_id,
                request_id,
                text,
                files,
                file_ids,
            } => self.relay_send(&who, &attachment_id, &request_id, (text, files, file_ids)),
            AgentOp::RelayTurnStatus {
                turn_id,
                after_message_id,
            } => self.relay_turn_status(&who, &turn_id, after_message_id.as_deref()),
            AgentOp::RelayNext => self.relay_next(&who),
            AgentOp::RelayTurns { after_turn_id } => {
                self.relay_turns(&who, after_turn_id.as_deref())
            }
            AgentOp::RelayRespond {
                turn_id,
                request_id,
                text,
                files,
                file_ids,
                outcome,
            } => self.relay_respond(
                &who,
                &turn_id,
                &request_id,
                (text, files, file_ids),
                outcome,
            ),
            AgentOp::RelayCancel {
                turn_id,
                request_id,
            } => self.relay_cancel(&who, &turn_id, &request_id),
            AgentOp::Send {
                recipient,
                request_id,
                text,
                files,
                file_ids,
            } => self.send(
                &who,
                &recipient,
                &request_id,
                text,
                files,
                SendContext {
                    file_ids,
                    ..Default::default()
                },
            ),
            AgentOp::RequestReply {
                recipient,
                request_id,
                text,
                files,
                file_ids,
            } => self.request_reply(&who, &recipient, &request_id, (text, files, file_ids)),
            AgentOp::Reply {
                message_id,
                request_id,
                text,
                files,
                file_ids,
            } => {
                let parent = self.message(&message_id)?;
                ensure!(parent.recipient == who.id, UNAVAILABLE);
                if parent.relay.as_ref().is_some_and(|r| {
                    r.kind == RelayMessageKind::Request && r.attachment_id == r.turn_id
                }) {
                    return self.relay_respond(
                        &who,
                        &message_id,
                        &request_id,
                        (text, files, file_ids),
                        RelayResponseKind::Complete,
                    );
                }
                ensure!(parent.relay.is_none(), "use relay_respond for a relay turn");
                self.send(
                    &who,
                    &parent.sender.clone(),
                    &request_id,
                    text,
                    files,
                    SendContext {
                        parent: Some(parent),
                        relay: None,
                        file_ids,
                    },
                )
            }
            AgentOp::Inbox => {
                let mut statement=self.db.prepare("SELECT payload,acknowledged FROM messages WHERE recipient=?1 AND acknowledged=0 ORDER BY rowid")?;
                let rows = statement.query_map([&who.id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
                })?;
                let mut inbox = Vec::new();
                let mut bytes = 0;
                for row in rows {
                    let (payload, acknowledged) = row?;
                    let mut message: Message = serde_json::from_str(&payload)?;
                    message.acknowledged = acknowledged;
                    if self.deliverable(&message)? && self.relay_inbox_visible(&message)? {
                        if inbox.len() >= 50 || bytes + payload.len() > MAX_FRAME_BYTES / 2 {
                            break;
                        }
                        bytes += payload.len();
                        self.wake_observe(&who, &message.id)?;
                        inbox.push(message);
                    }
                }
                Ok(json!(inbox))
            }
            AgentOp::Ack { message_id } => self.acknowledge(&who, &message_id),
            AgentOp::MessageStatus { message_id } => {
                let message = self.message(&message_id)?;
                ensure!(
                    message.sender == who.id || message.recipient == who.id,
                    UNAVAILABLE
                );
                let state = if message.expires_at <= self.timestamp {
                    "expired"
                } else if !self.deliverable(&message)?
                    || self.db.query_row(
                        "SELECT EXISTS(SELECT 1 FROM network_rejections WHERE message=?1)",
                        [&message.id],
                        |r| r.get::<_, bool>(0),
                    )?
                {
                    "revoked"
                } else if message.acknowledged {
                    "delivered"
                } else {
                    "queued"
                };
                Ok(json!({"message_id":message.id,"state":state}))
            }
        }
    }

    fn acknowledge(&self, who: &Agent, message_id: &str) -> Result<Value> {
        let message = self.message(message_id)?;
        ensure!(
            message.recipient == who.id && self.deliverable(&message)?,
            UNAVAILABLE
        );
        let changed = self.db.execute(
            "UPDATE messages SET acknowledged=1 WHERE id=?1 AND acknowledged=0",
            [message_id],
        )?;
        let sender = self.get_agent(&message.sender)?;
        if changed == 1 {
            self.web_state_changed(&sender.node_id)?;
        }
        if !self.local_node(&sender.node_id) {
            self.receipt(
                self.state.transport_host(&sender.node_id)?,
                message_id,
                true,
                message.expires_at,
            )?;
        }
        Ok(json!({"acknowledged":true}))
    }

    fn message(&self, message_id: &str) -> Result<Message> {
        let (payload, ack): (String, bool) = self
            .db
            .query_row(
                "SELECT payload,acknowledged FROM messages WHERE id=?1",
                [message_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .context(UNAVAILABLE)?;
        let mut message: Message = serde_json::from_str(&payload)?;
        message.acknowledged = ack;
        Ok(message)
    }
    fn deliverable(&self, message: &Message) -> Result<bool> {
        if !self.web_message_ready(message)? {
            return Ok(false);
        }
        if message.expires_at <= self.timestamp {
            return Ok(false);
        }
        let a = self.get_agent(&message.sender)?;
        let b = self.get_agent(&message.recipient)?;
        if !self.relay_authorized(message)? {
            return Ok(false);
        }
        Ok(if message.reply_to.is_some() {
            self.config.policy.can_reply(&a, &b)
        } else {
            self.config.policy.can_open(&a, &b)
        })
    }

    fn send(
        &mut self,
        sender: &Agent,
        recipient_id: &str,
        request_id: &str,
        text: String,
        files: Vec<FilePart>,
        context: SendContext,
    ) -> Result<Value> {
        uuid::Uuid::parse_str(request_id)
            .context("request_id must be a UUID; reuse it only when retrying the same message")?;
        let SendContext {
            parent,
            relay,
            file_ids,
        } = context;
        network::validate_contents(&text, &files, file_ids.len())?;
        ensure!(
            file_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == file_ids.len(),
            "duplicate file ID"
        );
        let reply_to = parent.as_ref().map(|p| p.id.clone());
        let fingerprint =
            message_fingerprint(recipient_id, &text, &files, &reply_to, &relay, &file_ids)?;
        let existing: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT id,fingerprint FROM messages WHERE sender=?1 AND request_id=?2",
                params![sender.id, request_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((message_id, previous)) = existing {
            ensure!(
                previous == fingerprint,
                "request_id already used with different content"
            );
            return Ok(json!({"message_id":message_id,"duplicate":true}));
        }
        requests::admit(request_id, self.timestamp)?;
        let recipient = self.get_agent(recipient_id)?;
        ensure!(sender.id != recipient.id, UNAVAILABLE);
        let remote = !self.local_node(&recipient.node_id);
        let message_id = crate::messages::message_id(&sender.id, request_id)?;
        let timestamp = self.timestamp;
        let (exchange_id, expires_at) = if let Some(parent) = parent {
            ensure!(
                self.config.policy.can_reply(sender, &recipient),
                UNAVAILABLE
            );
            let (a, b, expiry, count): (String, String, i64, u32) = self.db.query_row(
                "SELECT a,b,expires_at,count FROM exchanges WHERE id=?1",
                [&parent.exchange_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            ensure!(
                (a == sender.id && b == recipient.id) || (b == sender.id && a == recipient.id),
                UNAVAILABLE
            );
            ensure!(expiry > timestamp, "exchange expired");
            ensure!(
                count < MAX_EXCHANGE_MESSAGES,
                "exchange reply limit reached"
            );
            (parent.exchange_id, expiry)
        } else {
            ensure!(self.config.policy.can_open(sender, &recipient), UNAVAILABLE);
            let mut expiry = timestamp + EXCHANGE_TTL_SECONDS;
            if let Some(grant_id) = relay.as_ref().and_then(|relay| relay.grant_id.as_ref()) {
                let grant = self
                    .config
                    .policy
                    .relay_grants
                    .get(grant_id)
                    .context(UNAVAILABLE)?;
                expiry = expiry.min(grant.expires_at as i64);
            }
            (message_id.clone(), expiry)
        };
        if remote {
            let sent: u32 = self.db.query_row(
                "SELECT COUNT(*) FROM messages WHERE json_extract(payload,'$.exchange_id')=?1 AND sender=?2",
                params![exchange_id, sender.id],
                |r| r.get(0),
            )?;
            ensure!(
                sent < MAX_EXCHANGE_MESSAGES / 2,
                "remote exchange sender limit reached (16 messages)"
            );
        }
        let attachments = self.seal_attachments(sender, &file_ids, expires_at)?;
        let message = Message {
            id: message_id,
            exchange_id: exchange_id.clone(),
            sender: sender.id.clone(),
            recipient: recipient.id.clone(),
            text,
            files,
            attachments: attachments
                .iter()
                .map(|f| f.grant.descriptor().clone())
                .collect(),
            reply_to,
            created_at: timestamp,
            expires_at,
            acknowledged: false,
            relay,
        };
        self.validate_relay_message(&message)?;
        self.validate_local_relay(&message)?;
        let tx = self.db;
        if message.reply_to.is_none() {
            tx.execute(
                "INSERT INTO exchanges VALUES (?1,?2,?3,?4,0)",
                params![exchange_id, sender.id, recipient.id, expires_at],
            )?;
        }
        ensure!(
            tx.execute(
                "UPDATE exchanges SET count=count+1 WHERE id=?1 AND count<?2",
                params![exchange_id, MAX_EXCHANGE_MESSAGES]
            )? == 1,
            "exchange reply limit reached"
        );
        let payload = serde_json::to_string(&message)?;
        history::message_capacity(tx, payload.len())?;
        tx.execute("INSERT INTO messages(id,sender,recipient,request_id,fingerprint,payload) VALUES (?1,?2,?3,?4,?5,?6)",params![message.id,message.sender,message.recipient,request_id,fingerprint,payload])?;
        self.bind_attachments(&message, &attachments)?;
        self.record_relay_message(&message)?;
        self.web_state_changed(&recipient.node_id)?;
        self.gate_web_message(&message)?;
        self.save_activity(&sender.id, message.created_at)?;
        self.record_gent_message(&sender.id, message.created_at)?;
        if !remote {
            self.record_gent_message(&recipient.id, message.created_at)?;
        }
        if remote {
            self.record_web_demand(&recipient.node_id, &message.id)?;
            self.queue_message(
                self.state.transport_host(&recipient.node_id)?,
                request_id,
                &message,
            )?;
        }
        Ok(json!({"message_id":message.id,"exchange_id":exchange_id,"duplicate":false}))
    }
}
