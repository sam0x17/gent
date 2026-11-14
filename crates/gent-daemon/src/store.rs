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
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;
mod administration;
mod configuration;
pub(crate) use configuration::pending::schema as pending_configuration_schema;
pub(crate) use configuration::routing::schema as configuration_routing_schema;
mod diagnostics;
mod files;
pub(crate) mod handoff;
mod history;
pub mod invitations;
mod mesh;
mod network;
mod pairing;
mod permissions;
mod recovered;
mod relay;
pub(crate) mod removals;
mod requests;
#[cfg(test)]
mod storage_tests;
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
const UNAVAILABLE: &str = "recipient or message unavailable";

pub struct Store {
    db: Connection,
    home: PathBuf,
    config: Config,
    identity: Identity,
    owner_hash: String,
    pub(crate) sync_wakeup: Arc<Notify>,
    pub(crate) sync_health: Arc<crate::sync::health::Health>,
}
impl Store {
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
        if self.identity.state(&self.db)?.owner_epoch() > 0 {
            self.require_provisioning_member()
        } else if originally_owner {
            self.require_provisioning_owner()
        } else {
            self.require_provisioning_joined()
        }
    }

    pub fn open(home: &Path) -> Result<Self> {
        let config = config::load_for_runtime(home)?;
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
          CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL);")?;
        network::schema(&db)?;
        configuration::schema(&db)?;
        mesh::schema(&db)?;
        relay::schema(&db)?;
        files::schema(&mut db)?;
        requests::schema(&db, now())?;
        history::schema(&db)?;
        recovered::schema(&db)?;
        work::schema(&db)?;
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
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let timestamp = requests::clock(&tx, now())?;
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
        let mut value = match request {
            Request::Owner { action, .. } => session.owner(action)?,
            Request::Agent { credential, action } => {
                session.state.authorize_node(
                    self.identity.node.id(),
                    &self.identity.node.public_key(),
                    timestamp as u64,
                )?;
                session.agent(&credential, action, export_step)?
            }
        };
        tx.commit()?;
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

    /// The owner daemon renews its lease without requiring an agent turn.
    /// Agent RPCs never bypass expiry or trigger a renewal themselves.
    pub fn maintain(&mut self) -> Result<()> {
        // Local cleanup remains available after membership/lease loss.
        self.clean_invitations()?;
        self.clean_files()?;
        self.clean_history()?;
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
        let renew = self.identity.is_current_owner(&state)
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
            endpoint.confirm(receipt, &reader, now() as u64)?;
        }
        endpoint.confirmed_receipt(group, now() as u64)
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
    fn owner(&mut self, action: OwnerOp) -> Result<Value> {
        match action {
            OwnerOp::AgentRecover {
                directory,
                manifest_sha256,
                source_agent,
                agent_credential,
                name,
                provider,
            } => {
                let registered = self.agent(
                    &agent_credential,
                    AgentOp::Register {
                        name: name.clone(),
                        provider: provider.clone(),
                    },
                    files::ExportStep::Reserve,
                )?;
                let id = registered["agent"]["id"]
                    .as_str()
                    .context("missing recovered agent identity")?;
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
            OwnerOp::Pair { .. } | OwnerOp::Invitation { .. } | OwnerOp::Diagnose => {
                anyhow::bail!("pairing must use its owner-authenticated entry point")
            }
            OwnerOp::Status => Ok(
                json!({"process_id":std::process::id(),"node":self.config.node,"cluster":self.config.cluster,"transport":"local_unix_socket","remote_ready":self.remote_ready()?,"authority":{"revision":self.state.checkpoint().revision,"expires_at":self.state.state().expires_at,"fresh":self.state.require_fresh(self.timestamp as u64).is_ok()},"config_saved":!runtime::projection_pending(self.db)?}),
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
            OwnerOp::PermissionExplain { actor, peer } => self.permission_explain(&actor, &peer),
            OwnerOp::PermissionAdmins => {
                Ok(json!({"grants":self.state.state().policy.admin_grants,
                "retired":self.state.state().retired_admin_grants,"revision":self.state.checkpoint().revision}))
            }
            OwnerOp::PermissionAdminHistory {
                administrator,
                before,
            } => self.permission_admin_history(administrator.as_deref(), before),
            OwnerOp::Nodes => {
                let links = self
                    .db
                    .prepare("SELECT peer,peer_key FROM network_links")?
                    .query_map([], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                    })?
                    .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
                Ok(json!(self.state.state().nodes.iter().map(|(id, member)| {
                    json!({"id":id,"name":member.name,"can_configure":member.can_configure,"data_link":links.get(id).is_some_and(|key| key.as_slice() == member.signing_key),"status":if id == self.identity.node.id() { "local" } else { "unknown" },"revision":self.state.checkpoint().revision})
                }).collect::<Vec<_>>()))
            }
            OwnerOp::Agents => Ok(serde_json::to_value(self.all_agents()?)?),
            OwnerOp::FilesStatus => self.files_status(),
            OwnerOp::FilesClean { dry_run } => self.files_clean(dry_run),
            OwnerOp::HistoryStatus => self.history_status(),
            OwnerOp::OwnerHandoffStatus => handoff::status(self.db, &self.state),
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
            OwnerOp::Revoke { agent_id } => {
                self.ensure_local_origin(&agent_id)?;
                ensure!(
                    self.db.execute(
                        "UPDATE agents SET revoked=1 WHERE id=?1 AND node_id=?2",
                        params![agent_id, self.identity.node.id()]
                    )? == 1,
                    "unknown agent"
                );
                self.db.execute(
                    "UPDATE network_origins SET generation=generation+1 WHERE agent=?1",
                    [&agent_id],
                )?;
                self.announce(&agent_id)?;
                Ok(json!({"revoked":true}))
            }
        }
    }

    fn agent(
        &mut self,
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
                let agent = gent_crypto::agent_id(self.identity.node.id(), nonce)?;
                self.db.execute("INSERT INTO agents(id,credential_hash,node_id,name,provider,last_seen) VALUES (?1,?2,?3,?4,?5,?6)",params![agent,digest,self.config.node.id,name,provider,self.timestamp])?;
                self.db.execute("INSERT INTO network_origins(agent,nonce,legacy,generation) VALUES(?1,?2,NULL,1)",params![agent,nonce.to_string()])?;
                self.announce(&agent)?;
            }
        }
        let who=self.db.query_row("SELECT id,node_id,name,provider,last_seen,revoked FROM agents WHERE credential_hash=?1",[&digest],Self::decode_agent).optional()?.context("register this connection first")?;
        ensure!(!who.revoked, "registration revoked");
        ensure!(
            who.node_id == self.identity.node.id(),
            "credential belongs to another node"
        );
        self.db.execute(
            "UPDATE agents SET last_seen=?1 WHERE id=?2",
            params![self.timestamp, who.id],
        )?;
        match action {
            AgentOp::Register { .. } | AgentOp::Identity => Ok(
                json!({"agent":self.get_agent(&who.id)?,"cluster_id":self.config.cluster.id,"node_name":self.config.node.name,"delivery":"polling","remote_ready":self.remote_ready()?}),
            ),
            AgentOp::Agents => Ok(json!(
                self.all_agents()?
                    .into_iter()
                    .filter(|other| self.config.policy.visible(&who, other))
                    .collect::<Vec<_>>()
            )),
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
            AgentOp::Reply {
                message_id,
                request_id,
                text,
                files,
                file_ids,
            } => {
                let parent = self.message(&message_id)?;
                ensure!(parent.recipient == who.id, UNAVAILABLE);
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
                        inbox.push(message);
                    }
                }
                Ok(json!(inbox))
            }
            AgentOp::Ack { message_id } => {
                let message = self.message(&message_id)?;
                ensure!(
                    message.recipient == who.id && self.deliverable(&message)?,
                    UNAVAILABLE
                );
                self.db.execute(
                    "UPDATE messages SET acknowledged=1 WHERE id=?1",
                    [&message_id],
                )?;
                let sender = self.get_agent(&message.sender)?;
                if sender.node_id != self.identity.node.id() {
                    self.receipt(&sender.node_id, &message_id, true, message.expires_at)?;
                }
                Ok(json!({"acknowledged":true}))
            }
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
        let remote = recipient.node_id != self.identity.node.id();
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
            if let Some(relay) = &relay {
                let grant = self
                    .config
                    .policy
                    .relay_grants
                    .get(&relay.grant_id)
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
        if remote {
            self.queue_message(&recipient.node_id, request_id, &message)?;
        }
        Ok(json!({"message_id":message.id,"exchange_id":exchange_id,"duplicate":false}))
    }
}
