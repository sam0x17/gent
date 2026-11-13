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
    time::{SystemTime, UNIX_EPOCH},
};

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
fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
const UNAVAILABLE: &str = "recipient or message unavailable";

pub struct Store {
    db: Connection,
    home: PathBuf,
    config: Config,
    identity: Identity,
    owner_hash: String,
}
impl Store {
    pub fn open(home: &Path) -> Result<Self> {
        let config = config::load_for_runtime(home)?;
        let owner_hash = hash(&config::read_private(&home.join("owner.key"))?);
        ensure!(
            home.join("state.sqlite3").exists() || !home.join(runtime::KEY_FILE).exists(),
            "authority database is missing; restore this node's state"
        );
        let mut db = encrypted::open_database(home, "state.sqlite3")?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, credential_hash TEXT UNIQUE NOT NULL, node_id TEXT NOT NULL, name TEXT NOT NULL, provider TEXT NOT NULL, last_seen INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS exchanges (id TEXT PRIMARY KEY, a TEXT NOT NULL REFERENCES agents(id), b TEXT NOT NULL REFERENCES agents(id), expires_at INTEGER NOT NULL, count INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, sender TEXT NOT NULL REFERENCES agents(id), recipient TEXT NOT NULL REFERENCES agents(id), request_id TEXT NOT NULL, fingerprint TEXT NOT NULL, payload TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0, UNIQUE(sender,request_id));
          CREATE INDEX IF NOT EXISTS messages_inbox ON messages(recipient,acknowledged);
          CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL);")?;
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
        tx.commit()?;
        let mut store = Self {
            db,
            home: home.into(),
            config,
            owner_hash,
            identity,
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
        if let Request::Owner { credential, .. } = &request {
            ensure!(hash(credential) == self.owner_hash, "unauthorized");
        }
        let timestamp = now();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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
        let mut value = match request {
            Request::Owner { action, .. } => session.owner(action)?,
            Request::Agent { credential, action } => {
                session.state.authorize_node(
                    self.identity.node.id(),
                    &self.identity.node.public_key(),
                    timestamp as u64,
                )?;
                session.agent(&credential, action)?
            }
        };
        tx.commit()?;
        // Filesystem projection is retryable after the authoritative commit.
        // A caller must not interpret a projection failure as an unapplied edit.
        let projected = self.project_config();
        if value.get("applied").is_some() || value.get("config_saved").is_some() {
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
        if state.state().expires_at.saturating_sub(timestamp) <= 6 * 60 * 60 {
            let update = state.renew(&self.identity.owner, timestamp)?;
            self.identity.apply(&tx, update)?;
        }
        tx.commit()?;
        self.project_config()
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
        self.db
            .query_row(
                "SELECT id,node_id,name,provider,last_seen,revoked FROM agents WHERE id=?1",
                [id],
                Self::decode_agent,
            )
            .optional()?
            .context(UNAVAILABLE)
    }
    fn all_agents(&self) -> Result<Vec<Agent>> {
        Ok(self
            .db
            .prepare("SELECT id,node_id,name,provider,last_seen,revoked FROM agents ORDER BY id")?
            .query_map([], Self::decode_agent)?
            .collect::<Result<Vec<_>, _>>()?)
    }
    fn owner(&mut self, action: OwnerOp) -> Result<Value> {
        match action {
            OwnerOp::Status => Ok(
                json!({"node":self.config.node,"cluster":self.config.cluster,"transport":"local_unix_socket","remote_ready":false,"authority":{"revision":self.state.checkpoint().revision,"expires_at":self.state.state().expires_at,"fresh":self.state.require_fresh(self.timestamp as u64).is_ok()},"config_saved":!runtime::projection_pending(self.db)?}),
            ),
            OwnerOp::Agents => Ok(serde_json::to_value(self.all_agents()?)?),
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
            OwnerOp::SetPolicy { policy } => {
                let disk = config::load_for_runtime(self.home)?;
                ensure!(
                    disk.node.id == self.config.node.id
                        && disk.cluster.id == self.config.cluster.id,
                    "cannot change active identities while daemon runs"
                );
                let update = self.state.configure(
                    &self.identity.owner,
                    &disk.cluster.name,
                    (&disk.node.id, &disk.node.name),
                    policy,
                    self.timestamp as u64,
                )?;
                self.state = self.identity.apply(self.db, update)?;
                Ok(json!({"applied":true,"revision":self.state.checkpoint().revision}))
            }
            OwnerOp::Renew => {
                let update = self
                    .state
                    .renew(&self.identity.owner, self.timestamp as u64)?;
                self.state = self.identity.apply(self.db, update)?;
                Ok(json!({"applied":true,"revision":self.state.checkpoint().revision}))
            }
            OwnerOp::RenameNode { name } => {
                let update = self.state.configure(
                    &self.identity.owner,
                    &self.state.state().name,
                    (self.identity.node.id(), &name),
                    self.state.state().policy.clone(),
                    self.timestamp as u64,
                )?;
                self.state = self.identity.apply(self.db, update)?;
                Ok(json!({"applied":true,"revision":self.state.checkpoint().revision,"name":name}))
            }
            OwnerOp::Revoke { agent_id } => {
                ensure!(
                    self.db
                        .execute("UPDATE agents SET revoked=1 WHERE id=?1", [agent_id])?
                        == 1,
                    "unknown agent"
                );
                Ok(json!({"revoked":true}))
            }
        }
    }

    fn agent(&mut self, credential: &str, action: AgentOp) -> Result<Value> {
        ensure!(
            credential.len() == 64 && credential.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid registration credential"
        );
        let digest = hash(credential);
        if let AgentOp::Register { name, provider } = &action {
            config::label(name)?;
            config::label(provider)?;
            self.db.execute("INSERT INTO agents(id,credential_hash,node_id,name,provider,last_seen) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(credential_hash) DO NOTHING",params![id(),digest,self.config.node.id,name,provider,self.timestamp])?;
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
                json!({"agent":self.get_agent(&who.id)?,"cluster_id":self.config.cluster.id,"node_name":self.config.node.name,"delivery":"polling","remote_ready":false}),
            ),
            AgentOp::Agents => Ok(json!(
                self.all_agents()?
                    .into_iter()
                    .filter(|other| self.config.policy.visible(&who, other))
                    .collect::<Vec<_>>()
            )),
            AgentOp::Send {
                recipient,
                request_id,
                text,
                files,
            } => self.send(&who, &recipient, &request_id, text, files, None),
            AgentOp::Reply {
                message_id,
                request_id,
                text,
                files,
            } => {
                let parent = self.message(&message_id)?;
                ensure!(parent.recipient == who.id, UNAVAILABLE);
                self.send(
                    &who,
                    &parent.sender.clone(),
                    &request_id,
                    text,
                    files,
                    Some(parent),
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
                    if self.deliverable(&message)? {
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
                    [message_id],
                )?;
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
                } else if !self.deliverable(&message)? {
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
        parent: Option<Message>,
    ) -> Result<Value> {
        uuid::Uuid::parse_str(request_id)
            .context("request_id must be a UUID; reuse it only when retrying the same message")?;
        ensure!(text.len() <= MAX_TEXT_BYTES, "message text exceeds 64 KiB");
        ensure!(!text.is_empty() || !files.is_empty(), "message is empty");
        ensure!(files.len() <= 4, "at most four files per message");
        let mut total = 0;
        for file in &files {
            config::label(&file.name)?;
            config::label(&file.media_type)?;
            ensure!(
                !file.name.contains(['/', '\\']) && file.name != "." && file.name != "..",
                "filename must be a basename"
            );
            let bytes = STANDARD
                .decode(&file.data_base64)
                .context("invalid base64 file")?;
            total += bytes.len();
            ensure!(total <= MAX_FILE_BYTES, "combined files exceed 1 MiB");
        }
        let reply_to = parent.as_ref().map(|p| p.id.clone());
        let fingerprint = hash(&serde_json::to_string(
            &json!({"recipient":recipient_id,"text":text,"files":files,"reply_to":reply_to}),
        )?);
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
        let recipient = self.get_agent(recipient_id)?;
        ensure!(sender.id != recipient.id, UNAVAILABLE);
        ensure!(
            recipient.node_id == self.identity.node.id(),
            "remote delivery is not available yet"
        );
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
            (id(), timestamp + EXCHANGE_TTL_SECONDS)
        };
        let message = Message {
            id: id(),
            exchange_id: exchange_id.clone(),
            sender: sender.id.clone(),
            recipient: recipient.id.clone(),
            text,
            files,
            reply_to,
            created_at: timestamp,
            expires_at,
            acknowledged: false,
        };
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
        tx.execute("INSERT INTO messages(id,sender,recipient,request_id,fingerprint,payload) VALUES (?1,?2,?3,?4,?5,?6)",params![message.id,message.sender,message.recipient,request_id,fingerprint,serde_json::to_string(&message)?])?;
        Ok(json!({"message_id":message.id,"exchange_id":exchange_id,"duplicate":false}))
    }
}
