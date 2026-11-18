use super::mtls::{Peer, Policy as TlsPolicy};
use crate::{
    auth,
    managed_file::{self, Snapshot},
    node_home,
};
use anyhow::{Context, Result, ensure};
use gent_daemon::config;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

const MAX_CLIENTS: usize = 32;
const MAX_BINDINGS: usize = 4096;
const MAX_CLIENT_BINDINGS: usize = 256;
const MAX_LIFETIME: u64 = 8760 * 3600;
const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_WORKERS: usize = 16;
mod bindings;
pub(crate) mod conversations;
pub(crate) use conversations::Conversation;
mod downloads;
pub(crate) use downloads::{Download, DownloadTarget};
mod keys;
mod recovery;
pub(crate) use bindings::BindingKeys;
pub(crate) mod oauth;

#[derive(Debug)]
pub(crate) struct Busy;
impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("gateway is busy")
    }
}
impl std::error::Error for Busy {}

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub(crate) struct Registry {
    home: PathBuf,
    id: String,
    cluster: String,
    node: String,
    workers: Arc<tokio::sync::Semaphore>,
    pub(crate) access: super::access::AccessRoute,
    pub(crate) files: Arc<super::files::Runtime>,
    pub(crate) downloads: Arc<super::downloads::Runtime>,
}
#[derive(Clone)]
pub(crate) struct Permit {
    client: String,
    hash: String,
    oauth: Option<(String, String)>,
    peer: Peer,
    pub(crate) conversation_handles: bool,
}
impl Permit {
    pub(crate) fn client_id(&self) -> &str {
        &self.client
    }
}

// These records contain private agent credentials and never implement Debug.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    id: String,
    cluster: String,
    node: String,
    clock: u64,
    clients: BTreeMap<String, Client>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oauth: Option<oauth::Records>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Client {
    name: String,
    conversation_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    subject_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_hash: Option<String>,
    created_at: u64,
    expires_at: u64,
    export: PathBuf,
    revoked: bool,
    bindings: BTreeMap<String, recovery::Binding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oauth: Option<oauth::Registration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mtls: Option<TlsPolicy>,
    // The separate requirement marker rejects partial records that lose a
    // certificate policy while other mTLS clients keep the registry at v3.
    #[serde(default, skip_serializing_if = "is_false")]
    mtls_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_update: Option<keys::Update>,
    #[serde(default, skip_serializing_if = "is_false")]
    keys_updated: bool,
}
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    version: u32,
    registry: String,
    cluster: String,
    node: String,
    client: String,
    name: String,
    conversation_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    created_at: u64,
    expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oauth: Option<oauth::Registration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mtls: Option<TlsPolicy>,
    #[serde(default, skip_serializing_if = "is_zero")]
    key_revision: u64,
}

fn uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|v| !v.is_nil() && v.to_string() == value)
}
fn is_false(value: &bool) -> bool {
    !*value
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}
fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn metadata_key(key: &str) -> Result<()> {
    ensure!(
        key.len() <= 128
            && (key == "threadId"
                || key
                    .split_once('/')
                    .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty()))
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)),
        "conversation key must name a host-owned namespaced MCP metadata field or Codex threadId"
    );
    ensure!(
        !key.starts_with("io.modelcontextprotocol/"),
        "protocol metadata cannot identify a conversation"
    );
    Ok(())
}

fn conversation_key(key: &str) -> Result<()> {
    metadata_key(key)?;
    // Old registries may contain this syntactically valid key. Keep them
    // readable for inspection/revocation, but never issue or use its bindings.
    ensure!(
        key != "claudecode/toolUseId",
        "Claude tool-use IDs identify calls, not conversations; use the local hooked stdio integration"
    );
    Ok(())
}
fn token_id(token: &str) -> Result<&str> {
    let mut pieces = token.split('.');
    ensure!(
        pieces.next() == Some("gent_g1"),
        "invalid gateway credential"
    );
    let id = pieces.next().context("invalid gateway credential")?;
    ensure!(
        uuid(id) && pieces.next().is_some_and(hash) && pieces.next().is_none(),
        "invalid gateway credential"
    );
    Ok(id)
}
fn snapshot(path: &Path) -> Result<Snapshot> {
    let value = Snapshot::read(path)?;
    value.private()?;
    ensure!(
        value.text.as_ref().is_none_or(|s| s.len() <= MAX_BYTES),
        "gateway record is too large"
    );
    Ok(value)
}

fn directory_check(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.mode() & 0o077 == 0,
        "gateway directory must be private, owned by this user, and not a symlink"
    );
    Ok(())
}

impl State {
    fn validate(&self) -> Result<()> {
        let oauth = self.oauth.is_some() || self.clients.values().any(|c| c.oauth.is_some());
        let mtls = self.clients.values().any(|c| c.mtls.is_some());
        let assertions = self
            .clients
            .values()
            .any(|c| c.oauth.as_ref().is_some_and(|r| r.assertion.is_some()));
        let updates = self.clients.values().any(|c| c.key_update.is_some());
        let subjects = self.clients.values().any(|c| c.subject_key.is_some());
        let recovered = self.clients.values().any(|c| {
            c.bindings
                .values()
                .any(|b| matches!(b, recovery::Binding::Recovery(_)))
        });
        ensure!(
            self.version
                == if self.clients.values().any(conversations::enabled) {
                    8
                } else if recovered {
                    7
                } else if subjects {
                    6
                } else if updates {
                    5
                } else if assertions {
                    4
                } else if mtls {
                    3
                } else if oauth {
                    2
                } else {
                    1
                }
                && uuid(&self.id)
                && uuid(&self.cluster)
                && uuid(&self.node)
                && self.clients.len() <= MAX_CLIENTS,
            "invalid gateway registry"
        );
        let mut names = std::collections::BTreeSet::new();
        let mut oauth_ids = std::collections::BTreeSet::new();
        let mut count = 0;
        for (id, client) in &self.clients {
            config::label(&client.name)?;
            metadata_key(&client.conversation_key)?;
            ensure!(
                !conversations::enabled(client) || client.subject_key.is_none(),
                "explicit conversations are scoped to the OAuth grant, not host metadata"
            );
            ensure!(
                client.subject_required == client.subject_key.is_some(),
                "gateway subject policy is missing"
            );
            if let Some(subject) = &client.subject_key {
                bindings::subject_key(subject, &client.conversation_key)?;
                ensure!(client.oauth.is_some(), "subject binding requires OAuth");
            }
            if let Some(registration) = &client.oauth {
                registration.validate()?;
                ensure!(
                    oauth_ids.insert(registration.client_id(id)),
                    "duplicate OAuth client identity"
                );
            }
            let signed = client.oauth.as_ref().is_some_and(|r| r.assertion.is_some());
            ensure!(
                client.keys_updated == client.key_update.is_some(),
                "signing key revision state is missing"
            );
            if let Some(update) = &client.key_update {
                ensure!(
                    signed
                        && update.revision > 0
                        && update.pending_export.as_deref().is_none_or(hash),
                    "invalid signing key update record"
                );
            }
            if let Some(policy) = &client.mtls {
                policy.validate()?;
            }
            ensure!(
                client.mtls_required == client.mtls.is_some(),
                "gateway client certificate policy is missing or inconsistent"
            );
            ensure!(
                uuid(id)
                    && names.insert(&client.name)
                    && if signed {
                        client.token_hash.is_none()
                    } else {
                        client.token_hash.as_deref().is_some_and(hash)
                    }
                    && client.created_at <= client.expires_at
                    && client.expires_at - client.created_at <= MAX_LIFETIME
                    && client.created_at <= self.clock
                    && client.export.is_absolute()
                    && client.bindings.len() <= MAX_CLIENT_BINDINGS,
                "invalid gateway client record"
            );
            ensure!(
                client
                    .bindings
                    .iter()
                    .all(|(key, binding)| hash(key) && binding.valid()),
                "invalid gateway binding record"
            );
            count += client.bindings.len();
        }
        ensure!(count <= MAX_BINDINGS, "gateway binding capacity exceeded");
        if let Some(records) = &self.oauth {
            records.validate(self)?;
        }
        ensure!(
            !assertions || self.oauth.is_some(),
            "assertion replay state is missing"
        );
        Ok(())
    }
}

impl Registry {
    // Caller must be read-only; ordinary opening also allocates the lock file.
    fn inspect_existing(home: &Path) -> Result<Self> {
        directory_check(&home.join("gateway"))?;
        Self::open_locked(home)
    }
    pub(crate) fn open(home: &Path) -> Result<Self> {
        let home = managed_file::normalize(home)?;
        directory_check(&home.join("gateway"))?;
        let _lock = managed_file::lock(&home.join("gateway/state.lock"))?;
        Self::open_locked(&home)
    }
    fn open_locked(home: &Path) -> Result<Self> {
        let home = managed_file::normalize(home)?;
        let cfg = node_home::inspect(&home)?;
        let id = cfg
            .gateway_registry()?
            .context("configure a host with gent gateway clients add first")?;
        let value = Self {
            access: super::access::AccessRoute::Direct,
            home,
            id,
            cluster: cfg.cluster.id,
            node: cfg.node.id,
            workers: Arc::new(tokio::sync::Semaphore::new(MAX_WORKERS)),
            files: Arc::new(super::files::Runtime::default()),
            downloads: Arc::new(super::downloads::Runtime::default()),
        };
        value.read()?;
        Ok(value)
    }
    // Hold the slot inside the blocking operation. A disconnected HTTP peer
    // must not release capacity while its filesystem work is still running.
    async fn blocking<T: Send + 'static>(
        &self,
        operation: impl FnOnce(Self) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let slot = self.workers.clone().try_acquire_owned().map_err(|_| Busy)?;
        let registry = self.clone();
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            operation(registry)
        })
        .await
        .context("gateway worker unavailable")?
    }
    pub(crate) async fn authenticate_remote(
        &self,
        token: String,
        resource: String,
        peer: Peer,
    ) -> Result<Permit> {
        self.blocking(move |registry| registry.authenticate_peer(&token, Some(&resource), peer))
            .await
    }
    pub(crate) async fn credential_remote(
        &self,
        permit: Permit,
        conversation: impl Into<Conversation>,
    ) -> Result<String> {
        let conversation = conversation.into();
        self.blocking(move |registry| registry.conversation_credential(&permit, &conversation))
            .await
    }
    pub(crate) fn with_file_origins(mut self, entries: &[String]) -> Result<Self> {
        let state = self.read()?;
        let now = auth::now()?;
        self.files = Arc::new(super::files::Runtime::new(entries, |id| {
            let client = state
                .clients
                .get(id)
                .context("unknown file-import client")?;
            ensure!(
                !client.revoked && client.expires_at > now,
                "file-import client is inactive"
            );
            Ok(())
        })?);
        Ok(self)
    }
    fn directory(&self) -> PathBuf {
        self.home.join("gateway")
    }
    fn read(&self) -> Result<State> {
        ensure!(
            managed_file::normalize(&self.home)? == self.home,
            "gateway node directory changed"
        );
        directory_check(&self.directory())?;
        let cfg = node_home::inspect(&self.home)?;
        ensure!(
            cfg.gateway_registry()?.as_ref() == Some(&self.id)
                && cfg.cluster.id == self.cluster
                && cfg.node.id == self.node,
            "gateway registry or node identity changed; restore its original state"
        );
        let snapshot = snapshot(&self.directory().join("state.json"))?;
        let text = snapshot
            .text
            .as_deref()
            .context("gateway registry is missing; restore it from backup")?;
        ensure!(text.len() <= MAX_BYTES, "gateway registry is too large");
        let state: State = serde_json::from_str(text)
            .map_err(|_| anyhow::anyhow!("invalid gateway registry; restore it from backup"))?;
        state.validate()?;
        ensure!(
            state.id == self.id && state.cluster == self.cluster && state.node == self.node,
            "gateway registry belongs to another node"
        );
        snapshot.verify()?;
        Ok(state)
    }
    fn save(&self, state: &State) -> Result<()> {
        state.validate()?;
        let bytes = serde_json::to_string(state)? + "\n";
        ensure!(bytes.len() <= MAX_BYTES, "gateway registry is too large");
        snapshot(&self.directory().join("state.json"))?.write(&bytes)
    }
    #[cfg(test)]
    pub(crate) fn authenticate(&self, token: &str) -> Result<Permit> {
        self.authenticate_at(token, None)
    }
    #[cfg(test)]
    fn authenticate_at(&self, token: &str, resource: Option<&str>) -> Result<Permit> {
        self.authenticate_peer(token, resource, Peer::default())
    }
    fn authenticate_peer(&self, token: &str, resource: Option<&str>, peer: Peer) -> Result<Permit> {
        directory_check(&self.directory())?;
        let _lock = managed_file::lock(&self.directory().join("state.lock"))?;
        let mut state = self.read()?;
        let now = auth::now()?;
        let mut permit = if token.starts_with("gent_a1.") {
            oauth::access_permit(
                &state,
                token,
                resource.context("OAuth requires a resource audience")?,
                now,
            )?
        } else {
            Permit {
                client: token_id(token)?.into(),
                hash: digest(token),
                oauth: None,
                peer: Peer::default(),
                conversation_handles: false,
            }
        };
        permit.peer = peer;
        permit.conversation_handles = conversations::enabled(Self::client(&state, &permit, now)?);
        if state.clock != now {
            state.clock = now;
            self.save(&state)?;
        }
        Ok(permit)
    }
    fn client<'a>(state: &'a State, permit: &Permit, now: u64) -> Result<&'a Client> {
        ensure!(now >= state.clock, "gateway clock moved backward");
        let client = state
            .clients
            .get(&permit.client)
            .context("invalid gateway credential")?;
        let valid = if permit.oauth.is_some() {
            oauth::check_access(state, permit, now).is_ok()
        } else {
            client.oauth.is_none()
                && client
                    .token_hash
                    .as_ref()
                    .is_some_and(|hash| bool::from(hash.as_bytes().ct_eq(permit.hash.as_bytes())))
        };
        ensure!(
            !client.revoked && now < client.expires_at && valid,
            "inactive gateway credential"
        );
        if let Some(policy) = &client.mtls {
            policy.verify(&permit.peer, now)?;
        }
        Ok(client)
    }
    pub(crate) fn listing(&self) -> Result<Value> {
        let state = self.read()?;
        let now = auth::now()?.max(state.clock);
        let clients: Vec<_> = state
            .clients
            .iter()
            .map(|(id, c)| {
                json!({"id":id,"name":c.name,
            "conversation_key":c.conversation_key,"expires_at":c.expires_at,"revoked":c.revoked,
            "subject_key":c.subject_key,"conversation_handles":conversations::enabled(c),
            "active":!c.revoked && now<c.expires_at,"conversations":c.bindings.len(),"oauth":c.oauth,
            "key_revision":c.key_update.as_ref().map_or(0, |u| u.revision),
            "key_export_pending":c.key_update.as_ref().is_some_and(|u| u.pending_export.is_some()),
            "mtls":c.mtls.as_ref().map(TlsPolicy::summary)})
            })
            .collect();
        Ok(
            json!({"configured":true,"running":"not_probed","security_mode":"user_controlled_gateway",
            "cluster_id":self.cluster,"node_id":self.node,"clients":clients,
            "limits":{"clients":MAX_CLIENTS,"conversations_per_client":MAX_CLIENT_BINDINGS,"conversations_total":MAX_BINDINGS}}),
        )
    }
    pub(crate) fn revoke(&self, id: &str) -> Result<Value> {
        directory_check(&self.directory())?;
        let _lock = managed_file::lock(&self.directory().join("state.lock"))?;
        let mut state = self.read()?;
        let client = state
            .clients
            .get_mut(id)
            .context("unknown gateway client ID")?;
        client.revoked = true;
        self.save(&state)?;
        Ok(
            json!({"client":id,"revoked":true,"scope":"future host requests; already accepted work and agent data are retained"}),
        )
    }
    pub(super) fn tls_policies(&self) -> Result<Vec<TlsPolicy>> {
        let state = self.read()?;
        let now = auth::now()?;
        ensure!(now >= state.clock, "gateway clock moved backward");
        Ok(state
            .clients
            .into_values()
            .filter(|c| !c.revoked && now < c.expires_at)
            .filter_map(|c| c.mtls)
            .collect())
    }
}

pub(super) fn diagnose(home: &Path) -> Result<Value> {
    let cfg = node_home::inspect(home)?;
    if cfg.gateway_registry()?.is_none() {
        ensure!(
            !home.join("gateway/state.json").try_exists()?,
            "gateway state has no pin"
        );
        return Ok(json!({"configured":false}));
    }
    let registry = Registry::inspect_existing(home)?;
    let state = registry.read()?;
    let now = auth::now()?;
    Ok(json!({"configured":true, "clock_ahead":now < state.clock,
        "active_clients":state.clients.values().filter(|c| !c.revoked && now < c.expires_at).count(),
        "running":"not_probed"}))
}

#[cfg(test)]
pub(super) fn add(home: &Path, name: &str, key: &str, out: &Path, hours: u64) -> Result<Value> {
    add_client(home, name, key, out, hours, None, None)
}

pub(super) fn add_client(
    home: &Path,
    name: &str,
    binding: impl Into<BindingKeys>,
    out: &Path,
    hours: u64,
    oauth: Option<oauth::Registration>,
    mtls: Option<TlsPolicy>,
) -> Result<Value> {
    let binding = binding.into();
    let key = binding.conversation.as_str();
    let handles = key == conversations::KEY;
    let subject_key = binding.subject;
    ensure!(
        !handles || subject_key.is_none(),
        "explicit conversations cannot use a subject metadata key"
    );
    if let Some(subject) = &subject_key {
        bindings::subject_key(subject, key)?;
        ensure!(oauth.is_some(), "subject binding requires OAuth");
    }
    let signed = oauth.as_ref().is_some_and(|r| r.assertion.is_some());
    if let Some(registration) = &oauth {
        registration.validate()?;
    }
    if let Some(policy) = &mtls {
        policy.validate()?;
    }
    config::label(name)?;
    conversation_key(key)?;
    ensure!(
        (1..=8760).contains(&hours),
        "invalid gateway credential lifetime"
    );
    let home = managed_file::normalize(home)?;
    let home = home.as_path();
    directory_check(home)?;
    ensure!(
        config::path(home).is_file(),
        "initialize this node before adding a gateway client"
    );
    let directory = home.join("gateway");
    config::private_dir(&directory)?;
    directory_check(&directory)?;
    let _lock = managed_file::lock(&directory.join("state.lock"))?;
    let cfg = node_home::inspect(home)?;
    if cfg.gateway_registry()?.is_none() {
        let file = snapshot(&directory.join("state.json"))?;
        let state = if let Some(text) = &file.text {
            let state: State = serde_json::from_str(text)
                .map_err(|_| anyhow::anyhow!("invalid gateway registry"))?;
            state.validate()?;
            ensure!(
                state.clients.is_empty()
                    && state.cluster == cfg.cluster.id
                    && state.node == cfg.node.id,
                "gateway registry pin is missing; restore it"
            );
            state
        } else {
            State {
                version: 1,
                id: Uuid::new_v4().to_string(),
                cluster: cfg.cluster.id,
                node: cfg.node.id,
                clock: auth::now()?,
                clients: BTreeMap::new(),
                oauth: None,
            }
        };
        file.write(&(serde_json::to_string(&state)? + "\n"))?;
        config::edit_local(home, |cfg| {
            ensure!(
                cfg.cluster.id == state.cluster && cfg.node.id == state.node,
                "gateway node identity changed"
            );
            cfg.set_gateway_registry(state.id.clone())
        })?;
    }
    let registry = Registry::open_locked(home)?;
    let mut state = registry.read()?;
    let out = managed_file::normalize(out)?;
    let exported = snapshot(&out)?;
    let now = auth::now()?;
    ensure!(now >= state.clock, "gateway clock moved backward");
    let value: Export = if let Some(text) = &exported.text {
        serde_json::from_str(text)
            .map_err(|_| anyhow::anyhow!("invalid gateway credential export"))?
    } else {
        ensure!(
            !state.clients.values().any(|c| c.name == name),
            "gateway client exists; restore its original private export"
        );
        ensure!(
            state.clients.len() < MAX_CLIENTS,
            "gateway client capacity reached"
        );
        let id = Uuid::new_v4().to_string();
        Export {
            version: if handles {
                6
            } else if subject_key.is_some() {
                5
            } else if signed {
                3
            } else if mtls.is_some() {
                2
            } else {
                1
            },
            registry: registry.id.clone(),
            cluster: registry.cluster.clone(),
            node: registry.node.clone(),
            client: id.clone(),
            name: name.into(),
            conversation_key: key.into(),
            subject_key: subject_key.clone(),
            token: if signed {
                None
            } else {
                Some(format!("gent_g1.{id}.{}", config::secret()))
            },
            created_at: now,
            expires_at: now + hours * 3600,
            oauth: oauth.clone(),
            mtls: mtls.clone(),
            key_revision: 0,
        }
    };
    ensure!(
        value.version
            == if handles {
                6
            } else if subject_key.is_some() {
                5
            } else if signed && value.key_revision > 0 {
                4
            } else if signed {
                3
            } else if mtls.is_some() {
                2
            } else {
                1
            }
            && value.registry == registry.id
            && value.cluster == registry.cluster
            && value.node == registry.node
            && uuid(&value.client)
            && value.name == name
            && value.conversation_key == key
            && value.subject_key == subject_key
            && value.oauth == oauth
            && value.mtls == mtls
            && (signed || value.key_revision == 0)
            && if signed {
                value.token.is_none()
            } else {
                value
                    .token
                    .as_deref()
                    .is_some_and(|t| token_id(t).is_ok_and(|id| id == value.client))
            }
            && value.created_at <= now
            && value.expires_at.checked_sub(value.created_at) == Some(hours * 3600),
        "gateway credential export does not match this node or original options"
    );
    let hash = value.token.as_deref().map(digest);
    if let Some(client) = state.clients.get(&value.client) {
        ensure!(
            client.name == name
                && client.conversation_key == key
                && client.subject_key == subject_key
                && client.token_hash == hash
                && client.export == out
                && client.created_at == value.created_at
                && client.expires_at == value.expires_at,
            "gateway client options changed"
        );
        ensure!(
            client.key_update.as_ref().map_or(0, |u| u.revision) == value.key_revision
                && client
                    .key_update
                    .as_ref()
                    .is_none_or(|u| u.pending_export.is_none()),
            "signing key update/export is incomplete; retry keys set with its original arguments"
        );
        ensure!(
            client.oauth == oauth && client.mtls == mtls,
            "gateway client authorization mode changed"
        );
        ensure!(
            !client.revoked,
            "revoked gateway credentials cannot be reactivated"
        );
    } else {
        ensure!(
            value.key_revision == 0,
            "rotated export cannot recreate a missing client; restore the registry"
        );
        if let Some(registration) = &oauth {
            ensure!(
                !state.clients.iter().any(|(id, c)| c
                    .oauth
                    .as_ref()
                    .is_some_and(|r| r.client_id(id) == registration.client_id(&value.client))),
                "OAuth client identity already registered"
            );
        }
        ensure!(
            state.clients.len() < MAX_CLIENTS && !state.clients.values().any(|c| c.name == name),
            "gateway client name or capacity conflict"
        );
        ensure!(
            now < value.expires_at,
            "gateway credential export expired before registration"
        );
        // Export first, registry second. A retry after either write reuses the
        // same secret. No bearer or signing key is printed by the command.
        exported.write(&(serde_json::to_string(&value)? + "\n"))?;
        state.version = state.version.max(if handles {
            8
        } else if subject_key.is_some() {
            6
        } else if signed {
            4
        } else if mtls.is_some() {
            3
        } else if oauth.is_some() {
            2
        } else {
            1
        });
        if signed {
            state
                .oauth
                .get_or_insert_with(oauth::Records::default)
                .enable_assertions();
        }
        state.clients.insert(
            value.client.clone(),
            Client {
                name: name.into(),
                conversation_key: key.into(),
                subject_required: subject_key.is_some(),
                subject_key,
                token_hash: hash,
                created_at: value.created_at,
                expires_at: value.expires_at,
                export: out.clone(),
                revoked: false,
                bindings: BTreeMap::new(),
                oauth,
                mtls_required: mtls.is_some(),
                mtls,
                key_update: None,
                keys_updated: false,
            },
        );
        state.clock = now;
        registry.save(&state)?;
    }
    Ok(
        json!({"client":value.client,"name":name,"credential_file":out,"expires_at":value.expires_at,
        "conversation_key":key,"conversation_handles":handles,"security_mode":"user_controlled_gateway","oauth":value.oauth,
        "mtls":value.mtls.as_ref().map(TlsPolicy::summary),
        "scope": if handles { "explicit conversation handles scoped to this connector and OAuth grant" } else { "trusted host namespace; required conversation metadata selects each agent" }}),
    )
}
