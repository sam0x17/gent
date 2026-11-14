use super::mtls::{Peer, Policy as TlsPolicy};
use crate::{
    auth, contexts,
    managed_file::{self, Snapshot},
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
}
#[derive(Clone)]
pub(crate) struct Permit {
    client: String,
    hash: String,
    oauth: Option<(String, String)>,
    peer: Peer,
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
    token_hash: String,
    created_at: u64,
    expires_at: u64,
    export: PathBuf,
    revoked: bool,
    bindings: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oauth: Option<oauth::Registration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mtls: Option<TlsPolicy>,
    // The separate requirement marker rejects partial records that lose a
    // certificate policy while other mTLS clients keep the registry at v3.
    #[serde(default, skip_serializing_if = "is_false")]
    mtls_required: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    version: u32,
    registry: String,
    cluster: String,
    node: String,
    client: String,
    name: String,
    conversation_key: String,
    token: String,
    created_at: u64,
    expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oauth: Option<oauth::Registration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mtls: Option<TlsPolicy>,
}

fn uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|v| !v.is_nil() && v.to_string() == value)
}
fn is_false(value: &bool) -> bool {
    !*value
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
        ensure!(
            self.version
                == if mtls {
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
        let mut count = 0;
        for (id, client) in &self.clients {
            config::label(&client.name)?;
            metadata_key(&client.conversation_key)?;
            if let Some(registration) = &client.oauth {
                registration.validate()?;
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
                    && hash(&client.token_hash)
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
                    .all(|(key, credential)| hash(key) && hash(credential)),
                "invalid gateway binding record"
            );
            count += client.bindings.len();
        }
        ensure!(count <= MAX_BINDINGS, "gateway binding capacity exceeded");
        if let Some(records) = &self.oauth {
            records.validate(self)?;
        }
        Ok(())
    }
}

impl Registry {
    pub(crate) fn open(home: &Path) -> Result<Self> {
        let home = managed_file::normalize(home)?;
        directory_check(&home.join("gateway"))?;
        let _lock = managed_file::lock(&home.join("gateway/state.lock"))?;
        Self::open_locked(&home)
    }
    fn open_locked(home: &Path) -> Result<Self> {
        let home = managed_file::normalize(home)?;
        let cfg = contexts::inspect(&home)?;
        let id = cfg
            .gateway_registry()?
            .context("configure a host with gent gateway clients add first")?;
        let value = Self {
            home,
            id,
            cluster: cfg.cluster.id,
            node: cfg.node.id,
            workers: Arc::new(tokio::sync::Semaphore::new(MAX_WORKERS)),
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
    pub(crate) async fn credential_remote(&self, permit: Permit, meta: Value) -> Result<String> {
        self.blocking(move |registry| registry.credential(&permit, &meta))
            .await
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
        let cfg = contexts::inspect(&self.home)?;
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
            }
        };
        permit.peer = peer;
        Self::client(&state, &permit, now)?;
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
                && bool::from(client.token_hash.as_bytes().ct_eq(permit.hash.as_bytes()))
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
    pub(crate) fn credential(&self, permit: &Permit, meta: &Value) -> Result<String> {
        directory_check(&self.directory())?;
        let _lock = managed_file::lock(&self.directory().join("state.lock"))?;
        let mut state = self.read()?;
        let now = auth::now()?;
        let client = Self::client(&state, permit, now)?;
        conversation_key(&client.conversation_key)?;
        let conversation=meta.get(&client.conversation_key).and_then(Value::as_str)
            .filter(|s|!s.trim().is_empty() && s.len()<=512 && !s.chars().any(char::is_control))
            .context("host conversation metadata is missing or invalid; this connection cannot select an agent")?;
        let key = digest(conversation);
        let credential = if let Some(value) = client.bindings.get(&key) {
            value.clone()
        } else {
            ensure!(
                client.bindings.len() < MAX_CLIENT_BINDINGS
                    && state
                        .clients
                        .values()
                        .map(|c| c.bindings.len())
                        .sum::<usize>()
                        < MAX_BINDINGS,
                "gateway conversation capacity reached"
            );
            config::secret()
        };
        let dirty = state.clock != now || !client.bindings.contains_key(&key);
        if dirty {
            state.clock = now;
            state
                .clients
                .get_mut(&permit.client)
                .expect("client checked")
                .bindings
                .insert(key, credential.clone());
            self.save(&state)?;
        }
        Ok(credential)
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
            "active":!c.revoked && now<c.expires_at,"conversations":c.bindings.len(),"oauth":c.oauth,
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

#[cfg(test)]
pub(super) fn add(home: &Path, name: &str, key: &str, out: &Path, hours: u64) -> Result<Value> {
    add_client(home, name, key, out, hours, None, None)
}

pub(super) fn add_client(
    home: &Path,
    name: &str,
    key: &str,
    out: &Path,
    hours: u64,
    oauth: Option<oauth::Registration>,
    mtls: Option<TlsPolicy>,
) -> Result<Value> {
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
    let cfg = contexts::inspect(home)?;
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
            version: if mtls.is_some() { 2 } else { 1 },
            registry: registry.id.clone(),
            cluster: registry.cluster.clone(),
            node: registry.node.clone(),
            client: id.clone(),
            name: name.into(),
            conversation_key: key.into(),
            token: format!("gent_g1.{id}.{}", config::secret()),
            created_at: now,
            expires_at: now + hours * 3600,
            oauth: oauth.clone(),
            mtls: mtls.clone(),
        }
    };
    ensure!(
        value.version == if mtls.is_some() { 2 } else { 1 }
            && value.registry == registry.id
            && value.cluster == registry.cluster
            && value.node == registry.node
            && value.name == name
            && value.conversation_key == key
            && value.oauth == oauth
            && value.mtls == mtls
            && token_id(&value.token)? == value.client
            && value.created_at <= now
            && value.expires_at.checked_sub(value.created_at) == Some(hours * 3600),
        "gateway credential export does not match this node or original options"
    );
    let hash = digest(&value.token);
    if let Some(client) = state.clients.get(&value.client) {
        ensure!(
            client.name == name
                && client.conversation_key == key
                && client.token_hash == hash
                && client.export == out
                && client.created_at == value.created_at
                && client.expires_at == value.expires_at,
            "gateway client options changed"
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
        state.version = state.version.max(if mtls.is_some() {
            3
        } else if oauth.is_some() {
            2
        } else {
            1
        });
        state.clients.insert(
            value.client.clone(),
            Client {
                name: name.into(),
                conversation_key: key.into(),
                token_hash: hash,
                created_at: value.created_at,
                expires_at: value.expires_at,
                export: out.clone(),
                revoked: false,
                bindings: BTreeMap::new(),
                oauth,
                mtls_required: mtls.is_some(),
                mtls,
            },
        );
        state.clock = now;
        registry.save(&state)?;
    }
    Ok(
        json!({"client":value.client,"name":name,"credential_file":out,"expires_at":value.expires_at,
        "conversation_key":key,"security_mode":"user_controlled_gateway","oauth":value.oauth,
        "mtls":value.mtls.as_ref().map(TlsPolicy::summary),
        "scope":"trusted host namespace; required conversation metadata selects each agent"}),
    )
}
