use anyhow::{Context, Result, bail, ensure};
use gent_protocol::Policy;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub id: String,
    pub name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub id: String,
    pub name: String,
    pub local_only: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    /// Last signed revision projected to this file; edits require config apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_revision: Option<u64>,
    pub node: NodeConfig,
    pub cluster: ClusterConfig,
    /// Node-local transport settings are never replicated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayConfig>,
    /// Account routing metadata, local to this node and never replicated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceConfig>,
    #[serde(default)]
    pub policy: Policy,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

/// Machine-local selection only. These records never enter signed authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contexts {
    pub version: u32,
    pub active_cluster: String,
    pub profiles: BTreeMap<String, ContextProfile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextProfile {
    pub home: PathBuf,
    pub node_id: String,
}

impl Contexts {
    pub const LIMIT: usize = 128;
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && !self.profiles.is_empty() && self.profiles.len() <= Self::LIMIT,
            "invalid cluster profile registry"
        );
        ensure!(
            self.profiles.contains_key(&self.active_cluster),
            "active cluster is missing from the profile registry"
        );
        let mut homes = std::collections::BTreeSet::new();
        for (cluster, profile) in &self.profiles {
            for id in [cluster, &profile.node_id] {
                ensure!(
                    uuid::Uuid::parse_str(id).is_ok_and(|u| !u.is_nil() && u.to_string() == *id),
                    "invalid cluster profile identity"
                );
            }
            let text = profile
                .home
                .to_str()
                .context("profile path must be UTF-8")?;
            ensure!(
                profile.home.is_absolute()
                    && !text.chars().any(char::is_control)
                    && homes.insert(profile.home.clone()),
                "cluster profiles require distinct absolute directories"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub origin: String,
    pub account_id: String,
}
impl ServiceConfig {
    pub fn validate(&self) -> Result<()> {
        RelayConfig {
            endpoint: self.origin.clone(),
            credential_file: "unused".into(),
        }
        .validate()?;
        let id = uuid::Uuid::parse_str(&self.account_id).context("invalid service account")?;
        ensure!(
            !id.is_nil() && id.to_string() == self.account_id,
            "invalid service account"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    pub endpoint: String,
    pub credential_file: PathBuf,
}
impl RelayConfig {
    pub fn validate(&self) -> Result<reqwest::Url> {
        let url = reqwest::Url::parse(&self.endpoint)?;
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "relay endpoint must be an origin without credentials, path, query, or fragment"
        );
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
        ensure!(
            url.scheme() == "https" || (url.scheme() == "http" && loopback),
            "relay requires HTTPS except on loopback"
        );
        ensure!(
            !self.credential_file.as_os_str().is_empty(),
            "relay credential file is required"
        );
        Ok(url)
    }
}

pub fn secret() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

pub fn private_dir(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "state directory must be a real directory, not a symlink"
        );
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "state directory must be private (mode 0700); choose a dedicated directory"
        );
        return Ok(());
    }
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    Ok(())
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("missing parent directory")?;
    private_dir(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn read_private(path: &Path) -> Result<String> {
    read_credential(path, false)
}

/// Relay transport accepts a service-issued node credential or the local proof
/// token. Owner RPC and agent binding readers retain their separate format.
pub fn read_relay_credential(path: &Path) -> Result<String> {
    read_credential(path, true)
}

fn read_credential(path: &Path, relay: bool) -> Result<String> {
    let metadata = fs::symlink_metadata(path).context("credential file is unavailable")?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "credential must be a regular file"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "credential file must not be accessible to other users"
    );
    let value = fs::read_to_string(path)?;
    ensure!(
        (value.trim().len() == 64 && value.trim().bytes().all(|b| b.is_ascii_hexdigit()))
            || (relay && gent_protocol::service::transport_created_at(value.trim()).is_some()),
        "invalid credential file"
    );
    Ok(value.trim().into())
}

pub fn binding(path: &Path) -> Result<String> {
    if path.exists() {
        return read_private(path);
    }
    let parent = path.parent().context("missing binding directory")?;
    private_dir(parent)?;
    let value = secret();
    // create_new makes concurrent initialization fail rather than changing a live identity.
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(value.as_bytes())?;
    file.sync_all()?;
    Ok(value)
}

pub fn path(home: &Path) -> PathBuf {
    home.join("config.toml")
}
pub fn load(home: &Path) -> Result<Config> {
    let config = load_for_runtime(home)?;
    config.validate()?;
    Ok(config)
}
/// Read local identity/settings while allowing an unapplied shared-policy edit.
/// Existing runtime authority comes from the verified database, not this file.
pub(crate) fn load_for_runtime(home: &Path) -> Result<Config> {
    let config: Config = toml::from_str(
        &fs::read_to_string(path(home))
            .context("no Gent configuration; run gent cluster new <name> --local")?,
    )?;
    config.validate_local()?;
    Ok(config)
}
pub fn save(home: &Path, config: &Config) -> Result<()> {
    config.validate()?;
    private_dir(home)?;
    let _lock = configuration_lock(home)?;
    let mut next = config.clone();
    // A daemon may have loaded its projection before a concurrent switch.
    // Preserve the latest local registry inside the shared filesystem lock.
    if path(home).exists() {
        let previous = load_for_runtime(home)?;
        if let Some(contexts) = previous.contexts()? {
            ensure!(
                previous.cluster.id == next.cluster.id && previous.node.id == next.node.id,
                "cannot replace the identity of a registered cluster profile"
            );
            next.set_contexts(contexts)?;
        }
    }
    next.validate()?;
    write_private(&path(home), toml::to_string_pretty(&next)?.as_bytes())
}

/// Serialize local settings edits with daemon projections. The closure reads
/// the latest file under the same lock used by save, so two edits cannot merge
/// stale copies of the registry. This does not change signed cluster policy.
pub fn edit_local<T>(home: &Path, edit: impl FnOnce(&mut Config) -> Result<T>) -> Result<T> {
    let _lock = configuration_lock(home)?;
    let mut config = load_for_runtime(home)?;
    let result = edit(&mut config)?;
    config.validate_local()?;
    write_private(&path(home), toml::to_string_pretty(&config)?.as_bytes())?;
    Ok(result)
}

fn configuration_lock(home: &Path) -> Result<fs::File> {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        match state_lock(home, "config.lock") {
            Ok(lock) => return Ok(lock),
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock)
                }) =>
            {
                ensure!(
                    std::time::Instant::now() < until,
                    "configuration is busy; retry the command"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}
impl Config {
    pub fn contexts(&self) -> Result<Option<Contexts>> {
        self.extra
            .get("contexts")
            .cloned()
            .map(|value| -> Result<Contexts> {
                let contexts: Contexts = value
                    .try_into()
                    .context("invalid cluster profile registry")?;
                contexts.validate()?;
                let own = contexts
                    .profiles
                    .get(&self.cluster.id)
                    .context("original cluster profile is missing")?;
                ensure!(
                    own.node_id == self.node.id,
                    "original node does not match its profile"
                );
                Ok(contexts)
            })
            .transpose()
    }
    pub fn set_contexts(&mut self, contexts: Contexts) -> Result<()> {
        contexts.validate()?;
        self.extra
            .insert("contexts".into(), toml::Value::try_from(contexts)?);
        self.version = 2;
        self.contexts()?;
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_local()?;
        label(&self.node.name)?;
        label(&self.cluster.name)?;
        gent_crypto::validate_policy(&self.policy)?;
        Ok(())
    }
    /// Check routing and identity without rejecting an unapplied shared-policy
    /// edit. Live policy authority comes from the verified daemon database.
    pub fn validate_local(&self) -> Result<()> {
        ensure!(
            matches!(self.version, 1 | 2),
            "unsupported configuration version"
        );
        ensure!(
            self.contexts()?.is_some() == (self.version == 2),
            "configuration version does not match its profile registry"
        );
        ensure!(
            self.cluster.local_only || self.relay.is_some(),
            "a service cluster requires a configured relay"
        );
        for value in [&self.node.id, &self.cluster.id] {
            let parsed =
                uuid::Uuid::parse_str(value).context("invalid node or cluster identity")?;
            ensure!(
                !parsed.is_nil() && parsed.to_string() == *value,
                "identity must be a canonical nonzero UUID"
            );
        }
        if let Some(relay) = &self.relay {
            relay.validate()?;
        }
        if let Some(service) = &self.service {
            service.validate()?;
            ensure!(
                !self.cluster.local_only && self.relay.is_some(),
                "service metadata requires service transport"
            );
        }
        Ok(())
    }
}
pub fn label(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control),
        "label must contain 1-128 bytes without control characters"
    );
    Ok(())
}
pub fn initialize(home: &Path, name: &str) -> Result<Config> {
    label(name)?;
    private_dir(home)?;
    if path(home).exists() {
        bail!("already configured; existing identity has been preserved");
    }
    ensure!(
        !pending_join(home)?.exists(),
        "a node join is pending; rerun gent cluster join to preserve its identity"
    );
    let config = fresh(name)?;
    binding(&home.join("owner.key"))?;
    save(home, &config)?;
    Ok(config)
}

/// Allocate identities without publishing state. Hosted setup journals this
/// configuration before any filesystem or service operation can be retried.
pub fn fresh(name: &str) -> Result<Config> {
    label(name)?;
    Ok(Config {
        version: 1,
        applied_revision: None,
        node: NodeConfig {
            id: uuid::Uuid::new_v4().to_string(),
            name: std::env::var("HOSTNAME")
                .ok()
                .filter(|s| label(s).is_ok())
                .unwrap_or_else(|| "my-node".into()),
        },
        cluster: ClusterConfig {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            local_only: true,
        },
        relay: None,
        service: None,
        policy: Policy::default(),
        extra: BTreeMap::new(),
    })
}

pub fn pending_join(home: &Path) -> Result<PathBuf> {
    let mut name = home
        .file_name()
        .context("missing node directory name")?
        .to_os_string();
    name.push(".joining");
    Ok(home.with_file_name(name))
}

/// Persistent lock files stay in the final home across installation. Never
/// rename or remove them: that could split writers between different inodes.
pub fn state_lock(home: &Path, name: &str) -> Result<fs::File> {
    use fs2::FileExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = home.join(name);
    if let Ok(meta) = fs::symlink_metadata(&path) {
        ensure!(
            meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.nlink() == 1
                && meta.permissions().mode() & 0o077 == 0,
            "state lock must be a private regular file"
        );
    }
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    lock.try_lock_exclusive()
        .context("node is busy; stop its daemon or wait for the other setup command")?;
    Ok(lock)
}
