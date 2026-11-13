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
    #[serde(default)]
    pub policy: Policy,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
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
        value.trim().len() == 64 && value.trim().bytes().all(|b| b.is_ascii_hexdigit()),
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
    write_private(&path(home), toml::to_string_pretty(config)?.as_bytes())
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        self.validate_local()?;
        label(&self.node.name)?;
        label(&self.cluster.name)?;
        gent_crypto::validate_policy(&self.policy)?;
        Ok(())
    }
    fn validate_local(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported configuration version");
        ensure!(
            self.cluster.local_only,
            "this build supports local proofs only; remote enrollment is not implemented"
        );
        for value in [&self.node.id, &self.cluster.id] {
            let parsed =
                uuid::Uuid::parse_str(value).context("invalid node or cluster identity")?;
            ensure!(
                !parsed.is_nil() && parsed.to_string() == *value,
                "identity must be a canonical nonzero UUID"
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
    let config = Config {
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
        policy: Policy::default(),
        extra: BTreeMap::new(),
    };
    binding(&home.join("owner.key"))?;
    save(home, &config)?;
    Ok(config)
}
