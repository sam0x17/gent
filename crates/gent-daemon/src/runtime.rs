//! Local signing keys and the live daemon's signed configuration transaction.
//! Keys remain on the trusted endpoint; none are exposed through RPC or MCP.
use crate::{
    config::{self, Config},
    encrypted,
};
use anyhow::{Context, Result, ensure};
use gent_crypto::{Checkpoint, NodeIdentity, OwnerKey, SignedState, TrustAnchor, VerifiedState};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"GENTKEY1";
const PEER_MAGIC: &[u8; 8] = b"GENTKEY3";
const MAX_KEY_FILE: usize = gent_crypto::MAX_STATE_BYTES + 4096;
pub(crate) const KEY_FILE: &str = "identity.key";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    node: String,
    anchor: TrustAnchor,
    genesis: SignedState,
}

pub(crate) struct Identity {
    pub node: NodeIdentity,
    pub owner: Option<OwnerKey>,
    pub initial: VerifiedState,
    home: PathBuf,
    peer_fenced: bool,
    pub(crate) legacy_service_checked: bool,
}

pub(crate) enum SigningOwner<'a> {
    Bootstrap(&'a OwnerKey),
    Successor(Box<OwnerKey>),
}
impl std::ops::Deref for SigningOwner<'_> {
    type Target = OwnerKey;
    fn deref(&self) -> &OwnerKey {
        match self {
            Self::Bootstrap(key) => key,
            Self::Successor(key) => key,
        }
    }
}

impl gent_crypto::peer::ConfigurationSigner for SigningOwner<'_> {
    fn sign_revision(
        &self,
        previous: &VerifiedState,
        state: gent_crypto::ClusterState,
    ) -> Result<SignedState> {
        (**self).sign_revision(previous, state)
    }
}

impl Identity {
    /// Called under the database's immediate transaction, including first boot.
    /// An interrupted bootstrap retries the same immutable keys and genesis.
    pub fn load_or_create(home: &Path, config: &Config, db: &Connection, now: u64) -> Result<Self> {
        let path = home.join(KEY_FILE);
        let initialized: bool =
            db.query_row("SELECT EXISTS(SELECT 1 FROM authority)", [], |r| r.get(0))?;
        let marked: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM metadata WHERE key='signed_authority')",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            !marked || initialized,
            "saved authority is missing; restore this node's state"
        );
        if fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
            ensure!(
                !initialized && !marked && config.applied_revision.is_none(),
                "signing keys are missing; restore this node's keys"
            );
            let owner = OwnerKey::generate()?;
            let generated = NodeIdentity::generate()?;
            let node =
                NodeIdentity::from_secret_bytes(&config.node.id, &generated.expose_secret())?;
            let genesis = owner.create_cluster_with_id(
                (&config.cluster.id, &config.cluster.name),
                &node,
                &config.node.name,
                config.policy.clone(),
                now,
            )?;
            let bootstrap = Bootstrap {
                node: node.id().into(),
                anchor: genesis.anchor().clone(),
                genesis: genesis.signed().clone(),
            };
            let mut bytes = Zeroizing::new(Vec::new());
            bytes.extend_from_slice(MAGIC);
            bytes.extend_from_slice(node.expose_secret().as_ref());
            bytes.extend_from_slice(owner.expose_secret().as_ref());
            serde_json::to_writer(&mut *bytes, &bootstrap)?;
            let mut file = tempfile::NamedTempFile::new_in(home)?;
            file.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
            file.write_all(&bytes)?;
            file.as_file().sync_all()?;
            file.persist_noclobber(&path).map_err(|e| e.error)?;
            fs::File::open(home)?.sync_all()?;
        }
        let identity = Self::load(home, config)?;
        if !initialized {
            ensure!(
                config.applied_revision.is_none(),
                "saved authority is missing"
            );
            encrypted::initialize_authority(db, &identity.node, &identity.initial)?;
            db.execute("INSERT INTO metadata VALUES('signed_authority','1')", [])?;
            queue_projection(db)?;
        }
        identity.state(db)?;
        Ok(identity)
    }

    /// Read and verify the immutable bootstrap without initializing a runtime.
    pub(crate) fn load(home: &Path, config: &Config) -> Result<Self> {
        let path = home.join(KEY_FILE);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.permissions().mode() & 0o077 == 0,
            "signing keys must be a private regular file"
        );
        let mut bytes = Zeroizing::new(Vec::new());
        fs::File::open(&path)?
            .take(MAX_KEY_FILE as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() > 40 && bytes.len() <= MAX_KEY_FILE,
            "invalid signing key file"
        );
        let peer_fenced = &bytes[..8] == PEER_MAGIC;
        if peer_fenced {
            let variant = bytes.remove(8);
            ensure!(
                matches!(variant, b'1' | b'2'),
                "invalid peer identity format"
            );
            bytes[..8].copy_from_slice(if variant == b'1' { MAGIC } else { b"GENTKEY2" });
        }
        let (node, owner, initial) = if &bytes[..8] == MAGIC {
            ensure!(bytes.len() > 72, "invalid signing key file");
            let bootstrap: Bootstrap = serde_json::from_slice(&bytes[72..])?;
            let node = NodeIdentity::from_secret_bytes(&bootstrap.node, bytes[8..40].try_into()?)?;
            let owner = OwnerKey::from_secret_bytes(bytes[40..72].try_into()?);
            ensure!(
                owner.public_key() == bootstrap.anchor.owner_key,
                "wrong owner signing key"
            );
            (
                node,
                Some(owner),
                VerifiedState::bootstrap(bootstrap.anchor, bootstrap.genesis)?,
            )
        } else {
            ensure!(&bytes[..8] == b"GENTKEY2", "unsupported signing key file");
            let bootstrap: JoinedBootstrap = serde_json::from_slice(&bytes[40..])?;
            let node = NodeIdentity::from_secret_bytes(&bootstrap.node, bytes[8..40].try_into()?)?;
            (
                node,
                None,
                VerifiedState::restore(bootstrap.anchor, bootstrap.checkpoint, bootstrap.state)?,
            )
        };
        ensure!(
            node.id() == config.node.id && initial.anchor().cluster_id == config.cluster.id,
            "signing keys belong to another node or cluster"
        );
        ensure!(
            initial
                .state()
                .nodes
                .get(node.id())
                .is_some_and(|n| n.signing_key == node.public_key()),
            "node signing key does not match initial authority"
        );
        Ok(Self {
            node,
            owner,
            initial,
            home: home.into(),
            peer_fenced,
            legacy_service_checked: true,
        })
    }

    pub fn is_current_owner(&self, state: &VerifiedState) -> bool {
        if state.state().peer.is_some() {
            return false;
        }
        if let Some(successor) = state
            .state()
            .owner_transitions
            .last()
            .and_then(|t| t.transition.successor.as_ref())
        {
            return successor.node.id == self.node.id()
                && successor.node.signing_key == self.node.public_key();
        }
        state.owner_epoch() == 0
            && self
                .owner
                .as_ref()
                .is_some_and(|key| key.public_key() == state.state().owner_key)
    }

    pub fn was_owner(&self, state: &VerifiedState) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|key| key.public_key() == state.anchor().owner_key)
            || state.state().owner_transitions.iter().any(|t| {
                t.transition.successor.as_ref().is_some_and(|s| {
                    s.node.id == self.node.id() && s.node.signing_key == self.node.public_key()
                })
            })
    }

    pub fn signing_owner(&self, db: &Connection) -> Result<SigningOwner<'_>> {
        ensure!(
            !self.peer_fenced,
            "configuration migration has fenced legacy signing"
        );
        ensure!(
            self.legacy_service_checked,
            "checking the cluster authority; legacy changes wait for relay reconciliation"
        );
        self.migration_owner(db)
    }

    pub(crate) fn legacy_signing_fenced(&self) -> bool {
        self.peer_fenced
    }

    pub(crate) fn has_configuration_grant(&self, state: &VerifiedState) -> bool {
        state
            .state()
            .nodes
            .get(self.node.id())
            .is_some_and(|n| n.can_configure && n.signing_key == self.node.public_key())
    }

    pub(crate) fn can_administer(&self, state: &VerifiedState) -> bool {
        if state.state().peer.is_some() {
            self.has_configuration_grant(state)
        } else {
            self.is_current_owner(state) && !self.peer_fenced
        }
    }

    pub(crate) fn require_administrator(&self, db: &Connection) -> Result<()> {
        ensure!(
            self.can_administer(&self.state(db)?),
            "this node cannot administer the cluster"
        );
        Ok(())
    }

    /// This key can only prepare the one transition; it cannot be used by
    /// ordinary mutation paths after the identity file has been fenced.
    pub(super) fn migration_owner(&self, db: &Connection) -> Result<SigningOwner<'_>> {
        let state = self.state(db)?;
        ensure!(
            state.state().peer.is_none(),
            "legacy owner authority is retired"
        );
        ensure!(
            self.is_current_owner(&state),
            "local owner signing key is retired or belongs to another node"
        );
        ensure!(
            !crate::store::handoff::frozen(db, &state)?,
            "owner handoff is issued; signing is frozen until activation completes"
        );
        if state.owner_epoch() == 0 {
            return Ok(SigningOwner::Bootstrap(
                self.owner
                    .as_ref()
                    .context("owner signing key is missing")?,
            ));
        }
        Ok(SigningOwner::Successor(Box::new(
            crate::store::handoff::active_key(&self.home, db, &state, &self.node)?,
        )))
    }

    /// Persist this before committing a migration journal. Older executables
    /// reject GENTKEY3, including a binary restored by updater rollback. A
    /// crash before the journal commit leaves legacy signing fenced; the new
    /// executable can reconstruct the transition from its pinned old state.
    pub(super) fn fence_peer_authority(&mut self) -> Result<()> {
        let path = self.home.join(KEY_FILE);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.permissions().mode() & 0o077 == 0,
            "identity must remain a private regular file"
        );
        let mut old = Zeroizing::new(Vec::new());
        fs::File::open(&path)?
            .take(MAX_KEY_FILE as u64 + 1)
            .read_to_end(&mut old)?;
        ensure!(
            old.len() <= MAX_KEY_FILE,
            "identity file exceeds its size limit"
        );
        if old.len() > 41 && &old[..8] == PEER_MAGIC {
            ensure!(
                matches!(old[8], b'1' | b'2'),
                "invalid peer identity format"
            );
            self.peer_fenced = true;
            fs::File::open(&self.home)?.sync_all()?;
            return Ok(());
        }
        ensure!(
            old.len() > 40 && matches!(&old[..8], b"GENTKEY1" | b"GENTKEY2"),
            "identity changed during migration"
        );
        let mut fenced = Zeroizing::new(Vec::with_capacity(old.len() + 1));
        fenced.extend_from_slice(PEER_MAGIC);
        fenced.push(old[7]);
        fenced.extend_from_slice(&old[8..]);
        // Mark the process first too: a directory-sync error can follow a
        // successful rename and must not reopen the old signing path.
        self.peer_fenced = true;
        config::write_private(&path, &fenced)
    }

    pub fn state(&self, db: &Connection) -> Result<VerifiedState> {
        let state = encrypted::authority(db, &self.node)?;
        ensure!(
            state.anchor() == self.initial.anchor(),
            "authority does not match pinned identity"
        );
        Ok(state)
    }

    /// History is also the durable configuration publication queue. Each peer's
    /// stream cursor consumes it in revision order; no TOML write gates sync.
    pub fn apply(&self, db: &Connection, update: SignedState) -> Result<VerifiedState> {
        let mut state = self.state(db)?;
        state.advance_history(std::slice::from_ref(&update))?;
        encrypted::persist_authority(db, &self.node, &state, &[update])?;
        queue_projection(db)?;
        Ok(state)
    }
}

pub(crate) fn queue_projection(db: &Connection) -> Result<()> {
    db.execute("INSERT INTO metadata VALUES('config_projection','pending') ON CONFLICT(key) DO UPDATE SET value=excluded.value", [])?;
    Ok(())
}

pub(crate) fn projection_pending(db: &Connection) -> Result<bool> {
    Ok(db
        .query_row(
            "SELECT value FROM metadata WHERE key='config_projection'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .is_some())
}

/// Only the newest committed signed state is projected. Retries never replay an
/// older snapshot over a newer revision. The caller holds an immediate lock.
pub(crate) fn project(home: &Path, db: &Connection, identity: &Identity) -> Result<()> {
    if !projection_pending(db)? {
        return Ok(());
    }
    let state = identity.state(db)?;
    let mut disk = config::load_for_runtime(home)?;
    ensure!(
        disk.node.id == identity.node.id() && disk.cluster.id == state.anchor().cluster_id,
        "cannot change active identities while daemon runs"
    );
    disk.policy = state.state().policy.clone();
    disk.cluster.name.clone_from(&state.state().name);
    disk.node.name.clone_from(
        &state
            .state()
            .nodes
            .get(identity.node.id())
            .context("local node is no longer enrolled")?
            .name,
    );
    disk.applied_revision = Some(state.checkpoint().revision);
    config::save(home, &disk)?;
    db.execute("DELETE FROM metadata WHERE key='config_projection'", [])?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinedBootstrap {
    node: String,
    anchor: TrustAnchor,
    checkpoint: Checkpoint,
    state: SignedState,
}

/// Trusted enrollment boundary: the caller must already have authenticated this
/// anchor and complete enrollment history. No relay or MCP input invokes this.
pub(crate) fn install_joined(
    home: &Path,
    node: &NodeIdentity,
    state: &VerifiedState,
) -> Result<()> {
    install_joined_checkpoint(home, node, state, None, b"[]")
}

pub(crate) fn install_joined_checkpoint(
    home: &Path,
    node: &NodeIdentity,
    state: &VerifiedState,
    commit: Option<&gent_protocol::configuration_log::Commit>,
    decisions: &[u8],
) -> Result<()> {
    ensure!(
        state.state().peer.is_some() == commit.is_some(),
        "peer enrollment requires its committed checkpoint"
    );
    state.authorize_node(node.id(), &node.public_key(), crate::store::now() as u64)?;
    config::private_dir(home)?;
    ensure!(
        fs::read_dir(home)?.next().is_none(),
        "node directory is already configured"
    );
    let parent = home.parent().context("missing node directory parent")?;
    let staging = tempfile::tempdir_in(parent)?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend_from_slice(if commit.is_some() {
        b"GENTKEY32"
    } else {
        b"GENTKEY2".as_slice()
    });
    bytes.extend_from_slice(node.expose_secret().as_ref());
    serde_json::to_writer(
        &mut *bytes,
        &JoinedBootstrap {
            node: node.id().into(),
            anchor: state.anchor().clone(),
            checkpoint: state.checkpoint().clone(),
            state: state.signed().clone(),
        },
    )?;
    config::write_private(&staging.path().join(KEY_FILE), &bytes)?;
    config::write_private(&staging.path().join("state.sqlite3"), &[])?;
    config::binding(&staging.path().join("owner.key"))?;
    config::save(
        staging.path(),
        &Config {
            version: 1,
            applied_revision: None,
            node: config::NodeConfig {
                id: node.id().into(),
                name: state.state().nodes[node.id()].name.clone(),
            },
            cluster: config::ClusterConfig {
                id: state.anchor().cluster_id.clone(),
                name: state.state().name.clone(),
                local_only: true,
            },
            relay: None,
            service: None,
            policy: state.state().policy.clone(),
            extra: Default::default(),
        },
    )?;
    if let Some(commit) = commit {
        let db = encrypted::open_database(staging.path(), "state.sqlite3")?;
        crate::store::peer_configuration::install_checkpoint(&db, node, state, commit, decisions)?;
    }
    drop(crate::store::Store::open(staging.path())?);
    // Renaming over the empty destination publishes the whole initialized node.
    // A concurrent writer making the destination nonempty causes rename to fail.
    fs::rename(staging.path(), home)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
