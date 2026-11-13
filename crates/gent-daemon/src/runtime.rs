//! Local signing keys and the live daemon's signed configuration transaction.
//! Keys remain on the trusted endpoint; none are exposed through RPC or MCP.
use crate::{
    config::{self, Config},
    encrypted,
};
use anyhow::{Context, Result, ensure};
use gent_crypto::{NodeIdentity, OwnerKey, SignedState, TrustAnchor, VerifiedState};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"GENTKEY1";
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
    pub owner: OwnerKey,
    pub genesis: VerifiedState,
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
            bytes.len() > 72 && bytes.len() <= MAX_KEY_FILE && &bytes[..8] == MAGIC,
            "invalid signing key file"
        );
        let bootstrap: Bootstrap = serde_json::from_slice(&bytes[72..])?;
        ensure!(
            bootstrap.node == config.node.id && bootstrap.anchor.cluster_id == config.cluster.id,
            "signing keys belong to another node or cluster"
        );
        let node = NodeIdentity::from_secret_bytes(&bootstrap.node, bytes[8..40].try_into()?)?;
        let owner = OwnerKey::from_secret_bytes(bytes[40..72].try_into()?);
        ensure!(
            owner.public_key() == bootstrap.anchor.owner_key,
            "wrong owner signing key"
        );
        let genesis = VerifiedState::bootstrap(bootstrap.anchor, bootstrap.genesis)?;
        ensure!(
            genesis
                .state()
                .nodes
                .get(node.id())
                .is_some_and(|n| n.signing_key == node.public_key()),
            "node signing key does not match genesis"
        );
        if !initialized {
            ensure!(
                config.applied_revision.is_none(),
                "saved authority is missing"
            );
            encrypted::initialize_authority(db, &node, &genesis)?;
            db.execute("INSERT INTO metadata VALUES('signed_authority','1')", [])?;
            queue_projection(db)?;
        }
        let identity = Self {
            node,
            owner,
            genesis,
        };
        identity.state(db)?;
        Ok(identity)
    }

    pub fn state(&self, db: &Connection) -> Result<VerifiedState> {
        let state = encrypted::authority(db, &self.node)?;
        ensure!(
            state.anchor() == self.genesis.anchor(),
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
