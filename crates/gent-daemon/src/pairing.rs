//! Node bootstrap over a separately authenticated private channel (currently SSH).
//! No relay is allowed to supply these snapshots, requests, or grants in plaintext.
use crate::{
    config,
    encrypted::ordered::{OrderedEndpoint, configuration::ConfigurationInvitation},
    store::{Store, now},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use fs2::FileExt;
use gent_crypto::{
    Checkpoint, NodeIdentity, SignedConfigurationGrant, SignedState, TrustAnchor, VerifiedState,
    stream::Packet,
};
use gent_protocol::{MAX_FRAME_BYTES, PairingOp};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    future::Future,
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAccess {
    pub endpoint: String,
    pub credential: String,
}
impl Drop for RelayAccess {
    fn drop(&mut self) {
        self.credential.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub anchor: TrustAnchor,
    pub checkpoint: Checkpoint,
    pub state: String,
    pub writer: String,
    pub relay: Option<RelayAccess>,
}
impl Snapshot {
    fn verify(&self, cluster: &str) -> Result<VerifiedState> {
        ensure!(self.anchor.cluster_id == cluster, "wrong pairing cluster");
        let state = VerifiedState::restore(
            self.anchor.clone(),
            self.checkpoint.clone(),
            SignedState::decode(&STANDARD.decode(&self.state)?)?,
        )?;
        state.require_fresh(now() as u64)?;
        ensure!(
            state.state().nodes.contains_key(&self.writer),
            "pairing writer is not enrolled"
        );
        Ok(state)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub packet: String,
    pub grant: String,
}
impl Invitation {
    pub(crate) fn encode(invitation: &ConfigurationInvitation) -> Result<Self> {
        Ok(Self {
            packet: STANDARD.encode(invitation.packet.encode()?),
            grant: STANDARD.encode(invitation.grant.encode()?),
        })
    }
    fn decode(&self) -> Result<ConfigurationInvitation> {
        Ok(ConfigurationInvitation {
            packet: Packet::decode(&STANDARD.decode(&self.packet)?)?,
            grant: SignedConfigurationGrant::decode(&STANDARD.decode(&self.grant)?)?,
        })
    }
}

/// Implementations must authenticate the owner endpoint independently of Gent's
/// relay and protect the entire channel, including bootstrap metadata and tokens.
pub trait Peer {
    fn call(&mut self, action: PairingOp) -> impl Future<Output = Result<Value>>;
}

pub struct Options<'a> {
    pub cluster: &'a str,
    pub name: &'a str,
    /// Override when the owner's loopback development relay has a different route here.
    pub relay_endpoint: Option<&'a str>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Seed {
    version: u8,
    cluster: String,
    name: String,
    node: String,
    package_request: Uuid,
    stream_request: Uuid,
}
struct Pending {
    dir: PathBuf,
    runtime: PathBuf,
    seed: Seed,
    node: NodeIdentity,
    _lock: fs::File,
}
impl Pending {
    fn open(home: &Path, options: &Options<'_>) -> Result<Self> {
        config::label(options.name)?;
        ensure!(
            Uuid::parse_str(options.cluster)?.to_string() == options.cluster,
            "cluster ID must be a canonical UUID"
        );
        config::private_dir(home)?;
        ensure!(
            fs::read_dir(home)?.next().is_none(),
            "node directory is already configured"
        );
        let mut name = home
            .file_name()
            .context("missing node directory name")?
            .to_os_string();
        name.push(".joining");
        let dir = home.with_file_name(name);
        config::private_dir(&dir)?;
        let lock_path = dir.join("lock");
        if fs::symlink_metadata(&lock_path).is_ok() {
            read_private_bytes(&lock_path, 0)?;
        }
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&lock_path)?;
        lock.try_lock_exclusive()
            .context("another node join is running")?;
        let key = dir.join("join.key");
        let (node, seed) = if key.exists() {
            let bytes = read_private_bytes(&key, 8192)?;
            ensure!(
                bytes.len() > 40 && &bytes[..8] == b"GENTJOIN",
                "invalid pending identity"
            );
            let seed: Seed = serde_json::from_slice(&bytes[40..])?;
            ensure!(
                seed.version == 1 && seed.cluster == options.cluster && seed.name == options.name,
                "pending join belongs to another cluster or node name"
            );
            let node = NodeIdentity::from_secret_bytes(&seed.node, bytes[8..40].try_into()?)?;
            (node, seed)
        } else {
            ensure!(
                fs::read_dir(&dir)?
                    .all(|entry| entry.is_ok_and(|entry| entry.file_name() == "lock")),
                "pending pairing identity is missing; restore its state"
            );
            let node = NodeIdentity::generate()?;
            let seed = Seed {
                version: 1,
                cluster: options.cluster.into(),
                name: options.name.into(),
                node: node.id().into(),
                package_request: Uuid::new_v4(),
                stream_request: Uuid::new_v4(),
            };
            (node, seed)
        };
        let pending = Self {
            runtime: dir.join("node"),
            dir,
            node,
            seed,
            _lock: lock,
        };
        pending.save_seed()?;
        Ok(pending)
    }
    fn save_seed(&self) -> Result<()> {
        let mut bytes = Zeroizing::new(Vec::from(b"GENTJOIN".as_slice()));
        bytes.extend_from_slice(self.node.expose_secret().as_ref());
        serde_json::to_writer(&mut *bytes, &self.seed)?;
        config::write_private(&self.dir.join("join.key"), &bytes)
    }
    fn pin(&self, state: &VerifiedState) -> Result<()> {
        let path = self.dir.join("anchor.json");
        if path.exists() {
            let anchor: TrustAnchor = serde_json::from_slice(&read_private_bytes(&path, 8192)?)?;
            ensure!(
                &anchor == state.anchor(),
                "pairing authority changed; refusing replacement"
            );
        } else {
            ensure!(
                !config::path(&self.runtime).exists(),
                "pending pairing authority pin is missing"
            );
            config::write_private(&path, &serde_json::to_vec(state.anchor())?)?;
        }
        Ok(())
    }
    fn reset_stream(&mut self) -> Result<()> {
        // A grant that expired before first receipt cannot bootstrap a stream.
        // Preserve node identity and request a fresh package/stream, never reuse a key.
        self.seed.package_request = Uuid::new_v4();
        self.seed.stream_request = Uuid::new_v4();
        self.save_seed()?;
        Ok(())
    }
}

fn read_private_bytes(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.permissions().mode() & 0o077 == 0,
        "pairing state must be a private regular file"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "pairing state is too large");
    Ok(bytes)
}

async fn catch_up(
    endpoint: &mut OrderedEndpoint<'_>,
    peer: &mut impl Peer,
    target: Option<&Checkpoint>,
) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct History {
        record: Option<String>,
    }
    // One bounded record per request; checkpoints survive interruptions.
    for _ in 0..4096 {
        let state = endpoint.authority_state()?;
        if let Some(target) = target {
            ensure!(
                state.checkpoint().revision <= target.revision,
                "configuration grant precedes local state"
            );
            if state.checkpoint().revision == target.revision {
                ensure!(state.checkpoint() == target, "pairing history fork");
                return Ok(());
            }
        }
        let value = peer
            .call(PairingOp::History {
                revision: state.checkpoint().revision,
                digest: state.checkpoint().state_hash,
            })
            .await?;
        let history: History = serde_json::from_value(value)?;
        let Some(record) = history.record else {
            ensure!(target.is_none(), "missing pairing history");
            return Ok(());
        };
        endpoint.apply_authority(&[SignedState::decode(&STANDARD.decode(record)?)?])?;
    }
    anyhow::bail!("pairing history still catching up; rerun the join command")
}

/// Join using a protected owner channel. Files stay in a sibling staging
/// directory until membership, identity, and the configuration stream are ready.
pub async fn join(home: &Path, options: Options<'_>, peer: &mut impl Peer) -> Result<Value> {
    if let Some(endpoint) = options.relay_endpoint {
        config::RelayConfig {
            endpoint: endpoint.into(),
            credential_file: "relay.key".into(),
        }
        .validate()?;
    }
    let home = std::path::absolute(home)?;
    if config::path(&home).exists() {
        let config = config::load(&home)?;
        ensure!(
            config.cluster.id == options.cluster,
            "node already belongs to another cluster"
        );
        // Loading the runtime verifies that the identity and checkpoint still exist.
        drop(Store::open(&home)?);
        return Ok(
            json!({"joined":true,"already_joined":true,"node":config.node,"cluster":config.cluster}),
        );
    }
    let mut pending = Pending::open(&home, &options)?;
    let snapshot: Snapshot = serde_json::from_value(peer.call(PairingOp::Snapshot).await?)?;
    let mut state = snapshot.verify(options.cluster)?;
    pending.pin(&state)?;
    ensure!(
        snapshot.relay.is_some(),
        "owner has no configuration relay; configure [relay] and restart its daemon before joining"
    );
    let request = pending.node.request_enrollment(
        state.anchor(),
        state.checkpoint(),
        options.name,
        now() as u64,
    )?;
    let enrolled: Snapshot = serde_json::from_value(
        peer.call(PairingOp::Enroll {
            request: STANDARD.encode(request.encode()?),
        })
        .await?,
    )?;
    state = enrolled.verify(options.cluster)?;
    pending.pin(&state)?;
    state.authorize_node(pending.node.id(), &pending.node.public_key(), now() as u64)?;
    // Both snapshots arrive directly from the SSH-authenticated owner. This is
    // bootstrap authority only; an installed runtime advances through history.
    if !config::path(&pending.runtime).exists() {
        Store::install_joined(&pending.runtime, &pending.node, &state)?;
    }
    let mut endpoint = OrderedEndpoint::open_runtime(&pending.runtime, &pending.node)?;
    ensure!(
        endpoint.authority_state()?.anchor() == state.anchor(),
        "installed pairing authority differs"
    );
    for attempt in 0..3 {
        let invite_path = pending
            .dir
            .join(format!("invitation-{}.json", pending.seed.stream_request));
        let invitation = if invite_path.exists() {
            serde_json::from_slice::<Invitation>(&read_private_bytes(
                &invite_path,
                MAX_FRAME_BYTES,
            )?)?
            .decode()?
        } else {
            let package_path = pending
                .dir
                .join(format!("package-{}", pending.seed.package_request));
            let package = if package_path.exists() {
                read_private_bytes(&package_path, 24 * 1024)?.to_vec()
            } else {
                catch_up(&mut endpoint, peer, None).await?;
                let package = endpoint.key_package(pending.seed.package_request, now() as u64)?;
                config::write_private(&package_path, &package)?;
                package
            };
            let value = peer
                .call(PairingOp::Configuration {
                    request_id: pending.seed.stream_request.to_string(),
                    peer: pending.node.id().into(),
                    key_package: STANDARD.encode(package),
                })
                .await?;
            let wire: Invitation = serde_json::from_value(value)?;
            let invitation = wire.decode()?;
            config::write_private(&invite_path, &serde_json::to_vec(&wire)?)?;
            invitation
        };
        invitation.grant.verify(state.anchor())?;
        ensure!(
            invitation.grant.grant.writer == enrolled.writer,
            "unexpected configuration writer"
        );
        if endpoint
            .configuration_streams(now() as u64)?
            .iter()
            .any(|s| s.group == invitation.packet.group())
        {
            catch_up(&mut endpoint, peer, None).await?;
            endpoint.join_configuration(&invitation, now() as u64)?;
            break;
        }
        let current = endpoint.authority_state()?;
        if current.checkpoint().revision <= invitation.grant.grant.base.revision {
            catch_up(&mut endpoint, peer, Some(&invitation.grant.grant.base)).await?;
            if endpoint
                .authority_state()?
                .require_fresh(now() as u64)
                .is_ok()
            {
                endpoint.join_configuration(&invitation, now() as u64)?;
                break;
            }
        }
        ensure!(attempt < 2, "pairing grant expired; rerun the join command");
        // Drop the endpoint's borrow while updating the pending request IDs.
        drop(endpoint);
        pending.reset_stream()?;
        endpoint = OrderedEndpoint::open_runtime(&pending.runtime, &pending.node)?;
    }
    catch_up(&mut endpoint, peer, None).await?;
    drop(endpoint);
    drop(Store::open(&pending.runtime)?); // Project the latest verified policy.
    let mut config = config::load(&pending.runtime)?;
    {
        let relay = enrolled
            .relay
            .as_ref()
            .context("owner removed its configuration relay during pairing")?;
        let settings = config::RelayConfig {
            endpoint: options.relay_endpoint.unwrap_or(&relay.endpoint).into(),
            credential_file: "relay.key".into(),
        };
        settings.validate()?;
        ensure!(
            relay.credential.len() == 64 && relay.credential.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid development relay credential"
        );
        config::write_private(
            &pending.runtime.join("relay.key"),
            relay.credential.as_bytes(),
        )?;
        config.relay = Some(settings);
    }
    config::save(&pending.runtime, &config)?;
    fs::rename(&pending.runtime, &home)
        .context("publishing joined node; destination must remain empty")?;
    fs::File::open(home.parent().context("missing home parent")?)?.sync_all()?;
    let result = json!({"joined":true,"node":config.node,"cluster":config.cluster,"configuration_relay":config.relay.is_some(),"next":["gent","--home",home,"daemon","run"]});
    // Cleanup failure does not turn a committed installation into a failed join.
    let _ = fs::remove_dir_all(&pending.dir);
    Ok(result)
}
