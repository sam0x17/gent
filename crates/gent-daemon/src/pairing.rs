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
    Checkpoint, NodeIdentity, ReplacedNode, SignedConfigurationGrant, SignedState, TrustAnchor,
    VerifiedState, stream::Packet,
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
mod publication;
pub(crate) mod replacement;
pub use replacement::installed_replacement;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceRelay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<gent_protocol::configuration_log::Commit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_decisions: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRelay {
    pub account: config::ServiceConfig,
    pub relay_endpoint: String,
}
impl Snapshot {
    fn verify(&self, cluster: &str) -> Result<VerifiedState> {
        ensure!(self.anchor.cluster_id == cluster, "wrong pairing cluster");
        ensure!(
            self.relay.is_none() || self.service.is_none(),
            "ambiguous pairing transport"
        );
        if let Some(service) = &self.service {
            service.account.validate()?;
            config::RelayConfig {
                endpoint: service.relay_endpoint.clone(),
                credential_file: "relay.key".into(),
            }
            .validate()?;
        }
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
    /// Invitation channels prove this persisted identity before requesting any
    /// snapshot. SSH peers already authenticate through the owner's login.
    fn prepare_node(
        &mut self,
        _node: &NodeIdentity,
        _name: &str,
    ) -> impl Future<Output = Result<()>> {
        async { Ok(()) }
    }
    fn call(&mut self, action: PairingOp) -> impl Future<Output = Result<Value>>;
    /// Called with the committed node while setup and daemon locks are held.
    /// A receipt failure must not invalidate an already-published installation.
    fn published(&mut self, _node: &NodeIdentity, _name: &str) -> impl Future<Output = Result<()>> {
        async { Ok(()) }
    }
    fn prepare_service(&mut self, _service: &ServiceRelay) -> impl Future<Output = Result<()>> {
        async { anyhow::bail!("this pairing client does not support service enrollment") }
    }
    fn provision_service(
        &mut self,
        _runtime: &Path,
        _home: &Path,
        _service: &ServiceRelay,
    ) -> impl Future<Output = Result<()>> {
        async { anyhow::bail!("this pairing client does not support service enrollment") }
    }
}

pub struct Options<'a> {
    pub cluster: &'a str,
    pub name: &'a str,
    /// Override when the owner's loopback development relay has a different route here.
    pub relay_endpoint: Option<&'a str>,
    /// Explicit owner-authorized replacement of a lost joined node.
    pub replace_node: Option<&'a str>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replace_node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replacement: Option<ReplacedNode>,
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
        if let Some(id) = options.replace_node {
            ensure!(
                Uuid::parse_str(id).is_ok_and(|u| !u.is_nil() && u.to_string() == id),
                "replacement node must be a canonical UUID"
            );
        }
        ensure!(
            Uuid::parse_str(options.cluster)?.to_string() == options.cluster,
            "cluster ID must be a canonical UUID"
        );
        config::private_dir(home)?;
        let dir = config::pending_join(home)?;
        publication::check_home(home, &dir)?;
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
                seed.version == 1
                    && seed.cluster == options.cluster
                    && seed.name == options.name
                    && seed.replace_node.as_deref() == options.replace_node,
                "pending join belongs to another cluster, node name or replacement target"
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
                replace_node: options.replace_node.map(str::to_owned),
                replacement: None,
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

    fn pin_service(&self, service: &Option<ServiceRelay>) -> Result<()> {
        let path = self.dir.join("service-pin.json");
        if path.exists() {
            let previous: Option<ServiceRelay> =
                serde_json::from_slice(&read_private_bytes(&path, 8192)?)?;
            ensure!(
                previous == *service,
                "pairing service changed; restore the original service settings"
            );
        } else {
            // A pre-service pending join must not be converted mid-bootstrap.
            ensure!(
                service.is_none() || !config::path(&self.runtime).exists(),
                "pending join has no service pin"
            );
            config::write_private(&path, &serde_json::to_vec(service)?)?;
        }
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
    home: &Path,
    endpoint: &mut OrderedEndpoint<'_>,
    peer: &mut impl Peer,
    target: Option<&Checkpoint>,
) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct History {
        record: Option<String>,
        #[serde(default)]
        commit: Option<gent_protocol::configuration_log::Commit>,
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
        if let Some(commit) = history.commit {
            ensure!(history.record.is_none(), "ambiguous pairing history");
            Store::open(home)?.accept_configuration_commit(&commit)?;
            continue;
        }
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
    crate::recovery::ensure_active(home)?;
    if let Some(endpoint) = options.relay_endpoint {
        config::RelayConfig {
            endpoint: endpoint.into(),
            credential_file: "relay.key".into(),
        }
        .validate()?;
    }
    let home = std::path::absolute(home)?;
    config::private_dir(&home)?;
    let home = fs::canonicalize(home)?;
    let _service_lock = config::state_lock(&home, "service.lock")?;
    let _daemon_lock = config::state_lock(&home, "daemon.lock")?;
    if config::path(&home).exists() {
        let config = config::load(&home)?;
        replacement::check_intent(&home, &config, options.replace_node)?;
        ensure!(
            config.cluster.id == options.cluster,
            "node already belongs to another cluster"
        );
        // Loading the runtime verifies that the identity and checkpoint still exist.
        let store = Store::open(&home)?;
        let local_node = store.pairing_node()?;
        if store.needs_data_pairing()? {
            let node = store.pairing_node()?;
            drop(store);
            peer.prepare_node(&node, &config.node.name).await?;
            let snapshot: Snapshot = serde_json::from_value(peer.call(PairingOp::Snapshot).await?)?;
            let state = snapshot.verify(options.cluster)?;
            let mut endpoint = OrderedEndpoint::open_runtime(&home, &node)?;
            ensure!(
                endpoint.authority_state()?.anchor() == state.anchor(),
                "pairing authority changed"
            );
            catch_up(&home, &mut endpoint, peer, None).await?;
            drop(endpoint);
            connect_data(&home, &node, &snapshot.writer, peer).await?;
        }
        if let Some(account) = &config.service {
            let service = ServiceRelay {
                account: account.clone(),
                relay_endpoint: config
                    .relay
                    .as_ref()
                    .context("missing service relay")?
                    .endpoint
                    .clone(),
            };
            ensure!(
                options.relay_endpoint.is_none(),
                "service relay overrides are not supported"
            );
            peer.prepare_service(&service).await?;
            peer.provision_service(&home, &home, &service).await?;
        }
        cleanup_published(&home, &local_node);
        peer.published(&local_node, &config.node.name).await?;
        return Ok(
            json!({"joined":true,"already_joined":true,"node":config.node,"cluster":config.cluster}),
        );
    }
    let mut pending = Pending::open(&home, &options)?;
    if publication::started(&pending.dir) {
        let staged = config::load(&pending.runtime)?;
        let service = staged
            .service
            .as_ref()
            .map(|account| -> Result<_> {
                Ok(ServiceRelay {
                    account: account.clone(),
                    relay_endpoint: staged
                        .relay
                        .as_ref()
                        .context("missing staged relay")?
                        .endpoint
                        .clone(),
                })
            })
            .transpose()?;
        pending.pin_service(&service)?;
        if let Some(service) = &service {
            ensure!(
                options.relay_endpoint.is_none(),
                "service relay overrides are not supported"
            );
            peer.prepare_service(service).await?;
        }
        let config = publication::publish(&home, &pending)?;
        let _ = fs::remove_dir_all(&pending.dir);
        if let Some(service) = &service {
            peer.provision_service(&home, &home, service).await?;
        }
        peer.published(&pending.node, &config.node.name).await?;
        return Ok(
            json!({"joined":true,"node":config.node,"cluster":config.cluster,"configuration_relay":true,"next":"gent daemon install"}),
        );
    }
    peer.prepare_node(&pending.node, options.name).await?;
    let snapshot: Snapshot = serde_json::from_value(peer.call(PairingOp::Snapshot).await?)?;
    let mut state = snapshot.verify(options.cluster)?;
    pending.pin(&state)?;
    pending.pin_replacement(&state, &snapshot.writer)?;
    pending.pin_service(&snapshot.service)?;
    if let Some(service) = &snapshot.service {
        ensure!(
            options.relay_endpoint.is_none(),
            "service relay overrides are not supported"
        );
        peer.prepare_service(service).await?;
    }
    ensure!(
        snapshot.relay.is_some() || snapshot.service.is_some(),
        "owner has no configuration relay; configure [relay] and restart its daemon before joining"
    );
    let request = match &pending.seed.replacement {
        Some(target) => pending.node.request_replacement(
            state.anchor(),
            state.checkpoint(),
            options.name,
            target.clone(),
            now() as u64,
        )?,
        None => pending.node.request_enrollment(
            state.anchor(),
            state.checkpoint(),
            options.name,
            now() as u64,
        )?,
    };
    let action = PairingOp::Enroll {
        request: STANDARD.encode(request.encode()?),
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    let enrolled: Snapshot = loop {
        let value = peer.call(action.clone()).await?;
        if value["state"] != "pending" {
            break serde_json::from_value(value)?;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "configuration enrollment is still pending; retry the same join code"
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    };
    state = enrolled.verify(options.cluster)?;
    pending.pin(&state)?;
    pending.pin_service(&enrolled.service)?;
    state.authorize_node(pending.node.id(), &pending.node.public_key(), now() as u64)?;
    if let Some(target) = &pending.seed.replacement {
        ensure!(
            !state.state().nodes.contains_key(&target.id)
                && state.state().retired_nodes.contains(&target.id)
                && state.state().retired_keys.contains(&target.signing_key),
            "owner did not retire the replacement target"
        );
    }
    // Both snapshots arrive through an independently authenticated owner channel. This is
    // bootstrap authority only; an installed runtime advances through history.
    if !config::path(&pending.runtime).exists() {
        crate::runtime::install_joined_checkpoint(
            &pending.runtime,
            &pending.node,
            &state,
            enrolled.configuration.as_ref(),
            &if enrolled.configuration.is_some() {
                STANDARD.decode(
                    enrolled
                        .configuration_decisions
                        .as_ref()
                        .context("configuration retry history is missing from enrollment")?,
                )?
            } else {
                b"[]".to_vec()
            },
        )?;
    }
    pending.save_replacement()?;
    let mut endpoint = OrderedEndpoint::open_runtime(&pending.runtime, &pending.node)?;
    ensure!(
        endpoint.authority_state()?.anchor() == state.anchor(),
        "installed pairing authority differs"
    );
    for attempt in 0..if state.state().peer.is_some() { 0 } else { 3 } {
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
                catch_up(&pending.runtime, &mut endpoint, peer, None).await?;
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
            catch_up(&pending.runtime, &mut endpoint, peer, None).await?;
            endpoint.join_configuration(&invitation, now() as u64)?;
            break;
        }
        let current = endpoint.authority_state()?;
        if current.checkpoint().revision <= invitation.grant.grant.base.revision {
            catch_up(
                &pending.runtime,
                &mut endpoint,
                peer,
                Some(&invitation.grant.grant.base),
            )
            .await?;
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
    catch_up(&pending.runtime, &mut endpoint, peer, None).await?;
    drop(endpoint);
    connect_data(&pending.runtime, &pending.node, &enrolled.writer, peer).await?;
    drop(Store::open(&pending.runtime)?); // Project the latest verified policy.
    let mut config = config::load(&pending.runtime)?;
    if let Some(service) = &enrolled.service {
        peer.provision_service(&pending.runtime, &home, service)
            .await?;
        config = config::load(&pending.runtime)?;
    } else {
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
    let config = publication::publish(&home, &pending)?;
    peer.published(&pending.node, &config.node.name).await?;
    let result = json!({"joined":true,"node":config.node,"cluster":config.cluster,"configuration_relay":config.relay.is_some(),"next":["gent","--home",home,"daemon","run"]});
    // Cleanup failure does not turn a committed installation into a failed join.
    let _ = fs::remove_dir_all(&pending.dir);
    Ok(result)
}

fn cleanup_published(home: &Path, node: &NodeIdentity) {
    let Ok(dir) = config::pending_join(home) else {
        return;
    };
    if !publication::started(&dir) {
        return;
    }
    let Ok(bytes) = read_private_bytes(&dir.join("join.key"), 8192) else {
        return;
    };
    if bytes.len() > 40 && &bytes[..8] == b"GENTJOIN" && bytes[8..40] == *node.expose_secret() {
        // This node is already committed and verified. A crash after publishing
        // config.toml may have left its private staging copies behind.
        let _ = fs::remove_dir_all(dir);
    }
}

/// Establish independent writer streams in both directions through the same
/// authenticated channel as enrollment. Request IDs persist before any network call.
async fn connect_data(
    home: &Path,
    node: &NodeIdentity,
    writer: &str,
    peer: &mut impl Peer,
) -> Result<()> {
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PendingData {
        request: Uuid,
        peer: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DataInvitation {
        packet: String,
        key_package: String,
        legacy: Vec<gent_crypto::SignedLegacyAgentBinding>,
    }
    let path = home.join(format!("data-pairing-{writer}.json"));
    let saved = if path.exists() {
        serde_json::from_slice::<PendingData>(&read_private_bytes(&path, 4096)?)?
    } else {
        let saved = PendingData {
            request: Uuid::new_v4(),
            peer: writer.into(),
        };
        config::write_private(&path, &serde_json::to_vec(&saved)?)?;
        saved
    };
    ensure!(
        saved.peer == writer && !saved.request.is_nil(),
        "invalid saved data pairing"
    );
    let mut endpoint = OrderedEndpoint::open_runtime(home, node)?;
    let package = endpoint.key_package(saved.request, now() as u64)?;
    let store = Store::open(home)?;
    let legacy_agents = store.legacy_registrations()?;
    drop(store);
    let invitation: DataInvitation = serde_json::from_value(
        peer.call(PairingOp::Data {
            request_id: saved.request.to_string(),
            peer: node.id().into(),
            key_package: STANDARD.encode(package),
            legacy_agents,
        })
        .await?,
    )?;
    catch_up(home, &mut endpoint, peer, None).await?;
    let incoming = Packet::decode(&STANDARD.decode(invitation.packet)?)?;
    endpoint.join(&incoming, writer, &[node.id(), writer], now() as u64)?;
    let reverse_id =
        gent_crypto::scoped_id(b"gent/pair-return-stream/v1\0", &[saved.request.as_bytes()]);
    let outgoing = endpoint.create(
        reverse_id,
        &[(writer, &STANDARD.decode(invitation.key_package)?)],
        now() as u64,
    )?;
    let response = peer
        .call(PairingOp::AcceptData {
            peer: node.id().into(),
            packet: STANDARD.encode(outgoing.encode()?),
            outgoing_group: STANDARD.encode(incoming.group()),
        })
        .await?;
    ensure!(
        response.get("connected") == Some(&Value::Bool(true)),
        "invalid data pairing response"
    );
    drop(endpoint);
    Store::open(home)?.install_data_link(
        writer,
        outgoing.group(),
        incoming.group(),
        &invitation.legacy,
    )?;
    Ok(())
}
