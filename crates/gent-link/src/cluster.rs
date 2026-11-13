//! Recoverable service setup for owners and SSH-enrolled nodes. Service
//! credentials never establish cryptographic cluster trust.
use crate::{
    auth,
    managed_file::{self, Snapshot},
};
use anyhow::{Context, Result, ensure};
use gent_daemon::{
    config::{self, Config, RelayConfig, ServiceConfig},
    pairing::ServiceRelay,
    store::Store,
};
use gent_protocol::service::{TransportSession, transport_created_at};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

const RECORD: &str = "service.json";
const CREDENTIAL: &str = "relay.key";

// No Debug: the journal contains a pending or confirmed transport credential.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    version: u8,
    #[serde(default)]
    role: SetupRole,
    service: String,
    account_id: String,
    cluster_id: String,
    node_id: String,
    name: String,
    relay_endpoint: String,
    /// Cleared once config.toml exists. A later missing config requires restore.
    initial: Option<Config>,
    credential: Option<Credential>,
}

#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SetupRole {
    #[default]
    Owner,
    Joined,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    token: String,
    session_hash: String,
    /// An observed admission means this token cannot be created again after
    /// revocation. An unconfirmed candidate must outlive its admission window.
    confirmed: bool,
}

fn private_snapshot(path: &Path) -> Result<Snapshot> {
    let snapshot = Snapshot::read(path)?;
    snapshot.private()?;
    Ok(snapshot)
}
fn read(home: &Path) -> Result<Option<Setup>> {
    let snapshot = private_snapshot(&home.join(RECORD))?;
    snapshot
        .text
        .map(|text| {
            let value: Setup = serde_json::from_str(&text).map_err(|_| {
                anyhow::anyhow!("invalid service setup record; restore it from backup")
            })?;
            value.validate()?;
            Ok(value)
        })
        .transpose()
}
impl Setup {
    fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported service setup record");
        for id in [&self.cluster_id, &self.node_id] {
            ensure!(
                uuid::Uuid::parse_str(id).is_ok_and(|u| !u.is_nil() && u.to_string() == *id),
                "invalid setup identity"
            );
        }
        auth::origin(&self.service)?;
        auth::origin(&self.relay_endpoint)?;
        config::label(&self.name)?;
        if let Some(initial) = &self.initial {
            ensure!(
                self.role == SetupRole::Owner,
                "joined setup cannot initialize owner keys"
            );
            initial.validate()?;
            ensure!(
                initial.node.id == self.node_id && initial.cluster.id == self.cluster_id,
                "setup identities do not match"
            );
        }
        if let Some(credential) = &self.credential {
            ensure!(
                transport_created_at(&credential.token).is_some()
                    && credential.session_hash.len() == 64
                    && credential
                        .session_hash
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit()),
                "invalid setup credential"
            );
        }
        Ok(())
    }
    fn save(&self, home: &Path) -> Result<()> {
        self.validate()?;
        private_snapshot(&home.join(RECORD))?.write(&(serde_json::to_string(self)? + "\n"))
    }
    fn verify_config(&self, config: &Config) -> Result<()> {
        ensure!(
            config.node.id == self.node_id && config.cluster.id == self.cluster_id,
            "configuration belongs to another node or cluster; existing state was preserved"
        );
        Ok(())
    }
    fn verify_transport(&self, session: &TransportSession) -> Result<()> {
        ensure!(
            session.cluster_id == self.cluster_id
                && session.node_id == self.node_id
                && session.expires_at > auth::now()?,
            "unexpected or expired transport session"
        );
        Ok(())
    }
    fn candidate(&mut self, service: &auth::Service, home: &Path) -> Result<()> {
        self.credential = Some(Credential {
            token: auth::transport_candidate()?,
            session_hash: service.session_hash(),
            confirmed: false,
        });
        // Persist before sending any admission request.
        self.save(home)
    }

    fn account(&self) -> ServiceConfig {
        ServiceConfig {
            origin: self.service.clone(),
            account_id: self.account_id.clone(),
        }
    }
}

fn locks(home: &Path) -> Result<(PathBuf, fs::File, fs::File)> {
    let home = managed_file::normalize(home)?;
    config::private_dir(&home)?;
    managed_file::directory(&home)?;
    let service = managed_file::lock(&home.join("service.lock"))?;
    let daemon = managed_file::lock(&home.join("daemon.lock"))
        .context("stop the daemon with gent daemon stop before configuring this node")?;
    Ok((home, service, daemon))
}

pub fn local(home: &Path, name: &str) -> Result<Config> {
    let (home, _service, _daemon) = locks(home)?;
    ensure!(
        private_snapshot(&home.join(RECORD))?.text.is_none(),
        "service setup is pending; resume it with gent cluster connect"
    );
    if !config::path(&home).exists() {
        ensure!(
            fs::read_dir(&home)?.all(|e| e.is_ok_and(|e| matches!(
                e.file_name().to_str(),
                Some("auth" | "service.lock" | "daemon.lock")
            ))),
            "state exists without config.toml; restore it before creating a cluster"
        );
    }
    config::initialize(&home, name)
}

/// None resumes setup or refreshes an invalid, previously confirmed credential.
pub async fn connect(home: &Path, name: Option<&str>) -> Result<Value> {
    if let Some(name) = name {
        config::label(name)?;
    }
    let (home, _service_lock, _daemon_lock) = locks(home)?;
    let service = auth::Service::open(&home).await?;
    let mut setup = match read(&home)? {
        Some(setup) => {
            ensure!(
                auth::origin(&setup.service)? == service.origin()?
                    && setup.account_id == service.session.account_id,
                "this node is pinned to another service or account; sign into its original account"
            );
            ensure!(
                name.is_none_or(|name| name == setup.name),
                "already configured under a different name; use gent cluster connect to resume"
            );
            setup
        }
        None => {
            let name = name.context("no service setup to resume; run gent cluster new NAME")?;
            ensure!(
                !config::pending_join(&home)?.exists(),
                "a node join is pending; rerun gent cluster join to preserve its identity"
            );
            ensure!(
                private_snapshot(&config::path(&home))?.text.is_none(),
                "already configured; existing identity has been preserved"
            );
            // An auth-only home is normal. Missing configuration alongside
            // runtime state is a recovery problem, not permission to reset it.
            ensure!(
                fs::read_dir(&home)?.all(|e| e.is_ok_and(|e| matches!(
                    e.file_name().to_str(),
                    Some("auth" | "service.lock" | "daemon.lock")
                ))),
                "state exists without config.toml; restore it before creating a cluster"
            );
            let relay_endpoint = service.relay_endpoint().await?;
            let mut initial = config::fresh(name)?;
            initial.cluster.local_only = false;
            initial.relay = Some(RelayConfig {
                endpoint: relay_endpoint.clone(),
                credential_file: home.join(CREDENTIAL),
            });
            initial.service = Some(ServiceConfig {
                origin: service.origin()?.into(),
                account_id: service.session.account_id.clone(),
            });
            let setup = Setup {
                version: 1,
                role: SetupRole::Owner,
                service: service.origin()?.into(),
                account_id: service.session.account_id.clone(),
                cluster_id: initial.cluster.id.clone(),
                node_id: initial.node.id.clone(),
                name: name.into(),
                relay_endpoint,
                initial: Some(initial),
                credential: None,
            };
            setup.save(&home)?;
            setup
        }
    };
    let config_snapshot = private_snapshot(&config::path(&home))?;
    if config_snapshot.text.is_none() {
        let initial = setup
            .initial
            .as_ref()
            .context("configuration is missing; restore it before reconnecting")?;
        ensure!(
            !home.join("identity.key").exists() && !home.join("state.sqlite3").exists(),
            "runtime state exists without configuration; restore it before reconnecting"
        );
        config::binding(&home.join("owner.key"))?;
        config_snapshot.write(&toml_edit::ser::to_string_pretty(initial)?)?;
    }
    setup.verify_config(&config::load(&home)?)?;
    setup.initial = None;
    setup.save(&home)?;
    // Keys and signed genesis are durable before any service cluster is created.
    match setup.role {
        SetupRole::Owner => Store::open(&home)?.require_provisioning_owner()?,
        SetupRole::Joined => Store::open(&home)?.require_provisioning_joined()?,
    }
    let mut config = config::load(&home)?;
    setup.verify_config(&config)?;
    let config_snapshot = private_snapshot(&config::path(&home))?;
    let credential_snapshot = private_snapshot(&home.join(CREDENTIAL))?;
    ensure!(
        config
            .relay
            .as_ref()
            .is_some_and(|r| r.endpoint == setup.relay_endpoint
                && r.credential_file == home.join(CREDENTIAL)),
        "relay settings changed; restore the pinned endpoint before reconnecting"
    );
    ensure!(
        config
            .service
            .as_ref()
            .is_none_or(|s| *s == setup.account()),
        "local service metadata changed"
    );
    match setup.role {
        SetupRole::Owner => service.reserve_cluster(&setup.cluster_id).await?,
        SetupRole::Joined => service.require_cluster_owner(&setup.cluster_id).await?,
    }
    let session = provision(&mut setup, &service, &home).await?;
    config_snapshot.verify()?;
    credential_snapshot.write(&setup.credential.as_ref().expect("candidate saved").token)?;
    config.cluster.local_only = false;
    config.service = Some(setup.account());
    config_snapshot.write(&toml_edit::ser::to_string_pretty(&config)?)?;
    Ok(json!({"status":"configured", "service":setup.service,
        "cluster":config.cluster,"node":config.node,"relay_endpoint":setup.relay_endpoint,
        "credential_expires_at":session.expires_at,
        "next":"gent daemon install"}))
}

async fn provision(
    setup: &mut Setup,
    service: &auth::Service,
    home: &Path,
) -> Result<TransportSession> {
    if setup.credential.is_none() {
        setup.candidate(service, home)?;
    }
    let mut session = None;
    // At most one candidate replacement. Ambiguous failures keep their exact
    // token so a retry cannot consume another slot or orphan a live credential.
    for attempt in 0..2 {
        let credential = setup.credential.as_ref().expect("candidate saved");
        if let Some(found) = service.transport_session(&credential.token).await? {
            setup.verify_transport(&found)?;
            session = Some(found);
            break;
        }
        if !credential.confirmed
            && let Some(found) = service
                .enroll(&setup.cluster_id, &setup.node_id, &credential.token)
                .await
                .with_context(|| if credential.session_hash == service.session_hash() {
                    "could not provision this node; retry gent cluster connect"
                } else {
                    "pending credential belongs to an earlier sign-in; retry after its 15-minute admission window closes"
                })?
        {
            setup.verify_transport(&found)?;
            ensure!(
                found.expires_at <= service.session.expires_at,
                "transport credential outlives its issuing session"
            );
            session = Some(found);
            break;
        }
        ensure!(
            attempt == 0,
            "credential could not be admitted; check the system clock and retry"
        );
        setup.candidate(service, home)?;
    }
    let session = session.context("transport provisioning did not finish")?;
    let credential = setup.credential.as_mut().expect("candidate saved");
    credential.confirmed = true;
    setup.save(home)?;
    Ok(session)
}

/// The caller holds final-home daemon/service locks and this login's lock. The
/// staged runtime already has an SSH-approved node-only signing identity.
pub(crate) async fn provision_joined(
    runtime: &Path,
    home: &Path,
    service: &auth::Service,
    relay: &ServiceRelay,
) -> Result<()> {
    Store::open(runtime)?.require_provisioning_joined()?;
    let mut config = config::load(runtime)?;
    service.require_cluster_owner(&config.cluster.id).await?;
    let mut setup = match read(runtime)? {
        Some(setup) => {
            setup.verify_config(&config)?;
            ensure!(
                setup.role == SetupRole::Joined
                    && setup.account() == relay.account
                    && setup.relay_endpoint == relay.relay_endpoint,
                "joined service setup changed"
            );
            setup
        }
        None => {
            ensure!(
                config.service.is_none(),
                "service setup record is missing; restore it before reconnecting"
            );
            let setup = Setup {
                version: 1,
                role: SetupRole::Joined,
                service: relay.account.origin.clone(),
                account_id: relay.account.account_id.clone(),
                cluster_id: config.cluster.id.clone(),
                node_id: config.node.id.clone(),
                name: config.cluster.name.clone(),
                relay_endpoint: relay.relay_endpoint.clone(),
                initial: None,
                credential: None,
            };
            setup.save(runtime)?;
            setup
        }
    };
    ensure!(
        setup.account_id == service.session.account_id
            && auth::origin(&setup.service)? == service.origin()?,
        "joined account changed"
    );
    let settings = RelayConfig {
        endpoint: setup.relay_endpoint.clone(),
        credential_file: home.join(CREDENTIAL),
    };
    ensure!(
        config
            .service
            .as_ref()
            .is_none_or(|s| *s == setup.account())
            && config
                .relay
                .as_ref()
                .is_none_or(|r| r.endpoint == settings.endpoint
                    && r.credential_file == settings.credential_file),
        "joined transport settings changed"
    );
    let config_snapshot = private_snapshot(&config::path(runtime))?;
    let credential_snapshot = private_snapshot(&runtime.join(CREDENTIAL))?;
    provision(&mut setup, service, runtime).await?;
    config_snapshot.verify()?;
    credential_snapshot.write(&setup.credential.as_ref().expect("candidate saved").token)?;
    config.cluster.local_only = false;
    config.relay = Some(settings);
    config.service = Some(setup.account());
    config_snapshot.write(&toml_edit::ser::to_string_pretty(&config)?)?;
    Ok(())
}
