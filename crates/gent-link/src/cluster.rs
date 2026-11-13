//! Recoverable first-owner setup. Cryptographic invitation enrollment is a
//! separate operation; service credentials never establish cluster trust.
use crate::{
    auth,
    managed_file::{self, Snapshot},
};
use anyhow::{Context, Result, ensure};
use gent_daemon::{
    config::{self, Config, RelayConfig},
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
            let setup = Setup {
                version: 1,
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
    Store::open(&home)?.require_provisioning_owner()?;
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
    service.reserve_cluster(&setup.cluster_id).await?;
    if setup.credential.is_none() {
        setup.candidate(&service, &home)?;
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
        setup.candidate(&service, &home)?;
    }
    let session = session.context("transport provisioning did not finish")?;
    let credential = setup.credential.as_mut().expect("candidate saved");
    credential.confirmed = true;
    setup.save(&home)?;
    config_snapshot.verify()?;
    credential_snapshot.write(&setup.credential.as_ref().expect("candidate saved").token)?;
    config.cluster.local_only = false;
    config_snapshot.write(&toml_edit::ser::to_string_pretty(&config)?)?;
    Ok(json!({"status":"configured", "service":setup.service,
        "cluster":config.cluster,"node":config.node,"relay_endpoint":setup.relay_endpoint,
        "credential_expires_at":session.expires_at,
        "next":"gent daemon install"}))
}
