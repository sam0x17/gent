//! One session store and lock can serve several managed cluster profiles.
//! References bind the source directory, node, cluster, account and service.
use super::*;
use gent_daemon::config::{self, AccountSource, Config};
use std::path::PathBuf;

const FILE: &str = "account-source.json";

#[derive(Debug)]
pub(crate) struct LoginRequired;
impl std::fmt::Display for LoginRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("sign in with gent auth login before adding a service profile")
    }
}
impl std::error::Error for LoginRequired {}
pub(crate) struct Location {
    pub directory: PathBuf,
    pub source: Option<AccountSource>,
}
impl Location {
    pub fn open(home: &Path) -> Result<Self> {
        let local = managed_file::normalize(&home.join("auth"))?;
        let marker = Snapshot::read(&local.join(FILE))?;
        marker.private()?;
        let source: Option<AccountSource> = marker
            .text
            .as_ref()
            .map(|text| {
                serde_json::from_str(text).map_err(|_| {
                    anyhow::anyhow!("invalid account source record; restore it from backup")
                })
            })
            .transpose()?;
        let snapshot = Snapshot::read(&config::path(home))?;
        snapshot.private()?;
        if let Some(text) = snapshot.text.as_deref() {
            let cfg: Config = toml::from_str(text)?;
            cfg.validate_local()?;
            if let Some(pin) = cfg.account_source()? {
                ensure!(
                    source.as_ref() == Some(&pin),
                    "account source record is missing or changed; restore this profile's state"
                );
            }
        }
        if let Some(source) = &source {
            verify(source)?;
            ensure!(
                managed_file::normalize(home)? != source.home,
                "account source cannot refer to itself"
            );
            ensure!(
                Snapshot::read(&local.join("session.json"))?.text.is_none(),
                "shared and local account sessions conflict; restore this profile's account state"
            );
        }
        marker.verify()?;
        snapshot.verify()?;
        let directory = source
            .as_ref()
            .map(|s| s.home.join("auth"))
            .unwrap_or(local);
        Ok(Self { directory, source })
    }
    pub fn check_service(&self, origin_value: &str) -> Result<()> {
        if let Some(source) = &self.source {
            ensure!(
                origin(origin_value)? == origin(&source.service.origin)?,
                "shared login is pinned to its original account service"
            );
        }
        Ok(())
    }
    pub fn check_session(&self, session: &ServiceSession) -> Result<()> {
        if let Some(source) = &self.source {
            ensure!(
                session.account_id == source.service.account_id,
                "shared login belongs to another account; sign into the source profile's original account"
            );
        }
        Ok(())
    }
    pub(super) fn check_saved(&self, saved: &Saved) -> Result<()> {
        self.check_service(&saved.service)?;
        if let Some(session) = &saved.session {
            self.check_session(session)?;
        }
        Ok(())
    }
    pub fn describe(&self, mut value: Value) -> Value {
        if let Some(source) = &self.source {
            value["shared_account"] = json!({"source_cluster":source.cluster_id,"home":source.home,
                "scope":"login, renewal and logout affect every profile using this account store"});
        }
        value
    }
}

fn verify(source: &AccountSource) -> Result<()> {
    source.validate()?;
    ensure!(
        managed_file::normalize(&source.home)? == source.home,
        "account source directory changed"
    );
    let cfg = crate::contexts::inspect(&source.home)?;
    ensure!(
        cfg.cluster.id == source.cluster_id
            && cfg.node.id == source.node_id
            && cfg.account_source()?.is_none(),
        "account source identity changed; chained account references are not supported"
    );
    ensure!(
        Snapshot::read(&source.home.join("auth").join(FILE))?
            .text
            .is_none(),
        "account source must be a direct session store"
    );
    ensure!(
        managed_file::normalize(&source.home.join("auth"))? == source.home.join("auth"),
        "account source directory changed"
    );
    Ok(())
}

pub(crate) fn share(home: &Path) -> Result<AccountSource> {
    let location = Location::open(home)?;
    let saved = read(&location.directory.join("session.json"))?.ok_or(LoginRequired)?;
    location.check_saved(&saved)?;
    if saved.phase == Phase::Pending {
        return Err(LoginRequired.into());
    }
    ensure!(
        saved.phase == Phase::Active,
        "finish gent auth login or logout before adding a service profile"
    );
    if let Some(source) = location.source {
        return Ok(source);
    }
    let cfg = crate::contexts::inspect(home)?;
    let source = AccountSource {
        version: 1,
        home: managed_file::normalize(home)?,
        cluster_id: cfg.cluster.id,
        node_id: cfg.node.id,
        service: config::ServiceConfig {
            origin: origin(&saved.service)?.into(),
            account_id: saved
                .session
                .context("saved account is missing")?
                .account_id,
        },
    };
    verify(&source)?;
    Ok(source)
}

pub(crate) fn link(home: &Path, source: &AccountSource) -> Result<()> {
    verify(source)?;
    ensure!(
        managed_file::normalize(home)? != source.home,
        "account source cannot refer to itself"
    );
    let directory = managed_file::normalize(&home.join("auth"))?;
    config::private_dir(&directory)?;
    let _lock = managed_file::lock(&directory.join("session.lock"))?;
    ensure!(
        Snapshot::read(&directory.join("session.json"))?
            .text
            .is_none(),
        "profile already has its own account session"
    );
    let marker = Snapshot::read(&directory.join(FILE))?;
    marker.private()?;
    if let Some(text) = &marker.text {
        let saved: AccountSource =
            serde_json::from_str(text).context("invalid account source record")?;
        ensure!(saved == *source, "profile account source changed");
    } else {
        // Established configuration never authorizes reconstructing a lost pin.
        if config::path(home).exists() {
            ensure!(
                crate::contexts::inspect(home)?.account_source()?.is_none(),
                "account source record is missing; restore it"
            );
        }
        marker.write(&(serde_json::to_string(source)? + "\n"))?;
    }
    Ok(())
}

pub(crate) fn apply(home: &Path, cfg: &mut Config) -> Result<()> {
    if let Some(source) = Location::open(home)?.source {
        cfg.set_account_source(source)?;
    }
    Ok(())
}

pub(crate) fn optional(home: &Path) -> Result<Option<AccountSource>> {
    let location = Location::open(home)?;
    if read(&location.directory.join("session.json"))?.is_none() {
        return Ok(None);
    }
    share(home).map(Some)
}
