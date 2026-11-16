//! Local retirement, not identity migration. A sibling journal survives rename
//! so an interrupted reset can finish without archiving a newly enrolled node.
use super::*;
use crate::{integration, service};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, os::unix::fs::MetadataExt};

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
}
impl Identity {
    fn read(path: &Path) -> Result<Self> {
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.uid() == rustix::process::geteuid().as_raw()
                && meta.mode() & 0o077 == 0,
            "node reset requires private directories owned by this user"
        );
        Ok(Self {
            device: meta.dev(),
            inode: meta.ino(),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    home: PathBuf,
    archive: PathBuf,
    original: Identity,
    pending_join: Option<Identity>,
    homes: Vec<PathBuf>,
}

fn sibling(home: &Path, suffix: &str) -> Result<PathBuf> {
    let name = home.file_name().context("cannot reset a filesystem root")?;
    let mut name = name.to_os_string();
    name.push(suffix);
    Ok(home.with_file_name(name))
}

pub(super) fn ensure_idle(home: &Path) -> Result<()> {
    // Installed legacy children must also stop while their root is resetting.
    for ancestor in home.ancestors().filter(|p| p.file_name().is_some()) {
        ensure!(
            !sibling(ancestor, ".reset.json")?.try_exists()?,
            "node reset is incomplete; rerun gent node reset before using this node"
        );
    }
    Ok(())
}

fn legacy_homes(home: &Path) -> Result<Vec<PathBuf>> {
    let mut homes = BTreeSet::from([home.to_path_buf()]);
    // Include incomplete, unregistered setup directories, not just the registry.
    let children = home.join("clusters");
    if children.try_exists()? {
        Identity::read(&children)?;
        for entry in fs::read_dir(&children)? {
            let path = entry?.path();
            ensure!(
                homes.len() < 65,
                "too many legacy node directories to reset"
            );
            Identity::read(&path)?;
            homes.insert(path);
        }
    }
    let snapshot = Snapshot::read(&config::path(home))?;
    snapshot.private()?;
    if let Some(text) = snapshot.text {
        // A reset may archive invalid configuration, but must never follow an
        // external registry path or a shared login into somebody else's state.
        let value: toml::Value =
            toml::from_str(&text).context("repair config.toml syntax before resetting")?;
        ensure!(
            value.get("account_source").is_none(),
            "reset the original ~/.gent directory, not a legacy child"
        );
        if let Some(profiles) = value
            .get("contexts")
            .and_then(|v| v.get("profiles"))
            .and_then(|v| v.as_table())
        {
            for profile in profiles.values() {
                let path = PathBuf::from(
                    profile
                        .get("home")
                        .and_then(|v| v.as_str())
                        .context("invalid legacy node path")?,
                );
                ensure!(
                    path == managed_file::normalize(&path)?
                        && (path == home || path.parent() == Some(children.as_path())),
                    "legacy registry points outside this node; retire that external installation before resetting"
                );
                if path.try_exists()? {
                    Identity::read(&path)?;
                    homes.insert(path);
                }
            }
        }
    }
    ensure!(
        !home.join("auth/account-source.json").try_exists()?,
        "reset the original ~/.gent directory, not a legacy child"
    );
    Ok(homes.into_iter().collect())
}

fn load(home: &Path, snapshot: &Snapshot) -> Result<Journal> {
    snapshot.private()?;
    let job: Journal =
        serde_json::from_str(snapshot.text.as_deref().context("reset journal missing")?)
            .context("invalid node reset journal; preserve it and the archived state")?;
    ensure!(
        job.version == 1
            && job.home == home
            && job.archive.parent() == home.parent()
            && job.archive != home
            && managed_file::normalize(&job.archive)? == job.archive
            && !job.homes.is_empty()
            && job.homes.len() <= 65
            && job.homes.contains(&job.home)
            && job
                .homes
                .iter()
                .all(|h| h == home || h.parent() == Some(home.join("clusters").as_path())),
        "node reset journal does not belong to this directory"
    );
    Ok(job)
}

fn sync_parent(path: &Path) -> Result<()> {
    fs::File::open(path.parent().context("directory parent missing")?)?.sync_all()?;
    Ok(())
}

fn lock_state(homes: &[PathBuf]) -> Result<Vec<fs::File>> {
    let mut locks = Vec::new();
    for home in homes {
        for name in [
            "service.lock",
            "gateway-service.lock",
            "daemon.lock",
            "config.lock",
        ] {
            locks.push(managed_file::lock(&home.join(name)).context(
                "a Gent process is still using this node; stop it and rerun gent node reset",
            )?);
        }
        for name in [
            "auth/session.lock",
            "gateway/runtime.lock",
            "gateway/state.lock",
            "auth/enrollment/joining.lock",
        ] {
            let path = home.join(name);
            if path.parent().is_some_and(|p| p.is_dir()) {
                locks.push(managed_file::lock(&path).context(
                    "a Gent operation is still running; finish it and rerun gent node reset",
                )?);
            }
        }
    }
    Ok(locks)
}

fn archive(job: &Journal) -> Result<()> {
    ensure!(
        Identity::read(&job.home)? == job.original,
        "node directory changed during reset"
    );
    ensure!(!job.archive.try_exists()?, "reset archive already exists");
    // Mark before renaming, closing the crash window in which old paths could
    // otherwise activate an unmarked retired database.
    let marker = Snapshot::read(&job.home.join(gent_daemon::recovery::MARKER))?;
    marker.private()?;
    marker.write("{\"reason\":\"node reset; offline archive\"}\n")?;
    fs::rename(&job.home, &job.archive)?;
    sync_parent(&job.home)
}

fn finish(job: &Journal) -> Result<Value> {
    ensure!(
        Identity::read(&job.archive)? == job.original,
        "reset archive identity changed"
    );
    ensure!(
        job.archive
            .join(gent_daemon::recovery::MARKER)
            .try_exists()?,
        "reset archive protection is missing"
    );
    if let Some(identity) = job.pending_join {
        let pending = config::pending_join(&job.home)?;
        let retired = job.archive.join("retired-pending-join");
        if retired.try_exists()? {
            ensure!(
                Identity::read(&retired)? == identity && !pending.try_exists()?,
                "pending join changed during reset"
            );
        } else {
            ensure!(
                Identity::read(&pending)? == identity,
                "pending join changed during reset"
            );
            fs::rename(&pending, &retired)?;
            sync_parent(&pending)?;
            sync_parent(&retired)?;
        }
    }
    // Only the account session crosses the boundary. Never restore credentials,
    // identities, bindings, journals or database state into the fresh node.
    let session = Snapshot::read(&job.archive.join("auth/session.json"))?;
    session.private()?;
    if job.home.try_exists()? {
        Identity::read(&job.home)?;
        for entry in fs::read_dir(&job.home)? {
            ensure!(
                entry?.file_name() == "auth",
                "new node state appeared during reset; refusing to overwrite it"
            );
        }
    } else {
        config::private_dir(&job.home)?;
    }
    let auth = job.home.join("auth");
    if auth.try_exists()? {
        Identity::read(&auth)?;
        for entry in fs::read_dir(&auth)? {
            ensure!(
                entry?.file_name() == "session.json",
                "new account state appeared during reset; refusing to overwrite it"
            );
        }
    }
    if let Some(text) = &session.text {
        config::private_dir(&auth)?;
        let target = Snapshot::read(&auth.join("session.json"))?;
        target.private()?;
        ensure!(
            target.text.as_ref().is_none_or(|saved| saved == text),
            "account session changed during reset; preserved both copies"
        );
        if target.text.is_none() {
            target.write(text)?;
        }
    }
    sync_parent(&job.home)?;
    Ok(
        json!({"reset":true,"archive":job.archive,"home":job.home,"login_preserved":session.text.is_some(),
        "next":"Run gent node add NAME on an existing node, then gent cluster join CODE here. Reinstall host integrations and reload their MCP connections."}),
    )
}

pub(crate) async fn execute(root: &Path) -> Result<Value> {
    let home = managed_file::normalize(root)?;
    let journal_path = sibling(&home, ".reset.json")?;
    let _lock = managed_file::lock(&sibling(&home, ".reset.lock")?)?;
    let snapshot = Snapshot::read(&journal_path)?;
    snapshot.private()?;
    let job = if snapshot.text.is_some() {
        load(&home, &snapshot)?
    } else {
        gent_daemon::recovery::ensure_active(&home)?;
        if !home.try_exists()? {
            return Ok(json!({"reset":false,"home":home,"reason":"no local node state"}));
        }
        let original = Identity::read(&home)?;
        // Repeating a completed reset does not create another archive.
        if fs::read_dir(&home)?.all(|e| e.is_ok_and(|e| e.file_name() == "auth"))
            && !home.join("auth/account-source.json").try_exists()?
            && !home.join("auth/enrollment").try_exists()?
            && !config::pending_join(&home)?.try_exists()?
        {
            return Ok(json!({"reset":false,"home":home,"reason":"no local node state"}));
        }
        let job = Journal {
            version: 1,
            archive: sibling(&home, &format!(".retired-{}", uuid::Uuid::new_v4()))?,
            homes: legacy_homes(&home)?,
            original,
            pending_join: config::pending_join(&home)?
                .try_exists()?
                .then(|| Identity::read(&config::pending_join(&home)?))
                .transpose()?,
            home: home.clone(),
        };
        snapshot.write(&(serde_json::to_string(&job)? + "\n"))?;
        job
    };
    if !job.archive.try_exists()? {
        ensure!(
            Identity::read(&home)? == job.original,
            "node directory changed during reset"
        );
        for old in &job.homes {
            service::retire(old).await?;
        }
        integration::retire(&job.homes)?;
        let _locks = lock_state(&job.homes)?;
        // Serialize with an incomplete private-file/SSH join as well.
        let pending = config::pending_join(&home)?;
        let _pending_locks = if pending.try_exists()? {
            lock_state(&[pending])?
        } else {
            vec![]
        };
        archive(&job)?;
    }
    let result = finish(&job)?;
    Snapshot::read(&journal_path)?.remove()?;
    Ok(result)
}

#[cfg(test)]
mod tests;
