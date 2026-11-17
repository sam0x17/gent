//! Installation ownership, durable publication journal and atomic replacement.
use crate::build_info::{self, Build};
use anyhow::{Context, Result, ensure};
use gent_daemon::config;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone)]
pub(super) struct Installation {
    pub binary: PathBuf,
    pub directory: PathBuf,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Status {
    pub last_checked: Option<u64>,
    pub blessed_commit: Option<String>,
    pub phase: String,
    pub error: Option<String>,
    pub failed_commit: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub version: u32,
    pub home: PathBuf,
    pub old: Build,
    pub new: Build,
    pub old_hash: String,
    pub new_hash: String,
    pub starting: bool,
    #[serde(default)]
    pub automatic: bool,
}

fn artifact(path: &Path) -> Result<fs::Metadata> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file()
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.mode() & 0o002 == 0,
        "update file must be owned, regular and not world-writable"
    );
    Ok(meta)
}

fn owned(path: &Path) -> Result<fs::Metadata> {
    let meta = artifact(path)?;
    ensure!(meta.nlink() == 1, "update file must not be hard-linked");
    Ok(meta)
}

/// Cargo may hard-link its installation to cached build artifacts. Detach the
/// candidate before execution or hashing; published files must remain unlinked.
pub(super) fn snapshot_artifact(path: &Path) -> Result<PathBuf> {
    let before = artifact(path)?;
    let mut source = fs::File::open(path)?;
    let opened = source.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "Cargo artifact changed while opening"
    );
    let parent = path.parent().context("missing Cargo staging directory")?;
    let mut snapshot = tempfile::NamedTempFile::new_in(parent)?;
    let copied = std::io::copy(
        &mut source.by_ref().take(512 * 1024 * 1024 + 1),
        snapshot.as_file_mut(),
    )?;
    let after = source.metadata()?;
    ensure!(
        copied <= 512 * 1024 * 1024
            && copied == before.len()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "Cargo artifact changed or exceeds its size limit"
    );
    snapshot
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    snapshot.as_file().sync_all()?;
    let candidate = parent.join("gent-verified");
    snapshot.persist(&candidate).map_err(|e| e.error)?;
    Ok(candidate)
}

pub(super) fn hash(path: &Path) -> Result<String> {
    let before = owned(path)?;
    ensure!(
        before.len() <= 512 * 1024 * 1024,
        "update binary exceeds its size limit"
    );
    let mut file = fs::File::open(path)?;
    let opened = file.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "update binary changed while opening"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut total = 0;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count;
        ensure!(
            total <= 512 * 1024 * 1024,
            "update binary grew beyond its size limit"
        );
        hash.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    ensure!(
        before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "update binary changed while reading"
    );
    Ok(format!("{:x}", hash.finalize()))
}

fn replace(source: &Path, destination: &Path, expected: &str) -> Result<()> {
    owned(source)?;
    let parent = destination
        .parent()
        .context("missing installation directory")?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".gent-install-")
        .tempfile_in(parent)?;
    std::io::copy(&mut fs::File::open(source)?, temporary.as_file_mut())?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    temporary.as_file().sync_all()?;
    ensure!(
        hash(temporary.path())? == expected,
        "update copy does not match its verified bytes"
    );
    temporary.persist(destination).map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) async fn inspect(binary: &Path) -> Result<Build> {
    owned(binary)?;
    let bytes = super::process::capture(
        tokio::process::Command::new(binary).args(["--json", "version"]),
        8192,
        Duration::from_secs(10),
    )
    .await?;
    serde_json::from_slice(&bytes)
        .context("installed binary does not expose supported build metadata")
}

impl Installation {
    pub fn discover() -> Result<Option<Self>> {
        let root = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".cargo")))
            .context("cannot locate the Cargo installation")?;
        #[cfg(feature = "test-updates")]
        let root = std::env::var_os("GENT_TEST_UPDATE_ROOT")
            .map(PathBuf::from)
            .unwrap_or(root);
        let Some(bin) = fs::canonicalize(root.join("bin")).ok() else {
            return Ok(None);
        };
        let binary = bin.join("gent");
        let running = std::env::current_exe()?;
        let running = running.to_string_lossy();
        let running = running.strip_suffix(" (deleted)").unwrap_or(&running);
        // macOS may report the invocation spelling (/var or /tmp) while the
        // Cargo directory resolves through /private. Compare canonical paths.
        if fs::canonicalize(running).ok().as_deref() != Some(binary.as_path()) {
            return Ok(None);
        }
        let meta = fs::symlink_metadata(&bin)?;
        ensure!(
            meta.is_dir()
                && meta.uid() == rustix::process::geteuid().as_raw()
                && meta.mode() & 0o002 == 0,
            "Cargo bin directory is not owned or is world-writable"
        );
        owned(&binary)?;
        let directory = bin.parent().unwrap().join(".gent-updates");
        config::private_dir(&directory)?;
        Ok(Some(Self { binary, directory }))
    }

    pub fn lock(&self) -> Result<fs::File> {
        match config::state_lock(&self.directory, "update.lock") {
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock) =>
            {
                anyhow::bail!("another Gent update is running; retry when it finishes")
            }
            result => result,
        }
    }

    pub fn read<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let path = self.directory.join(name);
        if !path.exists() {
            return Ok(None);
        }
        let meta = owned(&path)?;
        ensure!(
            meta.mode() & 0o077 == 0 && meta.len() <= 64 * 1024,
            "invalid private update record"
        );
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 64 * 1024, "update record is too large");
        Ok(Some(
            serde_json::from_slice(&bytes).context("invalid update record")?,
        ))
    }

    pub fn write(&self, name: &str, value: &impl Serialize) -> Result<()> {
        config::write_private(&self.directory.join(name), &serde_json::to_vec(value)?)
    }

    pub fn status(&self) -> Result<Status> {
        Ok(self.read("status.json")?.unwrap_or_default())
    }

    pub fn pending(&self) -> Result<Option<Pending>> {
        let Some(pending) = self.read::<Pending>("pending.json")? else {
            return Ok(None);
        };
        ensure!(
            pending.version == 1
                && pending.home.is_absolute()
                && pending.new.commit.len() == 40
                && [&pending.old_hash, &pending.new_hash]
                    .into_iter()
                    .all(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit())),
            "invalid update activation record"
        );
        Ok(Some(pending))
    }

    fn clear_pending(&self) -> Result<()> {
        fs::remove_file(self.directory.join("pending.json"))?;
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    pub fn publish(
        &self,
        home: &Path,
        old: Build,
        new: Build,
        candidate: &Path,
        expected_old: &str,
        automatic: bool,
    ) -> Result<()> {
        ensure!(
            self.pending()?.is_none(),
            "another update is awaiting activation"
        );
        ensure!(
            hash(&self.binary)? == expected_old,
            "installed binary changed during build; update cancelled"
        );
        let new_hash = hash(candidate)?;
        replace(&self.binary, &self.directory.join("previous"), expected_old)?;
        let pending = Pending {
            version: 1,
            home: fs::canonicalize(home)?,
            old,
            new,
            old_hash: expected_old.into(),
            new_hash: new_hash.clone(),
            starting: false,
            automatic,
        };
        self.write("pending.json", &pending)?;
        // The durable journal precedes publication, so either old or new bytes
        // after a crash can be reconciled without truncating the executable.
        ensure!(
            hash(&self.binary)? == expected_old,
            "installed binary changed before publication"
        );
        replace(candidate, &self.binary, &new_hash)
    }

    pub fn rollback(&self, pending: &Pending, reason: &str) -> Result<()> {
        let current = hash(&self.binary)?;
        ensure!(
            current == pending.new_hash || current == pending.old_hash,
            "binary changed outside this update; refusing rollback"
        );
        replace(
            &self.directory.join("previous"),
            &self.binary,
            &pending.old_hash,
        )?;
        let mut status = self.status()?;
        status.phase = "rolled_back".into();
        status.error = Some(reason.into());
        status.failed_commit = Some(pending.new.commit.clone());
        self.write("status.json", &status)?;
        self.clear_pending()
    }

    pub fn interrupted_publication(&self, pending: &Pending) -> Result<()> {
        ensure!(
            !pending.starting && hash(&self.binary)? == pending.old_hash,
            "cannot discard an update that may have started"
        );
        let mut status = self.status()?;
        status.phase = "interrupted".into();
        status.error = Some("publication interrupted; the next check will retry".into());
        self.write("status.json", &status)?;
        self.clear_pending()
    }

    pub fn begin_startup(&self, home: &Path, current: &Build) -> Result<bool> {
        // A long build holds the update lock but must not prevent daemon start.
        if self.pending()?.is_none() {
            return Ok(false);
        }
        let _lock = self.lock()?;
        let Some(mut pending) = self.pending()? else {
            return Ok(false);
        };
        ensure!(
            pending.home == fs::canonicalize(home)?,
            "pending update belongs to another Gent home"
        );
        if *current == pending.new && hash(&self.binary)? == pending.new_hash {
            if pending.starting {
                self.rollback(&pending, "updated daemon exited before reporting readiness")?;
                return Ok(true);
            }
            pending.starting = true;
            self.write("pending.json", &pending)?;
        } else if hash(&self.binary)? == pending.old_hash {
            // Publication did not happen or a crash interrupted rollback.
            if pending.starting {
                self.rollback(&pending, "update rollback was interrupted")?;
            } else {
                self.interrupted_publication(&pending)?;
            }
        } else {
            ensure!(
                *current == pending.old,
                "unexpected running update revision"
            );
            return Ok(true);
        }
        Ok(false)
    }

    pub fn healthy(&self, current: &Build) -> Result<Option<Build>> {
        if self.pending()?.is_none() {
            return Ok(None);
        }
        let _lock = self.lock()?;
        let Some(pending) = self.pending()? else {
            return Ok(None);
        };
        if pending.new != *current {
            return Ok(None);
        }
        ensure!(
            pending.starting && hash(&self.binary)? == pending.new_hash,
            "update changed during startup"
        );
        let mut status = self.status()?;
        status.phase = "current".into();
        status.error = None;
        status.failed_commit = None;
        self.write("status.json", &status)?;
        self.clear_pending()?;
        Ok(pending.automatic.then_some(pending.new))
    }

    pub fn needs_restart(&self, home: &Path) -> Result<bool> {
        let Some(pending) = self.pending()? else {
            return Ok(false);
        };
        // Publication writes its final status while holding this lock. Defer
        // activation until the publisher is entirely finished.
        let Ok(_lock) = self.lock() else {
            return Ok(false);
        };
        Ok(pending.home == fs::canonicalize(home)?
            && !pending.starting
            && pending.old == build_info::current()
            && pending.new != build_info::current()
            && hash(&self.binary)? == pending.new_hash)
    }
}
