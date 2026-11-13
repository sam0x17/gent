use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

const LIMIT: u64 = 16 * 1024 * 1024;

/// Locks are persistent, empty files: deleting one can split concurrent writers
/// between old and new inodes. The OS user is a trusted endpoint.
pub fn lock(path: &Path) -> Result<File> {
    Snapshot::read(path)?.private()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e).context("Gent settings are busy; retry the command"),
        }
    }
}

// Canonical parents coordinate installers using /tmp and /private/tmp aliases.
// Refuse a linked final component even when its destination does not exist.
pub fn normalize(path: &Path) -> Result<PathBuf> {
    let mut clean = PathBuf::new();
    for part in std::path::absolute(path)?.components() {
        match part {
            Component::ParentDir => {
                clean.pop();
            }
            Component::CurDir => {}
            other => clean.push(other),
        }
    }
    if let Ok(meta) = fs::symlink_metadata(&clean) {
        ensure!(
            !meta.file_type().is_symlink(),
            "configuration path cannot be a symlink: {}",
            clean.display()
        );
    }
    for parent in clean.ancestors() {
        if parent.exists() {
            let base = fs::canonicalize(parent)?;
            let suffix = clean.strip_prefix(parent)?;
            return Ok(if suffix.as_os_str().is_empty() {
                base
            } else {
                base.join(suffix)
            });
        }
    }
    anyhow::bail!("cannot resolve configuration path")
}

pub fn directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir()
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.mode() & 0o022 == 0,
        "configuration directory must be owned by this user and not writable by others: {}",
        path.display()
    );
    Ok(())
}

fn regular(meta: &fs::Metadata, path: &Path) -> Result<()> {
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.mode() & 0o022 == 0,
        "configuration must be a regular file owned by this user, without links or shared write access: {}",
        path.display()
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl From<&fs::Metadata> for Stamp {
    fn from(m: &fs::Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mode: m.mode(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub path: PathBuf,
    pub text: Option<String>,
    stamp: Option<Stamp>,
}
impl Snapshot {
    pub fn read(path: &Path) -> Result<Self> {
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path: path.into(),
                    text: None,
                    stamp: None,
                });
            }
            Err(e) => return Err(e.into()),
        };
        regular(&meta, path)?;
        let file = File::open(path)?;
        ensure!(
            Stamp::from(&meta) == Stamp::from(&file.metadata()?),
            "configuration changed while opening; retry"
        );
        let mut bytes = Vec::new();
        (&file).take(LIMIT + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= LIMIT,
            "configuration is too large: {}",
            path.display()
        );
        ensure!(
            Stamp::from(&meta) == Stamp::from(&file.metadata()?),
            "configuration changed while reading; retry"
        );
        let text = String::from_utf8(bytes)
            .map_err(|_| anyhow::anyhow!("configuration is not UTF-8: {}", path.display()))?;
        Ok(Self {
            path: path.into(),
            text: Some(text),
            stamp: Some(Stamp::from(&meta)),
        })
    }
    pub fn private(&self) -> Result<()> {
        ensure!(
            self.stamp.as_ref().is_none_or(|m| m.mode & 0o077 == 0),
            "Gent installation record must be private: {}",
            self.path.display()
        );
        Ok(())
    }
    pub fn verify(&self) -> Result<()> {
        ensure!(
            *self == Self::read(&self.path)?,
            "configuration changed during installation; retry: {}",
            self.path.display()
        );
        Ok(())
    }
    pub fn write(&self, text: &str) -> Result<()> {
        if self.text.as_deref() == Some(text) {
            return self.verify();
        }
        let parent = self
            .path
            .parent()
            .context("missing configuration directory")?;
        directory(parent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(
                self.stamp.as_ref().map_or(0o600, |m| m.mode & 0o777),
            ))?;
        temporary.write_all(text.as_bytes())?;
        temporary.as_file().sync_all()?;
        self.verify()?;
        // Other Gent writers hold the same lock. Hosts do not honor that lock:
        // compare immediately before rename, but this is not a filesystem CAS.
        temporary.persist(&self.path).map_err(|e| e.error)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}
