use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

const LIMIT: u64 = 16 * 1024 * 1024;

mod locking;
pub use locking::lock;
mod validation;
pub use validation::{SnapshotChanged, retry_read};

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

/// Host configuration may use a shared group. Gent still requires the current
/// user's ownership and refuses world writes; secret records also call private().
pub(crate) fn owned_not_world_writable(meta: &fs::Metadata) -> bool {
    meta.uid() == rustix::process::geteuid().as_raw() && meta.mode() & 0o002 == 0
}

pub fn directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && owned_not_world_writable(&meta),
        "configuration directory must be owned by this user and not world-writable: {}",
        path.display()
    );
    Ok(())
}

fn regular(meta: &fs::Metadata, path: &Path) -> Result<()> {
    ensure!(
        meta.is_file() && meta.nlink() == 1 && owned_not_world_writable(meta),
        "configuration must be a regular file owned by this user, without links or world write access: {}",
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
            SnapshotChanged(path.into())
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
            SnapshotChanged(path.into())
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
            SnapshotChanged(self.path.clone())
        );
        Ok(())
    }
    pub fn write(&self, text: &str) -> Result<()> {
        self.write_mode(text, None)
    }
    /// Generated launchers are atomically installed with private executable mode.
    pub fn write_executable(&self, text: &str) -> Result<()> {
        self.write_mode(text, Some(0o700))
    }
    pub fn executable(&self) -> bool {
        self.stamp.as_ref().is_some_and(|m| m.mode & 0o777 == 0o700)
    }
    fn write_mode(&self, text: &str, mode: Option<u32>) -> Result<()> {
        if self.text.as_deref() == Some(text)
            && mode.is_none_or(|mode| self.stamp.as_ref().is_some_and(|m| m.mode & 0o777 == mode))
        {
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
            .set_permissions(fs::Permissions::from_mode(mode.unwrap_or_else(|| {
                self.stamp.as_ref().map_or(0o600, |m| m.mode & 0o777)
            })))?;
        temporary.write_all(text.as_bytes())?;
        temporary.as_file().sync_all()?;
        self.verify()?;
        // Other Gent writers hold the same lock. Hosts do not honor that lock:
        // compare immediately before rename, but this is not a filesystem CAS.
        temporary.persist(&self.path).map_err(|e| e.error)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
    pub fn remove(&self) -> Result<()> {
        self.verify()?;
        if self.text.is_some() {
            fs::remove_file(&self.path)?;
            File::open(
                self.path
                    .parent()
                    .context("missing configuration directory")?,
            )?
            .sync_all()?;
        }
        Ok(())
    }
}
