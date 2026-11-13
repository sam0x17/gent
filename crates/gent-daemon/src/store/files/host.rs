//! Directory-relative opens keep MCP file access inside this agent's handoff folders.
use super::*;
use rustix::fs::{
    AtFlags, Mode, OFlags, RenameFlags, linkat, mkdirat, open, openat, renameat_with, unlinkat,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, Metadata},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Stamp {
    device: u64,
    inode: u64,
    pub bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl Stamp {
    fn of(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            bytes: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
    fn after_rename(&self, other: &Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.bytes == other.bytes
            && self.modified == other.modified
    }
}

pub(super) fn basename(name: &str) -> Result<()> {
    ensure!(
        (1..=128).contains(&name.len())
            && !name.trim().is_empty()
            && !name.chars().any(char::is_control)
            && !name.contains(['/', '\\'])
            && name != "."
            && name != "..",
        "invalid file basename"
    );
    Ok(())
}
fn directory(parent: &File, name: &str) -> Result<File> {
    match mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(e.into()),
    }
    existing_directory(parent, name)
}
fn existing_directory(parent: &File, name: &str) -> Result<File> {
    let file = File::from(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let meta = file.metadata()?;
    ensure!(
        meta.mode() & 0o077 == 0 && meta.uid() == parent.metadata()?.uid(),
        "file directory must be private and owned by the node user"
    );
    Ok(file)
}
fn regular(parent: &File, name: &str) -> Result<File> {
    let file = File::from(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.nlink() == 1 && meta.uid() == parent.metadata()?.uid(),
        "file must be a regular file with a single hard link owned by the node user"
    );
    ensure!(
        meta.len() <= gent_crypto::files::MAX_FILE_BYTES as u64,
        "file exceeds 32 MiB"
    );
    Ok(file)
}
fn read(parent: &File, name: &str) -> Result<(Zeroizing<Vec<u8>>, Stamp)> {
    let file = regular(parent, name)?;
    let stamp = Stamp::of(&file.metadata()?);
    let mut bytes = Zeroizing::new(Vec::new());
    (&file)
        .take(gent_crypto::files::MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= gent_crypto::files::MAX_FILE_BYTES,
        "file exceeds 32 MiB"
    );
    ensure!(
        stamp == Stamp::of(&file.metadata()?),
        "file changed during read"
    );
    Ok((bytes, stamp))
}
pub(super) struct Folders {
    import: File,
    export: File,
    pub import_path: PathBuf,
    pub export_path: PathBuf,
}
impl Folders {
    pub fn open(home: &Path, agent: &str) -> Result<Self> {
        ensure!(
            uuid::Uuid::parse_str(agent)?.to_string() == agent,
            "invalid agent identity"
        );
        let root = File::from(open(
            home,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let files = directory(&root, "files")?;
        let agent_dir = directory(&files, agent)?;
        Ok(Self {
            import: directory(&agent_dir, "outbox")?,
            export: directory(&agent_dir, "inbox")?,
            import_path: home.join("files").join(agent).join("outbox"),
            export_path: home.join("files").join(agent).join("inbox"),
        })
    }
    pub fn read(&self, name: &str) -> Result<(Zeroizing<Vec<u8>>, Stamp)> {
        read(&self.import, name)
    }
    pub fn write(&self, descriptor: &FileDescriptor, bytes: &[u8]) -> Result<(PathBuf, Stamp)> {
        basename(&descriptor.name)?;
        ensure!(
            gent_protocol::file_objects::valid_id(&descriptor.id),
            "invalid file ID"
        );
        let dir = directory(&self.export, &descriptor.id)?;
        let tmp = format!(".gent-{}.tmp", uuid::Uuid::new_v4());
        let mut file = File::from(openat(
            &dir,
            &tmp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        let result = (|| -> Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            match linkat(&dir, &tmp, &dir, &descriptor.name, AtFlags::empty()) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => ensure!(
                    read(&dir, &descriptor.name)?.0.as_slice() == bytes,
                    "export destination already contains different bytes"
                ),
                Err(e) => return Err(e.into()),
            }
            Ok(())
        })();
        // A crash may leave a private temporary export. No existing path is overwritten.
        unlinkat(&dir, &tmp, AtFlags::empty())?;
        result?;
        dir.sync_all()?;
        let (saved, stamp) = read(&dir, &descriptor.name)?;
        ensure!(saved.as_slice() == bytes, "export changed during write");
        Ok((
            self.export_path.join(&descriptor.id).join(&descriptor.name),
            stamp,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cleanup {
    Removed,
    Missing,
    Preserved,
}

/// Claim the name before verifying/deleting it. The stable quarantine name lets
/// the next pass recover a crash even if the enclosing database commit failed.
/// A replacement at the original name is never unlinked or overwritten.
pub(super) struct TrackedFile<'a> {
    pub agent: &'a str,
    pub slot: &'a str,
    pub name: &'a str,
    pub id: &'a str,
    pub stamp: &'a Stamp,
    pub digest: &'a str,
}
pub(super) fn cleanup(home: &Path, file: TrackedFile<'_>, dry_run: bool) -> Result<Cleanup> {
    let TrackedFile {
        agent,
        slot,
        name,
        id,
        stamp,
        digest,
    } = file;
    ensure!(
        uuid::Uuid::parse_str(agent).is_ok_and(|id| !id.is_nil() && id.to_string() == agent)
            && gent_protocol::file_objects::valid_id(id)
            && (slot.is_empty() || gent_protocol::file_objects::valid_id(slot)),
        "invalid handoff identity"
    );
    basename(name)?;
    let parent = (|| -> Result<File> {
        let root = File::from(open(
            home,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let files = existing_directory(&root, "files")?;
        let agent = existing_directory(&files, agent)?;
        if slot.is_empty() {
            existing_directory(&agent, "outbox")
        } else {
            existing_directory(&existing_directory(&agent, "inbox")?, slot)
        }
    })();
    let parent = match parent {
        Ok(dir) => dir,
        Err(e) if missing(&e) => return Ok(Cleanup::Missing),
        Err(e) => return Err(e),
    };
    let quarantine = format!(".gent-clean-{id}.tmp");
    // Test existence without following a link or opening a special file.
    let has_quarantine = match rustix::fs::statat(&parent, &quarantine, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => true,
        Err(rustix::io::Errno::NOENT) => false,
        Err(e) => return Err(e.into()),
    };
    let mut restore = !has_quarantine;
    if !has_quarantine {
        let file = match regular(&parent, name) {
            Ok(file) => file,
            Err(e) if missing(&e) => return Ok(Cleanup::Missing),
            Err(e) => return Err(e),
        };
        if Stamp::of(&file.metadata()?) != *stamp {
            return Ok(Cleanup::Preserved);
        }
        if dry_run {
            let (bytes, current) = read(&parent, name)?;
            return Ok(
                if current == *stamp && format!("{:x}", Sha256::digest(&bytes)) == digest {
                    Cleanup::Removed
                } else {
                    Cleanup::Preserved
                },
            );
        }
        renameat_with(&parent, name, &parent, &quarantine, RenameFlags::NOREPLACE)?;
        parent.sync_all()?;
    }
    let unchanged = (|| -> Result<bool> {
        let (bytes, current) = read(&parent, &quarantine)?;
        restore |= stamp.device == current.device && stamp.inode == current.inode;
        Ok(stamp.after_rename(&current) && format!("{:x}", Sha256::digest(&bytes)) == digest)
    })();
    if unchanged.as_ref().is_ok_and(|same| *same) {
        if !dry_run {
            unlinkat(&parent, &quarantine, AtFlags::empty())?;
            parent.sync_all()?;
        }
        return Ok(Cleanup::Removed);
    }
    if !dry_run && restore {
        // If a host created a replacement while we held the old name, preserve
        // both. The ledger keeps the recovery name visible to the local owner.
        match renameat_with(&parent, &quarantine, &parent, name, RenameFlags::NOREPLACE) {
            Ok(()) => parent.sync_all()?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(e.into()),
        }
    }
    unchanged?;
    Ok(Cleanup::Preserved)
}

fn missing(error: &anyhow::Error) -> bool {
    error.downcast_ref::<rustix::io::Errno>() == Some(&rustix::io::Errno::NOENT)
}
