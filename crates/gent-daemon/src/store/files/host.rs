//! Directory-relative opens keep MCP file access inside this agent's handoff folders.
use super::*;
use rustix::fs::{
    AtFlags, Mode, OFlags, RenameFlags, mkdirat, open, openat, renameat_with, unlinkat,
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
        Ok(()) => parent.sync_all()?,
        Err(rustix::io::Errno::EXIST) => {}
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
            "invalid chat identity"
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
    pub fn existing_export(&self, descriptor: &FileDescriptor) -> Result<Option<Stamp>> {
        basename(&descriptor.name)?;
        ensure!(
            gent_protocol::file_objects::valid_id(&descriptor.id),
            "invalid file ID"
        );
        let dir = match existing_directory(&self.export, &descriptor.id) {
            Ok(dir) => dir,
            Err(error) if missing(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        match read(&dir, &descriptor.name) {
            Ok((bytes, stamp)) => {
                ensure!(
                    stamp.bytes == descriptor.byte_length
                        && format!("{:x}", Sha256::digest(&bytes)) == descriptor.sha256,
                    "export destination already contains different bytes"
                );
                Ok(Some(stamp))
            }
            Err(error) if missing(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// A committed reservation owns one stable temporary name. Retry can append
    /// to an unchanged prefix, but never truncates or replaces existing content.
    pub fn stage(
        &self,
        descriptor: &FileDescriptor,
        reservation: &str,
        bytes: &[u8],
    ) -> Result<Stamp> {
        basename(&descriptor.name)?;
        ensure!(
            gent_protocol::file_objects::valid_id(&descriptor.id)
                && gent_protocol::file_objects::valid_id(reservation),
            "invalid export identity"
        );
        let dir = directory(&self.export, &descriptor.id)?;
        let tmp = export_temporary(reservation);
        ensure!(
            tmp != descriptor.name,
            "export name conflicts with temporary name"
        );
        let mut file = match openat(
            &dir,
            &tmp,
            OFlags::RDWR
                | OFlags::APPEND
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => File::from(fd),
            Err(rustix::io::Errno::EXIST) => File::from(openat(
                &dir,
                &tmp,
                OFlags::RDWR
                    | OFlags::APPEND
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::empty(),
            )?),
            Err(error) => return Err(error.into()),
        };
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && meta.uid() == dir.metadata()?.uid()
                && meta.mode() & 0o077 == 0,
            "export temporary file must be private and have one hard link"
        );
        let initial = Stamp::of(&meta);
        let (prefix, current) = read(&dir, &tmp)?;
        ensure!(
            initial == current && bytes.starts_with(&prefix),
            "export temporary file changed; preserved for inspection"
        );
        ensure!(
            initial == Stamp::of(&file.metadata()?),
            "export temporary file changed during read"
        );
        file.write_all(&bytes[prefix.len()..])?;
        file.sync_all()?;
        dir.sync_all()?;
        let (saved, stamp) = read(&dir, &tmp)?;
        ensure!(
            saved.as_slice() == bytes && stamp == Stamp::of(&file.metadata()?),
            "export changed during write"
        );
        Ok(stamp)
    }

    pub fn publish(
        &self,
        descriptor: &FileDescriptor,
        reservation: &str,
        stamp: &Stamp,
    ) -> Result<(PathBuf, Stamp)> {
        basename(&descriptor.name)?;
        ensure!(
            gent_protocol::file_objects::valid_id(&descriptor.id)
                && gent_protocol::file_objects::valid_id(reservation),
            "invalid export identity"
        );
        let dir = directory(&self.export, &descriptor.id)?;
        let tmp = export_temporary(reservation);
        match read(&dir, &tmp) {
            Ok((bytes, current)) => {
                ensure!(
                    current == *stamp
                        && format!("{:x}", Sha256::digest(&bytes)) == descriptor.sha256,
                    "export temporary file changed; preserved for inspection"
                );
                renameat_with(&dir, &tmp, &dir, &descriptor.name, RenameFlags::NOREPLACE)?;
                dir.sync_all()?;
            }
            Err(error) if missing(&error) => {} // An interrupted publish may already have renamed it.
            Err(error) => return Err(error),
        }
        let (bytes, current) = read(&dir, &descriptor.name)?;
        ensure!(
            stamp.after_rename(&current)
                && format!("{:x}", Sha256::digest(&bytes)) == descriptor.sha256,
            "export destination changed; preserved for inspection"
        );
        Ok((
            self.export_path.join(&descriptor.id).join(&descriptor.name),
            current,
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
    cleanup_with(home, file, dry_run, true)
}
fn cleanup_with(
    home: &Path,
    file: TrackedFile<'_>,
    dry_run: bool,
    restore_recovery: bool,
) -> Result<Cleanup> {
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
        restore |=
            restore_recovery && stamp.device == current.device && stamp.inode == current.inode;
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

pub(super) fn export_temporary(id: &str) -> String {
    format!(".gent-export-{id}.tmp")
}

pub(super) struct ExportFile<'a> {
    pub agent: &'a str,
    pub slot: &'a str,
    pub name: &'a str,
    pub id: &'a str,
    pub stamp: Option<&'a Stamp>,
    pub digest: &'a str,
}

pub(super) fn clean_export(home: &Path, file: ExportFile<'_>, dry_run: bool) -> Result<Cleanup> {
    ensure!(
        uuid::Uuid::parse_str(file.agent)
            .is_ok_and(|id| !id.is_nil() && id.to_string() == file.agent)
            && gent_protocol::file_objects::valid_id(file.slot)
            && gent_protocol::file_objects::valid_id(file.id),
        "invalid export reservation identity"
    );
    basename(file.name)?;
    let root = File::from(open(
        home,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let parent = (|| -> Result<File> {
        let files = existing_directory(&root, "files")?;
        let agent = existing_directory(&files, file.agent)?;
        let inbox = existing_directory(&agent, "inbox")?;
        existing_directory(&inbox, file.slot)
    })();
    let parent = match parent {
        Ok(parent) => parent,
        Err(error) if missing(&error) => return Ok(Cleanup::Missing),
        Err(error) => return Err(error),
    };
    let temporary = export_temporary(file.id);
    let recovery = format!(".gent-clean-{}.tmp", file.id);
    let exists = |name: &str| -> Result<bool> {
        match rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    };
    let Some(stamp) = file.stamp else {
        // A process can exit after writing but before saving its stamp. Keep
        // capacity and paths visible; an authorized retry can verify/resume it.
        return Ok(
            if exists(&temporary)? || exists(file.name)? || exists(&recovery)? {
                Cleanup::Preserved
            } else {
                Cleanup::Missing
            },
        );
    };
    let file = TrackedFile {
        agent: file.agent,
        slot: file.slot,
        name: file.name,
        id: file.id,
        stamp,
        digest: file.digest,
    };
    if exists(&recovery)? {
        // Its original name may have been temporary or published. Never guess
        // where to restore a changed quarantine after an interrupted cleanup.
        return cleanup_with(home, file, dry_run, false);
    }
    let name = if exists(&temporary)? {
        temporary.as_str()
    } else {
        file.name
    };
    let current = match regular(&parent, name) {
        Ok(handle) => Stamp::of(&handle.metadata()?),
        Err(error) if missing(&error) => return Ok(Cleanup::Missing),
        Err(error) => return Err(error),
    };
    if !(if name == temporary {
        current == *file.stamp
    } else {
        file.stamp.after_rename(&current)
    }) {
        return Ok(Cleanup::Preserved);
    }
    cleanup_with(
        home,
        TrackedFile {
            name,
            stamp: &current,
            ..file
        },
        dry_run,
        false,
    )
}
