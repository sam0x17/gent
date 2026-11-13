//! Directory-relative opens keep MCP file access inside this agent's handoff folders.
use super::*;
use rustix::fs::{AtFlags, Mode, OFlags, linkat, mkdirat, open, openat, unlinkat};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};

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
fn read(parent: &File, name: &str) -> Result<Zeroizing<Vec<u8>>> {
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
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(gent_crypto::files::MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= gent_crypto::files::MAX_FILE_BYTES,
        "file exceeds 32 MiB"
    );
    Ok(bytes)
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
    pub fn read(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        read(&self.import, name)
    }
    pub fn write(&self, descriptor: &FileDescriptor, bytes: &[u8]) -> Result<PathBuf> {
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
                    read(&dir, &descriptor.name)?.as_slice() == bytes,
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
        Ok(self.export_path.join(&descriptor.id).join(&descriptor.name))
    }
}
