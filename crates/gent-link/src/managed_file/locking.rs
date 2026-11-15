use super::regular;
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

fn private(meta: &fs::Metadata, path: &Path) -> Result<()> {
    regular(meta, path)?;
    ensure!(
        meta.mode() & 0o077 == 0,
        "Gent settings lock must be private"
    );
    Ok(())
}

fn verify(file: &File, path: &Path) -> Result<()> {
    let opened = file.metadata()?;
    private(&opened, path)?;
    let named = fs::symlink_metadata(path)?;
    private(&named, path)?;
    ensure!(
        (opened.dev(), opened.ino()) == (named.dev(), named.ino()),
        "Gent settings lock was replaced; retry the command"
    );
    Ok(())
}

/// Locks are persistent files: deleting one can split concurrent writers
/// between old and new inodes. The OS user is a trusted endpoint.
pub fn lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    verify(&file, path)?;
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => {
                // Concurrent first opens can change ctime on macOS without
                // changing the inode or contents. A lock needs stable identity
                // and permissions, not the content stamps used by Snapshot.
                verify(&file, path)?;
                return Ok(file);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e).context("Gent settings are busy; retry the command"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        sync::{
            Barrier,
            atomic::{AtomicUsize, Ordering},
        },
    };

    #[test]
    fn concurrent_first_opens_serialize_one_persistent_inode() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings.lock");
        let barrier = Barrier::new(8);
        let active = AtomicUsize::new(0);
        let visits = AtomicUsize::new(0);
        let inodes = std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        let mut inodes = Vec::new();
                        for _ in 0..10 {
                            let guard = lock(&path).unwrap();
                            assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                            std::thread::yield_now();
                            visits.fetch_add(1, Ordering::SeqCst);
                            inodes.push(guard.metadata().unwrap().ino());
                            assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                        }
                        inodes
                    })
                })
                .collect();
            tasks
                .into_iter()
                .flat_map(|task| task.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(visits.load(Ordering::SeqCst), 80);
        assert!(inodes.iter().all(|inode| *inode == inodes[0]));
        assert_eq!(fs::metadata(&path).unwrap().ino(), inodes[0]);
        assert!(fs::read(path).unwrap().is_empty());
    }

    #[test]
    fn linked_shared_and_nonregular_lock_paths_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::write(&target, b"preserve this file").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let path = temp.path().join("settings.lock");
        symlink(&target, &path).unwrap();
        assert!(lock(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::hard_link(&target, &path).unwrap();
        assert!(lock(&path).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"preserve this file");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(lock(&path).is_err());
        fs::remove_dir(&path).unwrap();
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(lock(&path).is_err());
    }

    #[test]
    fn acquired_inode_must_still_match_the_private_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings.lock");
        let guard = lock(&path).unwrap();
        fs::rename(&path, temp.path().join("replaced.lock")).unwrap();
        let replacement = lock(&path).unwrap();
        assert!(
            verify(&guard, &path)
                .unwrap_err()
                .to_string()
                .contains("replaced")
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(verify(&replacement, &path).is_err());
    }
}
