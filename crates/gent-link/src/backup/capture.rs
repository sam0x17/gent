use super::{
    format::{self, Entry, Kind, Manifest},
    open_regular,
};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use gent_daemon::{config, recovery};
use rusqlite::{Connection, OpenFlags};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const DATABASES: [&str; 3] = ["state.sqlite3", "mls.sqlite3", "authority.sqlite3"];

#[derive(Debug, PartialEq, Eq, Clone)]
pub(super) struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    uid: u32,
    links: u64,
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
            uid: m.uid(),
            links: m.nlink(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Item {
    stamp: Stamp,
    kind: Kind,
    excluded: bool,
}

pub(super) struct Capture {
    home: PathBuf,
    inventory: BTreeMap<String, Item>,
    cfg: config::Config,
    _locks: Vec<File>,
    _databases: Vec<Connection>,
}

impl Capture {
    pub fn open(home: &Path) -> Result<Self> {
        recovery::ensure_active(home)?;
        ensure!(home.is_dir(), "node state directory is missing");
        config::private_dir(home)?;
        let mut locks = Vec::new();
        for name in [
            "service.lock",
            "daemon.lock",
            "config.lock",
            "invitation.lock",
        ] {
            locks.push(config::state_lock(home, name)?);
        }
        let cfg_path = config::path(home);
        let cfg_file = open_regular(&cfg_path, true)?;
        let cfg_stamp = Stamp::from(&cfg_file.metadata()?);
        ensure!(
            cfg_stamp.len <= 16 * 1024 * 1024,
            "node configuration is too large for backup"
        );
        let cfg = config::load(home)?;
        ensure!(
            Stamp::from(&fs::symlink_metadata(&cfg_path)?) == cfg_stamp,
            "node configuration changed during backup setup"
        );
        ensure!(
            home.join("identity.key").is_file() && home.join("state.sqlite3").is_file(),
            "initialize the node by running its daemon, then stop it before backup"
        );
        let first = inventory(home)?;
        for (path, item) in &first {
            if item.kind == Kind::File
                && is_lock(path)
                && !matches!(
                    path.as_str(),
                    "service.lock" | "daemon.lock" | "config.lock" | "invitation.lock"
                )
            {
                ensure!(locks.len() < 1024, "too many node mutation locks");
                let file = open_regular(&home.join(path), true)?;
                file.try_lock_exclusive()
                    .context("node settings are busy; close MCP/gateway processes before backup")?;
                locks.push(file);
            }
        }
        // Refuse active conversation credentials too. Per-file locks are also
        // held while each payload is read; stable inventories detect new files.
        for (path, item) in &first {
            if item.kind == Kind::File && !item.excluded {
                let file = open_regular(&home.join(path), false)?;
                file.try_lock_exclusive()
                    .context("node file is in use; close its MCP connection before backup")?;
            }
        }
        let mut databases = Vec::new();
        for name in DATABASES {
            let path = home.join(name);
            if !path.exists() {
                continue;
            }
            let file = open_regular(&path, true)?;
            ensure!(
                file.metadata()?.len() > 0,
                "cannot back up an uninitialized database"
            );
            let db = Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            db.busy_timeout(std::time::Duration::ZERO)?;
            // SQLite, not Gent, recovers hot journals and checkpoints WAL.
            db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| {
                r.get::<_, u64>(0)
            })?;
            let mode: String = db.query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))?;
            ensure!(
                mode == "delete",
                "database is busy or cannot leave WAL mode"
            );
            db.execute_batch("BEGIN EXCLUSIVE")?;
            let check: String = db.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            ensure!(check == "ok", "database integrity check failed");
            databases.push(db);
        }
        let inventory = inventory(home)?;
        // Sidecars must be gone after SQLite's recovery. Even empty sidecars
        // are refused rather than guessed to be dispensable.
        ensure!(
            !inventory.keys().any(|p| is_sidecar(p)),
            "database recovery left journal files; cannot capture consistent state"
        );
        Ok(Self {
            home: home.into(),
            inventory,
            cfg,
            _locks: locks,
            _databases: databases,
        })
    }

    pub fn verify(&self) -> Result<()> {
        ensure!(
            inventory(&self.home)? == self.inventory,
            "node files changed during backup; retry after closing writers"
        );
        Ok(())
    }

    pub fn manifest(&self) -> Result<Manifest> {
        let mut entries = Vec::new();
        let mut exclusions = vec![
            "Only this node profile is captured; provider conversation histories and external MCP bindings are not included.".into(),
            "Other cluster profiles, runtime sockets and lock files are not included.".into(),
            "External files referenced by configuration, journals or host setup records are not followed.".into(),
        ];
        let mut total = 0_u64;
        for (path, item) in &self.inventory {
            if path.is_empty() {
                continue;
            }
            if item.excluded {
                exclusions.push(format!("omitted: {path}"));
                continue;
            }
            let (bytes, sha256) = if item.kind == Kind::File {
                total = total
                    .checked_add(item.stamp.len)
                    .context("backup size overflow")?;
                ensure!(
                    total <= format::MAX_TOTAL_BYTES,
                    "node exceeds archive byte limit"
                );
                let mut file = open_regular(&self.home.join(path), false)?;
                file.try_lock_exclusive().context("node file is busy")?;
                let hash = format::copy_file(&mut file, &mut std::io::sink(), item.stamp.len)?;
                ensure!(
                    Stamp::from(&file.metadata()?) == item.stamp,
                    "node file changed during hashing"
                );
                (item.stamp.len, Some(hash))
            } else {
                (0, None)
            };
            entries.push(Entry {
                path: path.clone(),
                kind: item.kind,
                bytes,
                sha256,
            });
        }
        if let Some(contexts) = self.cfg.contexts()? {
            for (id, profile) in contexts.profiles {
                if id != self.cfg.cluster.id {
                    exclusions.push(format!("other profile {id}: {}", profile.home.display()));
                }
            }
        }
        if let Some(source) = self.cfg.account_source()? {
            exclusions.push(format!("external account store: {}", source.home.display()));
        }
        if let Some(relay) = &self.cfg.relay {
            let credential = crate::managed_file::normalize(&relay.credential_file)?;
            if !credential.starts_with(&self.home) {
                exclusions.push(format!(
                    "external relay credential: {}",
                    credential.display()
                ));
            }
        }
        let manifest = Manifest {
            version: 1,
            archive_id: uuid::Uuid::new_v4().to_string(),
            created_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            source_home: self.home.to_string_lossy().into(),
            node_id: self.cfg.node.id.clone(),
            cluster_id: self.cfg.cluster.id.clone(),
            entries,
            exclusions,
        };
        manifest.validate()?;
        self.verify()?;
        Ok(manifest)
    }
}

fn is_lock(path: &str) -> bool {
    path.ends_with(".lock")
}
fn is_sidecar(path: &str) -> bool {
    DATABASES.iter().any(|db| {
        ["-wal", "-shm", "-journal"]
            .iter()
            .any(|suffix| path == format!("{db}{suffix}"))
    })
}

fn inventory(home: &Path) -> Result<BTreeMap<String, Item>> {
    let mut result = BTreeMap::new();
    visit(home, "", &mut result)?;
    Ok(result)
}

fn visit(home: &Path, relative: &str, result: &mut BTreeMap<String, Item>) -> Result<()> {
    ensure!(
        result.len() <= format::MAX_ENTRIES,
        "too many node files for backup"
    );
    if !relative.is_empty() {
        format::safe_path(relative)?;
    }
    let metadata = fs::symlink_metadata(home.join(relative))?;
    ensure!(
        !metadata.file_type().is_symlink()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o022 == 0,
        "node contains linked, unowned or shared-writable state: {relative}"
    );
    ensure!(
        relative.rsplit('/').next() != Some(recovery::MARKER),
        "node contains offline recovery material"
    );
    let excluded = relative == "clusters" || relative == "daemon.sock" || is_lock(relative);
    ensure!(
        !is_lock(relative) || metadata.is_file(),
        "node lock path is not a regular file"
    );
    ensure!(
        relative != "clusters" || metadata.is_dir(),
        "profile container is not a directory"
    );
    ensure!(
        relative != "daemon.sock" || metadata.file_type().is_socket(),
        "daemon socket path is not a socket"
    );
    let kind = if metadata.is_dir() {
        Kind::Directory
    } else {
        ensure!(
            (metadata.is_file() && metadata.nlink() == 1)
                || (relative == "daemon.sock" && metadata.file_type().is_socket()),
            "node contains hard links or unsupported special files"
        );
        ensure!(
            metadata.len() <= format::MAX_FILE_BYTES,
            "node file exceeds archive limit"
        );
        Kind::File
    };
    if relative.ends_with(".sqlite3") {
        ensure!(
            DATABASES.contains(&relative),
            "unsupported additional SQLite database in node directory"
        );
    }
    result.insert(
        relative.into(),
        Item {
            stamp: Stamp::from(&metadata),
            kind,
            excluded,
        },
    );
    if kind == Kind::Directory && !excluded {
        for entry in fs::read_dir(home.join(relative))? {
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("node paths must be UTF-8"))?;
            let child = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            visit(home, &child, result)?;
        }
    }
    Ok(())
}
