//! Publish a closed staged runtime into an auth-only home. The immutable file
//! manifest precedes every copy, and config.toml is the last published file.
use super::*;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write};

const RECORD: &str = "publication.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    cluster: String,
    node: String,
    files: BTreeMap<String, Stamp>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Stamp {
    bytes: u64,
    digest: String,
}

fn stamp(path: &Path) -> Result<Stamp> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.nlink() == 1
            && meta.permissions().mode() & 0o077 == 0,
        "publication requires private, unlinked regular files"
    );
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
        bytes += n as u64;
    }
    ensure!(
        bytes == meta.len(),
        "publication source changed while reading"
    );
    Ok(Stamp {
        bytes,
        digest: format!("{:x}", digest.finalize()),
    })
}
fn allowed_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && !matches!(
            name,
            "auth" | "service.lock" | "daemon.lock" | "daemon.sock"
        )
}
fn read(dir: &Path) -> Result<Option<Manifest>> {
    let path = dir.join(RECORD);
    if !path.try_exists()? {
        return Ok(None);
    }
    let manifest: Manifest = serde_json::from_slice(&read_private_bytes(&path, 64 * 1024)?)
        .map_err(|_| anyhow::anyhow!("invalid join publication record"))?;
    ensure!(
        manifest.version == 1
            && manifest.files.len() <= 64
            && [
                "config.toml",
                "identity.key",
                "owner.key",
                "state.sqlite3",
                "relay.key"
            ]
            .iter()
            .all(|name| manifest.files.contains_key(*name))
            && manifest.files.keys().all(|name| allowed_name(name)),
        "invalid join publication manifest"
    );
    Ok(Some(manifest))
}

pub(super) fn started(dir: &Path) -> bool {
    dir.join(RECORD).exists()
}

pub(super) fn check_home(home: &Path, dir: &Path) -> Result<()> {
    let manifest = read(dir)?;
    for entry in fs::read_dir(home)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().context("unexpected node directory entry")?;
        if name == "auth" {
            config::private_dir(&entry.path())?;
            continue;
        }
        if matches!(name, "service.lock" | "daemon.lock") {
            continue;
        }
        ensure!(
            manifest
                .as_ref()
                .is_some_and(|m| m.files.contains_key(name)),
            "node directory already contains state; restore it before joining"
        );
    }
    Ok(())
}

pub(super) fn publish(home: &Path, pending: &Pending) -> Result<config::Config> {
    let staged = config::load(&pending.runtime)?;
    let replacement = replacement::check_intent(
        &pending.runtime,
        &staged,
        pending.seed.replace_node.as_deref(),
    )?;
    ensure!(
        replacement.as_ref().map(|record| &record.replaces) == pending.seed.replacement.as_ref(),
        "staged replacement differs from pending enrollment"
    );
    if let Some(record) = replacement {
        record.verify_node(&pending.node)?;
    }
    let manifest = match read(&pending.dir)? {
        Some(manifest) => manifest,
        None => {
            let mut files = BTreeMap::new();
            for entry in fs::read_dir(&pending.runtime)? {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("invalid staged file name"))?;
                ensure!(allowed_name(&name), "unexpected staged runtime file");
                files.insert(name, stamp(&entry.path())?);
            }
            ensure!(files.len() <= 64, "too many staged runtime files");
            let manifest = Manifest {
                version: 1,
                cluster: pending.seed.cluster.clone(),
                node: pending.seed.node.clone(),
                files,
            };
            config::write_private(&pending.dir.join(RECORD), &serde_json::to_vec(&manifest)?)?;
            read(&pending.dir)?.context("missing publication record")?
        }
    };
    ensure!(
        manifest.cluster == pending.seed.cluster && manifest.node == pending.node.id(),
        "publication identity changed"
    );
    check_home(home, &pending.dir)?;
    // Validate all sources before writing any target. Staging is immutable once
    // this record exists, including across failed or interrupted publication.
    for (name, expected) in &manifest.files {
        ensure!(
            stamp(&pending.runtime.join(name))? == *expected,
            "staged runtime changed after publication began"
        );
    }
    for name in manifest
        .files
        .keys()
        .filter(|n| n.as_str() != "config.toml")
        .chain(std::iter::once(&"config.toml".to_string()))
    {
        let target = home.join(name);
        let expected = &manifest.files[name];
        if fs::symlink_metadata(&target).is_ok() {
            ensure!(
                stamp(&target)? == *expected,
                "existing file conflicts with interrupted join publication"
            );
            continue;
        }
        let mut temp = tempfile::NamedTempFile::new_in(&pending.dir)?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        std::io::copy(&mut fs::File::open(pending.runtime.join(name))?, &mut temp)?;
        temp.flush()?;
        temp.as_file().sync_all()?;
        ensure!(
            stamp(temp.path())? == *expected,
            "staged runtime changed during publication"
        );
        temp.persist_noclobber(target).map_err(|e| e.error)?;
        fs::File::open(home)?.sync_all()?;
    }
    let config = config::load(home)?;
    ensure!(
        config.node.id == manifest.node && config.cluster.id == manifest.cluster,
        "published configuration has different identities"
    );
    Ok(config)
}
