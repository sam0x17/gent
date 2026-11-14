//! Versioned manifest and ordered raw payloads inside an age stream.
use super::open_regular;
use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{BufReader, Cursor, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

pub(super) const MAX_ENTRIES: usize = 65_536;
pub(super) const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub(super) const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_MANIFEST: usize = 16 * 1024 * 1024;
const MAX_CIPHERTEXT: u64 = MAX_TOTAL_BYTES + MAX_MANIFEST as u64 + 32 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"GENTBK01";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    File,
    Directory,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub path: String,
    pub kind: Kind,
    pub bytes: u64,
    pub sha256: Option<String>,
}
impl Entry {
    pub fn is_dir(&self) -> bool {
        self.kind == Kind::Directory
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub version: u8,
    pub archive_id: String,
    pub created_at: u64,
    pub source_home: String,
    pub node_id: String,
    pub cluster_id: String,
    pub entries: Vec<Entry>,
    pub exclusions: Vec<String>,
}

impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.created_at > 0 && self.created_at < (1 << 53),
            "unsupported archive metadata"
        );
        for id in [&self.archive_id, &self.node_id, &self.cluster_id] {
            ensure!(
                uuid::Uuid::parse_str(id).is_ok_and(|u| !u.is_nil() && u.to_string() == *id),
                "invalid archive identity"
            );
        }
        ensure!(
            Path::new(&self.source_home).is_absolute()
                && self.source_home.len() <= 8192
                && !self.source_home.chars().any(char::is_control),
            "invalid archive source directory"
        );
        ensure!(
            !self.entries.is_empty() && self.entries.len() <= MAX_ENTRIES,
            "archive entry limit exceeded"
        );
        ensure!(
            self.exclusions.len() <= MAX_ENTRIES + 256
                && self
                    .exclusions
                    .iter()
                    .all(|s| s.len() <= 8192 && !s.chars().any(char::is_control)),
            "invalid archive exclusions"
        );
        let mut known = BTreeMap::new();
        let mut previous = "";
        let mut total = 0_u64;
        for entry in &self.entries {
            safe_path(&entry.path)?;
            ensure!(
                entry.path.as_str() > previous,
                "archive paths are duplicated or out of order"
            );
            previous = &entry.path;
            ensure!(
                entry.path != "clusters"
                    && !entry.path.starts_with("clusters/")
                    && entry.path != "daemon.sock"
                    && !entry.path.ends_with(".lock")
                    && !entry
                        .path
                        .split('/')
                        .any(|p| p == gent_daemon::recovery::MARKER),
                "archive contains excluded runtime paths"
            );
            if let Some((parent, _)) = entry.path.rsplit_once('/') {
                ensure!(
                    known.get(parent) == Some(&Kind::Directory),
                    "archive parent is missing or is not a directory"
                );
            }
            if entry.is_dir() {
                ensure!(
                    entry.bytes == 0 && entry.sha256.is_none(),
                    "invalid directory entry"
                );
            } else {
                ensure!(
                    entry.bytes <= MAX_FILE_BYTES
                        && entry.sha256.as_ref().is_some_and(|s| {
                            s.len() == 64
                                && s.bytes()
                                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                        }),
                    "invalid file entry"
                );
                total = total
                    .checked_add(entry.bytes)
                    .context("archive size overflow")?;
                ensure!(total <= MAX_TOTAL_BYTES, "archive payload limit exceeded");
            }
            known.insert(entry.path.as_str(), entry.kind);
        }
        for required in ["config.toml", "identity.key", "state.sqlite3"] {
            ensure!(
                known.get(required) == Some(&Kind::File),
                "archive is missing required node state"
            );
        }
        Ok(())
    }

    pub fn summary(&self, state: &str) -> Value {
        json!({"state":state,"version":self.version,"archive_id":self.archive_id,
            "created_at":self.created_at,"node_id":self.node_id,"cluster_id":self.cluster_id,
            "source_home":self.source_home,"files":self.entries.iter().filter(|e| !e.is_dir()).count(),
            "directories":self.entries.iter().filter(|e| e.is_dir()).count(),
            "bytes":self.entries.iter().map(|e| e.bytes).sum::<u64>(),"exclusions":self.exclusions,
            "scope":"one offline node profile; historical state, not proof of current cluster authority"})
    }
}

pub(super) fn safe_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 1024
            && path.split('/').count() <= 64
            && !path.chars().any(|c| c.is_control() || c == '\\')
            && path
                .split('/')
                .all(|p| !matches!(p, "" | "." | "..") && p.len() <= 255),
        "unsafe or oversized archive path"
    );
    Ok(())
}

fn authenticator(identity: &age::x25519::Identity) -> Hmac<Sha256> {
    let secret = identity.to_string();
    let mut hash = Sha256::new();
    hash.update(b"gent-backup-manifest-key-v1\0");
    hash.update(secret.expose_secret().as_bytes());
    let key = Zeroizing::new(<[u8; 32]>::from(hash.finalize()));
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_ref()).expect("SHA-256 key length");
    mac.update(b"gent-backup-manifest-v1\0");
    mac
}

pub(super) fn write(
    output: impl Write,
    key: &age::x25519::Identity,
    manifest: &Manifest,
    home: &Path,
) -> Result<()> {
    manifest.validate()?;
    let bytes = Zeroizing::new(serde_jcs::to_vec(manifest)?);
    ensure!(bytes.len() <= MAX_MANIFEST, "archive manifest is too large");
    let mut mac = authenticator(key);
    mac.update(&bytes);
    let recipient = key.to_public();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?;
    let mut writer = encryptor.wrap_output(output)?;
    writer.write_all(MAGIC)?;
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.write_all(&mac.finalize().into_bytes())?;
    for entry in manifest.entries.iter().filter(|e| !e.is_dir()) {
        let mut file = open_regular(&home.join(&entry.path), false)?;
        file.try_lock_exclusive().context("node file is busy")?;
        let hash = copy_file(&mut file, &mut writer, entry.bytes)?;
        ensure!(
            Some(hash) == entry.sha256,
            "node file changed while writing archive"
        );
    }
    writer.finish()?;
    Ok(())
}

pub(super) fn read(
    archive: &Path,
    key: &age::x25519::Identity,
    destination: Option<&Path>,
) -> Result<Manifest> {
    read_selected(archive, key, destination, false)
}

/// Authenticate every payload, materializing only the database needed for a
/// historical export. The caller must guard the temporary directory first.
pub(super) fn read_database(
    archive: &Path,
    key: &age::x25519::Identity,
    destination: &Path,
) -> Result<Manifest> {
    read_selected(archive, key, Some(destination), true)
}

fn read_selected(
    archive: &Path,
    key: &age::x25519::Identity,
    destination: Option<&Path>,
    only_database: bool,
) -> Result<Manifest> {
    let file = open_regular(archive, false)?;
    let before = super::capture::Stamp::from(&file.metadata()?);
    ensure!(
        file.metadata()?.len() <= MAX_CIPHERTEXT,
        "archive exceeds ciphertext limit"
    );
    let mut input = BufReader::new(&file);
    // Bound the unauthenticated age header before passing it to age's parser.
    // Reading one byte here uses BufReader; payload bytes remain in the reader.
    let mut header = Vec::new();
    let mut start = 0;
    loop {
        ensure!(header.len() < 16 * 1024, "age header is too large");
        let mut byte = [0];
        input
            .read_exact(&mut byte)
            .context("truncated age header")?;
        header.push(byte[0]);
        if byte[0] == b'\n' {
            if header[start..].starts_with(b"--- ") {
                break;
            }
            start = header.len();
        }
    }
    ensure!(
        header.starts_with(b"age-encryption.org/v1\n"),
        "unsupported archive encryption"
    );
    let decryptor = age::Decryptor::new(Cursor::new(header).chain(input))
        .map_err(|_| anyhow::anyhow!("invalid archive encryption header"))?;
    ensure!(
        !decryptor.is_scrypt(),
        "expected an X25519 recovery archive"
    );
    let mut reader = decryptor
        .decrypt(std::iter::once(key as &dyn age::Identity))
        .map_err(|_| anyhow::anyhow!("archive decryption failed; check the recovery identity"))?;
    let manifest = read_payload(&mut reader, key, destination, only_database)?;
    ensure!(
        super::capture::Stamp::from(&file.metadata()?) == before,
        "archive changed during verification"
    );
    Ok(manifest)
}

fn read_payload(
    reader: &mut impl Read,
    key: &age::x25519::Identity,
    destination: Option<&Path>,
    only_database: bool,
) -> Result<Manifest> {
    let mut magic = [0; 8];
    reader.read_exact(&mut magic)?;
    ensure!(&magic == MAGIC, "unsupported Gent archive format");
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(
        length > 0 && length <= MAX_MANIFEST,
        "invalid archive manifest length"
    );
    let mut bytes = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes)?;
    let mut tag = [0; 32];
    reader.read_exact(&mut tag)?;
    let mut mac = authenticator(key);
    mac.update(&bytes);
    mac.verify_slice(&tag)
        .map_err(|_| anyhow::anyhow!("archive origin authentication failed"))?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid archive manifest"))?;
    ensure!(
        serde_jcs::to_vec(&manifest)? == *bytes,
        "archive manifest is not canonical"
    );
    manifest.validate()?;
    for entry in &manifest.entries {
        let destination = destination.filter(|_| !only_database || entry.path == "state.sqlite3");
        if entry.is_dir() {
            if let Some(destination) = destination {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(destination.join(&entry.path))?;
            }
            continue;
        }
        let hash = if let Some(destination) = destination {
            let mut output = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(destination.join(&entry.path))?;
            let hash = transfer(reader, &mut output, entry.bytes)?;
            output.sync_all()?;
            hash
        } else {
            transfer(reader, &mut std::io::sink(), entry.bytes)?
        };
        ensure!(Some(hash) == entry.sha256, "archive file hash mismatch");
    }
    let mut trailing = [0];
    // Forces authentication of the age final chunk and rejects extra plaintext.
    ensure!(
        reader.read(&mut trailing)? == 0,
        "archive has trailing payload"
    );
    Ok(manifest)
}

pub(super) fn copy_file(
    input: &mut impl Read,
    output: &mut impl Write,
    bytes: u64,
) -> Result<String> {
    let hash = transfer(input, output, bytes)?;
    let mut extra = [0];
    ensure!(
        input.read(&mut extra)? == 0,
        "node file changed size during backup"
    );
    Ok(hash)
}

fn transfer(input: &mut impl Read, output: &mut impl Write, mut bytes: u64) -> Result<String> {
    let mut buffer = Zeroizing::new([0_u8; 64 * 1024]);
    let mut hash = Sha256::new();
    while bytes > 0 {
        let count = usize::try_from(bytes.min(buffer.len() as u64))?;
        input.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
        bytes -= count as u64;
    }
    Ok(format!("{:x}", hash.finalize()))
}
