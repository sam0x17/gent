//! Offline archives. Never open saved runtime/MLS state through operational APIs.
mod capture;
mod format;
mod history;
#[cfg(test)]
mod tests;

use crate::managed_file;
use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, ensure};
use gent_daemon::{config, recovery};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(clap::Subcommand)]
pub enum Command {
    /// Generate a private recovery key; keep it outside node state and archives.
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    /// Back up a stopped node. This does not stop or restart its daemon.
    Create {
        archive: PathBuf,
        #[arg(long)]
        identity: PathBuf,
    },
    /// Verify every byte without extracting or contacting any service.
    Verify {
        archive: PathBuf,
        #[arg(long)]
        identity: PathBuf,
    },
    /// Verify, then show archive metadata and optionally its file inventory.
    Inspect {
        archive: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        files: bool,
    },
    /// Verify and extract into a new, guarded offline directory. Does not activate it.
    Extract {
        archive: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Export archived Gent messages and files as offline history, without keys or live queues.
    History {
        archive: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long, required_unless_present = "list")]
        output: Option<PathBuf>,
        /// List saved imports and their recipients instead of exporting content.
        #[arg(long, conflicts_with_all = ["output", "from_import"])]
        list: bool,
        /// Export one previously imported history set from this archive.
        #[arg(long)]
        from_import: Option<String>,
    },
}

pub fn execute(command: Command, home: Option<&Path>, context: Option<&str>) -> Result<Value> {
    match command {
        Command::Keygen { output } => {
            ensure!(context.is_none(), "--cluster applies only to backup create");
            let output = destination(&output)?;
            let key = age::x25519::Identity::generate();
            let mut temporary = private_temp(output.parent().context("missing key directory")?)?;
            writeln!(temporary, "{}", key.to_string().expose_secret())?;
            publish(temporary, &output)?;
            Ok(
                json!({"state":"created", "identity":output, "recipient":key.to_public().to_string(),
                "keep":"store this secret separately from node state and backup archives"}),
            )
        }
        Command::Create { archive, identity } => {
            let root = home
                .map(Path::to_path_buf)
                .or_else(|| std::env::var_os("GENT_HOME").map(PathBuf::from))
                .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".gent")))
                .context("cannot locate home; pass --home")?;
            recovery::ensure_active(&root)?;
            let home = crate::node_home::resolve(&root, context)?;
            create(&home, &archive, &identity)
        }
        Command::Verify { archive, identity }
        | Command::Inspect {
            archive,
            identity,
            files: false,
        } => {
            ensure!(context.is_none(), "--cluster applies only to backup create");
            let key = read_key(&identity)?;
            Ok(format::read(&archive, &key, None)?.summary("verified"))
        }
        Command::Inspect {
            archive,
            identity,
            files: true,
        } => {
            ensure!(context.is_none(), "--cluster applies only to backup create");
            let key = read_key(&identity)?;
            let manifest = format::read(&archive, &key, None)?;
            let mut value = manifest.summary("verified");
            value["entries"] = serde_json::to_value(&manifest.entries)?;
            Ok(value)
        }
        Command::Extract {
            archive,
            identity,
            output,
        } => {
            ensure!(context.is_none(), "--cluster applies only to backup create");
            extract(&archive, &identity, &output)
        }
        Command::History {
            archive,
            identity,
            output,
            list,
            from_import,
        } => {
            ensure!(context.is_none(), "--cluster applies only to backup create");
            if list {
                history::list(&archive, &identity)
            } else {
                let output = output.context("history export requires --output")?;
                if let Some(import) = from_import {
                    history::export_import(&archive, &identity, &output, &import)
                } else {
                    history::export(&archive, &identity, &output)
                }
            }
        }
    }
}

#[derive(clap::Args)]
#[group(required = true, multiple = false)]
pub struct HistorySelection {
    #[arg(long = "from-chat", alias = "from-agent", value_name = "CHAT_ID")]
    pub from_agent: Option<String>,
    #[arg(long)]
    pub from_import: Option<String>,
}

pub async fn import_history(
    home: &Path,
    archive: &Path,
    identity: &Path,
    selection: HistorySelection,
    target_agent: String,
    restore_revision: Option<u64>,
) -> Result<Value> {
    let prepared = prepare_history(archive, identity, selection)?;
    crate::owner(
        home,
        gent_protocol::OwnerOp::HistoryImport {
            directory: prepared
                .directory
                .to_str()
                .context("history path must be UTF-8")?
                .into(),
            manifest_sha256: prepared.manifest_sha256.clone(),
            source_agent: prepared.source_agent.clone(),
            target_agent,
            restore_revision,
        },
    )
    .await
}

pub struct PreparedHistory {
    _scratch: tempfile::TempDir,
    pub directory: PathBuf,
    pub manifest_sha256: String,
    pub source_agent: String,
}

pub fn prepare_history(
    archive: &Path,
    identity: &Path,
    selection: HistorySelection,
) -> Result<PreparedHistory> {
    use sha2::{Digest as _, Sha256};
    let scratch = tempfile::Builder::new()
        .prefix("gent-history-import-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let directory = scratch.path().join("history");
    let source_agent = match (selection.from_agent, selection.from_import) {
        (Some(agent), None) => {
            history::export(archive, identity, &directory)?;
            agent
        }
        (None, Some(import)) => {
            let report = history::export_import(archive, identity, &directory, &import)?;
            report["source_agent"]
                .as_str()
                .context("missing historical source chat")?
                .to_string()
        }
        _ => anyhow::bail!("select exactly one of --from-chat or --from-import"),
    };
    let directory = fs::canonicalize(directory)?;
    ensure!(
        gent_protocol::history::valid_id(&source_agent),
        "invalid archived chat identity"
    );
    {
        use std::io::{BufRead, BufReader};
        let mut reader = BufReader::new(File::open(directory.join("agents.jsonl"))?);
        let mut found = false;
        for _ in 0..65_536 {
            let mut line = Vec::new();
            let size = (&mut reader).take(4097).read_until(b'\n', &mut line)?;
            if size == 0 {
                break;
            }
            ensure!(
                size <= 4096 && line.last() == Some(&b'\n'),
                "invalid exported chat record"
            );
            let agent: gent_protocol::Agent =
                serde_json::from_slice(&line).context("invalid exported chat record")?;
            if agent.id == source_agent {
                found = true;
                break;
            }
        }
        ensure!(found, "archived chat is absent from this history");
    }
    let manifest_sha256 = format!(
        "{:x}",
        Sha256::digest(fs::read(directory.join("history.json"))?)
    );
    Ok(PreparedHistory {
        _scratch: scratch,
        directory,
        manifest_sha256,
        source_agent,
    })
}

fn create(home: &Path, archive: &Path, identity: &Path) -> Result<Value> {
    let home = managed_file::normalize(home)?;
    recovery::ensure_active(&home)?;
    let identity = managed_file::normalize(identity)?;
    let archive = destination(archive)?;
    ensure!(
        !identity.starts_with(&home) && !archive.starts_with(&home),
        "keep the recovery key and archive outside the selected node directory"
    );
    let key = read_key(&identity)?;
    let capture = capture::Capture::open(&home)?;
    let manifest = capture.manifest()?;
    let mut temporary = private_temp(archive.parent().context("missing archive directory")?)?;
    format::write(&mut temporary, &key, &manifest, &home)?;
    capture.verify()?;
    publish(temporary, &archive)?;
    let mut value = manifest.summary("created");
    value["archive"] = json!(archive);
    Ok(value)
}

fn extract(archive: &Path, identity: &Path, output: &Path) -> Result<Value> {
    let key = read_key(identity)?;
    let output = destination(output)?;
    let parent = output.parent().context("missing extraction parent")?;
    let staging = tempfile::Builder::new()
        .prefix(".gent-recovery-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    config::write_private(
        &staging.path().join(recovery::MARKER),
        b"{\"version\":1,\"state\":\"unverified_extraction\"}\n",
    )?;
    let manifest = format::read(archive, &key, Some(staging.path()))?;
    config::write_private(
        &staging.path().join(recovery::MARKER),
        &serde_json::to_vec(&json!({
            "version":1,"state":"verified_offline","archive_id":manifest.archive_id,
            "node_id":manifest.node_id,"cluster_id":manifest.cluster_id,
            "activation":"unsupported; use fresh identities and authenticated enrollment"
        }))?,
    )?;
    // Children were synced while writing; sync directories from deepest to root.
    for entry in manifest.entries.iter().rev().filter(|e| e.is_dir()) {
        File::open(staging.path().join(&entry.path))?.sync_all()?;
    }
    File::open(staging.path())?.sync_all()?;
    publish_directory(staging.path(), &output)?;
    // TempDir still owns only its old (now absent) staging path.
    File::open(parent)?.sync_all()?;
    let mut value = manifest.summary("extracted_offline");
    value["output"] = json!(output);
    value["activation"] = json!("unsupported");
    Ok(value)
}

fn publish_directory(staging: &Path, output: &Path) -> Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging,
        rustix::fs::CWD,
        output,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .context("cannot publish recovery directory without overwriting")?;
    Ok(())
}

fn destination(path: &Path) -> Result<PathBuf> {
    let path = managed_file::normalize(path)?;
    ensure!(
        matches!(fs::symlink_metadata(&path), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "output already exists or cannot be inspected"
    );
    let parent = path.parent().context("missing output directory")?;
    ensure!(parent.is_dir(), "create the output parent directory first");
    managed_file::directory(parent)?;
    Ok(path)
}

fn private_temp(parent: &Path) -> Result<tempfile::NamedTempFile> {
    let temporary = tempfile::Builder::new()
        .prefix(".gent-backup-")
        .tempfile_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(temporary)
}

fn publish(temporary: tempfile::NamedTempFile, output: &Path) -> Result<()> {
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(output).map_err(|e| e.error)?;
    File::open(output.parent().context("missing output parent")?)?.sync_all()?;
    Ok(())
}

fn open_regular(path: &Path, private: bool) -> Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & if private { 0o077 } else { 0o022 } == 0,
        "backup inputs must be owned regular files without links or shared write access"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    ensure!(
        capture::Stamp::from(&metadata) == capture::Stamp::from(&file.metadata()?),
        "backup input changed while opening"
    );
    Ok(file)
}

fn read_key(path: &Path) -> Result<age::x25519::Identity> {
    let file = open_regular(path, true)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(1025).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1024, "invalid recovery identity file");
    std::str::from_utf8(&bytes)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .context("expected one private age X25519 recovery identity")
}
