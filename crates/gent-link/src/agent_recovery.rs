//! New conversation bindings and history assignments, with retryable publication.
use crate::{
    backup,
    integration::{self, Host},
    managed_file::Snapshot,
    mcp::binding,
};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use gent_daemon::config::{self, Config};
use gent_protocol::OwnerOp;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

#[derive(clap::Args)]
pub struct Args {
    pub archive: PathBuf,
    #[arg(long)]
    pub identity: PathBuf,
    #[command(flatten)]
    pub source: backup::HistorySelection,
    /// Display name for the fresh chat.
    #[arg(long)]
    pub name: String,
    /// New private binding path for a host using explicit bindings.
    #[arg(long, required_unless_present_any = ["host", "gateway_client"], conflicts_with_all = ["host", "gateway_client", "conversation"])]
    pub binding: Option<PathBuf>,
    /// Prepare the binding selected by this local host's conversation metadata.
    #[arg(
        long,
        value_enum,
        requires = "conversation",
        conflicts_with = "gateway_client"
    )]
    pub host: Option<Host>,
    /// Prepare a conversation in this existing remote gateway host namespace.
    #[arg(long, requires = "conversation")]
    pub gateway_client: Option<String>,
    #[arg(long)]
    pub conversation: Option<String>,
    /// Exact host-reported user identifier, required for a user-scoped gateway host.
    #[arg(long, requires = "gateway_client")]
    pub subject: Option<String>,
    /// Claude's optional child-chat identifier within the conversation.
    #[arg(long, requires = "host")]
    pub subagent: Option<String>,
    /// Descriptive provider label for an explicit or gateway binding; defaults to generic.
    #[arg(long, conflicts_with = "host")]
    pub provider: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    cluster_id: String,
    node_id: String,
    fingerprint: String,
    credential_hash: String,
    pending_credential: Option<String>,
    result: Option<Completed>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completed {
    agent_id: String,
    import_id: String,
}

fn hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn journal(path: &Path) -> Result<(Snapshot, Option<Journal>)> {
    let path = binding::sidecar(path, ".recovery.json");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => ensure!(
            metadata.len() <= 16 * 1024,
            "binding recovery record is too large"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let snapshot = Snapshot::read(&path)?;
    snapshot.private()?;
    let saved = snapshot
        .text
        .as_ref()
        .map(|text| {
            serde_json::from_str(text)
                .map_err(|_| anyhow::anyhow!("invalid binding recovery record"))
        })
        .transpose()?;
    Ok((snapshot, saved))
}

fn validate(record: &Journal, cfg: &Config) -> Result<()> {
    let valid = match (&record.pending_credential, &record.result) {
        (Some(secret), None) => {
            secret.len() == 64
                && secret.bytes().all(|b| b.is_ascii_hexdigit())
                && hash(secret) == record.credential_hash
        }
        (None, Some(result)) => {
            gent_protocol::history::valid_id(&result.agent_id)
                && gent_protocol::history::valid_id(&result.import_id)
        }
        _ => false,
    };
    ensure!(
        record.version == 1
            && record.cluster_id == cfg.cluster.id
            && record.node_id == cfg.node.id
            && gent_protocol::history::valid_digest(&record.fingerprint)
            && gent_protocol::history::valid_digest(&record.credential_hash)
            && valid,
        "binding recovery record is invalid or belongs to another node"
    );
    Ok(())
}

pub(crate) fn ensure_ready(path: &Path, cfg: &Config) -> Result<()> {
    let (snapshot, saved) = journal(path)?;
    if let Some(saved) = saved {
        validate(&saved, cfg)?;
        ensure!(
            saved.result.is_some(),
            "binding recovery is pending; rerun the same gent chat recover command"
        );
        let credential = config::read_private(path)?;
        ensure!(
            hash(&credential) == saved.credential_hash,
            "recovered binding credential changed"
        );
    }
    snapshot.verify()?;
    Ok(())
}

/// Caller holds the stable binding lock. The journal precedes every credential
/// write, and completed bindings are never regenerated if their key is missing.
fn prepare(path: &Path, cfg: &Config, fingerprint: &str) -> Result<(Journal, File)> {
    let (snapshot, saved) = journal(path)?;
    let key = Snapshot::read(path)?;
    key.private()?;
    let mut record = if let Some(saved) = saved {
        validate(&saved, cfg)?;
        ensure!(
            saved.fingerprint == fingerprint,
            "binding recovery arguments changed; use the original request or a new destination"
        );
        saved
    } else {
        let scope = Snapshot::read(&binding::sidecar(path, ".scope.json"))?;
        ensure!(
            key.text.is_none() && scope.text.is_none(),
            "recovery requires an unused binding; use history import for an existing chat"
        );
        let credential = config::secret();
        Journal {
            version: 1,
            cluster_id: cfg.cluster.id.clone(),
            node_id: cfg.node.id.clone(),
            fingerprint: fingerprint.into(),
            credential_hash: hash(&credential),
            pending_credential: Some(credential),
            result: None,
        }
    };
    if record.result.is_some() {
        ensure!(
            key.text.is_some(),
            "completed recovery binding is missing; restore its current key or use a new destination"
        );
    }
    if let Some(existing) = &key.text {
        ensure!(
            hash(existing.trim()) == record.credential_hash,
            "binding changed during recovery"
        );
    }
    snapshot.write(&(serde_json::to_string(&record)? + "\n"))?;
    if key.text.is_none() {
        key.write(
            record
                .pending_credential
                .as_deref()
                .context("missing pending recovery credential")?,
        )?;
    }
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    file.try_lock_exclusive()
        .context("binding is in use by an MCP connection")?;
    let credential = config::read_private(path)?;
    ensure!(
        hash(&credential) == record.credential_hash,
        "binding changed during recovery"
    );
    binding::pin(path, cfg, &credential, true)?;
    // Keep a transient copy for the owner RPC even after a completed retry. It
    // is never written back to a completed journal or returned to the caller.
    record.pending_credential = Some(credential);
    Ok((record, file))
}

fn complete(path: &Path, cfg: &Config, record: &mut Journal, result: &Value) -> Result<()> {
    let credential = config::read_private(path)?;
    ensure!(
        hash(&credential) == record.credential_hash,
        "binding changed before recovery completed"
    );
    binding::pin(path, cfg, &credential, false)?;
    let completed = Completed {
        agent_id: result["agent"]["id"]
            .as_str()
            .context("recovery response lacks chat")?
            .into(),
        import_id: result["history"]["import_id"]
            .as_str()
            .context("recovery response lacks history")?
            .into(),
    };
    if let Some(previous) = &record.result {
        ensure!(
            previous.agent_id == completed.agent_id && previous.import_id == completed.import_id,
            "recovery identity changed"
        );
    }
    let (snapshot, current) = journal(path)?;
    let current = current.context("binding recovery record disappeared")?;
    validate(&current, cfg)?;
    ensure!(
        current.fingerprint == record.fingerprint
            && current.credential_hash == record.credential_hash,
        "binding recovery record changed"
    );
    record.pending_credential = None;
    record.result = Some(completed);
    validate(record, cfg)?;
    snapshot.write(&(serde_json::to_string(record)? + "\n"))?;
    Ok(())
}

pub async fn execute(home: &Path, args: Args) -> Result<Value> {
    let cfg = config::load(home)?;
    config::label(&args.name)?;
    let provider = args
        .host
        .map(|h| h.name().to_string())
        .unwrap_or_else(|| args.provider.unwrap_or_else(|| "generic".into()));
    config::label(&provider)?;
    if let Some(client) = args.gateway_client {
        ensure!(
            args.binding.is_none() && args.host.is_none(),
            "select one recovery destination"
        );
        let registry = crate::gateway::Registry::open(home)?;
        let prepared = backup::prepare_history(&args.archive, &args.identity, args.source)?;
        let request = hash(
            &json!([
                prepared.manifest_sha256,
                prepared.source_agent,
                args.name,
                provider
            ])
            .to_string(),
        );
        let ticket = registry.prepare_recovery(
            &client,
            args.conversation
                .as_deref()
                .context("gateway recovery requires --conversation")?,
            args.subject.as_deref(),
            &request,
        )?;
        let mut result = register(
            home,
            &prepared,
            ticket.credential.clone(),
            args.name,
            provider,
        )
        .await?;
        registry.complete_recovery(&ticket, &result)?;
        result["gateway_client"] = json!(client);
        result["state"] = json!("recovered");
        return Ok(result);
    }
    let path = match (args.binding, args.host) {
        (Some(path), None) => path,
        (None, Some(host)) => integration::recovery_binding(
            home,
            host,
            args.conversation
                .as_deref()
                .context("host recovery requires --conversation")?,
            args.subagent.as_deref(),
        )?,
        _ => anyhow::bail!("select one binding path or host conversation"),
    };
    let path = binding::normalize(&path)?;
    let _stable = binding::lock(&path)?;
    let prepared = backup::prepare_history(&args.archive, &args.identity, args.source)?;
    let fingerprint = hash(
        &json!([
            "gent-agent-recovery-v1",
            cfg.cluster.id,
            cfg.node.id,
            path,
            prepared.manifest_sha256,
            prepared.source_agent,
            args.name,
            provider
        ])
        .to_string(),
    );
    let (mut record, _credential) = prepare(&path, &cfg, &fingerprint)?;
    let result = register(
        home,
        &prepared,
        record
            .pending_credential
            .as_ref()
            .context("missing recovery credential")?
            .clone(),
        args.name,
        provider,
    )
    .await?;
    complete(&path, &cfg, &mut record, &result)?;
    let mut output = result;
    output["binding"] = json!(path);
    output["state"] = json!("recovered");
    Ok(output)
}

async fn register(
    home: &Path,
    prepared: &backup::PreparedHistory,
    credential: String,
    name: String,
    provider: String,
) -> Result<Value> {
    crate::owner(
        home,
        OwnerOp::AgentRecover {
            directory: prepared
                .directory
                .to_str()
                .context("history path must be UTF-8")?
                .into(),
            manifest_sha256: prepared.manifest_sha256.clone(),
            source_agent: prepared.source_agent.clone(),
            agent_credential: credential,
            name,
            provider,
        },
    )
    .await
}

#[cfg(test)]
mod tests;
