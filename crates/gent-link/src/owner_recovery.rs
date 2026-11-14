//! Private, local-owner evidence collection. No signer activation or key export.
use crate::managed_file::{self, Snapshot};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use gent_crypto::recovery::{RecoveryBaseline, RecoveryReviewer, SignedRecoveryObservation};
use gent_protocol::OwnerOp;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

#[cfg(test)]
mod tests;

#[derive(Subcommand)]
pub enum Command {
    /// Pin this node's accepted checkpoint in a new private challenge file.
    Challenge {
        #[arg(long)]
        out: PathBuf,
    },
    /// Save this node's signed observation for a trusted challenge file.
    Witness {
        challenge: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Compare signed reports offline. This never authorizes an owner change.
    Inspect {
        challenge: PathBuf,
        #[arg(num_args = 0..=1024)]
        reports: Vec<PathBuf>,
    },
}

fn read(path: &Path) -> Result<Vec<u8>> {
    let snapshot = Snapshot::read(path)?;
    snapshot
        .private()
        .context("recovery evidence must be private")?;
    Ok(snapshot
        .text
        .context("recovery evidence file is missing")?
        .into_bytes())
}

fn destination(path: &Path) -> Result<PathBuf> {
    let path = managed_file::normalize(path)?;
    let snapshot = Snapshot::read(&path)?;
    ensure!(snapshot.text.is_none(), "recovery output already exists");
    managed_file::directory(path.parent().context("output has no parent directory")?)?;
    Ok(path)
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output has no parent directory")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn inspect(challenge: &Path, reports: &[PathBuf]) -> Result<Value> {
    ensure!(reports.len() <= 1024, "too many recovery reports");
    let baseline = RecoveryBaseline::decode(&read(challenge)?)?;
    let mut review = RecoveryReviewer::new(baseline, gent_daemon::store::now() as u64)?;
    for path in reports {
        let report = SignedRecoveryObservation::decode(&read(path)?)?;
        review.observe(&report, gent_daemon::store::now() as u64)?;
    }
    Ok(serde_json::to_value(
        review.finish(gent_daemon::store::now() as u64)?,
    )?)
}

pub async fn execute(home: &Path, command: Command) -> Result<Value> {
    match command {
        Command::Challenge { out } => {
            let out = destination(&out)?;
            let value = crate::owner(home, OwnerOp::RecoveryChallenge).await?;
            let baseline: RecoveryBaseline = serde_json::from_value(value)?;
            baseline.verify(gent_daemon::store::now() as u64)?;
            write(&out, &baseline.encode()?)?;
            Ok(
                json!({"path":out,"challenge":baseline.challenge.id,"baseline":baseline.challenge.base,
                "valid_until":baseline.challenge.expires_at,"contains_private_configuration":true,
                "authorizes_owner_change":false}),
            )
        }
        Command::Witness { challenge, out } => {
            let out = destination(&out)?;
            let baseline = RecoveryBaseline::decode(&read(&challenge)?)?;
            baseline.verify(gent_daemon::store::now() as u64)?;
            let value = crate::owner(
                home,
                OwnerOp::RecoveryObserve {
                    challenge: String::from_utf8(baseline.challenge.encode()?)?,
                },
            )
            .await?;
            let report: SignedRecoveryObservation = serde_json::from_value(value)?;
            let checkpoint =
                report.verify(&baseline.challenge, gent_daemon::store::now() as u64)?;
            write(&out, &report.encode()?)?;
            Ok(
                json!({"path":out,"challenge":baseline.challenge.id,"node":report.observation.observer,
                "checkpoint":checkpoint,"valid_until":baseline.challenge.expires_at,
                "contains_private_configuration":true,"authorizes_owner_change":false}),
            )
        }
        Command::Inspect { challenge, reports } => inspect(&challenge, &reports),
    }
}
