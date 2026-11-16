//! Guard enrollment before it can allocate a second local identity.
use super::*;
use crate::{cluster, pairing, setup};
use serde_json::{Value, json};

pub(crate) async fn create(home: &Path, name: String, local: bool) -> Result<Value> {
    resolve(home, None)?;
    config::label(&name)?;
    if Snapshot::read(&config::path(home))?.text.is_some() {
        let cfg = inspect(home)?;
        let installation = cluster::installation(home)?;
        let same = if local {
            cfg.cluster.local_only && cfg.cluster.name == name
        } else {
            installation
                .as_ref()
                .is_some_and(|s| s.owner && s.name == name)
        };
        ensure!(
            same,
            "this node already belongs to cluster {}; run gent node reset before enrolling in another cluster",
            cfg.cluster.name
        );
        if installation.is_none_or(|s| !s.pending) {
            return Ok(
                json!({"status":"configured","already_configured":true,"cluster":cfg.cluster,"node":cfg.node}),
            );
        }
    }
    if local {
        Ok(json!(cluster::local(home, &name)?))
    } else {
        cluster::connect(home, Some(&name)).await
    }
}

pub(crate) async fn join(home: &Path, args: pairing::JoinArgs) -> Result<Value> {
    resolve(home, None)?;
    let cluster = args.target_cluster()?;
    if Snapshot::read(&config::path(home))?.text.is_some() {
        let cfg = inspect(home)?;
        ensure!(
            cfg.cluster.id == cluster,
            "this node already belongs to cluster {}; run gent node reset before enrolling in another cluster",
            cfg.cluster.name
        );
    }
    if let Some(result) = args.existing(home)? {
        return Ok(result);
    }
    pairing::join(home, args).await
}

pub(crate) async fn install(
    home: &Path,
    local: Option<String>,
    options: setup::Options,
    human: bool,
) -> Result<Value> {
    resolve(home, None)?;
    setup::install(home, local, options, human).await
}
