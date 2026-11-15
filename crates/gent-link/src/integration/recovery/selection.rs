//! Resolve host-specific selection, then save node-local intent under one lock.
use super::*;

fn binary(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() || path.components().count() > 1 {
        ensure!(path.is_file(), "host executable not found");
        return Ok(std::path::absolute(path)?);
    }
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let candidate = directory.join(path);
        if candidate.is_file() {
            return Ok(std::path::absolute(candidate)?);
        }
    }
    anyhow::bail!("host executable not found; use --host-binary")
}

pub(super) async fn enable(
    home: &Path,
    host: Host,
    thread_id: String,
    config_dir: Option<PathBuf>,
    host_binary: Option<PathBuf>,
) -> Result<Value> {
    let cfg = config::load(home)?;
    let host_binary = binary(host_binary.as_deref().unwrap_or_else(|| {
        Path::new(match host {
            Host::Codex => "codex",
            Host::ClaudeCode => "claude",
        })
    }))?;
    let (id, mut entry) = match host {
        Host::Codex => codex::select(home, &cfg, thread_id, config_dir, host_binary).await?,
        Host::ClaudeCode => {
            let selected = crate::integration::runtime::claude_recovery::select(
                home,
                config_dir,
                &host_binary,
                &thread_id,
            )
            .await?;
            (
                selected.agent,
                RecoveryAgent {
                    host: RecoveryHost::ClaudeCode,
                    id: uuid::Uuid::new_v4().to_string(),
                    thread_id,
                    config_dir: selected.directory,
                    host_binary,
                    credential_hash: hash(&selected.credential),
                    working_dir: Some(selected.working_dir),
                },
            )
        }
    };
    let _lock = lock(home)?;
    let latest = config::load(home)?;
    ensure!(
        latest.cluster.id == cfg.cluster.id && latest.node.id == cfg.node.id,
        "node changed during host recovery setup"
    );
    journal::initialize(home, &latest)?;
    config::edit_local(home, |current| {
        ensure!(
            current.cluster.id == cfg.cluster.id && current.node.id == cfg.node.id,
            "node changed during host recovery setup"
        );
        let mut saved = selections(current)?;
        if let Some(old) = saved.agents.get(&id) {
            let mut same = entry.clone();
            same.id = old.id.clone();
            if &same == old {
                entry.id = old.id.clone();
            }
        }
        saved.agents.insert(id.clone(), entry.clone());
        current.set_host_recovery(saved)
    })?;
    Ok(json!({"agent":id,"enabled":true,"selection":entry,
        "next":"The Gent daemon may restore this native conversation for unclaimed pending messages. Incomplete history or a retained native queue requires owner review."}))
}
