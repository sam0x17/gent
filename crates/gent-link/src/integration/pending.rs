//! One node-local demand page drives managed wake delivery and discovery recovery.
use super::{config, discovery, refresh, wake};
use anyhow::{Result, ensure};
use gent_protocol::OwnerOp;
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path, time::Duration};

const ATTEMPTS_PER_TICK: usize = 8;

#[derive(Deserialize)]
struct Page {
    agents: Vec<String>,
    next: Option<String>,
    #[serde(default)]
    binding_tags: BTreeMap<String, String>,
}

#[derive(Default)]
pub(crate) struct Pending {
    after: Option<String>,
    recovery_errors: BTreeMap<String, String>,
}

impl Pending {
    pub(crate) async fn tick(&mut self, home: &Path) -> Result<()> {
        let cfg = config::load(home)?;
        let folder = wake::codex_binding_dir(home, &cfg);
        if !folder.is_dir() && !cfg.discovery()?.enabled {
            self.after = None;
            return Ok(());
        }
        let page: Page = serde_json::from_value(
            crate::owner(
                home,
                OwnerOp::WakePendingAgents {
                    after: self.after.clone(),
                },
            )
            .await?,
        )?;
        if page.agents.is_empty() {
            self.after = None;
            return Ok(());
        }
        let recoveries = discovery::pending_recoveries(home, &cfg);
        let bindings = refresh::codex_sockets(home).and_then(|endpoints| {
            wake::pending_codex_bindings(&folder, &cfg, &page.binding_tags, &endpoints)
        });
        let mut attempted = 0;
        let mut failed = false;
        // Advance for skipped and failed recipients as well. Persistent work
        // on the first page cannot starve later pages or the next cycle.
        for id in &page.agents {
            let recovery = recoveries.as_ref().ok().and_then(|r| r.get(id));
            let binding = bindings.as_ref().ok().and_then(|b| b.get(id));
            if recovery.is_some() || binding.is_some() {
                if attempted == ATTEMPTS_PER_TICK {
                    break;
                }
                attempted += 1;
            }
            self.after = Some(id.clone());
            if let Some((socket, thread)) = binding {
                failed |= crate::wake::codex::catch_up(home, socket, thread, id)
                    .await
                    .is_err();
            }
            if let Some(entry) = recovery {
                match discovery::recover_pending(home, &cfg, id, entry).await {
                    Ok(()) => {
                        self.recovery_errors.remove(id);
                    }
                    Err(error) => {
                        let error = error.to_string();
                        if self.recovery_errors.get(id) != Some(&error) {
                            eprintln!("Gent discovered chat {id}: {error}");
                            self.recovery_errors.insert(id.clone(), error);
                        }
                    }
                }
            }
        }
        if self.after.as_ref() == page.agents.last() {
            self.after = page.next;
        }
        recoveries?;
        bindings?;
        ensure!(
            !failed,
            "Codex wake endpoint unavailable or submission uncertain"
        );
        Ok(())
    }
}

pub(crate) async fn maintain(home: &Path) {
    let mut timer = tokio::time::interval(Duration::from_secs(5));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending = Pending::default();
    let mut previous = None;
    loop {
        timer.tick().await;
        let error = pending.tick(home).await.err().map(|e| e.to_string());
        if error != previous {
            if let Some(error) = &error {
                eprintln!("Gent pending delivery: {error}");
            }
            previous = error;
        }
    }
}
