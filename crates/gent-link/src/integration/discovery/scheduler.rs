//! Index native chats and inspect only recipients with pending work.
use super::*;
use std::sync::{Arc, Mutex};

pub(crate) async fn maintain(home: &Path) {
    let mut timer = tokio::time::interval(Duration::from_secs(5));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut next_scan = tokio::time::Instant::now();
    let mut runner = None;
    let mut endpoint = None;
    let mut cursor = None;
    let mut recovery_errors = BTreeMap::<String, String>::new();
    let mut previous_error = None;
    loop {
        timer.tick().await;
        let result = async {
            let cfg = config::load(home)?;
            if !cfg.discovery()?.enabled {
                runner = None;
                endpoint = None;
                next_scan = tokio::time::Instant::now();
                return Ok(());
            }
            if tokio::time::Instant::now() >= next_scan {
                next_scan = tokio::time::Instant::now() + Duration::from_secs(60);
                refresh(home).await?;
            }
            if let Ok((_, socket)) = install::codex_runtime_target(home, None, false) {
                if endpoint.as_ref() != Some(&socket) {
                    runner = None;
                    let bindings =
                        Arc::new(Mutex::new(super::super::Bindings::new(home, Host::Codex)?));
                    runner = Some(crate::wake::codex::Runner::start(
                        home.into(),
                        socket.clone(),
                        bindings,
                    )?);
                    endpoint = Some(socket);
                }
            } else {
                runner = None;
                endpoint = None;
            }
            let (_, catalog) = storage::read(home, &cfg)?;
            if catalog
                .hosts
                .values()
                .any(|state| state["status"] == "partial" || state["status"] == "scanning")
            {
                next_scan = next_scan.min(tokio::time::Instant::now() + Duration::from_secs(5));
            }
            let entries: BTreeMap<_, _> = catalog
                .entries
                .values()
                .filter(|entry| entry.recovery.is_some())
                .map(|entry| (entry.agent.as_str(), entry))
                .collect();
            if !entries.is_empty() {
                let pending = crate::owner(
                    home,
                    gent_protocol::OwnerOp::WakePendingAgents {
                        after: cursor.clone(),
                    },
                )
                .await?;
                let ids = pending["agents"]
                    .as_array()
                    .context("invalid pending chats")?;
                let mut processed = 0;
                let mut attempted = 0;
                for id in ids {
                    let id = id.as_str().context("invalid pending chat")?;
                    cursor = Some(id.to_owned());
                    processed += 1;
                    let Some(entry) = entries.get(id) else {
                        continue;
                    };
                    enabled(home, &cfg)?;
                    // Existing recovery checks intact bindings, pending messages,
                    // native approvals/history and the durable shared retry budget.
                    let outcome = tokio::time::timeout(
                        Duration::from_secs(30),
                        super::super::recovery::recover_discovered(
                            home,
                            &entry.agent,
                            entry.recovery.as_ref().unwrap(),
                        ),
                    )
                    .await;
                    let error = match outcome {
                        Ok(Ok("needs_owner")) => {
                            Some("native chat needs owner review before recovery".into())
                        }
                        Ok(Ok("limited")) => {
                            Some("native recovery is waiting for its retry budget".into())
                        }
                        Ok(Ok(_)) => None,
                        Ok(Err(error)) => Some(error.to_string()),
                        Err(_) => Some("native recovery timed out; inspect the host".into()),
                    };
                    if let Some(error) = error {
                        if recovery_errors.get(id) != Some(&error) {
                            eprintln!("Gent discovered chat {id}: {error}");
                        }
                        recovery_errors.insert(id.into(), error);
                    } else {
                        recovery_errors.remove(id);
                    }
                    attempted += 1;
                    if attempted == 8 {
                        break;
                    }
                }
                if processed == ids.len() && pending["next"].is_null() {
                    cursor = None;
                }
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let error = result.err().map(|e| e.to_string());
        if error != previous_error {
            if let Some(error) = &error {
                eprintln!("Gent chat discovery pending: {error}");
            }
            previous_error = error;
        }
    }
}
