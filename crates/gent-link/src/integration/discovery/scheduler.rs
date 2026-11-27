//! Index native chats and inspect only recipients with pending work.
use super::*;
use std::sync::{Arc, Mutex};

pub(crate) async fn maintain(home: &Path) {
    let mut timer = tokio::time::interval(Duration::from_secs(5));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut next_scan = tokio::time::Instant::now();
    let mut runner = None;
    let mut endpoint = None;
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
