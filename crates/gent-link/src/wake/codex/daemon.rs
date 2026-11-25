use super::{Registry, Runner, Sweep};
use std::{collections::BTreeMap, path::Path, time::Duration};

/// The node's daemon lock elects this supervisor. The wake lock may belong to an
/// MCP executable from before Babysitter existed. Never wait for it or evict it.
pub(crate) async fn maintain_babysitter(home: &Path) {
    let mut runners = BTreeMap::<_, (Runner, std::fs::File)>::new();
    let mut timer = tokio::time::interval(Duration::from_secs(5));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        if !matches!(super::babysitter_running(home), Ok(true)) {
            runners.clear();
            continue;
        }
        let endpoints = crate::integration::refresh::codex_sockets(home).unwrap_or_default();
        runners.retain(|endpoint, (runner, _)| {
            endpoints.contains(endpoint) && !runner.0.is_finished()
        });
        for endpoint in endpoints {
            if let std::collections::btree_map::Entry::Vacant(entry) = runners.entry(endpoint)
                && let Ok(registry) = Registry::codex(home, entry.key())
                && let Ok(Some(ownership)) = registry.daemon_babysitter()
            {
                let runner =
                    Runner::spawn(home.into(), registry, |_, _| Ok(Some(Sweep::GoalsOnly)));
                entry.insert((runner, ownership));
            }
        }
    }
}
