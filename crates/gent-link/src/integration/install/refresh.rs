//! Refresh only recorded Gent fragments, preserving each installation's options.
//! Hosts retain control of live MCP connections and active native turns.
use super::*;

const REGISTRY: &str = "integration-targets.json";
const REPORT: &str = "integration-refresh.json";
const MAX_TARGETS: usize = 128;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    host: Host,
    directory: PathBuf,
    server: PathBuf,
}
impl Target {
    fn from_layout(layout: &Layout) -> Self {
        Self {
            host: layout.host,
            directory: layout.directory.clone(),
            server: layout.server.clone(),
        }
    }
    fn layout(&self) -> Result<Layout> {
        ensure!(
            self.directory.is_absolute() && self.server.is_absolute(),
            "integration target must be absolute"
        );
        Layout::at(self.host, self.directory.clone(), self.server.clone())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u8,
    targets: Vec<Target>,
}
fn read_index(home: &Path) -> Result<(Snapshot, Registry)> {
    let snapshot = Snapshot::read(&home.join(REGISTRY))?;
    snapshot.private()?;
    let registry: Registry = snapshot
        .text
        .as_ref()
        .map(|s| serde_json::from_str(s))
        .transpose()?
        .unwrap_or(Registry {
            version: 1,
            targets: vec![],
        });
    ensure!(
        registry.version == 1 && registry.targets.len() <= MAX_TARGETS,
        "unsupported integration target registry"
    );
    Ok((snapshot, registry))
}

fn read(home: &Path) -> Result<(Snapshot, Registry)> {
    let (snapshot, registry) = read_index(home)?;
    for target in &registry.targets {
        target.layout()?;
    }
    Ok((snapshot, registry))
}
pub(super) fn remember(home: &Path, layout: &Layout) -> Result<()> {
    let _lock = files::lock(&home.join("integration-targets.lock"))?;
    let (snapshot, mut registry) = read(home)?;
    let target = Target::from_layout(layout);
    if !registry.targets.contains(&target) {
        ensure!(
            registry.targets.len() < MAX_TARGETS,
            "too many managed integration targets"
        );
        registry.targets.push(target);
        snapshot.write(&serde_json::to_string_pretty(&registry)?)?;
    }
    Ok(())
}

fn refresh_one(home: &Path, layout: &Layout, binary: &Path) -> Result<Value> {
    // A remembered uninstall is a tombstone, never permission to reinstall.
    if Snapshot::read(&layout.record())?.text.is_none() {
        return Ok(json!({"state":"absent"}));
    }
    let _lock = files::lock(&layout.lock())?;
    let (_, state) = layout.read()?;
    if state.owner(home).is_err() {
        return Ok(json!({"state":"other_node"}));
    }
    let intended = state
        .pending
        .as_ref()
        .map(|p| p.after.as_ref())
        .unwrap_or(state.installed.as_ref());
    if intended.is_some_and(|s| s.binary != binary) {
        return Ok(json!({"state":"different_binary"}));
    }
    recover(layout)?;
    let (_, state) = layout.read()?;
    let Some(mut desired) = state.installed.clone() else {
        return Ok(json!({"state":"uninstalled"}));
    };
    if desired.binary != binary {
        return Ok(json!({"state":"different_binary"}));
    }
    // Older installs could disable incoming turns. Upgrade those records while
    // preserving custom endpoints and the installer's ownership checks.
    match layout.host {
        Host::Codex if desired.wake_socket.is_none() => {
            desired.wake_socket = Some(layout.wake_socket()?);
        }
        Host::ClaudeCode if desired.claude_wake.is_none() => {
            desired.claude_wake = Some(claude_wake::Installation::new(&config::load(home)?));
        }
        _ => {}
    }
    if let Some(wake) = &desired.claude_wake {
        let cfg = config::load(home)?;
        ensure!(
            wake.node_id == cfg.node.id && wake.cluster_id == cfg.cluster.id,
            "Claude binding changed; reinstall the integration"
        );
        if wake.version != 3 || wake.module != claude_wake::MODULE {
            desired.claude_wake = Some(claude_wake::Installation::new(&cfg));
        }
    }
    let changed = state.installed.as_ref() != Some(&desired)
        || layout
            .edits(state.installed.as_ref(), Some(&desired), false, true)?
            .iter()
            .any(|e| e.snapshot.text != e.text);
    // The existing journal validates every original fragment before changing
    // anything and resumes partial publications after a process interruption.
    mutate_locked(layout, home, Some(desired))?;
    Ok(json!({"state":if changed {"refreshed"} else {"current"},
        "runtime_reload":"host_controlled"}))
}

fn refresh_targets(home: &Path, binary: &Path, targets: Vec<Target>) -> Value {
    let mut entries = Vec::new();
    for target in targets {
        let result = target
            .layout()
            .and_then(|layout| refresh_one(home, &layout, binary));
        let mut entry =
            result.unwrap_or_else(|error| json!({"state":"blocked","error":error.to_string()}));
        entry["host"] = json!(target.host);
        entry["directory"] = json!(target.directory);
        entries.push(entry);
    }
    let blocked = entries.iter().filter(|e| e["state"] == "blocked").count();
    json!({"state":if blocked==0 {"current"} else {"needs_attention"},"blocked":blocked,
        "build":crate::build_info::current(),"entries":entries,
        "next":"Managed files are refreshed automatically. Hosts that cannot reload Gent in place need an MCP reconnect; active turns are not interrupted."})
}

fn targets(registry: Registry, hosts: &[Host]) -> Vec<Target> {
    let mut targets = registry.targets;
    targets.retain(|target| hosts.contains(&target.host));
    // Bootstrap pre-registry default installs. Arbitrary custom directories
    // are remembered by install/uninstall from this version onward.
    for &host in hosts {
        let mut layouts = vec![Layout::resolve(host, None)];
        if let Some(user) = std::env::var_os("HOME").map(PathBuf::from) {
            let directory = user.join(if host == Host::Codex {
                ".codex"
            } else {
                ".claude"
            });
            let server = if host == Host::Codex {
                directory.join("config.toml")
            } else {
                user.join(".claude.json")
            };
            layouts.push(Layout::at(host, directory, server));
        }
        for layout in layouts.into_iter().flatten() {
            if targets
                .iter()
                .any(|t| t.host == host && t.directory == layout.directory)
                || !layout.record().exists()
            {
                continue;
            }
            let saved_server = Snapshot::read(&layout.record()).and_then(|snapshot| {
                snapshot.private()?;
                let state: State =
                    serde_json::from_str(snapshot.text.as_deref().context("missing record")?)?;
                ensure!(state.host == host, "host record mismatch");
                Ok(state.server)
            });
            let mut target = Target::from_layout(&layout);
            if let Ok(server) = saved_server {
                target.server = server;
            }
            targets.push(target);
        }
    }
    targets
}

/// Runtime reads only completed installs owned by this node, including custom CODEX_HOME profiles.
pub(crate) fn codex_sockets(home: &Path) -> Result<std::collections::BTreeSet<PathBuf>> {
    // A moved or edited profile cannot prevent another intact profile from running.
    let (_, index) = read_index(home)?;
    Ok(targets(index, &[Host::Codex])
        .into_iter()
        .filter_map(|target| target.layout().ok())
        .filter_map(|layout| codex_runtime_target(home, Some(layout.directory), false).ok())
        .map(|(_, socket)| socket)
        .collect())
}

pub(crate) fn refresh(home: &Path) -> Result<Value> {
    let home = normalize(home)?;
    gent_daemon::recovery::ensure_active(&home)?;
    config::load(&home)?;
    let binary = std::fs::canonicalize(std::env::current_exe()?)?;
    let (_, registry) = read(&home)?;
    let targets = targets(registry, &[Host::Codex, Host::ClaudeCode]);
    let report = refresh_targets(&home, &binary, targets);
    let snapshot = Snapshot::read(&home.join(REPORT))?;
    snapshot.private()?;
    let text = serde_json::to_string_pretty(&report)?;
    if snapshot.text.as_deref() != Some(&text) {
        snapshot.write(&text)?;
    }
    Ok(report)
}

pub(crate) fn status(home: &Path) -> Result<Value> {
    let snapshot = Snapshot::read(&home.join(REPORT))?;
    snapshot.private()?;
    Ok(snapshot
        .text
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests;
