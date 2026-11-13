//! User-scope host installation. Only generated Gent fragments enter the journal.
mod document;
mod files;

use super::{Host, render_configuration};
use anyhow::{Context, Result, ensure};
use document::Document;
use files::{Snapshot, normalize};
use gent_daemon::config;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(clap::Args)]
pub struct Args {
    pub host: Host,
    /// Host config directory (CODEX_HOME or CLAUDE_CONFIG_DIR).
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    home: PathBuf,
    binary: PathBuf,
}
impl Spec {
    fn fragments(&self, host: Host) -> Result<Value> {
        for path in [&self.home, &self.binary] {
            ensure!(path.is_absolute(), "installation paths must be absolute");
            ensure!(
                !path
                    .to_str()
                    .context("installation paths must be UTF-8")?
                    .chars()
                    .any(char::is_control),
                "installation paths cannot contain control characters"
            );
        }
        render_configuration(&self.home, &self.binary, host)
    }
}

struct Layout {
    host: Host,
    directory: PathBuf,
    server: PathBuf,
    settings: Option<PathBuf>,
}
impl Layout {
    fn resolve(host: Host, explicit: Option<PathBuf>) -> Result<Self> {
        let user = std::env::var_os("HOME").map(PathBuf::from);
        let env_name = match host {
            Host::Codex => "CODEX_HOME",
            Host::ClaudeCode => "CLAUDE_CONFIG_DIR",
        };
        let override_dir = explicit.or_else(|| {
            std::env::var_os(env_name)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        });
        let custom = override_dir.is_some();
        let directory = override_dir
            .or_else(|| {
                user.as_ref().map(|u| {
                    u.join(if host == Host::Codex {
                        ".codex"
                    } else {
                        ".claude"
                    })
                })
            })
            .context("cannot locate host configuration; pass --config-dir")?;
        let server = match host {
            Host::Codex => directory.join("config.toml"),
            Host::ClaudeCode if custom => directory.join(".claude.json"),
            Host::ClaudeCode => user.context("HOME is required")?.join(".claude.json"),
        };
        Self::at(host, directory, server)
    }
    fn at(host: Host, directory: PathBuf, server: PathBuf) -> Result<Self> {
        Ok(Self {
            host,
            settings: (host == Host::ClaudeCode)
                .then(|| normalize(&directory.join("settings.json")))
                .transpose()?,
            directory: normalize(&directory)?,
            server: normalize(&server)?,
        })
    }
    fn record(&self) -> PathBuf {
        self.directory
            .join(format!(".gent-{}.json", self.host.name()))
    }
    fn lock(&self) -> PathBuf {
        self.directory
            .join(format!(".gent-{}.lock", self.host.name()))
    }
    fn read(&self) -> Result<(Snapshot, State)> {
        let snapshot = Snapshot::read(&self.record())?;
        snapshot.private()?;
        let state: State = match &snapshot.text {
            Some(text) => serde_json::from_str(text).map_err(|_| {
                anyhow::anyhow!(
                    "invalid Gent installation record: {}",
                    snapshot.path.display()
                )
            })?,
            None => State {
                version: 1,
                host: self.host,
                server: self.server.clone(),
                settings: self.settings.clone(),
                installed: None,
                pending: None,
            },
        };
        ensure!(
            state.version == 1
                && state.host == self.host
                && state.server == self.server
                && state.settings == self.settings,
            "Gent installation record does not match these target files; inspect {}",
            snapshot.path.display()
        );
        if let Some(spec) = &state.installed {
            spec.fragments(self.host)?;
        }
        if let Some(spec) = state.pending.as_ref().and_then(|p| p.after.as_ref()) {
            spec.fragments(self.host)?;
        }
        Ok((snapshot, state))
    }
    fn edits(
        &self,
        before: Option<&Spec>,
        after: Option<&Spec>,
        recovery: bool,
        check_enabled: bool,
    ) -> Result<Vec<Edit>> {
        let before = before.map(|s| s.fragments(self.host)).transpose()?;
        let after = after.map(|s| s.fragments(self.host)).transpose()?;
        let pointer = if self.host == Host::Codex {
            "/mcp_servers/gent"
        } else {
            "/mcpServers/gent"
        };
        let snapshot = Snapshot::read(&self.server)?;
        let doc = Document::parse(snapshot.text.as_deref(), self.host)
            .with_context(|| format!("inspect {}", self.server.display()))?;
        let target = after.as_ref().and_then(|v| v.pointer(pointer));
        matches_entry(
            doc.server()?,
            before.as_ref().and_then(|v| v.pointer(pointer)),
            target,
            recovery,
            &self.server,
        )?;
        let mut edits = vec![Edit {
            text: doc.set_server(target)?,
            snapshot,
        }];
        if let Some(path) = &self.settings {
            let snapshot = Snapshot::read(path)?;
            let doc = Document::parse(snapshot.text.as_deref(), Host::ClaudeCode)
                .with_context(|| format!("inspect {}", path.display()))?;
            ensure!(
                !check_enabled || !doc.hooks_disabled(),
                "Claude Code hooks are disabled in {}; Gent requires its identity hook; enable hooks before installing",
                path.display()
            );
            let pointer = "/settings/hooks/PreToolUse/0";
            let target = after.as_ref().and_then(|v| v.pointer(pointer));
            matches_entry(
                doc.hook()?,
                before.as_ref().and_then(|v| v.pointer(pointer)),
                target,
                recovery,
                path,
            )?;
            edits.push(Edit {
                text: doc.set_hook(target)?,
                snapshot,
            });
        }
        Ok(edits)
    }
}

fn matches_entry(
    actual: Option<&Value>,
    before: Option<&Value>,
    after: Option<&Value>,
    recovery: bool,
    path: &Path,
) -> Result<()> {
    ensure!(
        actual == before || (recovery && actual == after),
        "Gent entry is unowned, missing, or edited in {}; preserve your edits and restore the recorded Gent entry (or remove an unowned entry) before retrying",
        path.display()
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    host: Host,
    server: PathBuf,
    settings: Option<PathBuf>,
    installed: Option<Spec>,
    pending: Option<Transition>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transition {
    after: Option<Spec>,
}
struct Edit {
    snapshot: Snapshot,
    text: String,
}
impl Edit {
    fn apply(&self) -> Result<()> {
        // Uninstalling an absent integration must not create empty host files.
        if self.snapshot.text.is_none() && matches!(self.text.trim(), "" | "{}") {
            self.snapshot.verify()
        } else {
            self.snapshot.write(&self.text)
        }
    }
}
impl State {
    fn owner(&self, home: &Path) -> Result<()> {
        for spec in self
            .installed
            .iter()
            .chain(self.pending.iter().filter_map(|p| p.after.as_ref()))
        {
            ensure!(
                spec.home == home,
                "host integration belongs to another Gent home: {}; use that --home to uninstall it first",
                spec.home.display()
            );
        }
        Ok(())
    }
}
fn save(snapshot: &Snapshot, state: &State) -> Result<()> {
    snapshot.write(&format!("{}\n", serde_json::to_string_pretty(state)?))
}
fn recover(layout: &Layout) -> Result<()> {
    let (snapshot, mut state) = layout.read()?;
    let Some(pending) = &state.pending else {
        return Ok(());
    };
    let edits = layout.edits(
        state.installed.as_ref(),
        pending.after.as_ref(),
        true,
        false,
    )?;
    // Validate every file before changing any of them; on interruption the
    // journal accepts either generated version and reapplies to fresh documents.
    for edit in &edits {
        edit.snapshot.verify()?;
    }
    snapshot.verify()?;
    for edit in edits {
        edit.apply()?;
    }
    state.installed = state.pending.take().unwrap().after;
    save(&snapshot, &state)
}

pub fn change(home: &Path, args: Args, install: bool) -> Result<Value> {
    let home = normalize(home)?;
    let layout = Layout::resolve(args.host, args.config_dir)?;
    let desired = if install {
        config::load(&home).context("initialize this Gent node first")?;
        Some(Spec {
            home: home.clone(),
            binary: std::fs::canonicalize(std::env::current_exe()?)?,
        })
    } else {
        None
    };
    mutate(&layout, &home, desired)?;
    let mut result = inspect(&layout, &home)?;
    result["action"] = if install { "installed" } else { "uninstalled" }.into();
    result["next"] = "Restart the host's Gent MCP connection or open a new host session to load these user settings.".into();
    Ok(result)
}

fn mutate(layout: &Layout, home: &Path, desired: Option<Spec>) -> Result<()> {
    files::directory(&layout.directory)?;
    let lock = layout.lock();
    Snapshot::read(&lock)?.private()?;
    let _guard = super::lock(&lock)?;
    let (_, state) = layout.read()?;
    state.owner(home)?;
    recover(layout)?;
    let (snapshot, mut state) = layout.read()?;
    let edits = layout.edits(
        state.installed.as_ref(),
        desired.as_ref(),
        false,
        desired.is_some(),
    )?;
    for edit in &edits {
        edit.snapshot.verify()?;
    }
    if state.installed == desired {
        return Ok(());
    }
    state.pending = Some(Transition { after: desired });
    save(&snapshot, &state)?;
    recover(layout)
}

fn inspect(layout: &Layout, home: &Path) -> Result<Value> {
    let (_, state) = layout.read()?;
    let mut result = json!({"host":layout.host, "scope":"user", "server_config":layout.server,
        "settings_config":layout.settings, "record":layout.record(), "effective_host_config_verified":false});
    if state.pending.is_some() {
        result["state"] = "recovery_pending".into();
        result["next"] = "Rerun installation or uninstallation with the same Gent home and host config directory.".into();
        return Ok(result);
    }
    let server = Snapshot::read(&layout.server)?;
    let doc = Document::parse(server.text.as_deref(), layout.host)?;
    let fragments = state
        .installed
        .as_ref()
        .map(|s| s.fragments(layout.host))
        .transpose()?;
    let pointer = if layout.host == Host::Codex {
        "/mcp_servers/gent"
    } else {
        "/mcpServers/gent"
    };
    let mut exact = doc.server()? == fragments.as_ref().and_then(|f| f.pointer(pointer));
    let mut disabled = false;
    if let Some(path) = &layout.settings {
        let snapshot = Snapshot::read(path)?;
        let doc = Document::parse(snapshot.text.as_deref(), Host::ClaudeCode)?;
        exact &= doc.hook()?
            == fragments
                .as_ref()
                .and_then(|f| f.pointer("/settings/hooks/PreToolUse/0"));
        disabled = doc.hooks_disabled();
    }
    result["state"] = if !exact {
        "conflict"
    } else if state.installed.is_none() {
        "absent"
    } else if disabled {
        "hooks_disabled"
    } else {
        "configured"
    }
    .into();
    if let Some(spec) = &state.installed {
        result["gent_home"] = json!(spec.home);
        result["current_home"] = json!(spec.home == home);
        result["binary_available"] = json!(spec.binary.is_file());
    }
    Ok(result)
}

pub fn status(home: &Path, host: Option<Host>, config_dir: Option<PathBuf>) -> Result<Value> {
    let home = normalize(home)?;
    if let Some(host) = host {
        return inspect(&Layout::resolve(host, config_dir)?, &home);
    }
    Ok(json!([Host::Codex, Host::ClaudeCode].map(|host| {
        Layout::resolve(host, None)
            .and_then(|layout| inspect(&layout, &home))
            .unwrap_or_else(
                |error| json!({"host":host,"state":"error","detail":format!("{error:#}")}),
            )
    })))
}

#[cfg(test)]
mod tests;
