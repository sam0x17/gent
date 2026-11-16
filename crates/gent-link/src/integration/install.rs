//! User-scope host installation. Only generated Gent fragments enter the journal.
mod claude_runtime;
mod document;
use crate::managed_file as files;
pub(super) use claude_runtime::{ClaudeRuntime, claude_runtime_pinned, claude_runtime_target};

use super::{Host, claude_wake, render_configuration, vscode};
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
    /// Move this host's managed integration to the selected Gent profile.
    #[arg(long = "move")]
    pub move_profile: bool,
    /// Enable native queued delivery (Codex uses its default app-server socket).
    #[arg(long, conflicts_with = "wake_socket")]
    pub wake: bool,
    /// Opt into queued Codex wake through an existing local app-server socket.
    #[arg(long)]
    pub wake_socket: Option<PathBuf>,
    /// Experimental Codex VS Code connection to the selected shared server.
    #[arg(long)]
    pub vscode: bool,
    /// VS Code user settings JSONC (defaults to the stable Code installation).
    #[arg(long, requires = "vscode")]
    pub vscode_settings: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    home: PathBuf,
    binary: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wake_socket: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claude_wake: Option<claude_wake::Installation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    codex_ide: Option<vscode::Installation>,
}
impl Spec {
    fn fragments(&self, host: Host) -> Result<Value> {
        if let Some(ide) = &self.codex_ide {
            ensure!(
                host == Host::Codex && self.wake_socket.is_some() && self.claude_wake.is_none(),
                "Codex IDE integration requires queued Codex delivery"
            );
            ide.validate()?;
        }
        if let Some(wake) = &self.claude_wake {
            ensure!(
                host == Host::ClaudeCode && self.wake_socket.is_none(),
                "Claude wake installation belongs to another host"
            );
            wake.validate()?;
        }
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
        super::configure_wake(
            render_configuration(&self.home, &self.binary, host)?,
            host,
            self.wake_socket.as_deref(),
        )
    }
}

struct Layout {
    host: Host,
    directory: PathBuf,
    server: PathBuf,
    settings: Option<PathBuf>,
}

pub(super) fn default_wake_socket(host: Host, config_dir: Option<PathBuf>) -> Result<PathBuf> {
    Layout::resolve(host, config_dir)?.wake_socket()
}

/// Read an intact managed Codex opt-in without repairing or creating files.
pub(super) fn codex_runtime_target(
    home: &Path,
    config_dir: Option<PathBuf>,
    default_only: bool,
) -> Result<(PathBuf, PathBuf)> {
    let home = normalize(home)?;
    let layout = Layout::resolve(Host::Codex, config_dir)?;
    let (snapshot, state) = layout.read()?;
    state.owner(&home, false)?;
    ensure!(
        state.pending.is_none(),
        "Codex integration update is pending"
    );
    let spec = state
        .installed
        .as_ref()
        .context("install queued delivery first: gent integration install codex --wake")?;
    ensure!(
        spec.binary.is_file(),
        "the installed Gent executable is unavailable; reinstall the integration"
    );
    let socket = spec
        .wake_socket
        .as_ref()
        .context("queued delivery is not enabled; run gent integration install codex --wake")?;
    if default_only {
        ensure!(
            socket == &layout.wake_socket()?,
            "Gent startup uses Codex's default socket; start your custom server separately or reinstall with --wake"
        );
    }
    for edit in layout.edits(Some(spec), Some(spec), false, true)? {
        edit.snapshot.verify()?;
    }
    snapshot.verify()?;
    Ok((layout.directory, socket.clone()))
}

pub(super) fn codex_ide_target(home: &Path, directory: &Path, id: &str) -> Result<PathBuf> {
    let (directory, socket) = codex_runtime_target(home, Some(directory.into()), false)?;
    let effective = Layout::resolve(Host::Codex, None)?;
    ensure!(
        effective.directory == directory,
        "VS Code uses a different CODEX_HOME; reload it with the selected host directory"
    );
    let layout = Layout::resolve(Host::Codex, Some(directory))?;
    let (snapshot, state) = layout.read()?;
    ensure!(
        state.pending.is_none(),
        "Codex integration update is pending"
    );
    let ide = state
        .installed
        .as_ref()
        .and_then(|s| s.codex_ide.as_ref())
        .context("Codex IDE integration is not installed")?;
    ensure!(
        ide.id == id,
        "Codex IDE launcher belongs to an old installation"
    );
    snapshot.verify()?;
    Ok(socket)
}

impl Layout {
    fn ide_launcher(&self) -> PathBuf {
        self.directory.join("gent-vscode-codex")
    }
    fn ide_edits(
        &self,
        before: Option<&Spec>,
        after: Option<&Spec>,
        recovery: bool,
        check_enabled: bool,
    ) -> Result<Vec<Edit>> {
        let mut edits = Vec::new();
        let installations = [
            before.and_then(|s| s.codex_ide.as_ref()),
            after.and_then(|s| s.codex_ide.as_ref()),
        ];
        if installations.iter().all(Option::is_none) {
            return Ok(edits);
        }
        let launcher = self.ide_launcher();
        let generated = json!(launcher);
        let paths: std::collections::BTreeSet<_> = installations
            .iter()
            .flatten()
            .map(|v| &v.settings)
            .collect();
        for path in paths {
            ensure!(
                ![&self.server, &self.record(), &self.lock(), &launcher].contains(&path),
                "VS Code settings overlap Gent-managed files"
            );
            let snapshot = Snapshot::read(path)?;
            let doc = document::VscodeDocument::parse(snapshot.text.as_deref())?;
            let source = installations[0]
                .filter(|i| &i.settings == path)
                .map(|_| &generated);
            let target = installations[1]
                .filter(|i| &i.settings == path)
                .map(|_| &generated);
            matches_entry(doc.entry.as_ref(), source, target, recovery, path)?;
            edits.push(Edit {
                snapshot,
                text: Some(doc.set(target)?),
                executable: false,
            });
        }
        let script = |spec: Option<&Spec>| -> Result<Option<String>> {
            spec.and_then(|s| s.codex_ide.as_ref().map(|ide| (s, ide)))
                .map(|(s, ide)| ide.launcher(&s.home, &s.binary, &self.directory))
                .transpose()
        };
        let source = script(before)?;
        let target = script(after)?;
        let snapshot = Snapshot::read(&launcher)?;
        snapshot.private()?;
        ensure!(
            snapshot.text == source || (recovery && snapshot.text == target),
            "Codex IDE launcher is unowned, missing or edited"
        );
        ensure!(
            !check_enabled || recovery || source.is_none() || snapshot.executable(),
            "Codex IDE launcher must have private executable permissions (0700)"
        );
        // Install the executable before exposing its path in the editor. The
        // pending journal rejects use until every edit is committed.
        edits.insert(
            0,
            Edit {
                snapshot,
                text: target,
                executable: true,
            },
        );
        Ok(edits)
    }
    fn guard_fragment(&self, spec: Option<&Spec>) -> Result<Option<Value>> {
        let Some(spec) = spec.filter(|s| s.claude_wake.as_ref().is_some_and(|w| w.version >= 2))
        else {
            return Ok(None);
        };
        let args = [
            spec.binary.to_str().context("invalid executable path")?,
            "--home",
            spec.home.to_str().context("invalid Gent home")?,
            "--json",
            "integration",
            "claude-wake-guard",
            "--config-dir",
            self.directory.to_str().context("invalid host directory")?,
        ];
        let command = format!(
            "{}{} || exit 2",
            claude_wake::GUARD_MARKER,
            args.into_iter()
                .map(super::shell_arg)
                .collect::<Vec<_>>()
                .join(" ")
        );
        let mut hook = json!({"type":"command","command":command,"timeout":35});
        if spec.claude_wake.as_ref().is_some_and(|w| w.version >= 3) {
            hook["onFailure"] = "block".into();
        }
        Ok(Some(json!({"hooks":[hook]})))
    }

    fn plugin_files(&self, spec: Option<&Spec>) -> Result<Vec<(PathBuf, Option<String>)>> {
        let root = self.directory.join("skills/gent-wake");
        let wake = spec.and_then(|s| s.claude_wake.as_ref());
        let content = if let (Some(spec), Some(wake)) = (spec, wake) {
            let configuration = json!({"binary":spec.binary,"home":spec.home,
                "directory":self.directory,"installation_id":wake.id});
            Some([
                json!({"name":"gent-wake","version":"0.0.1",
                    "description":"Gent inbox delivery between completed turns"})
                .to_string()
                    + "\n",
                "{\"modules\":[\"./register.ts\"]}\n".into(),
                format!("const CONFIG = {configuration};\n{}", wake.module),
            ])
        } else {
            None
        };
        Ok([
            ".claude-plugin/plugin.json",
            "hooks/hooks.json",
            "hooks/register.ts",
        ]
        .into_iter()
        .enumerate()
        .map(|(i, path)| (root.join(path), content.as_ref().map(|v| v[i].clone())))
        .collect())
    }

    fn wake_socket(&self) -> Result<PathBuf> {
        ensure!(
            self.host == Host::Codex,
            "default app-server sockets are supported only for Codex; use `gent integration install claude-code --wake` for Claude"
        );
        // Codex resolves `--listen unix://` from this configuration directory.
        // Pin the advertised name; the running host owns its rendezvous link.
        Ok(self
            .directory
            .join("app-server-control/app-server-control.sock"))
    }

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
        let mut ide_edits = self.ide_edits(before, after, recovery, check_enabled)?;
        let manage_plugin = before.is_some_and(|s| s.claude_wake.is_some())
            || after.is_some_and(|s| s.claude_wake.is_some());
        let plugin_before = self.plugin_files(before)?;
        let plugin_after = self.plugin_files(after)?;
        let guard_before = self.guard_fragment(before)?;
        let guard_after = self.guard_fragment(after)?;
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
            text: Some(doc.set_server(target)?),
            snapshot,
            executable: false,
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
            let mut text = doc.set_hook(target)?;
            if guard_before.is_some() || guard_after.is_some() {
                let doc = Document::parse(Some(&text), Host::ClaudeCode)?;
                matches_entry(
                    doc.wake_guard()?,
                    guard_before.as_ref(),
                    guard_after.as_ref(),
                    recovery,
                    path,
                )?;
                text = doc.set_wake_guard(guard_after.as_ref())?;
            }
            edits.push(Edit {
                text: Some(text),
                snapshot,
                executable: false,
            });
        }
        if self.host == Host::ClaudeCode && manage_plugin {
            for ((path, before), (_, after)) in plugin_before.into_iter().zip(plugin_after) {
                let snapshot = Snapshot::read(&path)?;
                ensure!(
                    snapshot.text == before || (recovery && snapshot.text == after),
                    "Gent plugin file is unowned, missing, or edited: {}; preserve your changes before retrying",
                    path.display()
                );
                edits.push(Edit {
                    snapshot,
                    text: after,
                    executable: false,
                });
            }
        }
        edits.append(&mut ide_edits);
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
    text: Option<String>,
    executable: bool,
}
impl Edit {
    fn apply(&self) -> Result<()> {
        let Some(text) = &self.text else {
            return self.snapshot.remove();
        };
        // Uninstalling an absent integration must not create empty host files.
        if self.snapshot.text.is_none() && matches!(text.trim(), "" | "{}") {
            self.snapshot.verify()
        } else if self.executable {
            self.snapshot.write_executable(text)
        } else {
            self.snapshot.write(text)
        }
    }
}
impl State {
    fn owner(&self, home: &Path, move_profile: bool) -> Result<()> {
        if move_profile {
            ensure!(
                self.pending.as_ref().is_none_or(|pending| pending
                    .after
                    .as_ref()
                    .is_some_and(|spec| spec.home == home)),
                "another integration change is pending; finish it with its original profile and options before moving"
            );
            return Ok(());
        }
        for spec in self
            .installed
            .iter()
            .chain(self.pending.iter().filter_map(|p| p.after.as_ref()))
        {
            ensure!(
                spec.home == home,
                "host integration belongs to another Gent home: {}; use gent integration install HOST --move to move it to the selected profile, or select its cluster ID with --cluster before uninstalling (see gent --json clusters)",
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
    ensure!(
        install
            || (!args.move_profile
                && !args.wake
                && args.wake_socket.is_none()
                && !args.vscode
                && args.vscode_settings.is_none()),
        "move, wake and VS Code options apply only to installation"
    );
    ensure!(
        !args.vscode || (args.host == Host::Codex && (args.wake || args.wake_socket.is_some())),
        "--vscode requires Codex with --wake or --wake-socket"
    );
    let home = normalize(home)?;
    let layout = Layout::resolve(args.host, args.config_dir)?;
    let wake_socket = if args.wake && args.host == Host::Codex {
        Some(layout.wake_socket()?)
    } else {
        args.wake_socket
    };
    let desired = if install {
        let cfg = config::load(&home).context("initialize this Gent node first")?;
        let mut desired = Spec {
            home: home.clone(),
            binary: std::fs::canonicalize(std::env::current_exe()?)?,
            wake_socket,
            claude_wake: None,
            codex_ide: None,
        };
        if args.vscode {
            let settings = vscode::settings_path(args.vscode_settings)?;
            let previous = layout
                .read()?
                .1
                .installed
                .filter(|s| {
                    s.home == desired.home
                        && s.binary == desired.binary
                        && s.wake_socket == desired.wake_socket
                })
                .and_then(|s| s.codex_ide)
                .filter(|ide| ide.settings == settings);
            desired.codex_ide =
                Some(previous.unwrap_or_else(|| vscode::Installation::new(settings)));
        }
        if args.wake && args.host == Host::ClaudeCode {
            let previous = layout.read()?.1.installed;
            let existing = previous
                .filter(|s| s.home == desired.home && s.binary == desired.binary)
                .and_then(|s| s.claude_wake)
                .filter(|w| {
                    w.cluster_id == cfg.cluster.id
                        && w.node_id == cfg.node.id
                        && w.version == 3
                        && w.module == claude_wake::MODULE
                });
            desired.claude_wake =
                Some(existing.unwrap_or_else(|| claude_wake::Installation::new(&cfg)));
        }
        Some(desired)
    } else {
        None
    };
    mutate(&layout, &home, desired, args.move_profile)?;
    let mut result = inspect(&layout, &home)?;
    result["action"] = if install { "installed" } else { "uninstalled" }.into();
    result["next"] = "Restart the host's Gent MCP connection or open a new host session to load these user settings.".into();
    if install && args.vscode {
        result["next"] = "Start the selected server with gent integration start codex, then reload VS Code and open or explicitly resume a chat. The experimental route uses the extension's development-only executable override; existing embedded chats are not moved automatically.".into();
    }
    Ok(result)
}

fn mutate(layout: &Layout, home: &Path, desired: Option<Spec>, move_profile: bool) -> Result<()> {
    ensure!(
        !move_profile || desired.as_ref().is_some_and(|spec| spec.home == home),
        "moving requires an installation for the selected profile"
    );
    files::directory(&layout.directory)?;
    let lock = layout.lock();
    let _guard = files::lock(&lock)?;
    let (_, state) = layout.read()?;
    state.owner(home, move_profile)?;
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
    if let Some(spec) = &state.installed
        && let Some(ide) = &spec.codex_ide
    {
        let settings = Snapshot::read(&ide.settings)?;
        let document = document::VscodeDocument::parse(settings.text.as_deref())?;
        let launcher = Snapshot::read(&layout.ide_launcher())?;
        exact &= document.entry == Some(json!(layout.ide_launcher()))
            && launcher.text == Some(ide.launcher(&spec.home, &spec.binary, &layout.directory)?)
            && launcher.executable();
        result["vscode"] = json!({"experimental":true,"settings":ide.settings,"launcher":layout.ide_launcher(),"installation_id":ide.id});
    }
    if state
        .installed
        .as_ref()
        .is_some_and(|s| s.claude_wake.is_some())
    {
        for (path, content) in layout.plugin_files(state.installed.as_ref())? {
            exact &= Snapshot::read(&path)?.text == content;
        }
    }
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
        result["wake_socket"] = json!(spec.wake_socket);
        result["claude_wake"] = json!(spec.claude_wake.as_ref().map(|w| &w.id));
    }
    Ok(result)
}

/// Every helper call must still belong to this exact completed installation.
/// A pending uninstall/update fails closed before it touches a host setting.
pub(super) fn claude_wake(
    home: &Path,
    directory: &Path,
    id: &str,
) -> Result<claude_wake::Installation> {
    let home = normalize(home)?;
    gent_daemon::recovery::ensure_active(&home)?;
    // Default Claude settings keep .claude.json beside ~/.claude; an explicit
    // CLAUDE_CONFIG_DIR keeps it inside. Recover the exact recorded layout.
    let directory = normalize(directory)?;
    let record = Snapshot::read(&directory.join(".gent-claude-code.json"))?;
    record.private()?;
    let saved: State = serde_json::from_str(
        record
            .text
            .as_deref()
            .context("Claude integration is not installed")?,
    )?;
    let layout = Layout::at(Host::ClaudeCode, directory, saved.server)?;
    let (snapshot, state) = layout.read()?;
    ensure!(
        state.pending.is_none(),
        "Claude integration update is pending"
    );
    state.owner(&home, false)?;
    let spec = state
        .installed
        .as_ref()
        .context("Claude integration is not installed")?;
    let wake = spec
        .claude_wake
        .as_ref()
        .context("Claude automatic delivery is disabled")?;
    ensure!(wake.id == id, "Claude wake installation changed");
    ensure!(
        wake.version == 3,
        "Claude wake needs the failure-blocking command guard; reinstall the integration and restart Claude"
    );
    let edits = layout.edits(Some(spec), Some(spec), false, true)?;
    for edit in edits {
        edit.snapshot.verify()?;
    }
    snapshot.verify()?;
    record.verify()?;
    Ok(wake.clone())
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
