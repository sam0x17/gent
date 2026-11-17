//! Bounded diagnosis with fixed messages and whitelisted evidence. Never echo
//! parser errors, configuration bodies, credentials, agent data or host output.
use crate::{auth, gateway, hooks, integration, node_home, owner, service};
use gent_daemon::config;
use gent_protocol::OwnerOp;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(clap::Args, Default)]
#[group(id = "doctor_options")]
pub(crate) struct Options {
    /// Also check the saved account session at its pinned Gent service (five-second limit).
    #[arg(long)]
    online: bool,
    /// Inspect a nondefault Codex configuration directory.
    #[arg(long)]
    codex_config_dir: Option<PathBuf>,
    /// Inspect a nondefault Claude Code configuration directory.
    #[arg(long)]
    claude_config_dir: Option<PathBuf>,
    #[command(flatten)]
    hooks: hooks::Options,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Pass,
    Warn,
    Fail,
    Skip,
}
#[derive(Serialize)]
struct Check {
    id: &'static str,
    status: Status,
    summary: &'static str,
    evidence: Value,
    next: Option<Advice>,
}
#[derive(Serialize)]
struct Advice {
    message: &'static str,
    command: Option<Vec<String>>,
}
#[derive(Serialize)]
pub(crate) struct Report {
    version: u8,
    home: Option<PathBuf>,
    cluster_id: Option<String>,
    online: bool,
    checks: Vec<Check>,
}
impl Report {
    fn add(
        &mut self,
        id: &'static str,
        status: Status,
        summary: &'static str,
        evidence: Value,
        advice: Option<(&'static str, &[&str])>,
    ) {
        let next = advice.map(|(message, args)| Advice {
            message,
            command: if args.is_empty()
                || self
                    .home
                    .as_ref()
                    .is_some_and(|p| p.to_str().is_none_or(|s| s.chars().any(char::is_control)))
            {
                None
            } else {
                Some(self.command(args))
            },
        });
        self.checks.push(Check {
            id,
            status,
            summary,
            evidence,
            next,
        });
    }
    fn command(&self, args: &[&str]) -> Vec<String> {
        let mut command = vec!["gent".into()];
        if let Some(home) = &self.home {
            command.extend(["--home".into(), home.to_string_lossy().into_owned()]);
        }
        if let Some(cluster) = &self.cluster_id {
            command.extend(["--cluster".into(), cluster.clone()]);
        }
        command.extend(args.iter().map(|s| (*s).into()));
        command
    }
    pub(crate) fn exit_code(&self) -> i32 {
        if self
            .checks
            .iter()
            .any(|c| matches!(c.status, Status::Warn | Status::Fail))
        {
            3
        } else {
            0
        }
    }
    pub(crate) fn print(&self) {
        crate::ui::heading("Doctor");
        println!(
            "  {}",
            if self.exit_code() == 0 {
                "available checks passed"
            } else {
                "attention needed"
            }
        );
        for check in &self.checks {
            let status = match check.status {
                Status::Pass => "OK",
                Status::Warn => "WARN",
                Status::Fail => "FAIL",
                Status::Skip => "SKIP",
            };
            println!(
                "  {}  {:18}  {}",
                crate::ui::state(&format!("{status:4}")),
                check.id,
                check.summary
            );
            if let Some(home) = check.evidence["integration_home"].as_str() {
                println!("     Installed for: {}", home.escape_debug());
            }
            if let Some(next) = &check.next {
                println!("     {}", next.message);
                if let Some(command) = &next.command {
                    println!(
                        "     {}",
                        command
                            .iter()
                            .map(|s| shell_arg(s))
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                }
            }
        }
    }
}
fn shell_arg(arg: &str) -> String {
    if arg.chars().any(char::is_control) {
        return format!("{:?}", arg);
    }
    if !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./-:".contains(&b))
    {
        arg.into()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

pub(crate) async fn run(root: &Path, selected: Option<&str>, options: Options) -> Report {
    let mut report = Report {
        version: 1,
        home: None,
        cluster_id: None,
        online: options.online,
        checks: vec![],
    };
    let resolved = node_home::resolve(root, selected);
    match resolved {
        Ok(home) => {
            report.home = Some(home.clone());
            match node_home::inspect(&home) {
                Ok(cfg) => {
                    report.cluster_id = Some(cfg.cluster.id.clone());
                    let valid = cfg.validate().is_ok();
                    report.add("configuration", if valid { Status::Pass } else { Status::Warn },
                        if valid { "Private cluster configuration is valid." } else { "Local identity is valid but the editable names or policy are invalid." },
                        json!({"node_id":cfg.node.id}), (!valid).then_some(("Validate the local edit before applying it; signed daemon authority is separate.", &["config", "validate"][..])));
                    inspect_node(&mut report, &home, &cfg, options.online).await;
                }
                Err(_) => {
                    let absent = !home.exists();
                    report.add("configuration", Status::Fail, if absent { "Gent is not set up in this directory." } else { "Configuration is missing, invalid or not private." }, json!({}),
                        if absent { Some(("Start guided setup.", &["daemon", "install"])) } else { Some(("Inspect this node's config.toml and file permissions. Preserve existing keys and state.", &[])) });
                }
            }
        }
        Err(_) => report.add("configuration", Status::Fail, "This node cannot be opened safely.", json!({}),
            Some(("Inspect config.toml and directory permissions. Legacy profiles require gent node reset and fresh enrollment.", &[]))),
    }
    let home = report.home.clone();
    if let Some(home) = home.as_deref() {
        for (id, host, directory) in [
            ("codex", integration::Host::Codex, options.codex_config_dir),
            (
                "claude_code",
                integration::Host::ClaudeCode,
                options.claude_config_dir,
            ),
        ] {
            let result = integration::execute(
                home,
                integration::Command::Status {
                    host: Some(host),
                    config_dir: directory.clone(),
                    live: false,
                    host_binary: None,
                },
            );
            inspect_integration(&mut report, id, result.ok());
            let check = report.checks.last_mut().expect("integration check");
            if let Some(command) = check.next.as_mut().and_then(|n| n.command.as_mut())
                && command.iter().any(|arg| arg == "integration")
            {
                command.push(
                    if host == integration::Host::Codex {
                        "codex"
                    } else {
                        "claude-code"
                    }
                    .into(),
                );
                advice_path(check, "--config-dir", directory.as_deref());
            }
        }
    }
    let shell = options.hooks.shell;
    let rc_file = options.hooks.rc_file.clone();
    let result = hooks::execute(hooks::Command::Status(options.hooks));
    match result {
        Ok(value) if value["state"] == "absent" => report.add("shell", Status::Skip, "Optional shell hooks are not installed.", json!({"shell":value["shell"]}), None),
        Ok(value) if value["state"] == "installed" && value["binary_available"] == true => report.add("shell", Status::Pass, "Managed shell hooks refer to an available binary; the current shell was not tested.", json!({"shell":value["shell"]}), None),
        _ => report.add("shell", Status::Warn, "Shell hooks are edited, unavailable or could not be inspected.", json!({}), Some(("Inspect shell setup; use --shell and --rc-file for a nondefault startup file.", &["hooks", "status"]))),
    }
    let check = report.checks.last_mut().expect("shell check");
    if let Some(command) = check.next.as_mut().and_then(|n| n.command.as_mut())
        && let Some(shell) = shell
    {
        command.extend([
            "--shell".into(),
            match shell {
                hooks::Shell::Zsh => "zsh",
                hooks::Shell::Bash => "bash",
                hooks::Shell::Fish => "fish",
            }
            .into(),
        ]);
    }
    advice_path(check, "--rc-file", rc_file.as_deref());
    report
}

fn advice_path(check: &mut Check, flag: &str, path: Option<&Path>) {
    if let Some(path) = path
        && let Some(next) = &mut check.next
    {
        if let Some(text) = path.to_str().filter(|s| !s.chars().any(char::is_control)) {
            if let Some(command) = &mut next.command {
                command.extend([flag.into(), text.into()]);
            }
        } else {
            next.command = None;
        }
    }
}

fn protected_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| {
        m.is_file()
            && m.nlink() == 1
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o077 == 0
    })
}
fn credential_file(path: &Path) -> bool {
    protected_file(path) && fs::symlink_metadata(path).is_ok_and(|m| m.len() <= 512)
}
async fn inspect_node(report: &mut Report, home: &Path, cfg: &config::Config, online: bool) {
    let owner_ok = credential_file(&home.join("owner.key"))
        && config::read_private(&home.join("owner.key")).is_ok();
    let identity = home.join("identity.key");
    let db = home.join("state.sqlite3");
    let new = cfg.applied_revision.is_none()
        && fs::symlink_metadata(&identity).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        && fs::symlink_metadata(&db).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
    let state_ok = owner_ok && (new || (protected_file(&identity) && protected_file(&db)));
    report.add("local_state", if !state_ok {Status::Fail} else if new {Status::Skip} else {Status::Pass},
        if !state_ok {"Key or database files are missing, linked or insufficiently protected."} else if new {"The daemon has not initialized endpoint state yet."} else {"Key and database paths are protected; the live probe checks signed state."}, json!({}),
        (!state_ok).then_some(("Preserve this node. Inspect missing files and ownership before restarting; do not generate replacement keys or copy in an older database.", &[][..])));
    let socket = fs::symlink_metadata(home.join("daemon.sock"));
    let socket_ok = socket.as_ref().is_ok_and(|m| {
        m.file_type().is_socket()
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o077 == 0
    });
    let daemon = async {
        if !state_ok || !socket_ok {
            return None;
        }
        tokio::time::timeout(Duration::from_secs(2), owner(home, OwnerOp::Diagnose))
            .await
            .ok()?
            .ok()
    };
    let manager = async {
        tokio::time::timeout(Duration::from_secs(3), service::diagnose(home))
            .await
            .ok()
            .and_then(Result::ok)
    };
    let (daemon, manager, account) = tokio::join!(
        daemon,
        manager,
        auth::diagnose(home, cfg.service.as_ref(), online)
    );
    let daemon_pid = daemon.as_ref().and_then(|v| v["process_id"].as_u64());
    inspect_daemon(report, daemon, cfg);
    match manager {
        Some(v) if v["installed"] == true && v["available"] == true => report.add(
            "service",
            if v["running"] == true
                && v["binary_available"] == true
                && v["enabled"] == true
                && v["pid"].as_u64().is_some()
                && v["pid"].as_u64() == daemon_pid
            {
                Status::Pass
            } else {
                Status::Warn
            },
            "The managed service registration was inspected.",
            v.clone(),
            (v["running"] != true
                || v["binary_available"] != true
                || v["enabled"] != true
                || v["pid"].as_u64() != daemon_pid
                || daemon_pid.is_none())
            .then_some((
                "Inspect the service before starting or enabling it.",
                &["daemon", "status"][..],
            )),
        ),
        Some(v) if v["installed"] == false && v["loaded"] == false => report.add(
            "service",
            Status::Skip,
            "No managed service is installed for this node; foreground daemons are supported.",
            json!({"available":v["available"]}),
            None,
        ),
        _ => report.add(
            "service",
            Status::Warn,
            "The user service manager or Gent registration is unavailable or inconsistent.",
            json!({}),
            Some((
                "Inspect service status in the user's login session.",
                &["daemon", "status"],
            )),
        ),
    }
    let relay_key_ok = cfg.relay.as_ref().is_none_or(|r| {
        let path = home.join(&r.credential_file);
        credential_file(&path) && config::read_relay_credential(&path).is_ok()
    });
    if !relay_key_ok {
        report.add(
            "relay_credential",
            Status::Fail,
            "The configured relay credential is missing or invalid.",
            json!({}),
            Some((
                "Inspect the credential path and service setup. Preserve encryption keys.",
                &[],
            )),
        );
    }
    inspect_account(report, account.ok(), cfg.service.is_some(), online);
    match gateway::diagnose(home) {
        Ok(v) if v["configured"] == false => report.add("gateway", Status::Skip, "Optional remote MCP gateway is not configured.", json!({}), None),
        Ok(v) if v["clock_ahead"] == false && v["active_clients"].as_u64().is_some_and(|n| n > 0) => report.add("gateway", Status::Pass, "Gateway pins and host grants are valid; listener and provider behavior were not probed.", v, None),
        Ok(v) => report.add("gateway", Status::Warn, "Gateway access is blocked by its clock watermark or has no active host grants.", v, Some(("Check system time and host grant status.", &["gateway", "status"]))),
        Err(_) => report.add("gateway", Status::Fail, "Gateway state or its node/cluster pin is inconsistent.", json!({}), Some(("Preserve the registry and its config pin. Deleting it would lose established agent bindings.", &[]))),
    }
}

fn inspect_daemon(report: &mut Report, value: Option<Value>, cfg: &config::Config) {
    let Some(v) = value else {
        report.add("daemon", Status::Fail, "No authenticated diagnostic response from this node's daemon.", json!({}), Some(("Inspect daemon status and logs before restarting. An older daemon may need an upgrade.", &["daemon", "status"])));
        return;
    };
    if v["version"] != 1 || v["cluster_id"] != cfg.cluster.id || v["node_id"] != cfg.node.id {
        report.add(
            "daemon",
            Status::Fail,
            "The daemon response does not match this node or diagnostic version.",
            json!({}),
            Some((
                "Preserve state and inspect the process serving this node's socket.",
                &[],
            )),
        );
        return;
    }
    report.add(
        "daemon",
        Status::Pass,
        "The daemon responded under local owner authentication.",
        json!({"process_id":v["process_id"]}),
        None,
    );
    let a = &v["authority"];
    let ready = a["fresh"] == true && a["member"] == true && a["clock_ahead"] == false;
    report.add("authority", if ready {Status::Pass} else {Status::Fail}, if ready {"Signed configuration is current and this node is enrolled."} else {"Signed authority is expired, this node is removed, or the clock moved backward."},
        json!({"revision":a["revision"],"expires_at":a["expires_at"],"fresh":a["fresh"],"member":a["member"],"clock_ahead":a["clock_ahead"]}),
        (!ready).then_some(("Check system time and the active owner's renewal/revocation state. Reconnecting cannot override removal.", &[][..])));
    report.add("config_projection", if v["config_saved"] == true {Status::Pass} else {Status::Warn},
        if v["config_saved"] == true {"No committed configuration is waiting for a file write."} else {"Signed configuration is committed but its TOML projection is pending."}, json!({}),
        (v["config_saved"] != true).then_some(("Check free space and node directory permissions; normal daemon maintenance retries the write.", &[][..])));
    if v["relay"]["configured"] != true {
        report.add(
            "relay",
            Status::Skip,
            "This node has no relay configured.",
            json!({}),
            None,
        );
        return;
    }
    let h = &v["relay"]["health"];
    let now = auth::now().unwrap_or(0);
    let recent = h["observed_at"]
        .as_u64()
        .is_some_and(|at| at <= now && now - at <= 90);
    let trouble = h["local_error"] == true || h["retrying_streams"].as_u64().unwrap_or(0) > 0;
    let contact = h["notifications_connected"] == true
        || h["last_success_at"]
            .as_u64()
            .is_some_and(|at| at <= now && now - at <= 90);
    report.add("relay", if trouble || !recent || !contact {Status::Warn} else {Status::Pass},
        if trouble {"Ordered synchronization has pending retries or a local error."} else if !recent {"Relay observations are missing or stale."} else if contact {"Recent relay contact was observed; this does not prove peer delivery or file transfer."} else {"Relay is configured; no successful network contact has been observed yet."},
        json!({"observed_at":h["observed_at"],"last_success_at":h["last_success_at"],"last_failure_at":h["last_failure_at"],"notifications_connected":h["notifications_connected"],"retrying_streams":h["retrying_streams"],"local_error":h["local_error"]}),
        (trouble || !recent || !contact).then_some(("Inspect daemon logs, network access and relay credentials; retry after recovery.", &["daemon", "logs"][..])));
}

fn inspect_account(report: &mut Report, value: Option<Value>, required: bool, online: bool) {
    let Some(v) = value else {
        report.add(
            "account",
            Status::Fail,
            "Saved account state or its node pin is invalid.",
            json!({}),
            Some((
                "Inspect the account source and service/account pins; preserve cluster keys.",
                &[],
            )),
        );
        return;
    };
    let status = v["status"].as_str().unwrap_or("");
    let evidence = json!({"status":v["status"],"source":v["source"],"expires_at":v["expires_at"],"shared":v["shared"]});
    match status {
        "active" => report.add(
            "account",
            Status::Pass,
            "The Gent service accepted the saved account session.",
            evidence,
            None,
        ),
        "cached" => report.add(
            "account",
            Status::Skip,
            "A locally unexpired session is saved; remote validity was not checked.",
            evidence,
            Some((
                "Use --online to check this session without signing in or renewing.",
                &["doctor", "--online"],
            )),
        ),
        "signed_out" if !required => report.add(
            "account",
            Status::Skip,
            "No account session is required for this development node.",
            evidence,
            None,
        ),
        "signed_out" | "expired" | "login_pending" => report.add(
            "account",
            Status::Warn,
            "Account login is missing, expired or unfinished.",
            evidence,
            Some((
                "Complete account login; this does not replace encryption identity.",
                &["auth", "login"],
            )),
        ),
        "revocation_pending" => report.add(
            "account",
            Status::Warn,
            "Local logout is pending service revocation.",
            evidence,
            Some((
                "Retry the pending logout when the service is reachable.",
                &["auth", "logout"],
            )),
        ),
        _ => report.add(
            "account",
            Status::Warn,
            if online {
                "The saved session could not be verified at the service."
            } else {
                "The saved session state could not be classified."
            },
            evidence,
            Some((
                "Check connectivity and service availability, then repeat the diagnostic.",
                &["doctor", "--online"],
            )),
        ),
    }
}

fn inspect_integration(report: &mut Report, id: &'static str, value: Option<Value>) {
    match value {
        Some(v) if v["state"] == "absent" => report.add(id, Status::Skip, "Optional user-scope MCP integration is not installed.", json!({}), None),
        Some(v) if v["state"] == "configured" && v["current_home"] == true && v["binary_available"] == true => report.add(id, Status::Pass, "Managed MCP configuration matches this node; effective GUI/project settings were not tested.", json!({}), None),
        Some(v) if v["state"] == "configured" && v["current_home"] == false => report.add(id, Status::Warn, "This integration points to an obsolete Gent directory.", json!({"integration_home":v["gent_home"]}), Some(("Run gent node reset to retire legacy installations, re-enroll, then reinstall the host integration.", &["node", "reset"]))),
        _ => report.add(id, Status::Warn, "MCP configuration is edited, disabled, incomplete or points to an unavailable binary.", json!({}), Some(("Inspect installation status; preserve unrelated host settings and pending operations.", &["integration", "status"]))),
    }
}

#[cfg(test)]
mod tests;
