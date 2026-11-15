//! Host metadata selects credentials outside model-controlled tool arguments.
//! The local host and OS user are trusted; this is not remote authentication.
pub(crate) mod claude_wake;
mod install;
pub(crate) mod wake;
use anyhow::{Context, Result, ensure};
use clap::{Subcommand, ValueEnum};
use fs2::FileExt;
use gent_daemon::config;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const TICKET_TTL: u64 = 600;
const MAX_TICKETS: usize = 4096;
const MAX_BINDINGS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Host {
    Codex,
    ClaudeCode,
}
impl Host {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
        }
    }
    fn client(self) -> &'static str {
        match self {
            Self::Codex => "codex-mcp-client",
            Self::ClaudeCode => "claude-code",
        }
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Inspect user-scope installation without changing settings.
    Status {
        host: Option<Host>,
        /// Host config directory (CODEX_HOME or CLAUDE_CONFIG_DIR).
        #[arg(long, requires = "host")]
        config_dir: Option<PathBuf>,
    },
    /// Install the MCP connection and required conversation identity hook.
    Install(install::Args),
    /// Remove Gent-managed host entries, retaining conversations and Gent state.
    #[command(alias = "remove")]
    Uninstall(install::Args),
    /// Print MCP configuration and any required host hooks; does not edit settings.
    Config {
        host: Host,
        /// Use Codex's default local app-server socket for queued delivery.
        #[arg(long, conflicts_with = "wake_socket")]
        wake: bool,
        /// Codex config directory used to resolve --wake (defaults to CODEX_HOME).
        #[arg(long, requires = "wake")]
        config_dir: Option<PathBuf>,
        /// Opt into queued Codex wake through an existing local app-server socket.
        #[arg(long)]
        wake_socket: Option<PathBuf>,
    },
    /// Receive a host's PreToolUse event on stdin. For host configuration only.
    #[command(hide = true)]
    Hook { host: Host },
    /// Local native Claude plugin bridge. Input is bounded JSON on stdin.
    #[command(hide = true)]
    ClaudeWake {
        #[arg(long)]
        config_dir: PathBuf,
    },
    /// Retained Claude UserPromptSubmit command guard. For host settings only.
    #[command(hide = true)]
    ClaudeWakeGuard {
        #[arg(long)]
        config_dir: PathBuf,
    },
}

pub fn execute(home: &Path, command: Command) -> Result<Value> {
    match command {
        Command::ClaudeWake { .. } | Command::ClaudeWakeGuard { .. } => {
            anyhow::bail!("native bridge requires async dispatch")
        }
        Command::Status { host, config_dir } => install::status(home, host, config_dir),
        Command::Install(args) => install::change(home, args, true),
        Command::Uninstall(args) => install::change(home, args, false),
        Command::Config {
            host,
            wake,
            config_dir,
            wake_socket,
        } => {
            let socket = if wake {
                Some(install::default_wake_socket(host, config_dir)?)
            } else {
                wake_socket
            };
            configuration(home, host, socket.as_deref())
        }
        Command::Hook { host } => {
            ensure!(
                host == Host::ClaudeCode,
                "this host does not need a binding hook"
            );
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(gent_protocol::MAX_FRAME_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= gent_protocol::MAX_FRAME_BYTES,
                "hook input too large"
            );
            let input: Value = serde_json::from_slice(&bytes).context("invalid hook JSON")?;
            record_hook(home, &input, now()?)?;
            // No permission decision or model context is supplied by this hook.
            Ok(json!({}))
        }
    }
}

fn configuration(home: &Path, host: Host, wake_socket: Option<&Path>) -> Result<Value> {
    let home = fs::canonicalize(home).context("initialize this Gent node first")?;
    config::load(&home)?;
    let binary = fs::canonicalize(std::env::current_exe()?)?;
    configure_wake(
        render_configuration(&home, &binary, host)?,
        host,
        wake_socket,
    )
}

fn configure_wake(mut fragments: Value, host: Host, socket: Option<&Path>) -> Result<Value> {
    if let Some(socket) = socket {
        ensure!(
            host == Host::Codex,
            "queued wake is currently supported only for Codex"
        );
        let path = socket.to_str().context("wake socket path must be UTF-8")?;
        ensure!(
            socket.is_absolute() && !path.chars().any(char::is_control),
            "wake socket path must be absolute and contain no control characters"
        );
        fragments["mcp_servers"]["gent"]["args"]
            .as_array_mut()
            .expect("Codex arguments")
            .extend([json!("--wake-socket"), json!(path)]);
    }
    Ok(fragments)
}

fn render_configuration(home: &Path, binary: &Path, host: Host) -> Result<Value> {
    let binary = binary
        .to_str()
        .context("Gent executable path must be UTF-8")?;
    let home = home.to_str().context("Gent state path must be UTF-8")?;
    let args = ["--home", home, "mcp", "serve", "--host", host.name()];
    match host {
        Host::Codex => {
            Ok(json!({"host":host,"mcp_servers":{"gent":{"command":binary,"args":args}}}))
        }
        Host::ClaudeCode => {
            let command = [binary, "--home", home, "integration", "hook", "claude-code"]
                .map(shell_arg)
                .join(" ");
            Ok(
                json!({"host":host,"mcpServers":{"gent":{"type":"stdio","command":binary,"args":args}},"settings":{"hooks":{"PreToolUse":[{"matcher":"^mcp__gent__gent_","hooks":[{"type":"command","command":command,"timeout":10}]}]}}}),
            )
        }
    }
}
fn shell_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn digest(value: &Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("JSON serializes"))
    )
}
fn identifier(value: Option<&Value>) -> Result<&str> {
    let value = value
        .and_then(Value::as_str)
        .context("host conversation metadata is missing")?;
    ensure!(
        !value.is_empty()
            && value.len() <= 256
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "invalid host conversation metadata"
    );
    Ok(value)
}
fn session_key(session: &str, agent: Option<&str>) -> String {
    digest(&json!(["gent-host-binding-v1", session, agent]))
}
fn scope(home: &Path, host: Host) -> Result<PathBuf> {
    let config = config::load(home)?;
    let bindings = home.join("host-bindings");
    config::private_dir(home)?;
    config::private_dir(&bindings)?;
    let folder = scope_path(home, &config, host);
    config::private_dir(&folder)?;
    Ok(folder)
}

fn scope_path(home: &Path, cfg: &config::Config, host: Host) -> PathBuf {
    home.join("host-bindings")
        .join(digest(&json!([cfg.cluster.id, cfg.node.id, host.name()])))
}

pub(crate) fn recovery_binding(
    home: &Path,
    host: Host,
    conversation: &str,
    subagent: Option<&str>,
) -> Result<PathBuf> {
    identifier(Some(&json!(conversation)))?;
    if let Some(id) = subagent {
        ensure!(
            host == Host::ClaudeCode,
            "Codex child agents use their own conversation IDs"
        );
        identifier(Some(&json!(id)))?;
    }
    Ok(scope(home, host)?.join(format!("{}.key", session_key(conversation, subagent))))
}
fn private_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o077 == 0,
        "host binding state must be a private regular file without links"
    );
    Ok(())
}
fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    private_file(path)?;
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "host binding record is too large");
    Ok(bytes)
}
fn lock(path: &Path) -> Result<File> {
    match fs::symlink_metadata(path) {
        Ok(_) => private_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    let end = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < end =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e).context("host binding state is busy; retry the call"),
        }
    }
}

struct Binding {
    credential: String,
    _opened: crate::mcp::binding::Opened,
}
impl Binding {
    fn open(path: &Path, cfg: &config::Config) -> Result<Self> {
        let opened = crate::mcp::binding::open(path, cfg, true)?;
        Ok(Self {
            credential: opened.credential.clone(),
            _opened: opened,
        })
    }
}

pub struct Bindings {
    host: Host,
    cfg: config::Config,
    folder: PathBuf,
    active: BTreeMap<String, Binding>,
    wake_endpoint: Option<PathBuf>,
}
impl Bindings {
    pub fn new(home: &Path, host: Host) -> Result<Self> {
        Ok(Self {
            host,
            cfg: config::load(home)?,
            folder: scope(home, host)?,
            active: BTreeMap::new(),
            wake_endpoint: None,
        })
    }
    pub fn credential(
        &mut self,
        client: &str,
        meta: &Value,
        tool: &str,
        arguments: &Value,
    ) -> Result<String> {
        ensure!(
            client == self.host.client(),
            "MCP client does not match the configured host binding mode"
        );
        let key = match self.host {
            // sessionId can identify a tree of forked threads. Only threadId
            // identifies this conversation; never fall back to the tree root.
            Host::Codex => session_key(identifier(meta.get("threadId"))?, None),
            Host::ClaudeCode => {
                let id = identifier(meta.get("claudecode/toolUseId"))?;
                let path = self
                    .folder
                    .join("calls")
                    .join(format!("{}.json", digest(&json!(id))));
                let ticket: Ticket = serde_json::from_slice(&read_bounded(&path)
                    .context("Gent's Claude Code PreToolUse hook is required for every call; configure or re-enable it")?)?;
                ticket.verify(now()?, tool, arguments)?;
                ticket.binding
            }
        };
        if !self.active.contains_key(&key) {
            ensure!(
                self.active.len() < MAX_BINDINGS,
                "MCP connection binding limit reached; reconnect the host"
            );
            // Separate lock protects initial credential creation, including two
            // hosts reconnecting before either has opened the binding file.
            let _lock = lock(&self.folder.join("bindings.lock"))?;
            let binding = Binding::open(&self.folder.join(format!("{key}.key")), &self.cfg)?;
            self.active.insert(key.clone(), binding);
        }
        if self.host == Host::Codex
            && let Some(thread) = meta.get("threadId").and_then(Value::as_str)
            && wake::valid_thread(thread)
        {
            wake::remember(
                &self.folder,
                &self.cfg,
                thread,
                &self.active[&key].credential,
                self.wake_endpoint.as_deref(),
            )?;
        }
        Ok(self.active[&key].credential.clone())
    }

    pub(crate) fn enable_wake(&mut self, home: &Path, endpoint: &Path) -> Result<wake::Registry> {
        ensure!(
            self.host == Host::Codex,
            "queued wake requires Codex bindings"
        );
        let registry = wake::Registry::new(home, self.folder.clone(), self.cfg.clone(), endpoint)?;
        self.wake_endpoint = Some(registry.endpoint.clone());
        Ok(registry)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    version: u8,
    created_at: u64,
    binding: String,
    call: String,
}
impl Ticket {
    fn verify(&self, time: u64, tool: &str, arguments: &Value) -> Result<()> {
        ensure!(
            self.version == 1 && self.created_at <= time && time - self.created_at <= TICKET_TTL,
            "host call handoff expired; retry through the host hook"
        );
        ensure!(
            self.binding.len() == 64 && self.binding.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid host binding record"
        );
        ensure!(
            self.call == digest(&json!([tool, arguments])),
            "host call does not match its hook handoff"
        );
        Ok(())
    }
}

fn record_hook(home: &Path, input: &Value, time: u64) -> Result<()> {
    ensure!(
        input["hook_event_name"] == "PreToolUse",
        "expected a PreToolUse event"
    );
    let session = identifier(input.get("session_id"))?;
    let agent = input
        .get("agent_id")
        .map(|value| identifier(Some(value)))
        .transpose()?;
    let id = identifier(input.get("tool_use_id"))?;
    let tool = input["tool_name"]
        .as_str()
        .and_then(|t| t.strip_prefix("mcp__gent__"))
        .filter(|t| t.starts_with("gent_"))
        .context("expected a Gent tool call")?;
    let arguments = input
        .get("tool_input")
        .filter(|v| v.is_object())
        .context("expected tool arguments")?;
    let ticket = Ticket {
        version: 1,
        created_at: time,
        binding: session_key(session, agent),
        call: digest(&json!([tool, arguments])),
    };
    let folder = scope(home, Host::ClaudeCode)?.join("calls");
    config::private_dir(&folder)?;
    let _lock = lock(&folder.join("calls.lock"))?;
    let path = folder.join(format!("{}.json", digest(&json!(id))));
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let existing: Ticket = serde_json::from_slice(&read_bounded(&path)?)?;
            ensure!(
                existing.binding == ticket.binding && existing.call == ticket.call,
                "conflicting host call handoff"
            );
            existing.verify(time, tool, arguments)?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut count = 0;
    for entry in fs::read_dir(&folder)?.take(MAX_TICKETS + 2) {
        let entry = entry?;
        if entry.file_name() == "calls.lock" {
            continue;
        }
        let stale = fs::symlink_metadata(entry.path())?
            .modified()?
            .elapsed()
            .is_ok_and(|elapsed| elapsed.as_secs() > TICKET_TTL);
        if stale {
            private_file(&entry.path())?;
            fs::remove_file(entry.path())?;
        } else {
            count += 1;
        }
    }
    ensure!(
        count < MAX_TICKETS,
        "too many pending host call handoffs; retry after older calls expire"
    );
    // Only hashes and a timestamp persist. Hook input may contain user content;
    // never write that content, session IDs, credentials, or transcripts here.
    config::write_private(&path, &serde_json::to_vec(&ticket)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn home() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let folder = tempfile::tempdir().unwrap();
        fs::set_permissions(folder.path(), fs::Permissions::from_mode(0o700)).unwrap();
        config::initialize(folder.path(), "bindings").unwrap();
        folder
    }
    #[test]
    fn codex_threads_are_isolated_and_resume_without_model_selected_identity() {
        let home = home();
        let mut bindings = Bindings::new(home.path(), Host::Codex).unwrap();
        let call = |b: &mut Bindings, thread| {
            b.credential(
                "codex-mcp-client",
                &json!({"threadId":thread,"sessionId":"shared-root"}),
                "gent_register",
                &json!({}),
            )
        };
        let first = call(&mut bindings, "thread-a").unwrap();
        let second = call(&mut bindings, "thread-b").unwrap();
        assert_ne!(first, second);
        assert_eq!(first, call(&mut bindings, "thread-a").unwrap());
        assert!(
            bindings
                .credential(
                    "codex-mcp-client",
                    &json!({"sessionId":"shared-root"}),
                    "gent_register",
                    &json!({"threadId":"thread-a"})
                )
                .is_err()
        );
        assert!(
            bindings
                .credential(
                    "other",
                    &json!({"threadId":"thread-a"}),
                    "gent_identity",
                    &json!({})
                )
                .is_err()
        );
        assert!(call(&mut bindings, "../escape").is_err());
        let mut duplicate = Bindings::new(home.path(), Host::Codex).unwrap();
        assert!(call(&mut duplicate, "thread-a").is_err());
        drop(bindings);
        assert_eq!(first, call(&mut duplicate, "thread-a").unwrap());
        assert_ne!(
            scope(home.path(), Host::Codex).unwrap(),
            scope(home.path(), Host::ClaudeCode).unwrap()
        );
    }
    #[test]
    fn claude_handoff_is_per_call_with_session_and_subagent_isolation() {
        let home = home();
        let time = now().unwrap();
        let mut bindings = Bindings::new(home.path(), Host::ClaudeCode).unwrap();
        let mut input = json!({"hook_event_name":"PreToolUse","session_id":"old-chat","tool_use_id":"use-a","tool_name":"mcp__gent__gent_register","tool_input":{"name":"private content","provider":"claude-code"}});
        let call = |b: &mut Bindings, id| {
            b.credential(
                "claude-code",
                &json!({"claudecode/toolUseId":id}),
                "gent_register",
                &input["tool_input"],
            )
        };
        assert!(call(&mut bindings, "use-a").is_err());
        record_hook(home.path(), &input, time).unwrap();
        let a = call(&mut bindings, "use-a").unwrap();
        record_hook(home.path(), &input, time).unwrap();
        assert_eq!(a, call(&mut bindings, "use-a").unwrap());
        assert!(
            bindings
                .credential(
                    "claude-code",
                    &json!({"claudecode/toolUseId":"use-a"}),
                    "gent_inbox",
                    &json!({})
                )
                .is_err()
        );
        input["session_id"] = "new-chat".into();
        assert!(record_hook(home.path(), &input, time).is_err());
        input["tool_use_id"] = "use-b".into();
        record_hook(home.path(), &input, time).unwrap();
        let b = bindings
            .credential(
                "claude-code",
                &json!({"claudecode/toolUseId":"use-b"}),
                "gent_register",
                &input["tool_input"],
            )
            .unwrap();
        assert_ne!(a, b);
        input["agent_id"] = "child".into();
        input["tool_use_id"] = "use-c".into();
        record_hook(home.path(), &input, time).unwrap();
        assert_ne!(
            b,
            bindings
                .credential(
                    "claude-code",
                    &json!({"claudecode/toolUseId":"use-c"}),
                    "gent_register",
                    &input["tool_input"]
                )
                .unwrap()
        );
        let path = bindings
            .folder
            .join("calls")
            .join(format!("{}.json", digest(&json!("use-a"))));
        let bytes = read_bounded(&path).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(
            !text.contains("private content") && !text.contains("old-chat") && !text.contains(&a)
        );
        let ticket: Ticket = serde_json::from_slice(&bytes).unwrap();
        assert!(
            ticket
                .verify(time + TICKET_TTL + 1, "gent_register", &input["tool_input"])
                .is_err()
        );
        assert!(
            ticket
                .verify(time - 1, "gent_register", &input["tool_input"])
                .is_err()
        );
        input["tool_use_id"] = "linked".into();
        let path = bindings
            .folder
            .join("calls")
            .join(format!("{}.json", digest(&json!("linked"))));
        std::os::unix::fs::symlink(home.path().join("absent"), &path).unwrap();
        assert!(record_hook(home.path(), &input, time).is_err());
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    }
    #[test]
    fn host_state_rejects_shared_symlink_and_hard_link_files() {
        use std::os::unix::fs::PermissionsExt;
        let home = home();
        let path = home.path().join("credential");
        let cfg = config::load(home.path()).unwrap();
        let binding = Binding::open(&path, &cfg).unwrap();
        drop(binding);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Binding::open(&path, &cfg).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = home.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(Binding::open(&link, &cfg).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&path, &link).unwrap();
        assert!(Binding::open(&path, &cfg).is_err());
        assert_eq!(shell_arg("a '$HOME"), "'a '\"'\"'$HOME'");
    }
}
