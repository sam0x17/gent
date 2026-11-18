//! Presentation only. Protocol responses never pass through the human renderer.
mod progress;
mod render;
use anyhow::Result;
pub(crate) use progress::Progress;
use serde_json::Value;
use std::{
    io::{IsTerminal, Write},
    sync::atomic::{AtomicBool, Ordering},
};

static MACHINE: AtomicBool = AtomicBool::new(true);

#[derive(Clone, Copy)]
pub(crate) struct Output {
    pub json: bool,
    pub verbose: bool,
    pub title: &'static str,
}

impl Output {
    pub fn raw(self) -> bool {
        self.json || self.verbose
    }

    pub fn print(self, value: &Value) -> Result<()> {
        let text = if self.json {
            serde_json::to_string(value)?
        } else if self.verbose {
            serde_json::to_string_pretty(value)?
        } else {
            render::response(self.title, value)
        };
        let result = writeln!(std::io::stdout().lock(), "{}", text.trim_end());
        match result {
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            other => other.map_err(Into::into),
        }
    }
}

pub(crate) fn configure(machine: bool) {
    MACHINE.store(machine, Ordering::Relaxed);
}
pub(crate) fn human() -> bool {
    !MACHINE.load(Ordering::Relaxed)
}
pub(crate) fn terminal() -> bool {
    std::env::var("TERM").is_ok_and(|term| term != "dumb")
}
pub(crate) fn color() -> bool {
    std::io::stdout().is_terminal() && terminal() && std::env::var_os("NO_COLOR").is_none()
}
pub(crate) fn paint(text: &str, code: &str) -> String {
    if color() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.into()
    }
}
pub(crate) fn heading(title: &str) {
    println!("{}  {}", paint("gent", "1;36"), paint(title, "1"));
}
pub(crate) fn field(label: &str, value: &str) {
    println!(
        "  {}  {}",
        paint(&format!("{label:<18}"), "2"),
        state(&crate::display::visible(value))
    );
}
pub(crate) fn state(text: &str) -> String {
    paint(
        text,
        match text.trim() {
            "running" | "ready" | "current" | "active" | "online" | "local" | "OK" => "32",
            "failed" | "error" | "FAIL" => "31",
            "offline" | "stopped" | "pending" | "WARN" => "33",
            _ => "2",
        },
    )
}

impl Output {
    pub fn for_cli(cli: &crate::Cli) -> Self {
        use crate::{Command as C, integration::Command as I};
        let protocol = matches!(
            &cli.command,
            Some(C::Integration {
                command: I::Hook { .. }
                    | I::ClaudeWake { .. }
                    | I::ClaudeWakeGuard { .. }
                    | I::Config { .. }
                    | I::CodexIde(_)
                    | I::CodexWrapper(_)
            }) | Some(C::Mcp { .. })
                | Some(C::Daemon {
                    command: Some(crate::DaemonCommand::Run)
                })
                | Some(C::Gateway {
                    command: Some(crate::gateway::Command::Run(_))
                })
        );
        let title = match &cli.command {
            None | Some(C::Cluster { .. }) => "Cluster",
            Some(C::Version) => "Version",
            Some(C::Update { .. }) => "Updates",
            Some(C::Daemon { .. }) => "Daemon",
            Some(C::Setup { .. }) => "Setup",
            Some(C::Auth { .. }) => "Account",
            Some(C::Node { .. }) => "Node",
            Some(C::Nodes) => "Nodes",
            Some(C::Sync { .. }) => "Sync",
            Some(C::Agent { .. }) => "Chat",
            Some(C::Agents { .. } | C::Resolve { .. }) => "Chats",
            Some(C::Integration { .. } | C::Integrations) => "Integrations",
            Some(C::Hooks { .. } | C::Completions { .. }) => "Shell",
            Some(C::Config { .. }) => "Configuration",
            Some(C::Doctor(_)) => "Doctor",
            Some(C::Providers { .. }) => "Providers",
            Some(C::Gateway { .. }) => "Gateway",
            Some(C::Relay { .. }) => "Relay",
            Some(C::Permission { .. }) => "Permissions",
            Some(C::Group { .. }) => "Groups",
            Some(C::Backup { .. }) => "Backup",
            Some(C::Recovery { .. }) => "Recovery",
            Some(C::Work { .. }) => "Work",
            Some(C::Wake { .. }) => "Wake",
            Some(C::Files { .. }) => "Files",
            Some(C::History { .. }) => "History",
            Some(C::Transport { .. }) => "Transport",
            Some(C::Mcp { .. }) => "MCP",
        };
        Self {
            json: cli.json || protocol,
            verbose: cli.verbose,
            title,
        }
    }
}
