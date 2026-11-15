//! CLI adapters keep daemon enrollment separate from listener lifecycle.
use crate::{DaemonCommand, gateway::Run};

#[derive(clap::Subcommand)]
pub enum GatewayCommand {
    /// Inspect the managed listener and its private readiness channel.
    Status,
    /// Validate, register and start a systemd user service or macOS LaunchAgent.
    Install(Run),
    Start,
    Stop,
    Restart,
    /// Stop and remove this listener service, preserving clients and credentials.
    #[command(alias = "remove")]
    Uninstall,
    Logs {
        #[arg(long, default_value_t=100, value_parser=clap::value_parser!(u32).range(1..=10000))]
        lines: u32,
    },
}

pub(super) enum Install {
    Daemon { local: Option<String> },
    Gateway(Run),
}
pub(super) enum Action {
    Status,
    Install(Install),
    Start,
    Stop,
    Restart,
    Uninstall,
    Logs { lines: u32 },
}
impl From<DaemonCommand> for Action {
    fn from(value: DaemonCommand) -> Self {
        match value {
            DaemonCommand::Run => unreachable!("foreground runs do not use the service manager"),
            DaemonCommand::Status => Self::Status,
            DaemonCommand::Install { local, .. } => Self::Install(Install::Daemon { local }),
            DaemonCommand::Start => Self::Start,
            DaemonCommand::Stop => Self::Stop,
            DaemonCommand::Restart => Self::Restart,
            DaemonCommand::Uninstall => Self::Uninstall,
            DaemonCommand::Logs { lines } => Self::Logs { lines },
        }
    }
}
impl From<GatewayCommand> for Action {
    fn from(value: GatewayCommand) -> Self {
        match value {
            GatewayCommand::Status => Self::Status,
            GatewayCommand::Install(options) => Self::Install(Install::Gateway(options)),
            GatewayCommand::Start => Self::Start,
            GatewayCommand::Stop => Self::Stop,
            GatewayCommand::Restart => Self::Restart,
            GatewayCommand::Uninstall => Self::Uninstall,
            GatewayCommand::Logs { lines } => Self::Logs { lines },
        }
    }
}
