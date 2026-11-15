use anyhow::Result;
use clap::Subcommand;
use gent_protocol::OwnerOp;
use serde_json::Value;
use std::path::Path;

pub(crate) mod codex;

#[derive(Subcommand)]
pub enum Command {
    /// List local host dispatch evidence. This never starts or resumes a host.
    List {
        #[arg(long)]
        after: Option<String>,
    },
    /// Show journal capacity and records eligible for retention cleanup.
    Status,
    /// Retire old, observed submissions whose message history has been removed.
    Clean {
        #[arg(long)]
        dry_run: bool,
    },
    /// Inspect a dispatch separately from message receipts and reported work.
    Show { message: String },
}

pub async fn execute(home: &Path, command: Option<Command>) -> Result<Value> {
    let action = match command.unwrap_or(Command::List { after: None }) {
        Command::List { after } => OwnerOp::WakeList {
            after_message_id: after,
        },
        Command::Status => OwnerOp::WakeStatus,
        Command::Clean { dry_run } => OwnerOp::WakeClean { dry_run },
        Command::Show { message } => OwnerOp::WakeShow {
            message_id: message,
        },
    };
    crate::owner(home, action).await
}
