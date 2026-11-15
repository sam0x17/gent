use anyhow::Result;
use clap::Subcommand;
use gent_protocol::OwnerOp;
use serde_json::Value;
use std::path::Path;

#[derive(Subcommand)]
pub enum Command {
    /// List local host dispatch evidence. This never starts or resumes a host.
    List {
        #[arg(long)]
        after: Option<String>,
    },
    /// Inspect a dispatch separately from message receipts and reported work.
    Show { message: String },
}

pub async fn execute(home: &Path, command: Option<Command>) -> Result<Value> {
    let action = match command.unwrap_or(Command::List { after: None }) {
        Command::List { after } => OwnerOp::WakeList {
            after_message_id: after,
        },
        Command::Show { message } => OwnerOp::WakeShow {
            message_id: message,
        },
    };
    crate::owner(home, action).await
}
