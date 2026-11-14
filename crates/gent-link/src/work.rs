use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use gent_protocol::{OwnerOp, work::WorkResolution};
use serde_json::Value;
use std::path::Path;

#[derive(Subcommand)]
pub enum Command {
    /// List local execution reports, including unfinished attempts.
    List {
        #[arg(long)]
        after: Option<String>,
    },
    /// Show a recorded message and its complete local transition history.
    Show { message: String },
    /// Record a reviewed outcome or explicitly allow another attempt.
    /// Check the host's real work state first. This never executes or sends work.
    Reconcile {
        message: String,
        #[arg(long)]
        expect_revision: u64,
        #[arg(long, value_enum)]
        decision: Decision,
        /// What was checked, and why this resolution is appropriate.
        #[arg(long)]
        note: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Decision {
    Completed,
    Abandoned,
    RetryApproved,
}

pub async fn execute(home: &Path, command: Option<Command>) -> Result<Value> {
    let action = match command.unwrap_or(Command::List { after: None }) {
        Command::List { after } => OwnerOp::WorkList {
            after_message_id: after,
        },
        Command::Show { message } => OwnerOp::WorkShow {
            message_id: message,
        },
        Command::Reconcile {
            message,
            expect_revision,
            decision,
            note,
        } => OwnerOp::WorkReconcile {
            message_id: message,
            expect_revision,
            note,
            resolution: match decision {
                Decision::Completed => WorkResolution::Completed,
                Decision::Abandoned => WorkResolution::Abandoned,
                Decision::RetryApproved => WorkResolution::RetryApproved,
            },
        },
    };
    crate::owner(home, action).await
}
