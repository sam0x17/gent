use anyhow::Result;
use clap::Subcommand;
use gent_protocol::{OwnerOp, notifications::Failure, wake::DirectTurnEvidence};
use serde_json::Value;
use std::path::Path;
use uuid::Uuid;

pub(crate) mod codex;

pub(crate) async fn direct_turn_evidence(
    home: &Path,
    credential: &str,
    thread: &str,
    turn: Uuid,
) -> Result<Option<DirectTurnEvidence>> {
    let result = crate::owner(
        home,
        OwnerOp::WakeDirectTurnEvidence {
            agent_credential: credential.into(),
            thread_id: Uuid::parse_str(thread)?,
            turn,
        },
    )
    .await?;
    Ok(serde_json::from_value(result)?)
}

pub(crate) async fn verified_blocked_claim(
    home: &Path,
    credential: &str,
    thread: &str,
    goal: String,
    turn: Uuid,
    failed_at: i64,
    reason: Failure,
) -> Result<Value> {
    crate::owner(
        home,
        OwnerOp::BabysitterVerifiedBlockedClaim {
            agent_credential: credential.into(),
            thread_id: Uuid::parse_str(thread)?,
            goal,
            turn,
            failed_at,
            reason,
        },
    )
    .await
}

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
    let mut value = crate::owner(home, action).await?;
    fn describe(record: &mut Value) {
        if record.get("message_id").is_none() {
            return;
        }
        record["delivery_status"] = if !record["inbox_seen_at"].is_null() {
            "seen"
        } else if record["state"] == "submitted" {
            "submitted_not_seen"
        } else {
            "submission_uncertain"
        }
        .into();
    }
    describe(&mut value);
    if let Some(entries) = value["entries"].as_array_mut() {
        for entry in entries {
            describe(entry);
        }
    }
    Ok(value)
}
