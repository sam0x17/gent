use anyhow::{Context, Result};
use gent_protocol::OwnerOp;
use serde_json::Value;
use std::path::Path;

pub async fn show(home: &Path, agent: String) -> Result<Value> {
    crate::owner(home, OwnerOp::Agent { agent_id: agent }).await
}

pub async fn rename(
    home: &Path,
    agent: String,
    name: String,
    expected_generation: Option<u64>,
) -> Result<Value> {
    let expected_generation = match expected_generation {
        Some(generation) => generation,
        None => show(home, agent.clone()).await?["registration_generation"]
            .as_u64()
            .context("missing registration generation")?,
    };
    crate::owner(
        home,
        OwnerOp::RenameAgent {
            agent_id: agent,
            name,
            expected_generation,
        },
    )
    .await
}
