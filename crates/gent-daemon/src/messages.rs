//! Private node-to-node wire records. Only a verified MLS stream authenticates
//! the hosting node; labels and agent IDs supplied by a model never do.
use anyhow::{Result, ensure};
use gent_crypto::{Checkpoint, SignedLegacyAgentBinding, VerifiedState, agent_id, scoped_id};
use gent_protocol::Message;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const FRAGMENT_BYTES: usize = 256 * 1024;
pub const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PENDING_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub id: String,
    pub node: String,
    pub nonce: Option<Uuid>,
    pub legacy: Option<SignedLegacyAgentBinding>,
    pub generation: u64,
    pub name: String,
    pub provider: String,
    pub revoked: bool,
}
impl Registration {
    pub fn verify(&self, state: &VerifiedState, node: &str) -> Result<()> {
        ensure!(
            self.node == node && state.state().nodes.contains_key(node),
            "registration belongs to another node"
        );
        ensure!(
            (1..=(1 << 53) - 1).contains(&self.generation),
            "invalid registration generation"
        );
        crate::config::label(&self.name)?;
        crate::config::label(&self.provider)?;
        match (&self.nonce, &self.legacy) {
            (Some(nonce), None) => ensure!(
                agent_id(node, *nonce)? == self.id,
                "agent ID does not belong to node"
            ),
            (None, Some(binding)) => binding.verify(state.anchor(), &self.id, node)?,
            _ => anyhow::bail!("ambiguous agent binding"),
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    Registration {
        agent: Registration,
    },
    Message {
        sender: Box<Registration>,
        request_id: String,
        message: Message,
    },
    Receipt {
        message_id: String,
        delivered: bool,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: u8,
    pub authority: Checkpoint,
    pub event: Event,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frame {
    Part {
        version: u8,
        id: Uuid,
        digest: [u8; 32],
        total: usize,
        offset: usize,
        data: String,
    },
    Cancel {
        version: u8,
        id: Uuid,
    },
}

pub fn message_id(sender: &str, request: &str) -> Result<String> {
    let sender = Uuid::parse_str(sender)?;
    let request = Uuid::parse_str(request)?;
    ensure!(
        !sender.is_nil() && !request.is_nil(),
        "nil message identity"
    );
    Ok(scoped_id(
        b"gent/message-id/v1\0",
        &[sender.as_bytes(), request.as_bytes()],
    )
    .to_string())
}
pub fn packet_id(event: Uuid, offset: usize, cancelled: bool) -> Uuid {
    scoped_id(
        b"gent/event-fragment/v1\0",
        &[
            event.as_bytes(),
            &(offset as u64).to_be_bytes(),
            &[u8::from(cancelled)],
        ],
    )
}
